using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using FNPPAnalyzer.Config;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Rules.Network
{
    // HIDS-N1/N2/N3/N4: Network anomaly detection.
    public class SuspiciousNetworkActivityRule : IDetectionRule
    {
        public string RuleId => "NET";
        public string Name => "Network Anomaly Detection";
        public string Description => "Detects suspicious outbound connections, port scanning, and traffic bursts.";

        // NET-004: Processes that have established connections to external IPs
        // while their executable lives in a user-writable directory.
        private static readonly string[] UntrustedPathFragments =
        [
            @"\Temp\", @"\Downloads\", @"\AppData\Local\Temp\",
            @"\AppData\Roaming\", @"\Public\", @"C:\Temp\"
        ];

        // RFC-1918 + loopback — don't flag connections that stay on-LAN
        private static bool IsPrivateOrLoopback(IPAddress ip)
        {
            if (ip.Equals(IPAddress.Loopback) || ip.Equals(IPAddress.IPv6Loopback)) return true;
            byte[] b = ip.GetAddressBytes();
            if (b.Length != 4) return false;
            return b[0] == 10 ||
                   (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                   (b[0] == 192 && b[1] == 168) ||
                   b[0] == 127;
        }

        private readonly AppConfig _config;

        public SuspiciousNetworkActivityRule(AppConfig config) => _config = config;

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();
            var conns   = context.TcpConnections;
            var pidConns = context.TcpConnectionsWithPid;

            // HIDS-N1: Known C2/RAT ports (list configurable via config.json SuspiciousPorts)
            foreach (var conn in conns)
            {
                if ((conn.State == TcpState.Established || conn.State == TcpState.SynSent)
                    && _config.SuspiciousPorts.Contains(conn.RemoteEndPoint.Port))
                {
                    events.Add(new DetectionEvent
                    {
                        RuleId      = "NET-001",
                        RuleName    = "Suspicious Outbound Port",
                        Severity    = AlertSeverity.High,
                        Type        = AlertType.TROJ,
                        Description = $"Connection to suspicious port {conn.RemoteEndPoint.Port} at {conn.RemoteEndPoint.Address}",
                        DedupeKey   = $"{conn.RemoteEndPoint.Address}:{conn.RemoteEndPoint.Port}",
                        Metadata    = new { Local = conn.LocalEndPoint.ToString(), Remote = conn.RemoteEndPoint.ToString() }
                    });
                }
            }

            // HIDS-N2: This host holding connections to many distinct ports on one remote
            // IP — outbound port-scan behaviour (something on this machine probing a target).
            var scanCandidates = conns
                .GroupBy(c => c.RemoteEndPoint.Address)
                .Select(g => new { IP = g.Key, Ports = g.Select(c => c.RemoteEndPoint.Port).Distinct().Count() })
                .Where(x => x.Ports > 20);

            foreach (var candidate in scanCandidates)
                events.Add(new DetectionEvent
                {
                    RuleId      = "NET-002",
                    RuleName    = "Outbound Port Scan Detected",
                    Severity    = AlertSeverity.Medium,
                    Type        = AlertType.RECON,
                    Description = $"Possible outbound port scan: {candidate.Ports} distinct ports reached on {candidate.IP}.",
                    // Description embeds the (volatile) port count — key dedup on the
                    // target IP so this doesn't re-fire every cycle while ongoing.
                    DedupeKey   = candidate.IP.ToString()
                });

            // HIDS-N3: High total connection count
            int threshold = _config.Rules.TryGetValue("NET-003", out var cfg) ? cfg.Threshold : 100;
            if (conns.Length > threshold)
                events.Add(new DetectionEvent
                {
                    RuleId      = "NET-003",
                    RuleName    = "Connection Count Burst",
                    Severity    = AlertSeverity.Medium,
                    Type        = AlertType.RECON,
                    Description = $"High TCP connection count: {conns.Length} (threshold: {threshold}).",
                    // Volatile count in the description — constant key so an ongoing burst
                    // re-alerts once per cooldown, not once per 30s cycle.
                    DedupeKey   = "connection-burst"
                });

            // HIDS-N4: Process from untrusted path with external connections, or Tor circuit usage.
            // Uses PID-aware TCP table when available.
            if (pidConns.Count > 0)
            {
                // ScanContext already resolved every process's executable path once —
                // reuse it instead of re-walking MainModule for this rule too.
                var pidToPath = context.ProcessPaths;

                foreach (var c in pidConns)
                {
                    if (c.State != NetworkHelper.MIB_TCP_STATE_ESTAB &&
                        c.State != NetworkHelper.MIB_TCP_STATE_SYN_SENT)
                        continue;

                    if (IsPrivateOrLoopback(c.RemoteAddress)) continue;

                    // Sub-rule A: Tor circuit connection. Ports 9001/9030 are also used by
                    // ordinary services (SonarQube, HDFS, Tomcat clustering), so processes
                    // running from trusted install paths are excluded — flag only unknown
                    // processes or ones running from user-writable locations.
                    if (c.RemotePort == 9001 || c.RemotePort == 9030)
                    {
                        pidToPath.TryGetValue(c.OwningPid, out string? procPath);
                        if (procPath != null &&
                            PathTrust.IsUnderTrustedPath(procPath, _config.TrustedExecutionPaths))
                            continue;

                        events.Add(new DetectionEvent
                        {
                            RuleId         = "NET-004",
                            RuleName       = "Tor Circuit Connection",
                            Severity       = AlertSeverity.High,
                            Type           = AlertType.BACK,
                            Description    = $"PID {c.OwningPid} connected to Tor relay port {c.RemotePort} at {c.RemoteAddress}",
                            ExecutablePath = procPath ?? string.Empty,
                            DedupeKey      = procPath ?? $"tor:{c.RemoteAddress}",
                            Metadata       = new { Pid = c.OwningPid, Remote = $"{c.RemoteAddress}:{c.RemotePort}", ProcessPath = procPath }
                        });
                        continue;
                    }

                    // Sub-rule B: Process with executable in untrusted directory has external connection
                    if (!pidToPath.TryGetValue(c.OwningPid, out string? exePath)) continue;
                    bool fromUntrusted = UntrustedPathFragments.Any(f =>
                        exePath.Contains(f, StringComparison.OrdinalIgnoreCase));
                    if (!fromUntrusted) continue;

                    events.Add(new DetectionEvent
                    {
                        RuleId         = "NET-004",
                        RuleName       = "Untrusted Process External Connection",
                        Severity       = AlertSeverity.High,
                        Type           = AlertType.BACK,
                        Description    = $"Process from untrusted path has external TCP connection: {System.IO.Path.GetFileName(exePath)} → {c.RemoteAddress}:{c.RemotePort}",
                        ExecutablePath = exePath,
                        Metadata       = new { Pid = c.OwningPid, ProcessPath = exePath, Remote = $"{c.RemoteAddress}:{c.RemotePort}" }
                    });
                }
            }

            return events;
        }
    }
}
