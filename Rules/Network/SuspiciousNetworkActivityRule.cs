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

        // NET-001: Known C2/RAT/tunneling ports.
        // Sources: Metasploit defaults (4444-4446), Cobalt Strike (50050), Sliver (31337/8888),
        //          Havoc (40056), Empire (5000), IRC (6667/6697), Tor circuits (9001/9030/9050/9051),
        //          Radmin (4899), VNC plaintext (5900-5901), SOCKS5 (1080).
        private static readonly int[] SuspiciousPorts =
        [
            4444, 4445, 4446,       // Metasploit reverse handlers
            6667, 6697,             // IRC (DarkComet, njRAT C2)
            1337, 31337,            // "leet" RAT defaults
            50050,                  // Cobalt Strike team-server
            40056,                  // Havoc C2 default
            8888,                   // Sliver/various RATs
            9001, 9030, 9050, 9051, // Tor relay/SOCKS ports
            4899,                   // Radmin remote-admin tool
            5900, 5901,             // VNC (unencrypted remote access)
            1080,                   // SOCKS5 proxy tunneling
            5000,                   // Empire/PowerShell Empire default
        ];

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

            // HIDS-N1: Known C2/RAT ports
            foreach (var conn in conns)
            {
                if ((conn.State == TcpState.Established || conn.State == TcpState.SynSent)
                    && SuspiciousPorts.Contains(conn.RemoteEndPoint.Port))
                {
                    events.Add(new DetectionEvent
                    {
                        RuleId      = "NET-001",
                        RuleName    = "Suspicious Outbound Port",
                        Severity    = AlertSeverity.High,
                        Type        = AlertType.TROJ,
                        Description = $"Connection to suspicious port {conn.RemoteEndPoint.Port} at {conn.RemoteEndPoint.Address}",
                        Metadata    = new { Local = conn.LocalEndPoint.ToString(), Remote = conn.RemoteEndPoint.ToString() }
                    });
                }
            }

            // HIDS-N2: One remote IP connected to many distinct local ports → port scan
            var scanCandidate = conns
                .GroupBy(c => c.RemoteEndPoint.Address)
                .Select(g => new { IP = g.Key, Ports = g.Select(c => c.RemoteEndPoint.Port).Distinct().Count() })
                .FirstOrDefault(x => x.Ports > 20);

            if (scanCandidate != null)
                events.Add(new DetectionEvent
                {
                    RuleId      = "NET-002",
                    RuleName    = "Port Scan Detected",
                    Severity    = AlertSeverity.Medium,
                    Type        = AlertType.RECON,
                    Description = $"Possible port scan: {scanCandidate.IP} reached {scanCandidate.Ports} distinct ports."
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
                    Description = $"High TCP connection count: {conns.Length} (threshold: {threshold})."
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

                    // Sub-rule A: Tor circuit connection from any process
                    if (c.RemotePort == 9001 || c.RemotePort == 9030)
                    {
                        pidToPath.TryGetValue(c.OwningPid, out string? procPath);
                        events.Add(new DetectionEvent
                        {
                            RuleId         = "NET-004",
                            RuleName       = "Tor Circuit Connection",
                            Severity       = AlertSeverity.High,
                            Type           = AlertType.BACK,
                            Description    = $"PID {c.OwningPid} connected to Tor relay port {c.RemotePort} at {c.RemoteAddress}",
                            ExecutablePath = procPath ?? string.Empty,
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
