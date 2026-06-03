using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using WinEDR_MVP.Config;
using WinEDR_MVP.Engine;
using WinEDR_MVP.Models;

namespace WinEDR_MVP.Rules.Network
{
    // HIDS-N1/N2/N3/N4: Network anomaly detection.
    public class SuspiciousNetworkActivityRule : IDetectionRule
    {
        public string RuleId => "NET";
        public string Name => "Network Anomaly Detection";
        public string Description => "Detects suspicious outbound connections, port scanning, and traffic bursts.";

        private static readonly int[] SuspiciousPorts = [4444, 6667, 1337, 31337];

        private readonly AppConfig _config;

        public SuspiciousNetworkActivityRule(AppConfig config) => _config = config;

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();
            var conns = context.TcpConnections;

            // HIDS-N1: Known C2/RAT ports
            foreach (var conn in conns)
            {
                if ((conn.State == TcpState.Established || conn.State == TcpState.SynSent)
                    && SuspiciousPorts.Contains(conn.RemoteEndPoint.Port))
                {
                    events.Add(new DetectionEvent
                    {
                        RuleId = "NET-001",
                        RuleName = "Suspicious Outbound Port",
                        Severity = AlertSeverity.High,
                        Type = AlertType.TROJ,
                        Description = $"Connection to suspicious port {conn.RemoteEndPoint.Port} at {conn.RemoteEndPoint.Address}",
                        Metadata = new { Local = conn.LocalEndPoint.ToString(), Remote = conn.RemoteEndPoint.ToString() }
                    });
                }
            }

            // HIDS-N2: One remote IP connected to many distinct ports → port scan
            var scanCandidate = conns
                .GroupBy(c => c.RemoteEndPoint.Address)
                .Select(g => new { IP = g.Key, Ports = g.Select(c => c.RemoteEndPoint.Port).Distinct().Count() })
                .FirstOrDefault(x => x.Ports > 20);

            if (scanCandidate != null)
                events.Add(new DetectionEvent
                {
                    RuleId = "NET-002",
                    RuleName = "Port Scan Detected",
                    Severity = AlertSeverity.Medium,
                    Type = AlertType.RECON,
                    Description = $"Connected to {scanCandidate.Ports} distinct ports on {scanCandidate.IP}."
                });

            // HIDS-N3: High total connection count
            int threshold = _config.Rules.TryGetValue("NET-003", out var cfg) ? cfg.Threshold : 100;
            if (conns.Length > threshold)
                events.Add(new DetectionEvent
                {
                    RuleId = "NET-003",
                    RuleName = "Connection Count Burst",
                    Severity = AlertSeverity.Medium,
                    Type = AlertType.RECON,
                    Description = $"High TCP connection count: {conns.Length} (threshold: {threshold})."
                });

            // HIDS-N4: Simulated C2 pattern (port 9999 trigger)
            foreach (var conn in conns)
            {
                if (conn.RemoteEndPoint.Port == 9999)
                    events.Add(new DetectionEvent
                    {
                        RuleId = "NET-004",
                        RuleName = "Suspected C2 Traffic",
                        Severity = AlertSeverity.High,
                        Type = AlertType.BACK,
                        Description = "Detected suspicious traffic pattern (simulated payload match)."
                    });
            }

            return events;
        }
    }
}
