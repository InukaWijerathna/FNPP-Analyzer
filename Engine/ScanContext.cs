using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.NetworkInformation;

namespace FNPPAnalyzer.Engine
{
    public class ScanContext
    {
        public Process[] Processes { get; init; } = [];
        public TcpConnectionInformation[] TcpConnections { get; init; } = [];

        // PID-aware TCP connections from GetExtendedTcpTable; empty list if unavailable
        public List<TcpConnectionWithPid> TcpConnectionsWithPid { get; init; } = [];

        // Keyed by PID — loaded in one WMI query to avoid double round-trips
        public Dictionary<int, string?> ProcessCommandLines { get; init; } = new();
        public Dictionary<int, int> ParentPids { get; init; } = new();

        // Set by RuleEngine before each rule's Evaluate() runs — lets file-scanning rules
        // surface the path they're currently working on beneath the progress bar.
        public Action<string>? ReportDetail { get; set; }

        public void Release()
        {
            foreach (var p in Processes)
                try { p.Dispose(); } catch { }
        }
    }
}
