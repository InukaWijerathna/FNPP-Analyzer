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

        // proc.MainModule.FileName resolved once per process here — half a dozen rules used
        // to each call it independently, multiplying an already-expensive native call by
        // the number of rules that need a process's executable path.
        public Dictionary<int, string> ProcessPaths { get; init; } = new();

        // Recursive directory listing for each (expanded) UntrustedExecutionPaths entry,
        // keyed by the expanded path — several rules walk the exact same directory tree
        // every cycle; this does it once regardless of how many rules consume it.
        public Dictionary<string, string[]> UntrustedDirectoryFiles { get; init; } = new(StringComparer.OrdinalIgnoreCase);

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
