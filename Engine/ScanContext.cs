using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;

namespace FNPPAnalyzer.Engine
{
    /// <summary>
    /// Plain-data snapshot of one process, taken once per scan cycle. Rules consume this
    /// instead of live System.Diagnostics.Process objects so they are pure functions over
    /// data — unit-testable with fabricated snapshots, and free of per-rule native calls.
    /// </summary>
    public sealed record ProcessInfo(
        int Pid,
        string Name,             // e.g. "svchost" (no extension)
        string? ExecutablePath,  // null when MainModule was inaccessible
        string? CommandLine,     // null when WMI had no entry
        int? ParentPid);

    public class ScanContext
    {
        public IReadOnlyList<ProcessInfo> Processes { get; init; } = [];
        public TcpConnectionInformation[] TcpConnections { get; init; } = [];

        // PID-aware TCP connections from GetExtendedTcpTable; empty list if unavailable
        public List<TcpConnectionWithPid> TcpConnectionsWithPid { get; init; } = [];

        // PID → executable path, for rules that join network/PID data against processes.
        // Same data as Processes[i].ExecutablePath, pre-indexed.
        public Dictionary<int, string> ProcessPaths { get; init; } = new();

        // Recursive directory listing for each (expanded) UntrustedExecutionPaths entry,
        // keyed by the expanded path — several rules walk the exact same directory tree
        // every cycle; this does it once regardless of how many rules consume it.
        public Dictionary<string, string[]> UntrustedDirectoryFiles { get; init; } = new(StringComparer.OrdinalIgnoreCase);

        // Set by RuleEngine before each rule's Evaluate() runs — lets file-scanning rules
        // surface the path they're currently working on beneath the progress bar.
        public Action<string>? ReportDetail { get; set; }
    }
}
