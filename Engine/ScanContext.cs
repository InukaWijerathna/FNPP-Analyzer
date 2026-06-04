using System.Collections.Generic;
using System.Diagnostics;
using System.Net.NetworkInformation;

namespace FNPPScanner.Engine
{
    public class ScanContext
    {
        public Process[] Processes { get; init; } = [];
        public TcpConnectionInformation[] TcpConnections { get; init; } = [];

        // Keyed by PID — loaded in one WMI query to avoid double round-trips
        public Dictionary<int, string?> ProcessCommandLines { get; init; } = new();
        public Dictionary<int, int> ParentPids { get; init; } = new();

        public void Release()
        {
            foreach (var p in Processes)
                try { p.Dispose(); } catch { }
        }
    }
}
