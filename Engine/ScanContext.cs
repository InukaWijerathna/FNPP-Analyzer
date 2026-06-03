using System.Collections.Generic;
using System.Diagnostics;
using System.Net.NetworkInformation;

namespace WinEDR_MVP.Engine
{
    public class ScanContext
    {
        public Process[] Processes { get; init; } = [];
        public TcpConnectionInformation[] TcpConnections { get; init; } = [];
        public Dictionary<int, string?> ProcessCommandLines { get; init; } = new();

        public void Release()
        {
            foreach (var p in Processes)
                try { p.Dispose(); } catch { }
        }
    }
}
