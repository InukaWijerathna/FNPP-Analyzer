using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace FNPPAnalyzer.Engine
{
    public record TcpConnectionWithPid(
        IPAddress LocalAddress,
        int LocalPort,
        IPAddress RemoteAddress,
        int RemotePort,
        uint State,
        int OwningPid);

    public static class NetworkHelper
    {
        // TCP states returned by GetExtendedTcpTable
        public const uint MIB_TCP_STATE_ESTAB   = 5;
        public const uint MIB_TCP_STATE_SYN_SENT = 2;

        private enum TCP_TABLE_CLASS { TCP_TABLE_OWNER_PID_ALL = 5 }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable, ref int pdwSize, bool bOrder,
            int ulAf, TCP_TABLE_CLASS TableClass, uint Reserved);

        public static List<TcpConnectionWithPid> GetTcpWithPid()
        {
            var result = new List<TcpConnectionWithPid>();
            int size = 0;
            // First call: get required buffer size
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2 /*AF_INET*/,
                TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(buf, ref size, false, 2,
                        TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                    return result;

                int numEntries = Marshal.ReadInt32(buf);
                int rowSize    = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(buf + 4 + i * rowSize);
                    result.Add(new TcpConnectionWithPid(
                        LocalAddress:  new IPAddress(row.dwLocalAddr),
                        LocalPort:     NetworkPort(row.dwLocalPort),
                        RemoteAddress: new IPAddress(row.dwRemoteAddr),
                        RemotePort:    NetworkPort(row.dwRemotePort),
                        State:         row.dwState,
                        OwningPid:     (int)row.dwOwningPid));
                }
            }
            catch { }
            finally { Marshal.FreeHGlobal(buf); }
            return result;
        }

        // Windows stores port numbers in network byte order inside a DWORD
        private static int NetworkPort(uint raw) =>
            (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));
    }
}
