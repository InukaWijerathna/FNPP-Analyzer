using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Windows.Forms;
using WinEDR_MVP.Config;
using WinEDR_MVP.Engine;
using WinEDR_MVP.Rules.Files;
using WinEDR_MVP.Rules.Network;
using WinEDR_MVP.Rules.Persistence;
using WinEDR_MVP.Rules.Process;

namespace WinEDR_MVP
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.SetHighDpiMode(HighDpiMode.SystemAware);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (!EnableSeDebugPrivilege())
                MessageBox.Show(
                    "Could not enable SeDebugPrivilege.\n\nRun as Administrator for full process inspection.",
                    "WinEDR MVP — Privilege Warning",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);

            // ── Composition root ──────────────────────────────────────────
            const string configPath = "config.json";
            var config = AppConfig.Load(configPath);
            if (!System.IO.File.Exists(configPath))
                config.Save(configPath);

            var broker = new AlertBroker("alerts.log");
            var engine = new RuleEngine(broker);

            engine.Register(new SystemProcessMasqueradingRule(config));
            engine.Register(new SuspiciousExecutionRule(config));
            engine.Register(new SuspiciousNetworkActivityRule(config));
            engine.Register(new StartupPersistenceRule());
            engine.Register(new FileScannerRule(config));
            // ─────────────────────────────────────────────────────────────

            Application.Run(new MainForm(engine, broker));
        }

        // ── SeDebugPrivilege ──────────────────────────────────────────────
        private const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const int TOKEN_QUERY             = 0x0008;
        private const int SE_PRIVILEGE_ENABLED    = 0x00000002;

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES { public LUID Luid; public int Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES { public int PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr h, int access, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeValue(string? system, string name, out LUID luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr token, bool disable,
            ref TOKEN_PRIVILEGES newState, int bufLen, IntPtr prev, IntPtr retLen);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr h);

        private static bool EnableSeDebugPrivilege()
        {
            try
            {
                if (!OpenProcessToken(Process.GetCurrentProcess().Handle,
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr token)) return false;
                try
                {
                    if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out LUID luid)) return false;
                    var tp = new TOKEN_PRIVILEGES
                    {
                        PrivilegeCount = 1,
                        Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
                    };
                    AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                    return Marshal.GetLastWin32Error() == 0;
                }
                finally { CloseHandle(token); }
            }
            catch { return false; }
        }
        // ─────────────────────────────────────────────────────────────────
    }
}
