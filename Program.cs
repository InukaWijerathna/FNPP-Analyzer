using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using FNPPAnalyzer.Config;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;
using FNPPAnalyzer.Rules.Files;
using FNPPAnalyzer.Rules.Network;
using FNPPAnalyzer.Rules.Persistence;
using FNPPAnalyzer.Rules.Process;

namespace FNPPAnalyzer
{
    static class Program
    {
        static CancellationTokenSource? _cts;
        static Task? _scanTask;
        static AlertBroker? _broker;
        static readonly int ScanInterval = 30;

        static void Main()
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.CursorVisible = false;

            PrintBanner();

            if (!EnableSeDebugPrivilege())
                Warn("SeDebugPrivilege unavailable — run as Administrator for full inspection.");

            const string configPath = "config.json";
            var config = AppConfig.Load(configPath);
            if (!System.IO.File.Exists(configPath))
                config.Save(configPath);

            _broker = new AlertBroker("alerts.log");
            var engine = new RuleEngine(_broker);

            engine.Register(new SystemProcessMasqueradingRule(config));
            engine.Register(new SuspiciousExecutionRule(config));
            engine.Register(new SuspiciousNetworkActivityRule(config));
            engine.Register(new StartupPersistenceRule());
            engine.Register(new FileScannerRule(config));
            engine.Register(new ParentChildAnomalyRule());
            engine.Register(new LolBinRule());
            engine.Register(new UnsignedProcessRule(config));
            engine.Register(new KnownHashRule(config));
            engine.Register(new PeImportRule(config));

            _broker.AlertRaised += OnAlertRaised;

            PrintHelp();
            CommandLoop(engine);
        }

        // ── Command loop ──────────────────────────────────────────────────────

        static void CommandLoop(RuleEngine engine)
        {
            while (true)
            {
                Prompt();
                Console.CursorVisible = true;
                string? input = Console.ReadLine()?.Trim().ToLowerInvariant();
                Console.CursorVisible = false;

                switch (input)
                {
                    case "scan":   RunSingleScan(engine);  break;
                    case "start":  StartContinuous(engine); break;
                    case "stop":   StopContinuous();        break;
                    case "alerts": ShowAlerts();             break;
                    case "status": ShowStatus();             break;
                    case "clear":
                        Console.Clear();
                        PrintBanner();
                        break;
                    case "help":   PrintHelp(); break;
                    case "exit":
                    case "quit":
                        StopContinuous();
                        _scanTask?.Wait(2000);
                        Console.WriteLine();
                        Info("Shutting down FNPP Analyzer. Stay safe.");
                        Console.WriteLine();
                        return;
                    default:
                        if (!string.IsNullOrEmpty(input))
                            WriteColor($"  Unknown command '{input}'. Type 'help' for available commands.\n",
                                ConsoleColor.DarkGray);
                        break;
                }
            }
        }

        // ── Scan actions ──────────────────────────────────────────────────────

        static void RunSingleScan(RuleEngine engine)
        {
            Info("Running single detection cycle...");
            engine.RunCycle();
            Ok("Scan complete.");
        }

        static void StartContinuous(RuleEngine engine)
        {
            if (_scanTask != null && !_scanTask.IsCompleted)
            {
                Warn("Scanner is already running.");
                return;
            }
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            _scanTask = Task.Run(async () =>
            {
                Ok($"Continuous scan started (interval: {ScanInterval}s).");
                while (!token.IsCancellationRequested)
                {
                    engine.RunCycle();
                    try { await Task.Delay(ScanInterval * 1000, token); }
                    catch (OperationCanceledException) { break; }
                }
                WriteColor("  [-] Scan stopped.\n", ConsoleColor.DarkGray);
            }, token);
        }

        static void StopContinuous()
        {
            if (_cts == null || _cts.IsCancellationRequested)
            {
                WriteColor("  No active scan running.\n", ConsoleColor.DarkGray);
                return;
            }
            _cts.Cancel();
            Warn("Stopping scanner...");
        }

        // ── Display ───────────────────────────────────────────────────────────

        static void ShowAlerts()
        {
            var alerts = _broker!.GetAll();
            Console.WriteLine();
            Separator();
            WriteColor($"  ALERTS  ({alerts.Count} total)\n", ConsoleColor.White);
            Separator();

            if (alerts.Count == 0)
            {
                WriteColor("  No alerts recorded.\n", ConsoleColor.DarkGray);
            }
            else
            {
                foreach (var a in alerts)
                {
                    var sev = SevColor(a.Severity);
                    WriteColor($"  {a.Timestamp.ToLocalTime():HH:mm:ss}  ", ConsoleColor.DarkGray);
                    WriteColor($"{a.Severity,-6}  ", sev);
                    WriteColor($"{a.RuleId,-10}  ", ConsoleColor.DarkCyan);
                    WriteColor($"{a.Title}\n", ConsoleColor.White);
                    WriteColor($"  {"",24}{a.Description}\n", ConsoleColor.Gray);
                }
            }
            Separator();
        }

        static void ShowStatus()
        {
            bool running = _scanTask != null && !_scanTask.IsCompleted;
            Console.WriteLine();
            Separator();
            WriteColor("  STATUS\n", ConsoleColor.White);
            Separator();
            WriteColor("  Scanner   : ", ConsoleColor.DarkGray);
            WriteColor(running ? "RUNNING\n" : "STOPPED\n",
                running ? ConsoleColor.Green : ConsoleColor.Red);
            WriteColor($"  Interval  : {ScanInterval}s\n", ConsoleColor.DarkGray);
            WriteColor($"  Alerts    : {_broker!.GetAll().Count} recorded\n", ConsoleColor.DarkGray);
            WriteColor($"  Log file  : alerts.log\n", ConsoleColor.DarkGray);
            Separator();
        }

        static void OnAlertRaised(Alert alert)
        {
            var col = SevColor(alert.Severity);
            Console.WriteLine();
            WriteColor($"  [ALERT]  ", col);
            WriteColor($"{alert.Severity,-6}  ", col);
            WriteColor($"{alert.RuleId,-10}  ", ConsoleColor.DarkCyan);
            WriteColor($"{alert.Title}\n", ConsoleColor.White);
            WriteColor($"  {"",24}{alert.Description}\n", ConsoleColor.DarkGray);
            Prompt();
        }

        static void PrintBanner()
        {
            Console.Clear();
            WriteColor("\n", ConsoleColor.Cyan);
            WriteColor("   ███████╗███╗   ██╗██████╗ ██████╗ \n", ConsoleColor.Cyan);
            WriteColor("   ██╔════╝████╗  ██║██╔══██╗██╔══██╗\n", ConsoleColor.Cyan);
            WriteColor("   █████╗  ██╔██╗ ██║██████╔╝██████╔╝\n", ConsoleColor.Cyan);
            WriteColor("   ██╔══╝  ██║╚██╗██║██╔═══╝ ██╔═══╝ \n", ConsoleColor.Cyan);
            WriteColor("   ██║     ██║ ╚████║██║     ██║     \n", ConsoleColor.Cyan);
            WriteColor("   ╚═╝     ╚═╝  ╚═══╝╚═╝     ╚═╝     \n", ConsoleColor.Cyan);
            WriteColor("              A N A L Y Z E R\n", ConsoleColor.White);
            Console.ResetColor();
            Console.WriteLine();
            Separator();
        }

        static void PrintHelp()
        {
            Console.WriteLine();
            Separator();
            WriteColor("  COMMANDS\n", ConsoleColor.White);
            Separator();
            Cmd("scan   ", "Run a single detection cycle");
            Cmd("start  ", $"Start continuous scanning (every {ScanInterval}s)");
            Cmd("stop   ", "Stop continuous scanning");
            Cmd("alerts ", "Show all recorded alerts");
            Cmd("status ", "Show scanner status");
            Cmd("clear  ", "Clear screen");
            Cmd("help   ", "Show this help");
            Cmd("exit   ", "Exit FNPP Scanner");
            Separator();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        static void Prompt()    => WriteColor("\n  fnpp> ", ConsoleColor.Cyan);
        static void Separator() => WriteColor("  " + new string('─', 48) + "\n", ConsoleColor.DarkGray);
        static void Ok(string s)   => WriteColor($"  [+] {s}\n", ConsoleColor.Green);
        static void Info(string s) => WriteColor($"  [*] {s}\n", ConsoleColor.Cyan);
        static void Warn(string s) => WriteColor($"  [!] {s}\n", ConsoleColor.Yellow);

        static void Cmd(string name, string desc)
        {
            WriteColor($"  {name}  ", ConsoleColor.Cyan);
            WriteColor($"{desc}\n", ConsoleColor.Gray);
        }

        static ConsoleColor SevColor(AlertSeverity sev) => sev switch
        {
            AlertSeverity.High   => ConsoleColor.Red,
            AlertSeverity.Medium => ConsoleColor.Yellow,
            _                    => ConsoleColor.DarkGray
        };

        static void WriteColor(string text, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.Write(text);
            Console.ResetColor();
        }

        // ── SeDebugPrivilege ──────────────────────────────────────────────────

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
    }
}
