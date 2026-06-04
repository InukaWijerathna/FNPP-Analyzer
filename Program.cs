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
using Spectre.Console;

namespace FNPPAnalyzer
{
    static class Program
    {
        static CancellationTokenSource?   _cts;
        static Task?                      _scanTask;
        static AlertBroker?               _broker;
        static PostScanFilter?            _filter;
        static ProcessCreationWatcher?    _watcher;
        static readonly int ScanInterval = 30;

        static void Main()
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;

            PrintBanner();

            if (!EnableSeDebugPrivilege())
                AnsiConsole.MarkupLine("[yellow]  [[!]] SeDebugPrivilege unavailable — run as Administrator for full inspection.[/]");

            const string configPath = "config.json";
            var config = AppConfig.Load(configPath);
            if (!System.IO.File.Exists(configPath))
                config.Save(configPath);

            var whitelist = new SignatureWhitelist("whitelist.json");
            _broker  = new AlertBroker("alerts.log", whitelist);
            _filter  = new PostScanFilter(whitelist);
            var engine = new RuleEngine(_broker);

            engine.Register(new SystemProcessMasqueradingRule(config));
            engine.Register(new SuspiciousExecutionRule(config));
            engine.Register(new SuspiciousNetworkActivityRule(config));
            engine.Register(new StartupPersistenceRule());
            engine.Register(new ScheduledTaskPersistenceRule());
            engine.Register(new FileScannerRule(config));
            engine.Register(new ParentChildAnomalyRule());
            engine.Register(new LolBinRule());
            engine.Register(new UnsignedProcessRule(config));
            engine.Register(new KnownHashRule(config));
            engine.Register(new PeImportRule(config));
            engine.Register(new MemoryInjectionRule(config));

            _broker.AlertRaised += OnAlertRaised;

            // Real-time process creation watcher — runs between scan cycles
            _watcher = new ProcessCreationWatcher(_broker, config);
            _watcher.Start();

            MenuLoop(engine);

            _watcher.Stop();
            _watcher.Dispose();
        }

        // ── Menu ─────────────────────────────────────────────────────────────

        static void MenuLoop(RuleEngine engine)
        {
            while (true)
            {
                StatusBar();
                AnsiConsole.Write(new Rule("[bold cyan]Main Menu[/]").RuleStyle("grey"));

                var choice = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[grey]Select an option:[/]")
                        .HighlightStyle(new Style(Color.Cyan1, decoration: Decoration.Bold))
                        .AddChoices(
                            "1.  Scan Now        (run a single detection cycle)",
                            "2.  Live Monitor    (start continuous scanning)",
                            "3.  Stop Monitor    (stop continuous scanning)",
                            "4.  Alerts          (view all recorded alerts)",
                            "5.  Status          (scanner state & statistics)",
                            "6.  Clear           (clear screen & redraw banner)",
                            "7.  Quit"
                        ));

                switch (choice[0])
                {
                    case '1': ScanView(engine);          break;
                    case '2': StartMonitorView(engine);   break;
                    case '3': StopMonitorView();          break;
                    case '4': AlertsView();               break;
                    case '5': StatusView();               break;
                    case '6': AnsiConsole.Clear(); PrintBanner(); break;
                    case '7':
                        StopMonitor();
                        _scanTask?.Wait(2000);
                        AnsiConsole.WriteLine();
                        AnsiConsole.MarkupLine("[cyan]  Shutting down FNPP Analyzer. Stay safe.[/]");
                        AnsiConsole.WriteLine();
                        return;
                }
            }
        }

        // ── Scan views ────────────────────────────────────────────────────────

        static void ScanView(RuleEngine engine)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold cyan]Detection Scan[/]").RuleStyle("grey"));

            int priorCount = _broker!.GetAll().Count;

            AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .SpinnerStyle(new Style(Color.Cyan1))
                .Start("[cyan]Running detection cycle...[/]", ctx =>
                {
                    engine.RunCycle();
                    ctx.Status("[cyan]Verifying signatures...[/]");
                    var newAlerts = _broker.GetFrom(priorCount);
                    _filter!.Process(newAlerts);
                });

            var result = _filter!.Process(_broker.GetFrom(priorCount));
            ShowFilterSummary(result);
            Pause();
        }

        static void StartMonitorView(RuleEngine engine)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold cyan]Live Monitor[/]").RuleStyle("grey"));

            if (_scanTask != null && !_scanTask.IsCompleted)
            {
                AnsiConsole.MarkupLine("[yellow]  [[!]] Monitor is already running.[/]");
                Pause();
                return;
            }

            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            _scanTask = Task.Run(async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    int prior = _broker!.GetAll().Count;
                    engine.RunCycle();
                    _filter!.Process(_broker.GetFrom(prior));

                    try { await Task.Delay(ScanInterval * 1000, token); }
                    catch (OperationCanceledException) { break; }
                }
            }, token);

            AnsiConsole.MarkupLine($"[green]  [[+]] Live monitor started — scanning every {ScanInterval}s.[/]");
            AnsiConsole.MarkupLine("[grey]  Signed binaries are auto-whitelisted. Alerts appear in real time.[/]");
            Pause();
        }

        static void StopMonitorView()
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold cyan]Stop Monitor[/]").RuleStyle("grey"));
            StopMonitor();
            Pause();
        }

        static void StopMonitor()
        {
            if (_cts == null || _cts.IsCancellationRequested)
                AnsiConsole.MarkupLine("[grey]  No active monitor to stop.[/]");
            else
            {
                _cts.Cancel();
                AnsiConsole.MarkupLine("[yellow]  [[-]] Monitor stopped.[/]");
            }
        }

        // ── Filter summary ────────────────────────────────────────────────────

        static void ShowFilterSummary(FilterResult result)
        {
            if (result.Visible.Count == 0 && result.Suppressed.Count == 0)
            {
                AnsiConsole.MarkupLine("[grey]  No new findings this cycle.[/]");
                return;
            }

            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold cyan]Scan Results[/]").RuleStyle("grey"));

            if (result.Visible.Count > 0)
            {
                var table = new Table()
                    .BorderColor(Color.Grey)
                    .Border(TableBorder.Simple)
                    .AddColumn(new TableColumn("[grey]Time[/]").Centered())
                    .AddColumn(new TableColumn("[grey]Severity[/]").Centered())
                    .AddColumn(new TableColumn("[grey]Rule[/]"))
                    .AddColumn(new TableColumn("[white]Title[/]"))
                    .AddColumn(new TableColumn("[grey]Description[/]"));

                foreach (var a in result.Visible)
                {
                    string sev = a.Severity switch
                    {
                        AlertSeverity.High   => "[red bold]HIGH[/]",
                        AlertSeverity.Medium => "[yellow]MEDIUM[/]",
                        _                    => "[grey]LOW[/]",
                    };
                    table.AddRow(
                        $"[grey]{a.Timestamp.ToLocalTime():HH:mm:ss}[/]",
                        sev,
                        $"[cyan]{Markup.Escape(a.RuleId)}[/]",
                        $"[white]{Markup.Escape(a.Title)}[/]",
                        $"[grey]{Markup.Escape(a.Description)}[/]"
                    );
                }
                AnsiConsole.Write(table);
            }

            if (result.Suppressed.Count > 0)
                AnsiConsole.MarkupLine(
                    $"[grey]  {result.Suppressed.Count} alert(s) suppressed — Authenticode-signed binaries.[/]");

            if (result.NewlyWhitelisted.Count > 0)
            {
                AnsiConsole.MarkupLine($"[green]  [[+]] {result.NewlyWhitelisted.Count} path(s) added to whitelist:[/]");
                foreach (var p in result.NewlyWhitelisted)
                    AnsiConsole.MarkupLine($"[grey]       {Markup.Escape(p)}[/]");
            }
        }

        // ── Info views ────────────────────────────────────────────────────────

        static void AlertsView()
        {
            var alerts = _broker!.GetAll();
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule($"[bold white]Alerts[/]  [grey]{alerts.Count} recorded[/]").RuleStyle("grey"));

            if (alerts.Count == 0)
            {
                AnsiConsole.MarkupLine("[grey]  No alerts recorded.[/]");
                Pause();
                return;
            }

            var table = new Table()
                .BorderColor(Color.Grey)
                .Border(TableBorder.Simple)
                .AddColumn(new TableColumn("[grey]Time[/]").Centered())
                .AddColumn(new TableColumn("[grey]Severity[/]").Centered())
                .AddColumn(new TableColumn("[grey]Rule[/]"))
                .AddColumn(new TableColumn("[white]Title[/]"))
                .AddColumn(new TableColumn("[grey]Description[/]"));

            foreach (var a in alerts)
            {
                string sev = a.Severity switch
                {
                    AlertSeverity.High   => "[red bold]HIGH[/]",
                    AlertSeverity.Medium => "[yellow]MEDIUM[/]",
                    _                    => "[grey]LOW[/]",
                };
                string title = a.Suppressed
                    ? $"[grey]{Markup.Escape(a.Title)} [dim](whitelisted)[/][/]"
                    : $"[white]{Markup.Escape(a.Title)}[/]";

                table.AddRow(
                    $"[grey]{a.Timestamp.ToLocalTime():HH:mm:ss}[/]",
                    a.Suppressed ? "[grey]------[/]" : sev,
                    $"[cyan]{Markup.Escape(a.RuleId)}[/]",
                    title,
                    $"[grey]{Markup.Escape(a.Description)}[/]"
                );
            }

            AnsiConsole.Write(table);
            Pause();
        }

        static void StatusView()
        {
            bool running = _scanTask != null && !_scanTask.IsCompleted;
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold white]Status[/]").RuleStyle("grey"));

            var grid = new Grid()
                .AddColumn(new GridColumn().Width(16))
                .AddColumn(new GridColumn());

            grid.AddRow("[grey]Monitor    [/]", running ? "[green]RUNNING[/]" : "[red]STOPPED[/]");
            grid.AddRow("[grey]Interval   [/]", $"[white]{ScanInterval}s[/]");
            grid.AddRow("[grey]Alerts     [/]", $"[white]{_broker!.GetAll().Count} recorded[/]");
            grid.AddRow("[grey]Log        [/]", "[white]alerts.log[/]");
            grid.AddRow("[grey]Whitelist  [/]", "[white]whitelist.json[/]");

            AnsiConsole.Write(new Padder(grid).Padding(2, 0));
            Pause();
        }

        // ── Live alert display ────────────────────────────────────────────────

        static void OnAlertRaised(Alert alert)
        {
            if (alert.Suppressed) return;

            string sev = alert.Severity switch
            {
                AlertSeverity.High   => "[red bold]HIGH[/]",
                AlertSeverity.Medium => "[yellow]MEDIUM[/]",
                _                    => "[grey]LOW[/]",
            };
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine(
                $"  [bold red]■[/] ALERT  {sev}  [cyan]{Markup.Escape(alert.RuleId)}[/]  [white]{Markup.Escape(alert.Title)}[/]");
            AnsiConsole.MarkupLine(
                $"    [grey]{Markup.Escape(alert.Description)}[/]");
        }

        // ── Banner & chrome ───────────────────────────────────────────────────

        static void StatusBar()
        {
            bool running = _scanTask != null && !_scanTask.IsCompleted;
            int count = _broker?.GetAll().Count ?? 0;
            string state = running ? "[green]MONITORING[/]" : "[grey]IDLE[/]";
            AnsiConsole.MarkupLine($"[grey]  FNPP Analyzer  [/]{state}[grey]  │  Alerts: {count}  │  Log: alerts.log[/]");
            AnsiConsole.WriteLine();
        }

        static void PrintBanner()
        {
            AnsiConsole.Clear();

            var banner = new Markup(
                "[cyan]   ███████╗███╗   ██╗██████╗ ██████╗ \n" +
                "   ██╔════╝████╗  ██║██╔══██╗██╔══██╗\n" +
                "   █████╗  ██╔██╗ ██║██████╔╝██████╔╝\n" +
                "   ██╔══╝  ██║╚██╗██║██╔═══╝ ██╔═══╝ \n" +
                "   ██║     ██║ ╚████║██║     ██║     \n" +
                "   ╚═╝     ╚═╝  ╚═══╝╚═╝     ╚═╝     [/]\n" +
                "[white]             A N A L Y Z E R[/]"
            );

            var panel = new Panel(Align.Center(banner))
                .Header("[cyan] FNPP [/]")
                .BorderColor(Color.Cyan1)
                .Border(BoxBorder.Double)
                .Padding(2, 1);

            AnsiConsole.Write(panel);
            AnsiConsole.WriteLine();
        }

        static void Pause()
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[grey]  Press any key to continue...[/]");
            Console.ReadKey(true);
            AnsiConsole.WriteLine();
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
