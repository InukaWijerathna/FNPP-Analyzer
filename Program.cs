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

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("FNPPAnalyzer.Tests")]

namespace FNPPAnalyzer
{
    static class Program
    {
        static CancellationTokenSource?   _cts;
        static Task?                      _scanTask;
        static AlertBroker?               _broker;
        static PostScanFilter?            _filter;
        static ProcessCreationWatcher?    _watcher;
        static YaraEngine?                _yara;
        static SignatureWhitelist?        _whitelist;
        static KnownHashRule?             _knownHashRule;
        static readonly int               ScanInterval = 30;

        // Held during a manual scan so OnAlertRaised can redraw the progress bar
        // after writing alert text, preventing the auto-refresh timer from corrupting output.
        static ProgressContext?           _progressCtx;
        static readonly object            _consoleLock = new();

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

            _whitelist = new SignatureWhitelist("whitelist.json");
            _broker  = new AlertBroker("alerts.log", _whitelist);
            _filter  = new PostScanFilter(_whitelist);
            var engine = new RuleEngine(_broker);

            _yara = new YaraEngine(config.YaraRulesPath);
            if (_yara.IsLoaded)
                AnsiConsole.MarkupLine($"[grey]  [[i]] Loaded {_yara.RuleCount} YARA rule(s) from {config.YaraRulesPath}[/]");
            else
                AnsiConsole.MarkupLine($"[yellow]  [[!]] No YARA rules loaded from {config.YaraRulesPath} — FILE-005 will be inactive.[/]");

            engine.Register(new SystemProcessMasqueradingRule(config));
            engine.Register(new SuspiciousExecutionRule(config));
            engine.Register(new SuspiciousNetworkActivityRule(config));
            engine.Register(new StartupPersistenceRule());
            engine.Register(new ScheduledTaskPersistenceRule());
            engine.Register(new FileScannerRule(config));
            engine.Register(new ParentChildAnomalyRule());
            engine.Register(new LolBinRule());
            engine.Register(new UnsignedProcessRule(config));

            _knownHashRule = new KnownHashRule(config);
            engine.Register(_knownHashRule);

            engine.Register(new PeImportRule(config));
            engine.Register(new MemoryInjectionRule(config));
            engine.Register(new YaraScanRule(_yara, config));

            _broker.AlertRaised += OnAlertRaised;

            // Real-time process creation watcher — runs between scan cycles
            _watcher = new ProcessCreationWatcher(_broker, config);
            _watcher.Start();

            MenuLoop(engine);

            _watcher.Stop();
            _watcher.Dispose();
            _yara.Dispose();
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
                            "6.  Reload Rules    (reload IOCs, whitelist & YARA rules)",
                            "7.  Clear           (clear screen & redraw banner)",
                            "8.  Quit"
                        ));

                switch (choice[0])
                {
                    case '1': ScanView(engine);          break;
                    case '2': StartMonitorView(engine);   break;
                    case '3': StopMonitorView();          break;
                    case '4': AlertsView();               break;
                    case '5': StatusView();               break;
                    case '6': ReloadRulesView();          break;
                    case '7': AnsiConsole.Clear(); PrintBanner(); break;
                    case '8':
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
            // +1 for context build, +1 for signature verification, +N for each rule
            int totalSteps = engine.RuleCount + 2;

            FilterResult? result = null;

            AnsiConsole.Progress()
                .AutoClear(true)
                .AutoRefresh(false)     // we drive refreshes manually so the timer can't race with alert writes
                .HideCompleted(false)
                .Columns(
                    new TaskDescriptionColumn { Alignment = Justify.Left },
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                    new SpinnerColumn(Spinner.Known.Dots) { Style = new Style(Color.Cyan1) }
                )
                .Start(ctx =>
                {
                    _progressCtx = ctx;
                    try
                    {
                        var task = ctx.AddTask("[cyan]Initializing...[/]", maxValue: totalSteps);

                        // File-scanning rules can report a path on every single file — that's
                        // far too high a refresh rate for the terminal (garbles/overlaps the
                        // bar). Throttle detail-only ticks and keep the description on one
                        // line so the task's row height never changes between refreshes.
                        DateTime lastDetailTick = DateTime.MinValue;

                        var reporter = new Progress<ScanProgress>(p =>
                        {
                            bool isDetailTick = !string.IsNullOrEmpty(p.Detail);
                            var now = DateTime.UtcNow;
                            if (isDetailTick)
                            {
                                if (now - lastDetailTick < TimeSpan.FromMilliseconds(150)) return;
                                lastDetailTick = now;
                            }

                            lock (_consoleLock)
                            {
                                string prefix = $"[{p.Completed}/{totalSteps}] {p.Phase}";
                                string desc   = $"[grey][[{p.Completed}/{totalSteps}]][/] [cyan]{Markup.Escape(p.Phase)}[/]";

                                if (isDetailTick)
                                {
                                    // Reserve room for " — ", the bar, percentage, spinner and
                                    // grid padding so the whole row stays on one line — a
                                    // wrap changes the task's row height and corrupts the
                                    // live-rendered display (the bar/percentage end up on
                                    // their own line, out of sync with the description).
                                    const int otherColumnsReserve = 58;
                                    const string separator = " — ";
                                    int available = AnsiConsole.Profile.Width
                                                    - prefix.Length - separator.Length - otherColumnsReserve;

                                    if (available >= 12)
                                        desc += $"[grey]{separator}{Markup.Escape(TruncatePath(p.Detail!, available))}[/]";
                                }

                                task.Description = desc;
                                task.Value       = p.Completed;
                                ctx.Refresh();
                            }
                        });

                        engine.RunCycle(reporter);

                        lock (_consoleLock)
                        {
                            task.Description = $"[grey][[{totalSteps - 1}/{totalSteps}]][/] [cyan]Verifying signatures...[/]";
                            task.Value       = totalSteps - 1;
                            ctx.Refresh();
                        }
                        result = _filter!.Process(_broker.GetFrom(priorCount));
                        lock (_consoleLock)
                        {
                            task.Value = totalSteps;
                            ctx.Refresh();
                        }
                    }
                    finally
                    {
                        _progressCtx = null;
                    }
                });

            ShowFilterSummary(result!);
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

        static void ReloadRulesView()
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold cyan]Reload Rules[/]").RuleStyle("grey"));
            AnsiConsole.WriteLine();

            var grid = new Grid()
                .AddColumn(new GridColumn().Width(16))
                .AddColumn(new GridColumn());

            _whitelist?.Reload();
            grid.AddRow("[grey]Whitelist  [/]", "[green]reloaded[/] [grey](whitelist.json)[/]");

            _knownHashRule?.Reload();
            grid.AddRow("[grey]IOC Hashes [/]", "[green]reloaded[/] [grey](iocs.json)[/]");

            if (_yara != null)
            {
                bool ok = _yara.Reload();
                string status = ok
                    ? $"[green]reloaded[/] [grey]({_yara.RuleCount} rule(s) compiled)[/]"
                    : "[yellow]no rules loaded[/] [grey](directory empty or compile failed — FILE-005 inactive)[/]";
                grid.AddRow("[grey]YARA Rules [/]", status);
            }

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

            // Truncate description to one terminal-width line so it never wraps —
            // a wrapped line throws off Spectre.Console's cursor-position math and
            // causes the progress bar to overprint the alert text.
            string desc = alert.Description;
            if (desc.Length > 110) desc = desc[..107] + "…";

            lock (_consoleLock)
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine(
                    $"  [bold red]■[/] ALERT  {sev}  [cyan]{Markup.Escape(alert.RuleId)}[/]  [white]{Markup.Escape(alert.Title)}[/]");
                AnsiConsole.MarkupLine(
                    $"    [grey]{Markup.Escape(desc)}[/]");

                // If a progress bar is active, redraw it immediately after the alert
                // so it reappears below the new text rather than on top of it.
                _progressCtx?.Refresh();
            }
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

        // Elides the middle of long paths so the progress line stays a single row
        // (e.g. C:\Users\...\AppData\Local\Temp\payload.exe) — keeps the file name visible.
        internal static string TruncatePath(string path, int maxLen)
        {
            if (path.Length <= maxLen) return path;

            string name = System.IO.Path.GetFileName(path);
            if (name.Length >= maxLen) return name[^maxLen..];

            int keep = maxLen - name.Length - 1; // 1 for the ellipsis
            if (keep <= 0) return name;

            return $"{path[..keep]}…{name}";
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
