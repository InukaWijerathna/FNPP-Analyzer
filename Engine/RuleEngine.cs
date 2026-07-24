using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net.NetworkInformation;
using FNPPAnalyzer.Config;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Engine
{
    /// <summary>
    /// Carries one progress tick: how many steps are done, total steps, current phase label,
    /// and an optional sub-status detail (e.g. the file path a rule is currently scanning).
    /// </summary>
    public record ScanProgress(int Completed, int Total, string Phase, string? Detail = null);

    public class RuleEngine
    {
        private readonly List<IDetectionRule> _rules = new();
        private readonly IAlertSink _sink;
        private readonly AppConfig _config;

        public RuleEngine(IAlertSink sink, AppConfig config)
        {
            _sink = sink;
            _config = config;
        }

        public void Register(IDetectionRule rule) => _rules.Add(rule);

        /// <summary>Total registered rules — lets callers pre-size a progress bar.</summary>
        public int RuleCount => _rules.Count;

        /// <param name="progress">
        /// Optional progress sink. Receives ticks as each phase starts:
        /// (0, total, "Building scan context"), (1, total, ruleName), …
        /// </param>
        public void RunCycle(IProgress<ScanProgress>? progress = null)
        {
            int total = _rules.Count + 1; // +1 for context build
            int done  = 0;

            progress?.Report(new(done, total, "Building scan context"));
            var context = BuildContext();

            foreach (var rule in _rules)
            {
                done++;
                int stepDone = done;
                progress?.Report(new(stepDone, total, rule.Name));

                // Skips the rule's work entirely when it's disabled by its own RuleId.
                // Rules that emit several leaf IDs (e.g. "FILE" -> FILE-001/FILE-002)
                // aren't keyed in config under that umbrella ID, so this is a no-op for
                // them — the per-event check below is what actually enforces those.
                if (!_config.IsRuleEnabled(rule.RuleId)) continue;

                // Lets rules surface a sub-status (e.g. the file path being scanned)
                // beneath the main phase line without changing the step count.
                context.ReportDetail = detail => progress?.Report(new(stepDone, total, rule.Name, detail));

                try
                {
                    foreach (var evt in rule.Evaluate(context))
                    {
                        if (!_config.IsRuleEnabled(evt.RuleId)) continue;

                        _sink.Submit(new Alert
                        {
                            RuleId         = evt.RuleId,
                            Title          = evt.RuleName,
                            Description    = evt.Description,
                            Severity       = _config.SeverityOverride(evt.RuleId) ?? evt.Severity,
                            Type           = evt.Type,
                            SourceProcess  = "System",
                            ExecutablePath = evt.ExecutablePath,
                            Metadata       = evt.Metadata,
                            DedupeKey      = evt.DedupeKey
                        });
                    }
                }
                catch (Exception ex)
                {
                    lock (ConsoleSync.Lock) Console.Error.WriteLine($"[rule:{rule.RuleId}] {ex.Message}");
                }
            }

            context.ReportDetail = null;
        }

        private ScanContext BuildContext()
        {
            var (cmdLines, parentPids) = LoadProcessDetails();

            var snapshots = new List<ProcessInfo>();
            var paths     = new Dictionary<int, string>();

            // Live Process handles are consumed (and disposed) right here — rules only
            // ever see the plain-data ProcessInfo snapshots.
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    int pid = proc.Id;
                    string name = proc.ProcessName;

                    string? path = null;
                    // MainModule is a real native call and throws on protected processes.
                    try { path = proc.MainModule?.FileName; } catch { }
                    if (!string.IsNullOrEmpty(path)) paths[pid] = path;

                    snapshots.Add(new ProcessInfo(
                        Pid:            pid,
                        Name:           name,
                        ExecutablePath: string.IsNullOrEmpty(path) ? null : path,
                        CommandLine:    cmdLines.TryGetValue(pid, out var cmd) ? cmd : null,
                        ParentPid:      parentPids.TryGetValue(pid, out var ppid) ? ppid : null));
                }
                catch { }
                finally
                {
                    try { proc.Dispose(); } catch { }
                }
            }

            return new ScanContext
            {
                Processes = snapshots,
                ProcessPaths = paths,
                TcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections(),
                TcpConnectionsWithPid = NetworkHelper.GetTcpWithPid(),
                UntrustedDirectoryFiles = LoadUntrustedDirectoryFiles()
            };
        }

        // Single WMI query for both command lines and parent PIDs
        private static (Dictionary<int, string?> cmdLines, Dictionary<int, int> parentPids) LoadProcessDetails()
        {
            var cmdLines = new Dictionary<int, string?>();
            var parentPids = new Dictionary<int, int>();
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, ParentProcessId, CommandLine FROM Win32_Process");
                foreach (ManagementBaseObject obj in searcher.Get())
                {
                    int pid = Convert.ToInt32(obj["ProcessId"]);
                    cmdLines[pid] = obj["CommandLine"]?.ToString();
                    if (obj["ParentProcessId"] != null)
                        parentPids[pid] = Convert.ToInt32(obj["ParentProcessId"]);
                    obj.Dispose();
                }
            }
            catch { }
            return (cmdLines, parentPids);
        }

        // Recursively lists each untrusted directory once per cycle — FileScannerRule,
        // KnownHashRule, PeImportRule and YaraScanRule all consume the same listing.
        //
        // AttributesToSkip: only reparse points (junction/symlink loops would otherwise
        // recurse forever). The default also skips Hidden and System — which would blind
        // FILE-002 (hidden executables), so it's set explicitly.
        private static readonly System.IO.EnumerationOptions UntrustedDirEnumeration = new()
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible    = true, // one locked subfolder must not zero out the whole tree
            AttributesToSkip      = FileAttributes.ReparsePoint
        };

        private Dictionary<string, string[]> LoadUntrustedDirectoryFiles()
        {
            var result = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            foreach (var rawPath in _config.UntrustedExecutionPaths)
            {
                string dir = Environment.ExpandEnvironmentVariables(rawPath);
                if (result.ContainsKey(dir)) continue;
                if (!Directory.Exists(dir)) { result[dir] = []; continue; }

                try { result[dir] = Directory.GetFiles(dir, "*", UntrustedDirEnumeration); }
                catch (Exception ex)
                {
                    lock (ConsoleSync.Lock) Console.Error.WriteLine($"[ScanContext] {dir}: {ex.Message}");
                    result[dir] = [];
                }
            }
            return result;
        }
    }
}
