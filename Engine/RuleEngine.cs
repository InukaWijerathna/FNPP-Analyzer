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
        /// Caller is responsible for the final "Verifying signatures" tick.
        /// </param>
        public void RunCycle(IProgress<ScanProgress>? progress = null)
        {
            // +1 for context build; caller adds +1 for signature verification
            int total = _rules.Count + 1;
            int done  = 0;

            progress?.Report(new(done, total, "Building scan context"));
            var context = BuildContext();

            try
            {
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
                                Metadata       = evt.Metadata
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
            finally
            {
                context.Release();
            }
        }

        private ScanContext BuildContext()
        {
            var (cmdLines, parentPids) = LoadProcessDetails();
            var processes = Process.GetProcesses();
            return new ScanContext
            {
                Processes = processes,
                ProcessPaths = LoadProcessPaths(processes),
                TcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections(),
                TcpConnectionsWithPid = NetworkHelper.GetTcpWithPid(),
                ProcessCommandLines = cmdLines,
                ParentPids = parentPids,
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

        // proc.MainModule access is a real native call per process — resolve it once here
        // instead of letting each rule that needs an executable path repeat it.
        private static Dictionary<int, string> LoadProcessPaths(Process[] processes)
        {
            var paths = new Dictionary<int, string>(processes.Length);
            foreach (var proc in processes)
            {
                try
                {
                    string? path = proc.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(path)) paths[proc.Id] = path;
                }
                catch { }
            }
            return paths;
        }

        // Recursively lists each untrusted directory once per cycle — FileScannerRule,
        // KnownHashRule and YaraScanRule all used to walk these same trees independently.
        private Dictionary<string, string[]> LoadUntrustedDirectoryFiles()
        {
            var result = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            foreach (var rawPath in _config.UntrustedExecutionPaths)
            {
                string dir = Environment.ExpandEnvironmentVariables(rawPath);
                if (result.ContainsKey(dir)) continue;
                if (!Directory.Exists(dir)) { result[dir] = []; continue; }

                try { result[dir] = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories); }
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
