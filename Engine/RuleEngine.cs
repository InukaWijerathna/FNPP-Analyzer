using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Net.NetworkInformation;
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

        public RuleEngine(IAlertSink sink) => _sink = sink;

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

                    // Lets rules surface a sub-status (e.g. the file path being scanned)
                    // beneath the main phase line without changing the step count.
                    context.ReportDetail = detail => progress?.Report(new(stepDone, total, rule.Name, detail));

                    try
                    {
                        foreach (var evt in rule.Evaluate(context))
                            _sink.Submit(new Alert
                            {
                                RuleId         = evt.RuleId,
                                Title          = evt.RuleName,
                                Description    = evt.Description,
                                Severity       = evt.Severity,
                                Type           = evt.Type,
                                SourceProcess  = "System",
                                ExecutablePath = evt.ExecutablePath,
                                Metadata       = evt.Metadata
                            });
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"[rule:{rule.RuleId}] {ex.Message}");
                    }
                }

                context.ReportDetail = null;
            }
            finally
            {
                context.Release();
            }
        }

        private static ScanContext BuildContext()
        {
            var (cmdLines, parentPids) = LoadProcessDetails();
            return new ScanContext
            {
                Processes = Process.GetProcesses(),
                TcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections(),
                TcpConnectionsWithPid = NetworkHelper.GetTcpWithPid(),
                ProcessCommandLines = cmdLines,
                ParentPids = parentPids
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
    }
}
