using System;
using System.Collections.Generic;
using FNPPAnalyzer.Config;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Rules.Process
{
    // HIDS-P1: Detects system processes running outside their expected paths.
    public class SystemProcessMasqueradingRule : IDetectionRule
    {
        public string RuleId => "PROC-001";
        public string Name => "System Process Masquerading";
        public string Description => "Detects system process names running outside their expected paths.";

        private readonly AppConfig _config;

        public SystemProcessMasqueradingRule(AppConfig config) => _config = config;

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();

            foreach (var proc in context.Processes)
            {
                try
                {
                    string procName = proc.ProcessName.ToLower();
                    if (!_config.TrustedSystemProcesses.Contains(procName + ".exe")) continue;

                    string? path = proc.MainModule?.FileName;
                    if (string.IsNullOrEmpty(path)) continue;

                    bool isLegit = procName == "explorer"
                        ? path.Equals(@"C:\WINDOWS\explorer.exe", StringComparison.OrdinalIgnoreCase)
                        : StartsWithTrustedPath(path);

                    if (!isLegit)
                        events.Add(new DetectionEvent
                        {
                            RuleId         = RuleId,
                            RuleName       = Name,
                            Severity       = AlertSeverity.High,
                            Type           = AlertType.MAL,
                            Description    = $"System process {proc.ProcessName} running from unexpected location: {path}",
                            ExecutablePath = path,
                            Metadata       = new { ProcessId = proc.Id, Path = path }
                        });
                }
                catch { }
            }
            return events;
        }

        private bool StartsWithTrustedPath(string path)
        {
            foreach (var t in _config.TrustedExecutionPaths)
                if (path.StartsWith(t, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
    }
}
