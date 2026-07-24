using System;
using System.Collections.Generic;
using FNPPAnalyzer.Config;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Rules.Process
{
    // HIDS-P2/P3: Executables from untrusted paths; script engines running untrusted scripts.
    public class SuspiciousExecutionRule : IDetectionRule
    {
        public string RuleId => "PROC-002";
        public string Name => "Suspicious Process Execution";
        public string Description => "Detects executables and scripts running from user-writable directories.";

        private static readonly string[] ScriptEngines =
            ["powershell", "cmd", "wscript", "cscript", "mshta", "rundll32"];

        private readonly AppConfig _config;

        public SuspiciousExecutionRule(AppConfig config) => _config = config;

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();

            foreach (var proc in context.Processes)
            {
                string? exePath = proc.ExecutablePath;
                if (exePath == null) continue;

                string procName = proc.Name.ToLower();
                bool isScriptEngine = Array.Exists(ScriptEngines, e => procName.Contains(e));

                foreach (var rawPath in _config.UntrustedExecutionPaths)
                {
                    string bad = Environment.ExpandEnvironmentVariables(rawPath);
                    string normalized = bad.EndsWith('\\') ? bad : bad + '\\';

                    if (isScriptEngine)
                    {
                        // Script engines live in System32; check their command line for the script path.
                        if (proc.CommandLine != null &&
                            proc.CommandLine.Contains(normalized, StringComparison.OrdinalIgnoreCase))
                            events.Add(new DetectionEvent
                            {
                                RuleId = "PROC-003",
                                RuleName = "Script from Untrusted Path",
                                Severity = AlertSeverity.Medium,
                                Type = AlertType.TROJ,
                                Description = $"{proc.Name} executing a script from untrusted path: {bad}",
                                Metadata = new { ProcessId = proc.Pid, CommandLine = proc.CommandLine }
                            });
                    }
                    else if (exePath.StartsWith(normalized, StringComparison.OrdinalIgnoreCase))
                    {
                        events.Add(new DetectionEvent
                        {
                            RuleId         = "PROC-002",
                            RuleName       = "Executable from Untrusted Path",
                            Severity       = AlertSeverity.Medium,
                            Type           = AlertType.MAL,
                            Description    = $"{proc.Name} running from untrusted path: {exePath}",
                            ExecutablePath = exePath,
                            Metadata       = new { ProcessId = proc.Pid, Path = exePath }
                        });
                    }
                }
            }
            return events;
        }
    }
}
