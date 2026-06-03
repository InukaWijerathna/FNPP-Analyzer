using System;
using System.Collections.Generic;
using WinEDR_MVP.Config;
using WinEDR_MVP.Engine;
using WinEDR_MVP.Models;

namespace WinEDR_MVP.Rules.Process
{
    // HIDS-P2/P3: Executables from untrusted paths; script engines running untrusted scripts.
    public class SuspiciousExecutionRule : IDetectionRule
    {
        public string RuleId => "HIDS-P2/P3";
        public string Name => "Suspicious Process Execution";
        public string Description => "Detects executables or scripts running from user-writable directories.";

        private static readonly string[] ScriptEngines =
            ["powershell", "cmd", "wscript", "cscript", "mshta", "rundll32"];

        private readonly AppConfig _config;

        public SuspiciousExecutionRule(AppConfig config) => _config = config;

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();

            foreach (var proc in context.Processes)
            {
                try
                {
                    if (proc.MainModule == null) continue;
                    string exePath = proc.MainModule.FileName;
                    string procName = proc.ProcessName.ToLower();
                    bool isScriptEngine = Array.Exists(ScriptEngines, e => procName.Contains(e));

                    foreach (var rawPath in _config.UntrustedExecutionPaths)
                    {
                        string bad = Environment.ExpandEnvironmentVariables(rawPath);
                        string normalized = bad.EndsWith('\\') ? bad : bad + '\\';

                        if (isScriptEngine)
                        {
                            // Script engines live in System32; check their command line for the script path.
                            context.ProcessCommandLines.TryGetValue(proc.Id, out string? cmdLine);
                            if (cmdLine != null &&
                                cmdLine.Contains(normalized, StringComparison.OrdinalIgnoreCase))
                                events.Add(new DetectionEvent
                                {
                                    RuleId = "HIDS-P3",
                                    RuleName = "Script Running from Untrusted Path",
                                    Severity = AlertSeverity.Medium,
                                    Type = AlertType.TROJ,
                                    Description = $"{proc.ProcessName} executing a script from untrusted path: {bad}",
                                    Metadata = new { ProcessId = proc.Id, CommandLine = cmdLine }
                                });
                        }
                        else if (exePath.StartsWith(normalized, StringComparison.OrdinalIgnoreCase))
                        {
                            events.Add(new DetectionEvent
                            {
                                RuleId = "HIDS-P2",
                                RuleName = "Executable Running from Untrusted Path",
                                Severity = AlertSeverity.Medium,
                                Type = AlertType.MAL,
                                Description = $"{proc.ProcessName} running from untrusted path: {exePath}",
                                Metadata = new { ProcessId = proc.Id, Path = exePath }
                            });
                        }
                    }
                }
                catch { }
            }
            return events;
        }
    }
}
