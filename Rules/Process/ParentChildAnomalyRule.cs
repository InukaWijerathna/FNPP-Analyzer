using System;
using System.Collections.Generic;
using WinEDR_MVP.Engine;
using WinEDR_MVP.Models;

namespace WinEDR_MVP.Rules.Process
{
    // HIDS-P4: Office/browser apps spawning shell interpreters — the classic sign of macro
    // malware, phishing document exploitation, or browser exploit chains.
    public class ParentChildAnomalyRule : IDetectionRule
    {
        public string RuleId => "HIDS-P4";
        public string Name => "Suspicious Parent-Child Process";
        public string Description => "Detects shell interpreters spawned by Office, PDF readers, or browsers.";

        private static readonly string[] HighRiskParents =
        [
            "winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "mspub",  // Office
            "acrord32", "acrobat", "foxitreader",                                         // PDF readers
            "chrome", "firefox", "msedge", "iexplore", "opera"                           // Browsers
        ];

        private static readonly string[] SuspiciousChildren =
        [
            "cmd", "powershell", "pwsh", "wscript", "cscript",
            "mshta", "regsvr32", "rundll32", "certutil", "bitsadmin",
            "wmic", "msiexec", "cmstp", "installutil"
        ];

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            // Build PID → name map from current snapshot
            var pidToName = new Dictionary<int, string>(context.Processes.Length);
            foreach (var proc in context.Processes)
                try { pidToName[proc.Id] = proc.ProcessName.ToLower(); } catch { }

            var events = new List<DetectionEvent>();

            foreach (var proc in context.Processes)
            {
                try
                {
                    string childName = proc.ProcessName.ToLower();
                    if (!Array.Exists(SuspiciousChildren, c => childName.Contains(c))) continue;
                    if (!context.ParentPids.TryGetValue(proc.Id, out int parentPid)) continue;
                    if (!pidToName.TryGetValue(parentPid, out string? parentName)) continue;

                    if (Array.Exists(HighRiskParents, p => parentName.Contains(p)))
                    {
                        context.ProcessCommandLines.TryGetValue(proc.Id, out string? cmdLine);
                        events.Add(new DetectionEvent
                        {
                            RuleId = RuleId,
                            RuleName = Name,
                            Severity = AlertSeverity.High,
                            Type = AlertType.TROJ,
                            Description = $"{parentName} spawned {proc.ProcessName} — likely macro or exploit execution.",
                            Metadata = new { Parent = parentName, ChildPid = proc.Id, CommandLine = cmdLine }
                        });
                    }
                }
                catch { }
            }
            return events;
        }
    }
}
