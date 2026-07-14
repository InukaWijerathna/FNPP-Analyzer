using System;
using System.Collections.Generic;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Rules.Process
{
    // PROC-004: Office/browser apps spawning shell interpreters — the classic sign of macro
    // malware, phishing document exploitation, or browser exploit chains.
    public class ParentChildAnomalyRule : IDetectionRule
    {
        public string RuleId => "PROC-004";
        public string Name => "Suspicious Child Process";
        public string Description => "Detects shell interpreters spawned by Office applications or browsers.";

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
            var pidToName = new Dictionary<int, string>(context.Processes.Count);
            foreach (var proc in context.Processes)
                pidToName[proc.Pid] = proc.Name.ToLower();

            var events = new List<DetectionEvent>();

            foreach (var proc in context.Processes)
            {
                string childName = proc.Name.ToLower();
                if (!Array.Exists(SuspiciousChildren, c => childName.Contains(c))) continue;
                if (proc.ParentPid is not int parentPid) continue;
                if (!pidToName.TryGetValue(parentPid, out string? parentName)) continue;

                if (Array.Exists(HighRiskParents, p => parentName.Contains(p)))
                {
                    events.Add(new DetectionEvent
                    {
                        RuleId = RuleId,
                        RuleName = Name,
                        Severity = AlertSeverity.High,
                        Type = AlertType.TROJ,
                        Description = $"{parentName} spawned {proc.Name} — likely macro or exploit execution.",
                        Metadata = new { Parent = parentName, ChildPid = proc.Pid, CommandLine = proc.CommandLine }
                    });
                }
            }
            return events;
        }
    }
}
