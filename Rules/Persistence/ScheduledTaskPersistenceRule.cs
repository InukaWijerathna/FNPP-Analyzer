using System;
using System.Collections.Generic;
using System.IO;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;
using DiagProcess = System.Diagnostics.Process;
using DiagProcessStartInfo = System.Diagnostics.ProcessStartInfo;

namespace FNPPAnalyzer.Rules.Persistence
{
    // PERS-002: Detect suspicious entries in Windows Task Scheduler.
    // Uses `schtasks /query /fo LIST /v` — no extra packages required.
    public class ScheduledTaskPersistenceRule : IDetectionRule
    {
        public string RuleId => "PERS-002";
        public string Name => "Scheduled Task Persistence";
        public string Description => "Detects scheduled tasks whose executables live in untrusted paths or are missing.";

        private static readonly string[] UntrustedFragments =
        [
            @"\Temp\", @"\Downloads\", @"\AppData\Local\Temp\",
            @"\AppData\Roaming\", @"\Public\", @"C:\Temp\"
        ];

        private static readonly string[] TrustedPrefixes =
        [
            @"C:\Windows\",
            @"C:\Program Files\",
            @"C:\Program Files (x86)\",
        ];

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();

            string? output = RunSchtasks();
            if (output == null) return events;

            // schtasks /fo LIST /v prints one task per block, fields are "Key:  Value"
            string? currentTask = null;
            string? runAs       = null;

            foreach (string rawLine in output.Split('\n'))
            {
                string line = rawLine.Trim();
                if (line.StartsWith("TaskName:", StringComparison.OrdinalIgnoreCase))
                {
                    currentTask = ExtractValue(line);
                    runAs       = null;
                    continue;
                }

                if (line.StartsWith("Run As User:", StringComparison.OrdinalIgnoreCase))
                {
                    runAs = ExtractValue(line);
                    continue;
                }

                if (!line.StartsWith("Task To Run:", StringComparison.OrdinalIgnoreCase)) continue;

                string taskExe = ExtractValue(line);

                // Skip placeholders / COM activations that schtasks emits
                if (string.IsNullOrWhiteSpace(taskExe)  ||
                    taskExe.Equals("N/A", StringComparison.OrdinalIgnoreCase) ||
                    taskExe.StartsWith("COM", StringComparison.OrdinalIgnoreCase))
                    continue;

                // Expand environment variables (%SystemRoot%, %windir%, etc.)
                string exePath = Environment.ExpandEnvironmentVariables(taskExe.Trim('"')).Split(' ')[0];

                string? reason = Classify(exePath, runAs);
                if (reason != null)
                    events.Add(new DetectionEvent
                    {
                        RuleId         = "PERS-002",
                        RuleName       = "Scheduled Task Persistence",
                        Severity       = runAs?.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase) == true
                                             ? AlertSeverity.High : AlertSeverity.Medium,
                        Type           = AlertType.MAL,
                        Description    = $"Suspicious scheduled task [{reason}]: {currentTask} → {exePath}" +
                                         (runAs != null ? $" (RunAs: {runAs})" : ""),
                        ExecutablePath = exePath,
                        Metadata       = new { TaskName = currentTask, Executable = exePath, RunAsUser = runAs }
                    });
            }

            return events;
        }

        private static string? Classify(string exePath, string? runAs)
        {
            if (string.IsNullOrWhiteSpace(exePath)) return null;

            // Flag executables from user-writable directories
            foreach (var frag in UntrustedFragments)
                if (exePath.Contains(frag, StringComparison.OrdinalIgnoreCase))
                    return "runs from untrusted path";

            // Flag missing executables that aren't in known trusted install locations
            if (!File.Exists(exePath))
            {
                foreach (var prefix in TrustedPrefixes)
                    if (exePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        return null; // stale but not suspicious (software uninstalled cleanly)

                return "target executable not found";
            }

            return null;
        }

        private static string ExtractValue(string line)
        {
            int colon = line.IndexOf(':');
            return colon >= 0 ? line[(colon + 1)..].Trim() : line.Trim();
        }

        private static string? RunSchtasks()
        {
            try
            {
                var psi = new DiagProcessStartInfo("schtasks", "/query /fo LIST /v")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    UseShellExecute        = false,
                    CreateNoWindow         = true
                };
                using var proc = DiagProcess.Start(psi);
                if (proc == null) return null;
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(15_000);
                return output;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[PERS-002] schtasks failed: {ex.Message}");
                return null;
            }
        }
    }
}
