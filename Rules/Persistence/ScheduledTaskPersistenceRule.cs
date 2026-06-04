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
            @"\Temp\", @"\Downloads\", @"\AppData\Local\Temp\", @"C:\Temp\"
        ];

        private static readonly string[] TrustedPrefixes =
        [
            @"C:\Windows\",
            @"C:\Program Files\",
            @"C:\Program Files (x86)\",
            @"C:\ProgramData\Microsoft\",   // Windows Defender, .NET runtime tasks, etc.
        ];

        // Only flag paths that end in a recognized executable extension.
        // Unquoted schtasks paths with spaces get truncated by the space-split;
        // the truncated fragment has no extension and would be a false positive.
        private static readonly string[] ExecutableExtensions =
            [".exe", ".cmd", ".bat", ".ps1", ".vbs", ".js", ".msi", ".dll"];

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();

            string? output = RunSchtasks();
            if (output == null) return events;

            // schtasks /fo LIST /v prints one task per block; fields are "Key:  Value"
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

                // Skip placeholders / COM activations emitted by schtasks
                if (string.IsNullOrWhiteSpace(taskExe) ||
                    taskExe.Equals("N/A", StringComparison.OrdinalIgnoreCase) ||
                    taskExe.StartsWith("COM", StringComparison.OrdinalIgnoreCase))
                    continue;

                string? exePath = ParseExePath(taskExe);
                if (exePath == null) continue;

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

        // Extracts and validates the executable path from the "Task To Run:" field.
        // Returns null when the path should be silently skipped.
        private static string? ParseExePath(string taskToRun)
        {
            string raw = taskToRun.Trim();
            string candidate;

            if (raw.StartsWith('"'))
            {
                // Properly quoted: "C:\Path With Spaces\exe.exe" [-args]
                int closing = raw.IndexOf('"', 1);
                candidate = closing > 1 ? raw[1..closing] : raw[1..];
            }
            else
            {
                // Unquoted: take only the first space-delimited token.
                // Paths with spaces will be truncated here — that's intentional;
                // the extension check below will discard the fragment as a non-match.
                candidate = raw.Split(' ')[0];
            }

            candidate = Environment.ExpandEnvironmentVariables(candidate.Trim());

            // Skip relative names (e.g. "sc.exe", "BthUdTask.exe") that resolve via
            // PATH / System32 — they're legitimate Windows tools, not persistence.
            if (!candidate.Contains('\\') && !candidate.Contains('/'))
                return null;

            // Skip fragments without a recognized executable extension — these are
            // almost always the result of an unquoted path being split at a space.
            string ext = Path.GetExtension(candidate).ToLowerInvariant();
            if (Array.IndexOf(ExecutableExtensions, ext) < 0)
                return null;

            return candidate;
        }

        private static string? Classify(string exePath, string? runAs)
        {
            // Flag executables from user-writable / temp directories
            foreach (var frag in UntrustedFragments)
                if (exePath.Contains(frag, StringComparison.OrdinalIgnoreCase))
                    return "runs from untrusted path";

            // Flag missing executables outside known trusted install locations
            if (!File.Exists(exePath))
            {
                foreach (var prefix in TrustedPrefixes)
                    if (exePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        return null; // stale entry from an uninstalled app — not suspicious

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
