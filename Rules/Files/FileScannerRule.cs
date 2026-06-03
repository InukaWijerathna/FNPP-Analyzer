using System;
using System.Collections.Generic;
using System.IO;
using WinEDR_MVP.Config;
using WinEDR_MVP.Engine;
using WinEDR_MVP.Models;

namespace WinEDR_MVP.Rules.Files
{
    // MAL-F1/F5: File-based indicators in untrusted directories.
    public class FileScannerRule : IDetectionRule
    {
        public string RuleId => "FILE";
        public string Name => "File Indicator Scan";
        public string Description => "Scans untrusted directories for suspicious file-based indicators.";

        private readonly AppConfig _config;

        public FileScannerRule(AppConfig config) => _config = config;

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();

            foreach (var rawPath in _config.UntrustedExecutionPaths)
            {
                string dir = Environment.ExpandEnvironmentVariables(rawPath);
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly))
                    {
                        var info = new FileInfo(file);

                        // MAL-F1: Double extension (e.g. report.pdf.exe)
                        if (file.EndsWith(".pdf.exe", StringComparison.OrdinalIgnoreCase) ||
                            file.EndsWith(".doc.exe", StringComparison.OrdinalIgnoreCase) ||
                            file.EndsWith(".txt.js",  StringComparison.OrdinalIgnoreCase))
                            events.Add(new DetectionEvent
                            {
                                RuleId = "FILE-001",
                                RuleName = "Double Extension File",
                                Severity = AlertSeverity.High,
                                Type = AlertType.MAL,
                                Description = $"Double extension detected: {info.Name}",
                                Metadata = new { Path = file }
                            });

                        // MAL-F5: Hidden executable
                        if (info.Attributes.HasFlag(FileAttributes.Hidden) &&
                            (file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                             file.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)))
                            events.Add(new DetectionEvent
                            {
                                RuleId = "FILE-002",
                                RuleName = "Hidden Executable",
                                Severity = AlertSeverity.Medium,
                                Type = AlertType.MAL,
                                Description = $"Hidden executable found: {info.Name}",
                                Metadata = new { Path = file }
                            });
                    }
                }
                catch { }
            }
            return events;
        }
    }
}
