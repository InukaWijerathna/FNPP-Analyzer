using System;
using System.Collections.Generic;
using System.IO;
using FNPPAnalyzer.Config;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Rules.Files
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
                if (!context.UntrustedDirectoryFiles.TryGetValue(dir, out var files)) continue;

                foreach (var file in files)
                {
                    try
                    {
                        context.ReportDetail?.Invoke(file);
                        var info = new FileInfo(file);

                        // MAL-F1: Double extension (e.g. report.pdf.exe)
                        if (file.EndsWith(".pdf.exe", StringComparison.OrdinalIgnoreCase) ||
                            file.EndsWith(".doc.exe", StringComparison.OrdinalIgnoreCase) ||
                            file.EndsWith(".txt.js",  StringComparison.OrdinalIgnoreCase))
                            events.Add(new DetectionEvent
                            {
                                RuleId         = "FILE-001",
                                RuleName       = "Double Extension File",
                                Severity       = AlertSeverity.High,
                                Type           = AlertType.MAL,
                                Description    = $"Double extension detected: {info.Name}",
                                ExecutablePath = file,
                                Metadata       = new { Path = file }
                            });

                        // MAL-F5: Hidden executable
                        if (info.Attributes.HasFlag(FileAttributes.Hidden) &&
                            (file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                             file.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)))
                            events.Add(new DetectionEvent
                            {
                                RuleId         = "FILE-002",
                                RuleName       = "Hidden Executable",
                                Severity       = AlertSeverity.Medium,
                                Type           = AlertType.MAL,
                                Description    = $"Hidden executable found: {info.Name}",
                                ExecutablePath = file,
                                Metadata       = new { Path = file }
                            });
                    }
                    catch (UnauthorizedAccessException) { }  // file's attributes unreadable — expected
                    catch (Exception ex) { lock (ConsoleSync.Lock) Console.Error.WriteLine($"[FILE-001/002] {file}: {ex.GetType().Name}: {ex.Message}"); }
                }
            }
            return events;
        }
    }
}
