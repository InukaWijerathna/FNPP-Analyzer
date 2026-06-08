using System;
using System.Collections.Generic;
using System.IO;
using FNPPAnalyzer.Config;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Rules.Files
{
    // FILE-005: Matches running process executables and files in untrusted directories
    // against compiled YARA rules (see YaraEngine / YaraRules/*.yar). Severity and alert
    // type are taken from each rule's `meta.severity` / `meta.type`, falling back to
    // Medium/MAL when a rule doesn't specify them.
    public class YaraScanRule : IDetectionRule
    {
        public string RuleId => "FILE-005";
        public string Name => "YARA Rule Match";
        public string Description => "Scans executables and untrusted-directory files against compiled YARA rules.";

        private const long MaxScanBytes = 64 * 1024 * 1024;

        private readonly YaraEngine _yara;
        private readonly AppConfig _config;

        public YaraScanRule(YaraEngine yara, AppConfig config)
        {
            _yara = yara;
            _config = config;
        }

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();
            if (!_yara.IsLoaded) return events;

            var scanned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // 1. Running process executables
            foreach (var proc in context.Processes)
            {
                try
                {
                    string? path = proc.MainModule?.FileName;
                    if (string.IsNullOrEmpty(path) || !scanned.Add(path)) continue;

                    context.ReportDetail?.Invoke(path);
                    ScanAndCollect(path, events, processId: proc.Id, processName: proc.ProcessName);
                }
                catch { }
            }

            // 2. Files in untrusted directories
            foreach (var rawPath in _config.UntrustedExecutionPaths)
            {
                string dir = Environment.ExpandEnvironmentVariables(rawPath);
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories))
                    {
                        if (!scanned.Add(file)) continue;
                        context.ReportDetail?.Invoke(file);
                        ScanAndCollect(file, events);
                    }
                }
                catch (Exception ex) { Console.Error.WriteLine($"[FILE-005] {dir}: {ex.Message}"); }
            }

            return events;
        }

        private void ScanAndCollect(string path, List<DetectionEvent> events, int? processId = null, string? processName = null)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists || info.Length > MaxScanBytes) return;
            }
            catch { return; }

            foreach (var match in _yara.ScanFile(path))
            {
                string desc = processId.HasValue
                    ? $"Process {processName} ({path}) matches YARA rule '{match.Identifier}'"
                    : $"{Path.GetFileName(path)} matches YARA rule '{match.Identifier}'";

                events.Add(new DetectionEvent
                {
                    RuleId         = "FILE-005",
                    RuleName       = $"YARA Match: {match.Identifier}",
                    Severity       = ResolveSeverity(match),
                    Type           = ResolveType(match),
                    Description    = desc,
                    ExecutablePath = path,
                    Metadata       = new
                    {
                        Path = path,
                        ProcessId = processId,
                        Rule = match.Identifier,
                        Tags = match.Tags,
                        MatchedStrings = match.MatchedStrings
                    }
                });
            }
        }

        private static AlertSeverity ResolveSeverity(YaraRuleMatch match) =>
            match.Metas.TryGetValue("severity", out var sev) && sev is string s
            && Enum.TryParse<AlertSeverity>(s, ignoreCase: true, out var parsed)
                ? parsed
                : AlertSeverity.Medium;

        private static AlertType ResolveType(YaraRuleMatch match) =>
            match.Metas.TryGetValue("type", out var type) && type is string t
            && Enum.TryParse<AlertType>(t, ignoreCase: true, out var parsed)
                ? parsed
                : AlertType.MAL;
    }
}
