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

        // YARA scanning is the most expensive part of this rule — memoize per file by
        // path+mtime+size so re-scans of unchanged files (every cycle, every 30s in live
        // monitor) are free.
        private readonly FileScanCache<IReadOnlyList<YaraRuleMatch>> _matchCache = new();

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

            // 3. In-memory scan of processes running from untrusted locations — catches
            // fileless/in-memory payloads (reflective loading, process hollowing) that
            // never touch disk in a form the on-disk scan above would see. Scoped to
            // processes outside TrustedExecutionPaths since scanning every process's
            // memory every cycle would be far too costly for live monitoring.
            foreach (var proc in context.Processes)
            {
                try
                {
                    string? path = proc.MainModule?.FileName;
                    if (string.IsNullOrEmpty(path) || StartsWithTrustedPath(path)) continue;

                    context.ReportDetail?.Invoke($"{proc.ProcessName} (PID {proc.Id}) [memory]");
                    ScanProcessMemoryAndCollect(proc.Id, proc.ProcessName, path, events);
                }
                catch { }
            }

            return events;
        }

        private void ScanAndCollect(string path, List<DetectionEvent> events, int? processId = null, string? processName = null)
        {
            foreach (var match in ScanFileCached(path))
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

        private void ScanProcessMemoryAndCollect(int processId, string processName, string path, List<DetectionEvent> events)
        {
            foreach (var match in _yara.ScanProcess(processId))
            {
                events.Add(new DetectionEvent
                {
                    RuleId         = "FILE-005",
                    RuleName       = $"YARA Match: {match.Identifier}",
                    Severity       = ResolveSeverity(match),
                    Type           = ResolveType(match),
                    Description    = $"Process {processName} (PID {processId}) memory matches YARA rule '{match.Identifier}'",
                    ExecutablePath = path,
                    Metadata       = new
                    {
                        Path = path,
                        ProcessId = processId,
                        Rule = match.Identifier,
                        Tags = match.Tags,
                        MatchedStrings = match.MatchedStrings,
                        Scope = "memory"
                    }
                });
            }
        }

        private bool StartsWithTrustedPath(string path)
        {
            foreach (var t in _config.TrustedExecutionPaths)
                if (path.StartsWith(t, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private IReadOnlyList<YaraRuleMatch> ScanFileCached(string path)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists || info.Length > MaxScanBytes) return [];
                return _matchCache.GetOrCompute(path, info, () => _yara.ScanFile(path));
            }
            catch { return []; }
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
