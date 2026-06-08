using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnYara;

namespace FNPPAnalyzer.Engine
{
    /// <summary>One matched YARA rule, flattened from dnYara's native types for easy alerting.</summary>
    public sealed record YaraRuleMatch(
        string Identifier,
        IReadOnlyList<string> Tags,
        IReadOnlyDictionary<string, object> Metas,
        IReadOnlyList<string> MatchedStrings);

    /// <summary>
    /// Owns the dnYara native context for the application's lifetime, compiles every
    /// .yar/.yara file found in <c>rulesDirectory</c> once at startup, and exposes
    /// simplified scan helpers. Compiling is expensive — rules are loaded once and the
    /// app must be restarted to pick up changes (same convention as iocs.json).
    /// </summary>
    public sealed class YaraEngine : IDisposable
    {
        private readonly YaraContext _context;
        private readonly Scanner _scanner;
        private readonly CompiledRules? _rules;

        /// <summary>True when at least one rule file was found and compiled successfully.</summary>
        public bool IsLoaded => _rules != null;

        /// <summary>Number of compiled YARA rules available for scanning.</summary>
        public int RuleCount => _rules == null ? 0 : (int)_rules.RuleCount;

        public YaraEngine(string rulesDirectory)
        {
            _context = new YaraContext();
            _scanner = new Scanner();

            if (!Directory.Exists(rulesDirectory)) return;

            var files = Directory.GetFiles(rulesDirectory, "*.yar", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(rulesDirectory, "*.yara", SearchOption.TopDirectoryOnly))
                .ToArray();
            if (files.Length == 0) return;

            try
            {
                using var compiler = new Compiler();
                foreach (var file in files)
                    compiler.AddRuleFile(file);
                _rules = compiler.Compile();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[YARA] Failed to compile rules from {rulesDirectory}: {ex.Message}");
            }
        }

        public IReadOnlyList<YaraRuleMatch> ScanFile(string path)
        {
            if (_rules == null) return [];
            try
            {
                return _scanner.ScanFile(path, _rules).Select(ToMatch).ToArray();
            }
            catch
            {
                return [];
            }
        }

        public IReadOnlyList<YaraRuleMatch> ScanProcess(int processId)
        {
            if (_rules == null) return [];
            try
            {
                return _scanner.ScanProcess(processId, _rules).Select(ToMatch).ToArray();
            }
            catch
            {
                return [];
            }
        }

        private static YaraRuleMatch ToMatch(ScanResult result) => new(
            result.MatchingRule.Identifier,
            result.MatchingRule.Tags.ToArray(),
            result.MatchingRule.Metas.ToDictionary(kv => kv.Key, kv => kv.Value),
            result.Matches.Keys.ToArray());

        public void Dispose()
        {
            _rules?.Dispose();
            _context.Dispose();
        }
    }
}
