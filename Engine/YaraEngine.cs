using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
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
    /// .yar/.yara file found in <c>rulesDirectory</c> at startup, and exposes simplified
    /// scan helpers. Call <see cref="Reload"/> to recompile and hot-swap the ruleset
    /// (e.g. after editing files in the rules directory) without restarting.
    /// </summary>
    public sealed class YaraEngine : IDisposable
    {
        private readonly YaraContext _context;
        private readonly Scanner _scanner;
        private readonly string _rulesDirectory;

        // Guards _rules so Reload() can't dispose a ruleset while a scan is reading
        // through its native handle (scans take the read lock, Reload takes the write lock).
        private readonly ReaderWriterLockSlim _rulesLock = new(LockRecursionPolicy.NoRecursion);
        private CompiledRules? _rules;

        /// <summary>True when at least one rule file was found and compiled successfully.</summary>
        public bool IsLoaded
        {
            get { _rulesLock.EnterReadLock(); try { return _rules != null; } finally { _rulesLock.ExitReadLock(); } }
        }

        /// <summary>Number of compiled YARA rules available for scanning.</summary>
        public int RuleCount
        {
            get { _rulesLock.EnterReadLock(); try { return _rules == null ? 0 : (int)_rules.RuleCount; } finally { _rulesLock.ExitReadLock(); } }
        }

        public YaraEngine(string rulesDirectory)
        {
            _context = new YaraContext();
            _scanner = new Scanner();
            _rulesDirectory = rulesDirectory;
            _rules = Compile(rulesDirectory);
        }

        /// <summary>Recompiles every .yar/.yara file in the rules directory and swaps it in.
        /// Returns true if a ruleset was loaded (false if the directory is empty/missing or compilation failed).</summary>
        public bool Reload()
        {
            var fresh = Compile(_rulesDirectory);

            _rulesLock.EnterWriteLock();
            try
            {
                var old = _rules;
                _rules = fresh;
                old?.Dispose();
            }
            finally { _rulesLock.ExitWriteLock(); }

            return fresh != null;
        }

        private static CompiledRules? Compile(string rulesDirectory)
        {
            if (!Directory.Exists(rulesDirectory)) return null;

            var files = Directory.GetFiles(rulesDirectory, "*.yar", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(rulesDirectory, "*.yara", SearchOption.TopDirectoryOnly))
                .ToArray();
            if (files.Length == 0) return null;

            try
            {
                using var compiler = new Compiler();
                foreach (var file in files)
                    compiler.AddRuleFile(file);
                return compiler.Compile();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[YARA] Failed to compile rules from {rulesDirectory}: {ex.Message}");
                return null;
            }
        }

        public IReadOnlyList<YaraRuleMatch> ScanFile(string path)
        {
            _rulesLock.EnterReadLock();
            try
            {
                if (_rules == null) return [];
                return _scanner.ScanFile(path, _rules).Select(ToMatch).ToArray();
            }
            catch
            {
                return [];
            }
            finally { _rulesLock.ExitReadLock(); }
        }

        public IReadOnlyList<YaraRuleMatch> ScanProcess(int processId)
        {
            _rulesLock.EnterReadLock();
            try
            {
                if (_rules == null) return [];
                return _scanner.ScanProcess(processId, _rules).Select(ToMatch).ToArray();
            }
            catch
            {
                return [];
            }
            finally { _rulesLock.ExitReadLock(); }
        }

        private static YaraRuleMatch ToMatch(ScanResult result) => new(
            result.MatchingRule.Identifier,
            result.MatchingRule.Tags.ToArray(),
            result.MatchingRule.Metas.ToDictionary(kv => kv.Key, kv => kv.Value),
            result.Matches.Keys.ToArray());

        public void Dispose()
        {
            _rules?.Dispose();
            _rulesLock.Dispose();
            _context.Dispose();
        }
    }
}
