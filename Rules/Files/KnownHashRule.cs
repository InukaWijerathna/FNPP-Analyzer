using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using FNPPAnalyzer.Config;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Rules.Files
{
    // FILE-003: Computes SHA-256 of running process executables and files in untrusted directories,
    // then compares against a known-bad IOC list.
    // Hashes sourced from public CISA/CERT advisories and VirusTotal reports.
    // Extra hashes can be loaded at runtime from iocs.json (see LoadExternalIocs).
    public class KnownHashRule : IDetectionRule
    {
        public string RuleId => "FILE-003";
        public string Name => "Known Malware Hash";
        public string Description => "Matches file SHA-256 hashes against a known-bad IOC database.";

        // Baseline IOC set — deliberately tiny. Only hashes that are widely documented in
        // public advisories and reproducible across sources are shipped here; a hardcoded
        // list is stale on arrival, so real coverage comes from iocs.json, which can be
        // fed from a live source (e.g. abuse.ch MalwareBazaar / ThreatFox exports) and
        // hot-reloaded via the Reload Rules menu.
        private static readonly HashSet<string> BuiltInHashes = new(StringComparer.OrdinalIgnoreCase)
        {
            // WannaCry ransomware (2017) — MS17-010 exploit + file encryptor
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            // NotPetya (2017) — destructive wiper disguised as ransomware
            "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
            // HermeticWiper — Ukraine cyber-attacks (2022)
            "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1d4892559c21dce48dbd2fd9b",
            // WhisperGate wiper stage 2 — Ukraine (2022)
            "dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3d26cf6fdb9a987",
        };

        private const long MaxScanBytes = 64 * 1024 * 1024;
        private const string ExternalIocPath = "iocs.json";

        // Built fresh on load/reload and never mutated afterwards — readers can use it
        // without locking, and Reload() swaps the reference atomically.
        private volatile HashSet<string> _allHashes;
        private readonly AppConfig _config;

        public KnownHashRule(AppConfig config)
        {
            _config = config;
            _allHashes = BuildHashSet();
        }

        /// <summary>Re-reads iocs.json from disk, restoring the built-in set first so removed entries take effect.</summary>
        public void Reload() => _allHashes = BuildHashSet();

        private static HashSet<string> BuildHashSet()
        {
            var hashes = new HashSet<string>(BuiltInHashes, StringComparer.OrdinalIgnoreCase);
            LoadExternalIocs(hashes);
            return hashes;
        }

        // Loads extra SHA-256 hashes from iocs.json beside the executable into the given set.
        // Format: { "sha256": ["hash1", "hash2", ...] }
        private static void LoadExternalIocs(HashSet<string> hashes)
        {
            if (!File.Exists(ExternalIocPath)) return;
            try
            {
                using var stream = File.OpenRead(ExternalIocPath);
                var doc = JsonDocument.Parse(stream);
                if (doc.RootElement.TryGetProperty("sha256", out var arr))
                    foreach (var el in arr.EnumerateArray())
                    {
                        string? h = el.GetString();
                        if (!string.IsNullOrWhiteSpace(h))
                            hashes.Add(h.Trim());
                    }
            }
            catch (Exception ex)
            {
                lock (ConsoleSync.Lock) Console.Error.WriteLine($"[FILE-003] Failed to load iocs.json: {ex.Message}");
            }
        }

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events  = new List<DetectionEvent>();
            var scanned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // 1. Hash running process executables
            foreach (var proc in context.Processes)
            {
                try
                {
                    string? path = proc.ExecutablePath;
                    if (path == null || !scanned.Add(path)) continue;

                    context.ReportDetail?.Invoke(path);
                    string? hash = HashCached(path);
                    if (hash != null && _allHashes.Contains(hash))
                        events.Add(MakeEvent(
                            $"Running process {proc.Name} matches known malware hash",
                            new { ProcessId = proc.Pid, Path = path, SHA256 = hash },
                            path));
                }
                catch { }
            }

            // 2. Hash files in untrusted directories (recursive)
            foreach (var rawPath in _config.UntrustedExecutionPaths)
            {
                string dir = Environment.ExpandEnvironmentVariables(rawPath);
                if (!context.UntrustedDirectoryFiles.TryGetValue(dir, out var files)) continue;

                foreach (var file in files)
                {
                    if (!scanned.Add(file)) continue;
                    context.ReportDetail?.Invoke(file);
                    string? hash = HashCached(file);
                    if (hash != null && _allHashes.Contains(hash))
                        events.Add(MakeEvent(
                            $"File matches known malware hash: {Path.GetFileName(file)}",
                            new { Path = file, SHA256 = hash },
                            file));
                }
            }

            return events;
        }

        private static DetectionEvent MakeEvent(string desc, object metadata, string path) => new()
        {
            RuleId         = "FILE-003",
            RuleName       = "Known Malware Hash",
            Severity       = AlertSeverity.High,
            Type           = AlertType.MAL,
            Description    = desc,
            ExecutablePath = path,
            Metadata       = metadata
        };

        // FileHasher provides the process-wide mtime+size cache (shared with the whitelist
        // and signature verifier) — this rule only adds its size cap on top.
        private static string? HashCached(string path)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists || info.Length > MaxScanBytes) return null;
                return FileHasher.Sha256(path);
            }
            catch { return null; }
        }
    }
}
