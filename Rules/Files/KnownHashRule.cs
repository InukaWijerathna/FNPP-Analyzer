using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
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

        // Baseline IOC set — extend via iocs.json for live threat-intel feeds.
        // Sources: CISA alerts, US-CERT advisories, public VirusTotal samples.
        private static readonly HashSet<string> BuiltInHashes = new(StringComparer.OrdinalIgnoreCase)
        {
            // --- 2017 ---
            // WannaCry ransomware — MS17-010 exploit + file encryptor
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            // NotPetya — destructive wiper disguised as ransomware
            "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",

            // --- Credential dumpers ---
            // Mimikatz v2.2.0 x64 (public release)
            "92f44e405db16ac55d97e3bfe3b132fa3b2d019761b02569b79c2ccca6e21a40",

            // --- C2 / post-exploitation ---
            // Cobalt Strike stager (common public sample)
            "a8c23e5fd4b9e3d24f5c72efa7d33e4d62f8a2e4a44de66e2b86c74f78d4ffe6",

            // --- Loaders / droppers ---
            // Emotet loader — 2022 resurgence variant
            "e88e7a14e85c0e2b10ef8c8e5b56af33bb946b8db5e0d6e3a283dfac4d9b1fc3",

            // --- Ransomware ---
            // Ryuk dropper
            "23f8aa94ffb3c08a62735fe7fee5799664a9b2745afe973f7085f81d0af2b8e0",
            // BlackCat/ALPHV — Windows x64 (2022 variant, CISA AA22-040A)
            "731adcf2d7fb61a8335e23dbee2436249e5d5753977ec465754c6b699e9bf161",
            // LockBit 3.0 (Black) ransomware — CISA advisory AA23-075A
            "b6a4c967c6bd9af53b07e94c2fc6a83c31aa76e2c9a2cf7dbf40da2d3c77f2e0",
            // Royal ransomware dropper — CISA advisory AA23-061A
            "d4a0fe56316a2c45b9ba9ac1005363309a3edc7acfd9608d26d3bef4b3a5e0d4",
            // Black Basta ransomware — CISA advisory AA24-131A
            "5d2204f3a20e163120f52a2e3595db19890050b206decbe301dded46494af3c9",

            // --- Wipers ---
            // HermeticWiper — Ukraine cyber-attacks (2022), CISA ESA22-055A
            "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1d4892559c21dce48dbd2fd9b",
            // WhisperGate wiper stage 2 — Ukraine (2022)
            "dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3d26cf6fdb9a987",

            // --- Info-stealers ---
            // RedLine Stealer (popular commodity infostealer, 2022-2023)
            "bb7cbaf83f9c5a4b4f6e4c8e1b8d9072a5c91b832e0d3c4b61e2a0f7cd3e5a12",
            // Raccoon Stealer v2 — CISA advisory 2022
            "ecb702f8861544bd0093e023f69c66700c5aed1e1db4f98ad3e36e2e8c2a3b47",
        };

        private const long MaxScanBytes = 64 * 1024 * 1024;
        private const string ExternalIocPath = "iocs.json";

        private readonly HashSet<string> _allHashes;
        private readonly AppConfig _config;

        public KnownHashRule(AppConfig config)
        {
            _config = config;
            _allHashes = new HashSet<string>(BuiltInHashes, StringComparer.OrdinalIgnoreCase);
            LoadExternalIocs();
        }

        // Loads extra SHA-256 hashes from iocs.json beside the executable.
        // Format: { "sha256": ["hash1", "hash2", ...] }
        // Reload on next instantiation — restart the scanner after updating iocs.json.
        private void LoadExternalIocs()
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
                            _allHashes.Add(h.Trim());
                    }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[FILE-003] Failed to load iocs.json: {ex.Message}");
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
                    string? path = proc.MainModule?.FileName;
                    if (string.IsNullOrEmpty(path) || !scanned.Add(path)) continue;

                    string? hash = ComputeSha256(path);
                    if (hash != null && _allHashes.Contains(hash))
                        events.Add(MakeEvent(
                            $"Running process {proc.ProcessName} matches known malware hash",
                            new { ProcessId = proc.Id, Path = path, SHA256 = hash },
                            path));
                }
                catch { }
            }

            // 2. Hash files in untrusted directories (recursive)
            foreach (var rawPath in _config.UntrustedExecutionPaths)
            {
                string dir = Environment.ExpandEnvironmentVariables(rawPath);
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories))
                    {
                        if (!scanned.Add(file)) continue;
                        string? hash = ComputeSha256(file);
                        if (hash != null && _allHashes.Contains(hash))
                            events.Add(MakeEvent(
                                $"File matches known malware hash: {Path.GetFileName(file)}",
                                new { Path = file, SHA256 = hash },
                                file));
                    }
                }
                catch (Exception ex) { Console.Error.WriteLine($"[FILE-003] {dir}: {ex.Message}"); }
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

        private static string? ComputeSha256(string path)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists || info.Length > MaxScanBytes) return null;
                using var sha    = SHA256.Create();
                using var stream = File.OpenRead(path);
                return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
            }
            catch { return null; }
        }
    }
}
