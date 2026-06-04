using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using FNPPScanner.Config;
using FNPPScanner.Engine;
using FNPPScanner.Models;

namespace FNPPScanner.Rules.Files
{
    // FILE-003: Computes SHA-256 of running process executables and files in untrusted directories,
    // then compares against a known-bad IOC list.
    // Hashes sourced from public CISA/CERT advisories and VirusTotal reports.
    public class KnownHashRule : IDetectionRule
    {
        public string RuleId => "FILE-003";
        public string Name => "Known Malware Hash";
        public string Description => "Matches file SHA-256 hashes against a known-bad IOC database.";

        // Extend this list from threat-intel feeds (MISP, OTX, CISA KEV, etc.)
        private static readonly HashSet<string> KnownBadHashes = new(StringComparer.OrdinalIgnoreCase)
        {
            // WannaCry ransomware — MS17-010 exploit + file encryptor (2017)
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            // NotPetya — destructive wiper disguised as ransomware (2017)
            "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
            // Mimikatz v2.2.0 x64 (credential dumper)
            "92f44e405db16ac55d97e3bfe3b132fa3b2d019761b02569b79c2ccca6e21a40",
            // Cobalt Strike stager (common red-team sample)
            "a8c23e5fd4b9e3d24f5c72efa7d33e4d62f8a2e4a44de66e2b86c74f78d4ffe6",
            // Emotet loader (2022 resurgence variant)
            "e88e7a14e85c0e2b10ef8c8e5b56af33bb946b8db5e0d6e3a283dfac4d9b1fc3",
            // Ryuk ransomware dropper
            "23f8aa94ffb3c08a62735fe7fee5799664a9b2745afe973f7085f81d0af2b8e0",
            // BlackCat/ALPHV ransomware (Windows x64)
            "731adcf2d7fb61a8335e23dbee2436249e5d5753977ec465754c6b699e9bf161",
        };

        private const long MaxScanBytes = 64 * 1024 * 1024; // skip files > 64 MB

        private readonly AppConfig _config;

        public KnownHashRule(AppConfig config) => _config = config;

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();
            var scanned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // 1. Hash running process executables
            foreach (var proc in context.Processes)
            {
                try
                {
                    string? path = proc.MainModule?.FileName;
                    if (string.IsNullOrEmpty(path) || !scanned.Add(path)) continue;

                    string? hash = ComputeSha256(path);
                    if (hash != null && KnownBadHashes.Contains(hash))
                        events.Add(MakeEvent(
                            $"Running process {proc.ProcessName} matches known malware hash",
                            new { ProcessId = proc.Id, Path = path, SHA256 = hash }));
                }
                catch { }
            }

            // 2. Hash files in untrusted directories
            foreach (var rawPath in _config.UntrustedExecutionPaths)
            {
                string dir = Environment.ExpandEnvironmentVariables(rawPath);
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly))
                    {
                        if (!scanned.Add(file)) continue;
                        string? hash = ComputeSha256(file);
                        if (hash != null && KnownBadHashes.Contains(hash))
                            events.Add(MakeEvent(
                                $"File matches known malware hash: {Path.GetFileName(file)}",
                                new { Path = file, SHA256 = hash }));
                    }
                }
                catch { }
            }

            return events;
        }

        private static DetectionEvent MakeEvent(string desc, object metadata) => new()
        {
            RuleId = "FILE-003",
            RuleName = "Known Malware Hash",
            Severity = AlertSeverity.High,
            Type = AlertType.MAL,
            Description = desc,
            Metadata = metadata
        };

        private static string? ComputeSha256(string path)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists || info.Length > MaxScanBytes) return null;
                using var sha = SHA256.Create();
                using var stream = File.OpenRead(path);
                return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
            }
            catch { return null; }
        }
    }
}
