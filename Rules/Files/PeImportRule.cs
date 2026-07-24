using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using FNPPAnalyzer.Config;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Rules.Files
{
    // FILE-004: Scans PE files in untrusted directories for suspicious imported API combinations.
    // PE import names are stored as plain ASCII strings, making them detectable via string scan.
    public class PeImportRule : IDetectionRule
    {
        public string RuleId => "FILE-004";
        public string Name => "Suspicious PE Imports";
        public string Description => "Detects executables importing API combinations associated with malware behaviour.";

        private const long MaxFileBytes = 32 * 1024 * 1024; // skip files > 32 MB

        // Each entry: display name, required APIs (ALL must be present), severity, type
        private sealed record ApiSignature(string Name, string[] Required, AlertSeverity Severity, AlertType Type);

        private static readonly ApiSignature[] Signatures =
        [
            new("Process Injector",
                ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                AlertSeverity.High, AlertType.TROJ),

            new("Process Injector (NT)",
                ["NtCreateThreadEx", "VirtualAllocEx"],
                AlertSeverity.High, AlertType.TROJ),

            new("Keylogger",
                ["GetAsyncKeyState", "SetWindowsHookEx"],
                AlertSeverity.High, AlertType.TROJ),

            new("Keylogger (Raw Input)",
                ["RegisterRawInputDevices", "GetRawInputData"],
                AlertSeverity.Medium, AlertType.TROJ),

            new("Credential Dumper",
                ["LsaEnumerateLogonSessions", "LsaGetLogonSessionData"],
                AlertSeverity.High, AlertType.TROJ),

            new("Ransomware (Crypto APIs)",
                ["CryptEncrypt", "CryptGenKey", "FindFirstFileW"],
                AlertSeverity.High, AlertType.RANSOM),

            new("Ransomware (BCrypt)",
                ["BCryptEncrypt", "BCryptGenerateSymmetricKey"],
                AlertSeverity.High, AlertType.RANSOM),

            new("Anti-Debug",
                ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"],
                AlertSeverity.Medium, AlertType.MAL),

            new("Token Impersonation",
                ["DuplicateTokenEx", "ImpersonateLoggedOnUser", "CreateProcessAsUserW"],
                AlertSeverity.High, AlertType.BACK),
        ];

        private readonly AppConfig _config;

        // String-extraction is the costly part — memoize per file by path+mtime+size so
        // re-scans of unchanged files (every cycle, every 30s in live monitor) are free.
        private readonly FileScanCache<List<DetectionEvent>> _cache = new();

        public PeImportRule(AppConfig config) => _config = config;

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();

            // Reuses the per-cycle directory listing from ScanContext instead of doing its
            // own walk — this also makes coverage recursive, consistent with FILE-001/002/003/005.
            foreach (var rawPath in _config.UntrustedExecutionPaths)
            {
                string dir = Environment.ExpandEnvironmentVariables(rawPath);
                if (!context.UntrustedDirectoryFiles.TryGetValue(dir, out var files)) continue;

                foreach (var file in files)
                {
                    if (!file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                        !file.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                        continue;

                    context.ReportDetail?.Invoke(file);
                    events.AddRange(ScanFileCached(file));
                }
            }
            return events;
        }

        private List<DetectionEvent> ScanFileCached(string path)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists || info.Length > MaxFileBytes) return [];
                return _cache.GetOrCompute(path, info, () => ScanFile(path));
            }
            catch { return []; }
        }

        // Returns a List (not an iterator) so exceptions from one file don't abort the
        // whole directory scan — the caller's catch only wraps Directory.GetFiles, not each file.
        private static List<DetectionEvent> ScanFile(string path)
        {
            var results = new List<DetectionEvent>();
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists || info.Length > MaxFileBytes) return results;

                // PE import names are stored as null-terminated ASCII strings — extract all
                // printable ASCII sequences ≥4 chars (same technique as Unix `strings`)
                var strings = ExtractStrings(path);
                string fileName = Path.GetFileName(path);

                foreach (var sig in Signatures)
                {
                    bool allFound = true;
                    foreach (var api in sig.Required)
                        if (!strings.Contains(api)) { allFound = false; break; }

                    if (allFound)
                        results.Add(new DetectionEvent
                        {
                            RuleId = "FILE-004",
                            RuleName = $"Suspicious PE Imports: {sig.Name}",
                            Severity = sig.Severity,
                            Type = sig.Type,
                            Description = $"{fileName} imports APIs associated with {sig.Name}: {string.Join(", ", sig.Required)}",
                            Metadata = new { Path = path, Signature = sig.Name }
                        });
                }
            }
            catch { }
            return results;
        }

        private static HashSet<string> ExtractStrings(string path, int minLen = 4)
        {
            var result = new HashSet<string>(StringComparer.Ordinal);
            byte[] data = File.ReadAllBytes(path);
            var sb = new StringBuilder(64);

            foreach (byte b in data)
            {
                if (b >= 32 && b < 127)
                    sb.Append((char)b);
                else
                {
                    if (sb.Length >= minLen) result.Add(sb.ToString());
                    sb.Clear();
                }
            }
            if (sb.Length >= minLen) result.Add(sb.ToString());
            return result;
        }
    }
}
