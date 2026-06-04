using System;
using System.Collections.Generic;
using FNPPAnalyzer.Config;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Rules.Process
{
    // PROC-006: Detects unsigned executables running from Windows system directories.
    // Uses WinVerifyTrust (Authenticode) — the correct Windows API for signature verification.
    // Scoped to processes whose names are in TrustedSystemProcesses config; legitimate
    // OEM drivers in DriverStore/SystemApps are excluded to prevent false positives.
    public class UnsignedProcessRule : IDetectionRule
    {
        public string RuleId => "PROC-006";
        public string Name => "Unsigned System Process";
        public string Description => "Detects unsigned executables running from Windows system directories.";

        // Legitimate OEM/driver paths — always skip, they contain third-party signed binaries
        private static readonly string[] ExcludedPrefixes =
        [
            @"C:\Windows\System32\DriverStore\",
            @"C:\Windows\SysWOW64\DriverStore\",
            @"C:\Windows\SystemApps\",
            @"C:\Windows\WinSxS\",
        ];

        private static readonly string[] SystemPrefixes =
        [
            @"C:\Windows\System32\",
            @"C:\Windows\SysWOW64\",
            @"C:\Windows\",
        ];

        private readonly AppConfig _config;

        public UnsignedProcessRule(AppConfig config) => _config = config;

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();
            var checked_ = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var proc in context.Processes)
            {
                try
                {
                    // Only check processes whose name appears in TrustedSystemProcesses —
                    // everything else (OEM tools, third-party utilities) is expected to vary.
                    string procName = proc.ProcessName.ToLower();
                    if (!_config.TrustedSystemProcesses.Contains(procName + ".exe")) continue;

                    string? path = proc.MainModule?.FileName;
                    if (string.IsNullOrEmpty(path) || !checked_.Add(path)) continue;

                    // Skip DriverStore, SystemApps, WinSxS — OEM / packaged-app territory
                    bool excluded = false;
                    foreach (var prefix in ExcludedPrefixes)
                        if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        { excluded = true; break; }
                    if (excluded) continue;

                    bool inSystem = false;
                    foreach (var prefix in SystemPrefixes)
                        if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        { inSystem = true; break; }
                    if (!inSystem) continue;

                    if (AuthenticodeVerifier.Verify(path) != SignatureStatus.Valid)
                        events.Add(new DetectionEvent
                        {
                            RuleId         = RuleId,
                            RuleName       = Name,
                            Severity       = AlertSeverity.High,
                            Type           = AlertType.MAL,
                            Description    = $"Unsigned executable in system path: {proc.ProcessName} ({path})",
                            ExecutablePath = path,
                            Metadata       = new { ProcessId = proc.Id, Path = path }
                        });
                }
                catch { }
            }
            return events;
        }

    }
}
