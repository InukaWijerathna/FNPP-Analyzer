using System;
using System.Collections.Generic;
using System.IO;
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

        private static readonly string WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        private static readonly string System32Dir = Environment.GetFolderPath(Environment.SpecialFolder.System);
        private static readonly string SysWow64Dir = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);

        // Legitimate OEM/driver paths — always skip, they contain third-party signed binaries
        private static readonly string[] ExcludedPrefixes =
        [
            Path.Combine(System32Dir, "DriverStore"),
            Path.Combine(SysWow64Dir, "DriverStore"),
            Path.Combine(WindowsDir, "SystemApps"),
            Path.Combine(WindowsDir, "WinSxS"),
        ];

        private static readonly string[] SystemPrefixes =
        [
            System32Dir,
            SysWow64Dir,
            WindowsDir,
        ];

        private readonly AppConfig _config;

        public UnsignedProcessRule(AppConfig config) => _config = config;

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();
            var checked_ = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var proc in context.Processes)
            {
                // Only check processes whose name appears in TrustedSystemProcesses —
                // everything else (OEM tools, third-party utilities) is expected to vary.
                string procName = proc.Name.ToLower();
                if (!_config.TrustedSystemProcesses.Contains(procName + ".exe")) continue;

                string? path = proc.ExecutablePath;
                if (path == null || !checked_.Add(path)) continue;

                // Skip DriverStore, SystemApps, WinSxS — OEM / packaged-app territory
                if (PathTrust.IsUnderTrustedPath(path, ExcludedPrefixes)) continue;
                if (!PathTrust.IsUnderTrustedPath(path, SystemPrefixes)) continue;

                if (AuthenticodeVerifier.Verify(path) != SignatureStatus.Valid)
                    events.Add(new DetectionEvent
                    {
                        RuleId         = RuleId,
                        RuleName       = Name,
                        Severity       = AlertSeverity.High,
                        Type           = AlertType.MAL,
                        Description    = $"Unsigned executable in system path: {proc.Name} ({path})",
                        ExecutablePath = path,
                        Metadata       = new { ProcessId = proc.Pid, Path = path }
                    });
            }
            return events;
        }

    }
}
