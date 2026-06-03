using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using WinEDR_MVP.Config;
using WinEDR_MVP.Engine;
using WinEDR_MVP.Models;

namespace WinEDR_MVP.Rules.Process
{
    // MAL-S: Detects processes in trusted system directories that are not signed by Microsoft.
    // Legitimate Windows system processes are always Authenticode-signed.
    // An unsigned binary in System32 is a strong masquerading indicator.
    public class UnsignedProcessRule : IDetectionRule
    {
        public string RuleId => "MAL-S";
        public string Name => "Unsigned System Process";
        public string Description => "Detects unsigned executables running from system directories.";

        private static readonly string[] SystemPaths =
        [
            @"C:\Windows\System32",
            @"C:\Windows\SysWOW64",
            @"C:\Windows\"
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
                    string? path = proc.MainModule?.FileName;
                    if (string.IsNullOrEmpty(path) || !checked_.Add(path)) continue;

                    bool inSystemPath = false;
                    foreach (var sp in SystemPaths)
                        if (path.StartsWith(sp, StringComparison.OrdinalIgnoreCase))
                        { inSystemPath = true; break; }

                    if (!inSystemPath) continue;

                    if (!IsMicrosoftSigned(path))
                        events.Add(new DetectionEvent
                        {
                            RuleId = RuleId,
                            RuleName = Name,
                            Severity = AlertSeverity.High,
                            Type = AlertType.MAL,
                            Description = $"Unsigned executable in system path: {proc.ProcessName} ({path})",
                            Metadata = new { ProcessId = proc.Id, Path = path }
                        });
                }
                catch { }
            }
            return events;
        }

        private static bool IsMicrosoftSigned(string path)
        {
            try
            {
                if (!File.Exists(path)) return true; // benefit of doubt if unreadable
                var cert = X509CertificateLoader.LoadCertificateFromFile(path);
                string subject = cert.Subject;
                return subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)
                    || subject.Contains("Windows", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false; // no certificate = unsigned
            }
        }
    }
}
