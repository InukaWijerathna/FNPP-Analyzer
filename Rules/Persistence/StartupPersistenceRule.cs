using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Rules.Persistence
{
    // HIDS-B1: Suspicious entries in Windows startup registry keys.
    public class StartupPersistenceRule : IDetectionRule
    {
        public string RuleId => "PERS-001";
        public string Name => "Startup Registry Persistence";
        public string Description => "Detects suspicious entries in Windows startup registry keys.";

        private static readonly string[] MonitoredKeys =
        [
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        ];

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();

            foreach (var keyPath in MonitoredKeys)
            {
                foreach (var root in new[] { Registry.CurrentUser, Registry.LocalMachine })
                {
                    try
                    {
                        using RegistryKey? key = root.OpenSubKey(keyPath);
                        if (key == null) continue;

                        foreach (var name in key.GetValueNames())
                        {
                            string? value = key.GetValue(name)?.ToString();
                            if (value == null) continue;

                            string? reason = ClassifySuspicious(value);
                            if (reason != null)
                                events.Add(new DetectionEvent
                                {
                                    RuleId = "PERS-001",
                                    RuleName = "Startup Registry Persistence",
                                    Severity = AlertSeverity.Medium,
                                    Type = AlertType.MAL,
                                    Description = $"Startup entry [{reason}] in {keyPath}: {name} -> {value}"
                                });
                        }
                    }
                    catch (System.Security.SecurityException) { }  // access denied on HKLM keys without elevation
                    catch (UnauthorizedAccessException) { }
                    catch (Exception ex) { Console.Error.WriteLine($"[PERS-001] {keyPath}: {ex.GetType().Name}: {ex.Message}"); }
                }
            }
            return events;
        }

        // Paths where legitimate software is expected — don't flag missing files here
        private static readonly string[] TrustedInstallPrefixes =
        [
            @"C:\Program Files\",
            @"C:\Program Files (x86)\",
            @"C:\Windows\",
        ];

        private static readonly string[] ExeExtensions =
            [".exe", ".cmd", ".bat", ".ps1", ".vbs", ".js"];

        // Extracts the executable path from a registry Run value.
        // Registry entries are frequently stored WITHOUT quotes even when the path
        // contains spaces (e.g. Docker Desktop, IDMan, XMouseButtonControl).
        // Strategy: if quoted → take between the quotes; if unquoted → try all
        // token-length prefixes from longest to shortest and return the first one
        // that ends in a known executable extension.
        private static string ExtractExePath(string value)
        {
            string raw = value.Trim();

            if (raw.StartsWith('"'))
            {
                int closing = raw.IndexOf('"', 1);
                string path = closing > 1 ? raw[1..closing] : raw[1..];
                return Environment.ExpandEnvironmentVariables(path);
            }

            string[] tokens = raw.Split(' ');
            for (int n = tokens.Length; n > 0; n--)
            {
                string candidate = string.Join(" ", tokens, 0, n);
                string ext = Path.GetExtension(candidate).ToLowerInvariant();
                if (Array.IndexOf(ExeExtensions, ext) >= 0)
                    return Environment.ExpandEnvironmentVariables(candidate);
            }

            return Environment.ExpandEnvironmentVariables(tokens[0]);
        }

        private static string? ClassifySuspicious(string value)
        {
            string exePath = ExtractExePath(value);
            if (string.IsNullOrWhiteSpace(exePath)) return null;

            if (exePath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase))
                return "runs from Temp";

            if (!File.Exists(exePath))
            {
                foreach (var prefix in TrustedInstallPrefixes)
                    if (exePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        return null; // stale entry for uninstalled software — not suspicious

                return "target executable not found";
            }

            return null;
        }
    }
}
