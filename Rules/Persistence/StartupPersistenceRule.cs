using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;
using WinEDR_MVP.Engine;
using WinEDR_MVP.Models;

namespace WinEDR_MVP.Rules.Persistence
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
                    catch { }
                }
            }
            return events;
        }

        private static string? ClassifySuspicious(string value)
        {
            // Strip surrounding quotes and arguments to isolate the executable path
            string raw = value.TrimStart('"');
            int end = raw.IndexOf('"');
            string exePath = end > 0 ? raw[..end] : raw.Split(' ')[0];

            if (exePath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase))
                return "runs from Temp";

            if (!string.IsNullOrWhiteSpace(exePath) && !File.Exists(exePath))
                return "target file not found";

            return null;
        }
    }
}
