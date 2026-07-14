using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Config
{
    public class AppConfig
    {
        public List<string> TrustedSystemProcesses { get; set; } = new();
        public List<string> TrustedExecutionPaths { get; set; } = new();
        public List<string> UntrustedExecutionPaths { get; set; } = new();
        public Dictionary<string, RuleConfig> Rules { get; set; } = new();
        public int NetworkScanWindowSeconds { get; set; } = 30;
        public string YaraRulesPath { get; set; } = "YaraRules";

        // NET-001 remote ports worth alerting on. Kept deliberately conservative:
        // common dev/admin ports that used to live here (5000 Flask/UPnP, 8888 Jupyter,
        // 5900-5901 VNC, 1080 SOCKS) fired constantly on developer machines. Add them
        // back per-install via config.json if they're suspicious in your environment.
        public List<int> SuspiciousPorts { get; set; } =
        [
            4444, 4445, 4446,       // Metasploit reverse handlers
            6667, 6697,             // IRC (DarkComet, njRAT C2)
            1337, 31337,            // "leet" RAT defaults
            50050,                  // Cobalt Strike team-server
            40056,                  // Havoc C2 default
            9001, 9030, 9050, 9051, // Tor relay/SOCKS ports
            4899,                   // Radmin remote-admin tool
        ];

        /// <summary>True unless config.json explicitly sets Rules[ruleId].Enabled = false.</summary>
        public bool IsRuleEnabled(string ruleId) =>
            !Rules.TryGetValue(ruleId, out var cfg) || cfg.Enabled;

        /// <summary>Severity override from config.json for this rule ID, if one is set and valid.</summary>
        public AlertSeverity? SeverityOverride(string ruleId) =>
            Rules.TryGetValue(ruleId, out var cfg)
            && !string.IsNullOrEmpty(cfg.Severity)
            && Enum.TryParse<AlertSeverity>(cfg.Severity, ignoreCase: true, out var sev)
                ? sev
                : null;

        public static AppConfig Load(string path)
        {
            if (!File.Exists(path)) return CreateDefault();
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<AppConfig>(json) ?? CreateDefault();
        }

        public void Save(string path)
        {
            File.WriteAllText(path, JsonSerializer.Serialize(this,
                new JsonSerializerOptions { WriteIndented = true }));
        }

        public static AppConfig CreateDefault() => new()
        {
            TrustedSystemProcesses = ["svchost.exe", "explorer.exe", "lsass.exe", "services.exe", "csrss.exe"],
            TrustedExecutionPaths = TrustedSystemPaths(),
            UntrustedExecutionPaths =
            [
                @"%USERPROFILE%\Downloads",
                @"%USERPROFILE%\AppData\Local\Temp",
                @"C:\Temp"
            ],
            Rules = new Dictionary<string, RuleConfig>
            {
                ["NET-003"] = new RuleConfig { Enabled = true, Threshold = 200, Severity = "Medium" }
            }
        };

        // Resolved via SpecialFolder rather than hardcoded "C:\..." so the default config
        // still points at the right places on the (rare) installs where Windows isn't on C:.
        private static List<string> TrustedSystemPaths()
        {
            string[] candidates =
            [
                Environment.GetFolderPath(Environment.SpecialFolder.System),         // System32
                Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),      // SysWOW64
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            ];
            return candidates.Where(p => !string.IsNullOrEmpty(p)).ToList();
        }
    }

    public class RuleConfig
    {
        public bool Enabled { get; set; } = true;
        public int Threshold { get; set; }
        public string? Severity { get; set; }
    }
}
