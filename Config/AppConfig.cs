using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace FNPPScanner.Config
{
    public class AppConfig
    {
        public List<string> TrustedSystemProcesses { get; set; } = new();
        public List<string> TrustedExecutionPaths { get; set; } = new();
        public List<string> UntrustedExecutionPaths { get; set; } = new();
        public Dictionary<string, RuleConfig> Rules { get; set; } = new();
        public int NetworkScanWindowSeconds { get; set; } = 30;

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
            TrustedExecutionPaths =
            [
                @"C:\Windows\System32",
                @"C:\Windows\SysWOW64",
                @"C:\Program Files",
                @"C:\Program Files (x86)"
            ],
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
    }

    public class RuleConfig
    {
        public bool Enabled { get; set; } = true;
        public int Threshold { get; set; }
        public string? Severity { get; set; }
    }
}
