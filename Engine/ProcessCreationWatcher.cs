using System;
using System.Management;
using FNPPAnalyzer.Config;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Engine
{
    // Real-time process creation monitor using WMI event subscription.
    // Fires within ~1 second of any new Win32_Process being created.
    // This fills the gap between periodic scan cycles — e.g. a process that
    // spawns and exits in under 30 s would otherwise be missed entirely.
    public class ProcessCreationWatcher : IDisposable
    {
        private readonly ManagementEventWatcher _watcher;
        private readonly IAlertSink _sink;
        private readonly AppConfig  _config;

        private static readonly string[] SuspiciousEngines =
            ["powershell", "wscript", "cscript", "mshta", "cmd"];

        // PowerShell argument flags that strongly indicate obfuscation/evasion
        private static readonly string[] SuspiciousPsArgs =
            ["-enc", "-encodedcommand", "-e ", "-windowstyle hidden", "-w hidden",
             "iex", "invoke-expression", "downloadstring", "frombase64string",
             "-ep bypass", "-executionpolicy bypass"];

        public ProcessCreationWatcher(IAlertSink sink, AppConfig config)
        {
            _sink   = sink;
            _config = config;

            // WITHIN 1 — WMI polls every 1 second for new Win32_Process instances.
            // Lower values increase CPU cost; 1 s is a sensible real-time trade-off.
            var query = new WqlEventQuery(
                "SELECT * FROM __InstanceCreationEvent WITHIN 1 " +
                "WHERE TargetInstance ISA 'Win32_Process'");

            _watcher = new ManagementEventWatcher(query);
            _watcher.EventArrived += OnProcessCreated;
        }

        public void Start()
        {
            try { _watcher.Start(); }
            catch (Exception ex)
            {
                lock (ConsoleSync.Lock) Console.Error.WriteLine($"[ProcessCreationWatcher] Could not start: {ex.Message}");
            }
        }

        public void Stop()
        {
            try { _watcher.Stop(); } catch { }
        }

        public void Dispose() => _watcher.Dispose();

        private void OnProcessCreated(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var proc    = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                string name = (proc["Name"]?.ToString() ?? "").ToLowerInvariant();
                string cmd  = proc["CommandLine"]?.ToString() ?? "";
                string path = proc["ExecutablePath"]?.ToString() ?? "";
                int    pid  = Convert.ToInt32(proc["ProcessId"]);

                CheckNewProcess(name, cmd, path, pid);
            }
            catch { }
        }

        private void CheckNewProcess(string name, string cmd, string path, int pid)
        {
            // 1. Executable launched from untrusted directory
            foreach (var raw in _config.UntrustedExecutionPaths)
            {
                string dir = Environment.ExpandEnvironmentVariables(raw);
                if (!string.IsNullOrEmpty(path) &&
                    path.StartsWith(dir, StringComparison.OrdinalIgnoreCase))
                {
                    Submit("PROC-RT-001", "Process from Untrusted Path (Real-Time)",
                        AlertSeverity.Medium, AlertType.MAL,
                        $"New process from untrusted path detected in real-time: {path}",
                        path, pid);
                    return;
                }
            }

            // 2. Script engine with obfuscation or download flags
            bool isEngine = Array.Exists(SuspiciousEngines, e => name.Contains(e));
            if (isEngine && !string.IsNullOrEmpty(cmd))
            {
                string cmdLow = cmd.ToLowerInvariant();
                foreach (var arg in SuspiciousPsArgs)
                {
                    if (cmdLow.Contains(arg))
                    {
                        Submit("PROC-RT-002", "Suspicious Script Engine Launch (Real-Time)",
                            AlertSeverity.High, AlertType.TROJ,
                            $"{name} launched with suspicious argument '{arg}': {cmd}",
                            path, pid);
                        return;
                    }
                }
            }

            // 3. mshta / wscript with remote URL in command line
            if ((name.Contains("mshta") || name.Contains("wscript") || name.Contains("cscript"))
                && !string.IsNullOrEmpty(cmd))
            {
                string cmdLow = cmd.ToLowerInvariant();
                if (cmdLow.Contains("http://") || cmdLow.Contains("https://") ||
                    cmdLow.Contains("ftp://")   || cmdLow.Contains("\\\\"))
                {
                    Submit("PROC-RT-003", "Script Engine Fetching Remote Content (Real-Time)",
                        AlertSeverity.High, AlertType.TROJ,
                        $"{name} executing remote content: {cmd}",
                        path, pid);
                }
            }
        }

        private void Submit(
            string ruleId, string title, AlertSeverity severity, AlertType type,
            string description, string exePath, int pid)
        {
            _sink.Submit(new Alert
            {
                RuleId         = ruleId,
                Title          = title,
                Severity       = severity,
                Type           = type,
                Description    = description,
                SourceProcess  = "WMI-Watcher",
                ExecutablePath = exePath,
                Metadata       = new { ProcessId = pid, Path = exePath }
            });
        }
    }
}
