using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Net.NetworkInformation;
using FNPPScanner.Models;

namespace FNPPScanner.Engine
{
    public class RuleEngine
    {
        private readonly List<IDetectionRule> _rules = new();
        private readonly IAlertSink _sink;

        public RuleEngine(IAlertSink sink) => _sink = sink;

        public void Register(IDetectionRule rule) => _rules.Add(rule);

        public void RunCycle()
        {
            var context = BuildContext();
            try
            {
                foreach (var rule in _rules)
                {
                    try
                    {
                        foreach (var evt in rule.Evaluate(context))
                            _sink.Submit(new Alert
                            {
                                RuleId = evt.RuleId,
                                Title = evt.RuleName,
                                Description = evt.Description,
                                Severity = evt.Severity,
                                Type = evt.Type,
                                SourceProcess = "System",
                                Metadata = evt.Metadata
                            });
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"[rule:{rule.RuleId}] {ex.Message}");
                    }
                }
            }
            finally
            {
                context.Release();
            }
        }

        private static ScanContext BuildContext()
        {
            var (cmdLines, parentPids) = LoadProcessDetails();
            return new ScanContext
            {
                Processes = Process.GetProcesses(),
                TcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections(),
                ProcessCommandLines = cmdLines,
                ParentPids = parentPids
            };
        }

        // Single WMI query for both command lines and parent PIDs
        private static (Dictionary<int, string?> cmdLines, Dictionary<int, int> parentPids) LoadProcessDetails()
        {
            var cmdLines = new Dictionary<int, string?>();
            var parentPids = new Dictionary<int, int>();
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, ParentProcessId, CommandLine FROM Win32_Process");
                foreach (ManagementBaseObject obj in searcher.Get())
                {
                    int pid = Convert.ToInt32(obj["ProcessId"]);
                    cmdLines[pid] = obj["CommandLine"]?.ToString();
                    if (obj["ParentProcessId"] != null)
                        parentPids[pid] = Convert.ToInt32(obj["ParentProcessId"]);
                    obj.Dispose();
                }
            }
            catch { }
            return (cmdLines, parentPids);
        }
    }
}
