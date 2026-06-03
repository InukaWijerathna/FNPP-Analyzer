using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Net.NetworkInformation;
using WinEDR_MVP.Models;

namespace WinEDR_MVP.Engine
{
    public class RuleEngine
    {
        private readonly List<IDetectionRule> _rules = new();
        private readonly IAlertSink _sink;

        public RuleEngine(IAlertSink sink) => _sink = sink;

        public void Register(IDetectionRule rule) => _rules.Add(rule);

        public void RunCycle()
        {
            Console.WriteLine($"Detection cycle started at {DateTime.Now}");
            var context = BuildContext();
            try
            {
                foreach (var rule in _rules)
                {
                    try
                    {
                        foreach (var evt in rule.Evaluate(context))
                        {
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
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Rule {rule.RuleId} failed: {ex.Message}");
                    }
                }
            }
            finally
            {
                context.Release();
            }
        }

        private static ScanContext BuildContext() => new()
        {
            Processes = Process.GetProcesses(),
            TcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections(),
            ProcessCommandLines = LoadCommandLines()
        };

        private static Dictionary<int, string?> LoadCommandLines()
        {
            var result = new Dictionary<int, string?>();
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, CommandLine FROM Win32_Process");
                foreach (ManagementBaseObject obj in searcher.Get())
                {
                    result[Convert.ToInt32(obj["ProcessId"])] = obj["CommandLine"]?.ToString();
                    obj.Dispose();
                }
            }
            catch { }
            return result;
        }
    }
}
