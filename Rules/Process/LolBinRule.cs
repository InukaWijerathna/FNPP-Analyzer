using System;
using System.Collections.Generic;
using FNPPScanner.Engine;
using FNPPScanner.Models;

namespace FNPPScanner.Rules.Process
{
    // HIDS-P5: Living-Off-the-Land Binary abuse.
    // Detects legitimate Windows tools used to download payloads, execute scripts, or
    // bypass defences — a common technique in fileless malware and red-team operations.
    public class LolBinRule : IDetectionRule
    {
        public string RuleId => "PROC-005";
        public string Name => "LOLBin Abuse";
        public string Description => "Detects built-in Windows tools invoked with malicious arguments.";

        private sealed record LolPattern(string[] TriggerArgs, string Reason, AlertSeverity Severity, AlertType Type);

        // Each entry: process name fragment → patterns that flag abuse
        private static readonly Dictionary<string, LolPattern[]> Patterns = new(StringComparer.OrdinalIgnoreCase)
        {
            ["certutil"] =
            [
                new(["-urlcache", "-f"], "certutil downloading remote payload", AlertSeverity.High, AlertType.MAL),
                new(["-decode"],         "certutil decoding base64 payload",    AlertSeverity.High, AlertType.MAL)
            ],
            ["regsvr32"] =
            [
                new(["/i:http", "scrobj.dll"], "regsvr32 Squiblydoo — remote scriptlet execution", AlertSeverity.High, AlertType.TROJ),
                new(["/i:\\\\"],               "regsvr32 loading remote UNC scriptlet",             AlertSeverity.High, AlertType.TROJ)
            ],
            ["mshta"] =
            [
                new(["http://"],        "mshta executing remote HTA file",  AlertSeverity.High, AlertType.TROJ),
                new(["https://"],       "mshta executing remote HTA file",  AlertSeverity.High, AlertType.TROJ),
                new(["vbscript:"],      "mshta executing inline VBScript",  AlertSeverity.High, AlertType.TROJ),
                new(["javascript:"],    "mshta executing inline JavaScript", AlertSeverity.High, AlertType.TROJ)
            ],
            ["wmic"] =
            [
                new(["process", "call", "create"], "wmic spawning process — fileless execution technique", AlertSeverity.High, AlertType.TROJ)
            ],
            ["rundll32"] =
            [
                new(["javascript:"],  "rundll32 executing JavaScript",              AlertSeverity.High, AlertType.TROJ),
                new(["vbscript:"],    "rundll32 executing VBScript",                AlertSeverity.High, AlertType.TROJ),
                new([",#"],           "rundll32 calling export by ordinal (evasion)", AlertSeverity.Medium, AlertType.MAL)
            ],
            ["bitsadmin"] =
            [
                new(["/transfer", "http"], "bitsadmin downloading remote file", AlertSeverity.Medium, AlertType.MAL)
            ],
            ["powershell"] =
            [
                new(["-enc"],                              "PowerShell encoded command (obfuscation)",         AlertSeverity.High,   AlertType.TROJ),
                new(["-encodedcommand"],                   "PowerShell encoded command (obfuscation)",         AlertSeverity.High,   AlertType.TROJ),
                new(["-w", "hidden", "-ep", "bypass"],     "PowerShell hidden + bypass execution",             AlertSeverity.High,   AlertType.TROJ),
                new(["iex", "downloadstring"],             "PowerShell download-and-execute (fileless)",       AlertSeverity.High,   AlertType.TROJ),
                new(["invoke-expression", "webclient"],    "PowerShell download-and-execute (fileless)",       AlertSeverity.High,   AlertType.TROJ),
                new(["frombase64string"],                  "PowerShell decoding base64 payload",               AlertSeverity.Medium, AlertType.MAL),
                new(["-windowstyle", "hidden"],            "PowerShell hidden window (stealthy execution)",    AlertSeverity.Medium, AlertType.MAL)
            ],
            ["cmstp"] =
            [
                new(["/s", "/ns", "http"], "cmstp loading remote INF (UAC bypass + RCE)", AlertSeverity.High, AlertType.TROJ)
            ],
            ["installutil"] =
            [
                new(["/logfile=", "/logtoConsole=false"], "installutil executing .NET code (AppLocker bypass)", AlertSeverity.High, AlertType.TROJ)
            ]
        };

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();

            foreach (var proc in context.Processes)
            {
                try
                {
                    string procName = proc.ProcessName.ToLower();
                    if (!Patterns.TryGetValue(procName, out var lolPatterns)) continue;

                    context.ProcessCommandLines.TryGetValue(proc.Id, out string? cmdLine);
                    if (string.IsNullOrWhiteSpace(cmdLine)) continue;

                    foreach (var pattern in lolPatterns)
                    {
                        bool allMatch = true;
                        foreach (var arg in pattern.TriggerArgs)
                            if (!cmdLine.Contains(arg, StringComparison.OrdinalIgnoreCase))
                            { allMatch = false; break; }

                        if (allMatch)
                            events.Add(new DetectionEvent
                            {
                                RuleId = RuleId,
                                RuleName = Name,
                                Severity = pattern.Severity,
                                Type = pattern.Type,
                                Description = $"{proc.ProcessName}: {pattern.Reason}",
                                Metadata = new { ProcessId = proc.Id, CommandLine = cmdLine }
                            });
                    }
                }
                catch { }
            }
            return events;
        }
    }
}
