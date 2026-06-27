using System.Threading;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Tests;

public class AlertBrokerTests : IDisposable
{
    private readonly string _logPath = Path.Combine(Path.GetTempPath(), $"fnpp_broker_test_{Guid.NewGuid():N}.log");
    private readonly string _whitelistPath = Path.Combine(Path.GetTempPath(), $"fnpp_broker_wl_{Guid.NewGuid():N}.json");

    public void Dispose()
    {
        try { File.Delete(_logPath); } catch { }
        try { File.Delete(_whitelistPath); } catch { }
    }

    private static Alert MakeAlert(string ruleId, string path) => new()
    {
        RuleId         = ruleId,
        Title          = ruleId,
        Description    = "test",
        Severity       = AlertSeverity.Medium,
        ExecutablePath = path
    };

    private AlertBroker NewBroker(TimeSpan cooldown, SignatureWhitelist? whitelist = null) =>
        new(_logPath, whitelist ?? new SignatureWhitelist(_whitelistPath), cooldown);

    [Fact]
    public void RepeatedAlert_WithinCooldown_IsDropped()
    {
        var broker = NewBroker(TimeSpan.FromMinutes(10));

        broker.Submit(MakeAlert("PROC-002", @"C:\Temp\evil.exe"));
        broker.Submit(MakeAlert("PROC-002", @"C:\Temp\evil.exe"));

        Assert.Single(broker.GetAll());
    }

    [Fact]
    public void RepeatedAlert_AfterCooldownElapses_FiresAgain()
    {
        var broker = NewBroker(TimeSpan.FromMilliseconds(20));

        broker.Submit(MakeAlert("PROC-002", @"C:\Temp\evil.exe"));
        Thread.Sleep(60);
        broker.Submit(MakeAlert("PROC-002", @"C:\Temp\evil.exe"));

        Assert.Equal(2, broker.GetAll().Count);
    }

    [Fact]
    public void DifferentPaths_AreNotDeduped_EvenForTheSameRule()
    {
        var broker = NewBroker(TimeSpan.FromMinutes(10));

        broker.Submit(MakeAlert("PROC-002", @"C:\Temp\a.exe"));
        broker.Submit(MakeAlert("PROC-002", @"C:\Temp\b.exe"));

        Assert.Equal(2, broker.GetAll().Count);
    }

    [Fact]
    public void HighTrustRule_BypassesWhitelistGate_EvenWhenPathAlreadyWhitelisted()
    {
        var whitelist = new SignatureWhitelist(_whitelistPath);
        whitelist.Add(@"C:\Windows\System32\svchost.exe");
        var broker = NewBroker(TimeSpan.FromMinutes(10), whitelist);

        broker.Submit(MakeAlert("PROC-001", @"C:\Windows\System32\svchost.exe"));

        Assert.Single(broker.GetAll());
    }

    [Fact]
    public void LowTrustRule_OnWhitelistedPath_IsDroppedSilently()
    {
        var whitelist = new SignatureWhitelist(_whitelistPath);
        whitelist.Add(@"C:\Windows\System32\svchost.exe");
        var broker = NewBroker(TimeSpan.FromMinutes(10), whitelist);

        broker.Submit(MakeAlert("PROC-002", @"C:\Windows\System32\svchost.exe"));

        Assert.Empty(broker.GetAll());
    }
}
