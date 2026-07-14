using System.Threading;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Tests;

public class AlertBrokerTests : IDisposable
{
    private readonly string _logPath = Path.Combine(Path.GetTempPath(), $"fnpp_broker_test_{Guid.NewGuid():N}.log");

    public void Dispose()
    {
        try { File.Delete(_logPath); } catch { }
    }

    private static Alert MakeAlert(string ruleId, string path, string description = "test", string? dedupeKey = null) => new()
    {
        RuleId         = ruleId,
        Title          = ruleId,
        Description    = description,
        Severity       = AlertSeverity.Medium,
        ExecutablePath = path,
        DedupeKey      = dedupeKey
    };

    private AlertBroker NewBroker(TimeSpan cooldown) => new(_logPath, cooldown);

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
    public void DedupeKey_WinsOverVolatileDescription()
    {
        // NET-002/NET-003-style alerts embed live counts in the description; without a
        // DedupeKey they would re-fire every cycle because the fingerprint never repeats.
        var broker = NewBroker(TimeSpan.FromMinutes(10));

        broker.Submit(MakeAlert("NET-003", "", "High TCP connection count: 137", dedupeKey: "connection-burst"));
        broker.Submit(MakeAlert("NET-003", "", "High TCP connection count: 145", dedupeKey: "connection-burst"));

        Assert.Single(broker.GetAll());
    }

    [Fact]
    public void PathlessAlert_WithoutDedupeKey_FallsBackToDescription()
    {
        var broker = NewBroker(TimeSpan.FromMinutes(10));

        broker.Submit(MakeAlert("PERS-001", "", "entry A"));
        broker.Submit(MakeAlert("PERS-001", "", "entry B"));
        broker.Submit(MakeAlert("PERS-001", "", "entry A"));

        Assert.Equal(2, broker.GetAll().Count);
    }

    [Fact]
    public void SuppressedAlert_IsStored_ButDoesNotRaiseTheLiveEvent()
    {
        var broker = NewBroker(TimeSpan.FromMinutes(10));
        int raised = 0;
        broker.AlertRaised += _ => raised++;

        var suppressed = MakeAlert("PROC-002", @"C:\Temp\signed.exe");
        suppressed.Suppressed = true;
        broker.Submit(suppressed);
        broker.Submit(MakeAlert("PROC-002", @"C:\Temp\other.exe"));

        Assert.Equal(2, broker.GetAll().Count);
        Assert.Equal(1, raised);
    }
}
