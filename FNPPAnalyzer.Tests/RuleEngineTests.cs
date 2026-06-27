using FNPPAnalyzer.Config;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Tests;

public class RuleEngineTests
{
    private sealed class RecordingSink : IAlertSink
    {
        public List<Alert> Alerts { get; } = new();
        public void Submit(Alert alert) => Alerts.Add(alert);
    }

    // RuleId mimics rules like FileScannerRule whose own RuleId ("FILE") is an umbrella
    // that never appears in config — only the leaf IDs of the events it emits do.
    private sealed class StubRule : IDetectionRule
    {
        private readonly DetectionEvent[] _events;

        public StubRule(string ruleId, params DetectionEvent[] events)
        {
            RuleId = ruleId;
            _events = events;
        }

        public bool EvaluateCalled { get; private set; }
        public string RuleId { get; }
        public string Name => RuleId;
        public string Description => "stub";

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            EvaluateCalled = true;
            return _events;
        }
    }

    private static DetectionEvent MakeEvent(string ruleId, AlertSeverity severity = AlertSeverity.Medium) => new()
    {
        RuleId      = ruleId,
        RuleName    = ruleId,
        Severity    = severity,
        Description = "test"
    };

    [Fact]
    public void DisabledRule_IsSkippedEntirely_WithoutEvaluating()
    {
        var config = AppConfig.CreateDefault();
        config.Rules["PROC-001"] = new RuleConfig { Enabled = false };
        var sink = new RecordingSink();
        var engine = new RuleEngine(sink, config);
        var rule = new StubRule("PROC-001", MakeEvent("PROC-001"));
        engine.Register(rule);

        engine.RunCycle();

        Assert.False(rule.EvaluateCalled);
        Assert.Empty(sink.Alerts);
    }

    [Fact]
    public void DisabledLeafRuleId_IsFilteredPerEvent_EvenWhenRuleClassRuns()
    {
        var config = AppConfig.CreateDefault();
        config.Rules["FILE-002"] = new RuleConfig { Enabled = false };
        var sink = new RecordingSink();
        var engine = new RuleEngine(sink, config);
        engine.Register(new StubRule("FILE", MakeEvent("FILE-001"), MakeEvent("FILE-002")));

        engine.RunCycle();

        Assert.Single(sink.Alerts);
        Assert.Equal("FILE-001", sink.Alerts[0].RuleId);
    }

    [Fact]
    public void SeverityOverride_AppliesToMatchingLeafRuleId()
    {
        var config = AppConfig.CreateDefault();
        config.Rules["NET-003"] = new RuleConfig { Severity = "High" };
        var sink = new RecordingSink();
        var engine = new RuleEngine(sink, config);
        engine.Register(new StubRule("NET-003", MakeEvent("NET-003", AlertSeverity.Medium)));

        engine.RunCycle();

        Assert.Single(sink.Alerts);
        Assert.Equal(AlertSeverity.High, sink.Alerts[0].Severity);
    }

    [Fact]
    public void RuleWithNoConfigEntry_RunsNormally_AtItsOwnSeverity()
    {
        var config = AppConfig.CreateDefault();
        var sink = new RecordingSink();
        var engine = new RuleEngine(sink, config);
        var rule = new StubRule("PROC-099", MakeEvent("PROC-099", AlertSeverity.Low));
        engine.Register(rule);

        engine.RunCycle();

        Assert.True(rule.EvaluateCalled);
        Assert.Single(sink.Alerts);
        Assert.Equal(AlertSeverity.Low, sink.Alerts[0].Severity);
    }
}
