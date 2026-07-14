using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Tests;

// PostScanFilter is the IAlertSink that sits in front of the broker: whitelist check,
// Authenticode verification, suppression, and Medium→High escalation all happen at
// submit time, before an alert is stored or displayed. cmd.exe serves as the reliably
// Valid (catalog-signed) file — AuthenticodeVerifierTests pins that assumption.
public class PostScanFilterTests : IDisposable
{
    private sealed class RecordingSink : IAlertSink
    {
        public List<Alert> Alerts { get; } = new();
        public void Submit(Alert alert) => Alerts.Add(alert);
    }

    private static readonly string SignedSystemFile =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");

    private readonly string _whitelistPath = Path.Combine(Path.GetTempPath(), $"fnpp_psf_test_{Guid.NewGuid():N}.json");
    private readonly string _unsignedFile = Path.Combine(Path.GetTempPath(), $"fnpp_psf_unsigned_{Guid.NewGuid():N}.exe");
    private readonly RecordingSink _sink = new();

    public PostScanFilterTests() => File.WriteAllBytes(_unsignedFile, new byte[16]);

    public void Dispose()
    {
        try { File.Delete(_whitelistPath); } catch { }
        try { File.Delete(_unsignedFile); } catch { }
    }

    private static Alert MakeAlert(string ruleId, string path) => new()
    {
        RuleId         = ruleId,
        Title          = ruleId,
        Description    = "test",
        Severity       = AlertSeverity.Medium,
        ExecutablePath = path
    };

    private PostScanFilter NewFilter(out SignatureWhitelist whitelist)
    {
        whitelist = new SignatureWhitelist(_whitelistPath);
        return new PostScanFilter(whitelist, _sink);
    }

    [Fact]
    public void HighTrustRule_OnUnsignedPath_KeepsOriginalSeverity_AndIsNeverWhitelisted()
    {
        var filter = NewFilter(out var whitelist);

        filter.Submit(MakeAlert("PROC-001", _unsignedFile));

        var forwarded = Assert.Single(_sink.Alerts);
        Assert.Equal(AlertSeverity.Medium, forwarded.Severity); // no escalation for high-trust rules
        Assert.False(forwarded.Suppressed);
        Assert.False(whitelist.IsWhitelisted(_unsignedFile));
        Assert.Empty(filter.DrainNewlyWhitelisted());
    }

    [Fact]
    public void LowTrustRule_OnUnsignedPath_EscalatesSeverity_StaysVisible_AndIsNotWhitelisted()
    {
        var filter = NewFilter(out var whitelist);

        filter.Submit(MakeAlert("PROC-002", _unsignedFile));

        var forwarded = Assert.Single(_sink.Alerts);
        Assert.Equal(AlertSeverity.High, forwarded.Severity); // Medium -> High escalation
        Assert.False(forwarded.Suppressed);
        Assert.False(whitelist.IsWhitelisted(_unsignedFile));
    }

    [Fact]
    public void LowTrustRule_OnValidlySignedPath_IsSuppressedAndWhitelisted_BeforeReachingTheSink()
    {
        var filter = NewFilter(out var whitelist);

        filter.Submit(MakeAlert("PROC-002", SignedSystemFile));

        // Suppressed flag is settled BEFORE the next sink sees the alert — the live
        // display can trust it (this was previously decided after the event fired).
        var forwarded = Assert.Single(_sink.Alerts);
        Assert.True(forwarded.Suppressed);
        Assert.True(whitelist.IsWhitelisted(SignedSystemFile));
        Assert.Single(filter.DrainNewlyWhitelisted());
    }

    [Fact]
    public void HighTrustRule_OnValidlySignedPath_IsNeitherSuppressedNorWhitelisted()
    {
        var filter = NewFilter(out var whitelist);

        filter.Submit(MakeAlert("FILE-003", SignedSystemFile));

        var forwarded = Assert.Single(_sink.Alerts);
        Assert.False(forwarded.Suppressed);
        Assert.False(whitelist.IsWhitelisted(SignedSystemFile));
    }

    [Fact]
    public void LowTrustRule_OnAlreadyWhitelistedPath_IsDroppedEntirely()
    {
        var filter = NewFilter(out var whitelist);
        whitelist.Add(_unsignedFile);

        filter.Submit(MakeAlert("PROC-002", _unsignedFile));

        Assert.Empty(_sink.Alerts);
    }

    [Fact]
    public void HighTrustRule_OnAlreadyWhitelistedPath_StillPassesThrough()
    {
        var filter = NewFilter(out var whitelist);
        whitelist.Add(_unsignedFile);

        filter.Submit(MakeAlert("FILE-003", _unsignedFile));

        Assert.Single(_sink.Alerts);
    }

    [Fact]
    public void PathlessAlert_PassesThroughUnchanged()
    {
        var filter = NewFilter(out _);

        filter.Submit(MakeAlert("PERS-001", ""));

        var forwarded = Assert.Single(_sink.Alerts);
        Assert.Equal(AlertSeverity.Medium, forwarded.Severity);
        Assert.False(forwarded.Suppressed);
    }

    [Fact]
    public void CollectResult_PartitionsBySuppressedFlag_AndDrainsWhitelistAdditions()
    {
        var filter = NewFilter(out _);

        filter.Submit(MakeAlert("PROC-002", SignedSystemFile)); // suppressed + whitelisted
        filter.Submit(MakeAlert("PROC-002", _unsignedFile));    // visible

        var result = filter.CollectResult(_sink.Alerts);

        Assert.Single(result.Visible);
        Assert.Single(result.Suppressed);
        Assert.Single(result.NewlyWhitelisted);
        Assert.Empty(filter.DrainNewlyWhitelisted()); // drained by CollectResult
    }
}
