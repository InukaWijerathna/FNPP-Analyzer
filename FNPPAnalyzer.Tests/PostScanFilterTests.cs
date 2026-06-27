using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Tests;

// AuthenticodeVerifier currently only recognizes embedded Authenticode signatures, not
// catalog signatures — which is how most stock Windows system binaries (notepad.exe,
// cmd.exe, explorer.exe, all confirmed via Get-AuthenticodeSignature) are actually signed.
// So a real "Valid" result isn't reliably reproducible against any file on a stock
// Windows box; these tests use a plain unsigned temp file (a real, reliably-NotSigned
// path) to exercise the same branch instead.
public class PostScanFilterTests : IDisposable
{
    private readonly string _whitelistPath = Path.Combine(Path.GetTempPath(), $"fnpp_psf_test_{Guid.NewGuid():N}.json");
    private readonly string _unsignedFile = Path.Combine(Path.GetTempPath(), $"fnpp_psf_unsigned_{Guid.NewGuid():N}.exe");

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

    [Fact]
    public void HighTrustRule_OnUnsignedPath_KeepsOriginalSeverity_AndIsNeverWhitelisted()
    {
        var whitelist = new SignatureWhitelist(_whitelistPath);
        var filter = new PostScanFilter(whitelist);

        var result = filter.Process([MakeAlert("PROC-001", _unsignedFile)]);

        Assert.Single(result.Visible);
        Assert.Equal(AlertSeverity.Medium, result.Visible[0].Severity); // no escalation for high-trust rules
        Assert.Empty(result.Suppressed);
        Assert.Empty(result.NewlyWhitelisted);
        Assert.False(whitelist.IsWhitelisted(_unsignedFile));
    }

    [Fact]
    public void LowTrustRule_OnUnsignedPath_EscalatesSeverity_StaysVisible_AndIsNotWhitelisted()
    {
        var whitelist = new SignatureWhitelist(_whitelistPath);
        var filter = new PostScanFilter(whitelist);

        var result = filter.Process([MakeAlert("PROC-002", _unsignedFile)]);

        Assert.Single(result.Visible);
        Assert.Equal(AlertSeverity.High, result.Visible[0].Severity); // Medium -> High escalation
        Assert.Empty(result.Suppressed);
        Assert.Empty(result.NewlyWhitelisted);
        Assert.False(whitelist.IsWhitelisted(_unsignedFile));
    }

    [Fact]
    public void HighTrustRule_OnAlreadyWhitelistedPath_StillVisible()
    {
        var whitelist = new SignatureWhitelist(_whitelistPath);
        whitelist.Add(_unsignedFile);
        var filter = new PostScanFilter(whitelist);

        var result = filter.Process([MakeAlert("FILE-003", _unsignedFile)]);

        Assert.Single(result.Visible);
        Assert.Empty(result.Suppressed);
    }

    [Fact]
    public void LowTrustRule_OnAlreadyWhitelistedPath_IsSuppressed()
    {
        var whitelist = new SignatureWhitelist(_whitelistPath);
        whitelist.Add(_unsignedFile);
        var filter = new PostScanFilter(whitelist);

        var result = filter.Process([MakeAlert("PROC-002", _unsignedFile)]);

        Assert.Empty(result.Visible);
        Assert.Single(result.Suppressed);
    }
}
