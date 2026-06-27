using FNPPAnalyzer.Engine;

namespace FNPPAnalyzer.Tests;

// Regression coverage for the prefix-boundary bug: a plain StartsWith comparison let
// "C:\Program FilesEvil\x.exe" pass as trusted against root "C:\Program Files" because
// there was no directory-separator boundary check.
public class PathTrustTests
{
    private static readonly string[] TrustedRoots = [@"C:\Program Files", @"C:\Windows\System32\"];

    [Fact]
    public void PathInsideTrustedRoot_IsTrusted()
    {
        Assert.True(PathTrust.IsUnderTrustedPath(@"C:\Program Files\Vendor\app.exe", TrustedRoots));
    }

    [Fact]
    public void PathExactlyEqualToTrustedRoot_IsNotTrusted()
    {
        // The root itself is a directory, not a file under it — same boundary logic applies.
        Assert.False(PathTrust.IsUnderTrustedPath(@"C:\Program Files", TrustedRoots));
    }

    [Fact]
    public void LookalikeDirectoryWithNoSeparator_IsNotTrusted()
    {
        Assert.False(PathTrust.IsUnderTrustedPath(@"C:\Program FilesEvil\malware.exe", TrustedRoots));
    }

    [Fact]
    public void TrustedRoot_WithExistingTrailingSeparator_StillMatchesCorrectly()
    {
        Assert.True(PathTrust.IsUnderTrustedPath(@"C:\Windows\System32\cmd.exe", TrustedRoots));
        Assert.False(PathTrust.IsUnderTrustedPath(@"C:\Windows\System32Evil\cmd.exe", TrustedRoots));
    }

    [Fact]
    public void PathOutsideAllTrustedRoots_IsNotTrusted()
    {
        Assert.False(PathTrust.IsUnderTrustedPath(@"C:\Temp\payload.exe", TrustedRoots));
    }

    [Fact]
    public void ComparisonIsCaseInsensitive()
    {
        Assert.True(PathTrust.IsUnderTrustedPath(@"c:\program files\vendor\app.exe", TrustedRoots));
    }
}
