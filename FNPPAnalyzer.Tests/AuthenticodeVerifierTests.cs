using FNPPAnalyzer.Engine;

namespace FNPPAnalyzer.Tests;

// Regression coverage for the catalog-signature gap: WinVerifyTrust's WTD_CHOICE_FILE
// path only checks embedded Authenticode signatures, but most stock Windows binaries
// are signed via a catalog file instead (confirmed via Get-AuthenticodeSignature —
// notepad.exe, cmd.exe, explorer.exe are all Valid/Catalog). Verify falls back to an
// explicit CryptCATAdmin catalog lookup so these still resolve to Valid.
public class AuthenticodeVerifierTests : IDisposable
{
    private readonly string _unsignedFile = Path.Combine(Path.GetTempPath(), $"fnpp_av_test_{Guid.NewGuid():N}.exe");

    public AuthenticodeVerifierTests() => File.WriteAllBytes(_unsignedFile, new byte[16]);

    public void Dispose()
    {
        try { File.Delete(_unsignedFile); } catch { }
    }

    [Theory]
    [InlineData("notepad.exe")]
    [InlineData("cmd.exe")]
    public void CatalogSignedSystemBinary_ReturnsValid(string fileName)
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), fileName);

        Assert.Equal(SignatureStatus.Valid, AuthenticodeVerifier.Verify(path));
    }

    [Fact]
    public void UnsignedFile_DoesNotReturnValid()
    {
        Assert.NotEqual(SignatureStatus.Valid, AuthenticodeVerifier.Verify(_unsignedFile));
    }

    [Fact]
    public void NonexistentFile_ReturnsUnknown()
    {
        string missing = Path.Combine(Path.GetTempPath(), $"fnpp_av_missing_{Guid.NewGuid():N}.exe");

        Assert.Equal(SignatureStatus.Unknown, AuthenticodeVerifier.Verify(missing));
    }
}
