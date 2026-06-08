using FNPPAnalyzer.Engine;

namespace FNPPAnalyzer.Tests;

public class SignatureWhitelistTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"fnpp_whitelist_test_{Guid.NewGuid():N}.json");

    public void Dispose()
    {
        try { File.Delete(_path); } catch { }
    }

    [Fact]
    public void NewWhitelist_WithNoFile_IsEmpty()
    {
        var whitelist = new SignatureWhitelist(_path);

        Assert.False(whitelist.IsWhitelisted(@"C:\Windows\System32\svchost.exe"));
        Assert.Empty(whitelist.GetAll());
    }

    [Fact]
    public void Add_PersistsToDisk_AndIsWhitelistedAfterwards()
    {
        var whitelist = new SignatureWhitelist(_path);
        string exe = Path.Combine(Path.GetTempPath(), "fnpp_test_app.exe");

        bool added = whitelist.Add(exe);

        Assert.True(added);
        Assert.True(whitelist.IsWhitelisted(exe));
        Assert.True(File.Exists(_path));
    }

    [Fact]
    public void Add_SamePathTwice_ReturnsFalseOnSecondCall()
    {
        var whitelist = new SignatureWhitelist(_path);
        string exe = Path.Combine(Path.GetTempPath(), "fnpp_test_app.exe");

        Assert.True(whitelist.Add(exe));
        Assert.False(whitelist.Add(exe));
    }

    [Fact]
    public void IsWhitelisted_NormalizesPathSeparatorsAndCase()
    {
        var whitelist = new SignatureWhitelist(_path);
        string exe = Path.Combine(Path.GetTempPath(), "fnpp_test_app.exe");

        whitelist.Add(exe.ToUpperInvariant());

        Assert.True(whitelist.IsWhitelisted(exe.ToLowerInvariant()));
    }

    [Fact]
    public void Reload_PicksUpChangesWrittenDirectlyToFile()
    {
        var whitelist = new SignatureWhitelist(_path);
        string exe = Path.Combine(Path.GetTempPath(), "fnpp_test_reload.exe");
        Assert.False(whitelist.IsWhitelisted(exe));

        // Simulate an external edit to whitelist.json (same persisted format: a JSON string array)
        File.WriteAllText(_path, $"[\"{Path.GetFullPath(exe).Replace("\\", "\\\\")}\"]");
        whitelist.Reload();

        Assert.True(whitelist.IsWhitelisted(exe));
    }
}
