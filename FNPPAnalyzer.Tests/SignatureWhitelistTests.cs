using FNPPAnalyzer.Engine;

namespace FNPPAnalyzer.Tests;

// The whitelist is keyed by path AND content hash: monitored directories are
// user-writable, so a path-only whitelist could be bypassed by swapping the file
// at an already-whitelisted path. These tests pin the hash-verification behaviour.
public class SignatureWhitelistTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"fnpp_whitelist_test_{Guid.NewGuid():N}.json");
    private readonly string _exe  = Path.Combine(Path.GetTempPath(), $"fnpp_whitelist_app_{Guid.NewGuid():N}.exe");

    public SignatureWhitelistTests() => File.WriteAllBytes(_exe, [1, 2, 3, 4]);

    public void Dispose()
    {
        try { File.Delete(_path); } catch { }
        try { File.Delete(_exe); } catch { }
    }

    [Fact]
    public void NewWhitelist_WithNoFile_IsEmpty()
    {
        var whitelist = new SignatureWhitelist(_path);

        Assert.False(whitelist.IsWhitelisted(_exe));
        Assert.Empty(whitelist.GetAll());
    }

    [Fact]
    public void Add_PersistsToDisk_AndIsWhitelistedAfterwards()
    {
        var whitelist = new SignatureWhitelist(_path);

        bool added = whitelist.Add(_exe);

        Assert.True(added);
        Assert.True(whitelist.IsWhitelisted(_exe));
        Assert.True(File.Exists(_path));
    }

    [Fact]
    public void Add_SamePathTwice_ReturnsFalseOnSecondCall()
    {
        var whitelist = new SignatureWhitelist(_path);

        Assert.True(whitelist.Add(_exe));
        Assert.False(whitelist.Add(_exe));
    }

    [Fact]
    public void Add_NonexistentFile_IsRefused()
    {
        var whitelist = new SignatureWhitelist(_path);
        string missing = Path.Combine(Path.GetTempPath(), $"fnpp_wl_missing_{Guid.NewGuid():N}.exe");

        Assert.False(whitelist.Add(missing));
        Assert.False(whitelist.IsWhitelisted(missing));
    }

    [Fact]
    public void ReplacedFileContent_IsNoLongerWhitelisted()
    {
        // The whitelist-swap attack: whitelist a benign file, then overwrite the same
        // path with different content — the entry must stop vouching for it.
        var whitelist = new SignatureWhitelist(_path);
        whitelist.Add(_exe);
        Assert.True(whitelist.IsWhitelisted(_exe));

        File.WriteAllBytes(_exe, [9, 9, 9, 9, 9]);

        Assert.False(whitelist.IsWhitelisted(_exe));
        // Stale entry is dropped entirely so the new content gets re-verified upstream
        Assert.Empty(whitelist.GetAll());
    }

    [Fact]
    public void IsWhitelisted_NormalizesPathSeparatorsAndCase()
    {
        var whitelist = new SignatureWhitelist(_path);

        whitelist.Add(_exe.ToUpperInvariant());

        Assert.True(whitelist.IsWhitelisted(_exe.ToLowerInvariant()));
    }

    [Fact]
    public void Reload_PicksUpChangesWrittenDirectlyToFile()
    {
        var whitelist = new SignatureWhitelist(_path);
        Assert.False(whitelist.IsWhitelisted(_exe));

        // Simulate an external edit (persisted format: { "path": "sha256" })
        var other = new SignatureWhitelist(_path + ".other");
        other.Add(_exe);
        File.Copy(_path + ".other", _path, overwrite: true);
        File.Delete(_path + ".other");

        whitelist.Reload();

        Assert.True(whitelist.IsWhitelisted(_exe));
    }

    [Fact]
    public void LegacyPathArrayFormat_IsMigrated_ByHashingFilesStillOnDisk()
    {
        string missing = Path.Combine(Path.GetTempPath(), $"fnpp_wl_gone_{Guid.NewGuid():N}.exe");
        File.WriteAllText(_path,
            $"[\"{_exe.Replace("\\", "\\\\")}\", \"{missing.Replace("\\", "\\\\")}\"]");

        var whitelist = new SignatureWhitelist(_path);

        Assert.True(whitelist.IsWhitelisted(_exe));    // existing file re-hashed and kept
        Assert.False(whitelist.IsWhitelisted(missing)); // gone — dropped, never trusted blind
    }
}
