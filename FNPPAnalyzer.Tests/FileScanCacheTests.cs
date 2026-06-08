using FNPPAnalyzer.Engine;

namespace FNPPAnalyzer.Tests;

// FileScanCache keys on FileInfo.LastWriteTimeUtc/Length, and those properties read
// straight from the filesystem (not virtual, so they can't be faked) — so these tests
// drive the cache against real temp files whose metadata we control directly.
public class FileScanCacheTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"fnpp_cache_test_{Guid.NewGuid():N}.tmp");

    public FileScanCacheTests() => File.WriteAllBytes(_path, new byte[100]);

    public void Dispose()
    {
        try { File.Delete(_path); } catch { }
    }

    private FileInfo CurrentInfo() => new(_path);

    [Fact]
    public void FirstLookup_Computes_AndCachesResult()
    {
        var cache = new FileScanCache<int>();
        int calls = 0;

        int result = cache.GetOrCompute(_path, CurrentInfo(), () => { calls++; return 42; });

        Assert.Equal(42, result);
        Assert.Equal(1, calls);
    }

    [Fact]
    public void UnchangedFile_ReturnsCachedValue_WithoutRecomputing()
    {
        var cache = new FileScanCache<int>();
        int calls = 0;

        int first  = cache.GetOrCompute(_path, CurrentInfo(), () => { calls++; return 1; });
        int second = cache.GetOrCompute(_path, CurrentInfo(), () => { calls++; return 2; });

        Assert.Equal(1, first);
        Assert.Equal(1, second);   // still the first computed value
        Assert.Equal(1, calls);    // compute only ran once
    }

    [Fact]
    public void ChangedLastWriteTime_InvalidatesCache_AndRecomputes()
    {
        var cache = new FileScanCache<int>();
        int calls = 0;

        cache.GetOrCompute(_path, CurrentInfo(), () => { calls++; return 1; });

        File.SetLastWriteTimeUtc(_path, DateTime.UtcNow.AddMinutes(5));
        int second = cache.GetOrCompute(_path, CurrentInfo(), () => { calls++; return 2; });

        Assert.Equal(2, second);
        Assert.Equal(2, calls);
    }

    [Fact]
    public void ChangedLength_InvalidatesCache_AndRecomputes()
    {
        var cache = new FileScanCache<int>();
        int calls = 0;
        var mtime = File.GetLastWriteTimeUtc(_path);

        cache.GetOrCompute(_path, CurrentInfo(), () => { calls++; return 1; });

        File.WriteAllBytes(_path, new byte[200]);
        File.SetLastWriteTimeUtc(_path, mtime); // keep mtime constant so only length differs

        int second = cache.GetOrCompute(_path, CurrentInfo(), () => { calls++; return 2; });

        Assert.Equal(2, second);
        Assert.Equal(2, calls);
    }

    [Fact]
    public void DifferentPaths_AreCachedIndependently()
    {
        string otherPath = Path.Combine(Path.GetTempPath(), $"fnpp_cache_test_{Guid.NewGuid():N}.tmp");
        File.WriteAllBytes(otherPath, new byte[50]);
        try
        {
            var cache = new FileScanCache<string>();

            string a = cache.GetOrCompute(_path, CurrentInfo(), () => "result-a");
            string b = cache.GetOrCompute(otherPath, new FileInfo(otherPath), () => "result-b");

            Assert.Equal("result-a", a);
            Assert.Equal("result-b", b);
        }
        finally { try { File.Delete(otherPath); } catch { } }
    }
}
