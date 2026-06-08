using System;
using System.Collections.Concurrent;
using System.IO;

namespace FNPPAnalyzer.Engine
{
    /// <summary>
    /// Memoizes a per-file scan result keyed by path + last-write-time + size, so rules
    /// that re-scan the same untrusted directories and process executables every cycle
    /// (every 30s in live monitor) skip re-hashing/re-parsing files that haven't changed
    /// since the last pass. A changed mtime or size — the cheapest signal a file was
    /// rewritten — invalidates the entry.
    /// </summary>
    public sealed class FileScanCache<TResult>
    {
        private sealed record Entry(DateTime LastWriteUtc, long Length, TResult Result);

        private readonly ConcurrentDictionary<string, Entry> _cache = new(StringComparer.OrdinalIgnoreCase);

        public TResult GetOrCompute(string path, FileInfo info, Func<TResult> compute)
        {
            if (_cache.TryGetValue(path, out var cached)
                && cached.LastWriteUtc == info.LastWriteTimeUtc
                && cached.Length == info.Length)
                return cached.Result;

            var result = compute();
            _cache[path] = new Entry(info.LastWriteTimeUtc, info.Length, result);
            return result;
        }
    }
}
