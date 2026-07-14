using System;
using System.IO;
using System.Security.Cryptography;

namespace FNPPAnalyzer.Engine
{
    /// <summary>
    /// Process-wide cached SHA-256 hashing. The whitelist re-verifies file identity on
    /// every lookup and KnownHashRule hashes every scanned file each cycle — both would
    /// re-read unchanged files constantly without the mtime+size memoization.
    /// </summary>
    public static class FileHasher
    {
        private static readonly FileScanCache<string?> Cache = new();

        /// <summary>Lowercase hex SHA-256 of the file, or null if it can't be read.</summary>
        public static string? Sha256(string path)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists) return null;
                return Cache.GetOrCompute(path, info, () => Compute(path));
            }
            catch { return null; }
        }

        private static string? Compute(string path)
        {
            try
            {
                using var stream = File.OpenRead(path);
                return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            }
            catch { return null; }
        }
    }
}
