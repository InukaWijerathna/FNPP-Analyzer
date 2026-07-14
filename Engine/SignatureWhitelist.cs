using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace FNPPAnalyzer.Engine
{
    /// <summary>
    /// Whitelist of verified binaries, keyed by path AND content hash. A bare path key
    /// would be a bypass: the monitored directories (Downloads, Temp) are user-writable,
    /// so an attacker could park a signed binary at a path once and then swap in malware
    /// at the same path. Every lookup re-hashes the file (mtime+size cached) and only
    /// matches when the content is byte-identical to what was originally whitelisted.
    /// </summary>
    public class SignatureWhitelist
    {
        // Normalized path → lowercase hex SHA-256 recorded when the path was whitelisted.
        private readonly Dictionary<string, string> _entries;
        private readonly string _filePath;
        private readonly object _lock = new();

        public SignatureWhitelist(string filePath = "whitelist.json")
        {
            _filePath = filePath;
            _entries  = Load(filePath);
        }

        public bool IsWhitelisted(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string key = Normalize(path);

            string? expectedHash;
            lock (_lock)
            {
                if (!_entries.TryGetValue(key, out expectedHash)) return false;
            }

            // Hash outside the lock — it can hit the disk on a changed file.
            string? currentHash = FileHasher.Sha256(path);
            if (currentHash != null && currentHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                return true;

            // File replaced (or unreadable) since it was whitelisted — the entry no longer
            // vouches for what's on disk. Drop it so the new content gets re-verified.
            lock (_lock)
            {
                if (_entries.TryGetValue(key, out var stillExpected) && stillExpected == expectedHash)
                {
                    _entries.Remove(key);
                    Persist();
                }
            }
            return false;
        }

        /// <summary>Records the file's current content hash and persists the whitelist.</summary>
        /// <returns>True if newly added; false if already present with the same hash or unreadable.</returns>
        public bool Add(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;

            string? hash = FileHasher.Sha256(path);
            if (hash == null) return false; // can't fingerprint it — never whitelist blind

            string key = Normalize(path);
            lock (_lock)
            {
                if (_entries.TryGetValue(key, out var existing) &&
                    existing.Equals(hash, StringComparison.OrdinalIgnoreCase))
                    return false;

                _entries[key] = hash;
                Persist();
                return true;
            }
        }

        /// <summary>Re-reads the whitelist file from disk, replacing the in-memory set.</summary>
        public void Reload()
        {
            var fresh = Load(_filePath);
            lock (_lock)
            {
                _entries.Clear();
                foreach (var kv in fresh) _entries[kv.Key] = kv.Value;
            }
        }

        public IReadOnlyCollection<string> GetAll()
        {
            lock (_lock) return new List<string>(_entries.Keys);
        }

        // ── Persistence ───────────────────────────────────────────────────────

        private void Persist()
        {
            try
            {
                File.WriteAllText(_filePath,
                    JsonSerializer.Serialize(_entries,
                        new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        private static Dictionary<string, string> Load(string filePath)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (!File.Exists(filePath)) return result;
                string json = File.ReadAllText(filePath);

                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in doc.RootElement.EnumerateObject())
                    {
                        string? hash = prop.Value.GetString();
                        if (!string.IsNullOrEmpty(hash)) result[prop.Name] = hash;
                    }
                }
                else if (doc.RootElement.ValueKind == JsonValueKind.Array)
                {
                    // Legacy format: a plain path array from before hashes were recorded.
                    // Migrate by hashing whatever is on disk right now — entries whose file
                    // is gone or unreadable are dropped rather than trusted blind.
                    foreach (var el in doc.RootElement.EnumerateArray())
                    {
                        string? path = el.GetString();
                        if (string.IsNullOrEmpty(path)) continue;
                        string? hash = FileHasher.Sha256(path);
                        if (hash != null) result[Normalize(path)] = hash;
                    }
                }
            }
            catch
            {
                result.Clear();
            }
            return result;
        }

        private static string Normalize(string path)
        {
            try
            {
                return Path.GetFullPath(path)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            }
            catch
            {
                return path.Trim();
            }
        }
    }
}
