using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace FNPPAnalyzer.Engine
{
    public class SignatureWhitelist
    {
        private readonly HashSet<string> _paths;
        private readonly string _filePath;
        private readonly object _lock = new();

        public SignatureWhitelist(string filePath = "whitelist.json")
        {
            _filePath = filePath;
            _paths    = Load(filePath);
        }

        public bool IsWhitelisted(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            lock (_lock) return _paths.Contains(Normalize(path));
        }

        /// <summary>Adds a path and immediately persists the whitelist.</summary>
        /// <returns>True if the path was newly added; false if already present.</returns>
        public bool Add(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string key = Normalize(path);
            lock (_lock)
            {
                if (!_paths.Add(key)) return false;
                Persist();
                return true;
            }
        }

        public IReadOnlyCollection<string> GetAll()
        {
            lock (_lock) return new HashSet<string>(_paths, StringComparer.OrdinalIgnoreCase);
        }

        // ── Persistence ───────────────────────────────────────────────────────

        private void Persist()
        {
            try
            {
                File.WriteAllText(_filePath,
                    JsonSerializer.Serialize(_paths,
                        new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        private static HashSet<string> Load(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                var list = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(filePath));
                return new HashSet<string>(list ?? [], StringComparer.OrdinalIgnoreCase);
            }
            catch
            {
                return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }
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
