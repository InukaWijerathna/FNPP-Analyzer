using System;
using System.Collections.Generic;
using System.IO;

namespace FNPPAnalyzer.Engine
{
    public static class PathTrust
    {
        /// <summary>
        /// True if <paramref name="path"/> is at or beneath one of <paramref name="trustedRoots"/>.
        /// Compares against the root plus a trailing separator so "C:\Program Files" doesn't
        /// match "C:\Program FilesEvil\x.exe" — a plain StartsWith has no directory boundary.
        /// </summary>
        public static bool IsUnderTrustedPath(string path, IEnumerable<string> trustedRoots)
        {
            foreach (var root in trustedRoots)
            {
                string boundary = root.TrimEnd('\\', '/') + Path.DirectorySeparatorChar;
                if (path.StartsWith(boundary, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }
}
