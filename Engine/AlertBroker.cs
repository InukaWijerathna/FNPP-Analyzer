using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Engine
{
    /// <summary>
    /// Terminal alert sink: deduplicates, stores, logs, and raises events. Signature-based
    /// suppression happens upstream in <see cref="PostScanFilter"/> before alerts get here,
    /// so an alert's Suppressed flag is already settled when AlertRaised fires.
    /// </summary>
    public class AlertBroker : IAlertSink
    {
        // Re-alerting the same fingerprint within this window is treated as the same ongoing
        // condition and dropped; past it, it's treated as a fresh occurrence worth re-raising —
        // otherwise a single past detection on a path would silence that exact finding forever,
        // even if the underlying malicious behaviour recurs.
        private static readonly TimeSpan DefaultDedupeCooldown = TimeSpan.FromHours(1);

        // When _lastSeen exceeds this, expired entries are pruned on the next submit —
        // keeps the map bounded during long live-monitor sessions.
        private const int LastSeenPruneThreshold = 512;

        private readonly List<Alert> _alerts = new();
        private readonly Dictionary<string, DateTime> _lastSeen = new();
        private readonly string _logPath;
        private readonly TimeSpan _dedupeCooldown;
        private readonly object _lock = new();

        public event Action<Alert>? AlertRaised;

        public string LogPath => _logPath;

        public AlertBroker(string logPath = "alerts.log")
            : this(logPath, DefaultDedupeCooldown)
        {
        }

        /// <summary>Test-only seam — lets tests use a short cooldown instead of waiting an hour.</summary>
        internal AlertBroker(string logPath, TimeSpan dedupeCooldown)
        {
            _logPath        = logPath;
            _dedupeCooldown = dedupeCooldown;
        }

        public void Submit(Alert alert)
        {
            // Identity for dedup, most-specific first: an explicit DedupeKey (for alerts
            // whose Description embeds volatile values), then the executable path (so the
            // same rule firing on two different binaries stays two alerts), then the
            // description as a last resort.
            string identity = alert.DedupeKey
                ?? (string.IsNullOrEmpty(alert.ExecutablePath) ? alert.Description : alert.ExecutablePath);
            string fingerprint = $"{alert.RuleId}:{identity}";

            DateTime now = DateTime.UtcNow;

            lock (_lock)
            {
                if (_lastSeen.TryGetValue(fingerprint, out var last) && now - last < _dedupeCooldown)
                    return;

                if (_lastSeen.Count > LastSeenPruneThreshold)
                    PruneExpired(now);

                _lastSeen[fingerprint] = now;
                _alerts.Add(alert);
                WriteLog(alert);
            }

            // Suppressed alerts are stored (greyed out in the Alerts view) but never
            // interrupt the terminal.
            if (!alert.Suppressed)
                AlertRaised?.Invoke(alert);
        }

        private void PruneExpired(DateTime now)
        {
            var expired = new List<string>();
            foreach (var kv in _lastSeen)
                if (now - kv.Value >= _dedupeCooldown)
                    expired.Add(kv.Key);
            foreach (var key in expired)
                _lastSeen.Remove(key);
        }

        public IReadOnlyList<Alert> GetAll()
        {
            lock (_lock) return _alerts.AsReadOnly();
        }

        /// <summary>Returns alerts recorded at or after the given index (0-based snapshot offset).</summary>
        public IReadOnlyList<Alert> GetFrom(int offset)
        {
            lock (_lock)
            {
                if (offset >= _alerts.Count) return Array.Empty<Alert>();
                return _alerts.GetRange(offset, _alerts.Count - offset).AsReadOnly();
            }
        }

        private void WriteLog(Alert alert)
        {
            try { File.AppendAllText(_logPath, JsonSerializer.Serialize(alert) + Environment.NewLine); }
            catch (Exception ex) { lock (ConsoleSync.Lock) Console.Error.WriteLine($"Log write failed: {ex.Message}"); }
        }
    }
}
