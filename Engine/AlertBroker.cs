using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Engine
{
    public class AlertBroker : IAlertSink
    {
        // Re-alerting the same fingerprint within this window is treated as the same ongoing
        // condition and dropped; past it, it's treated as a fresh occurrence worth re-raising —
        // otherwise a single past detection on a path would silence that exact finding forever,
        // even if the underlying malicious behaviour recurs.
        private static readonly TimeSpan DefaultDedupeCooldown = TimeSpan.FromHours(1);

        private readonly List<Alert> _alerts = new();
        private readonly Dictionary<string, DateTime> _lastSeen = new();
        private readonly string _logPath;
        private readonly SignatureWhitelist _whitelist;
        private readonly TimeSpan _dedupeCooldown;
        private readonly object _lock = new();

        public event Action<Alert>? AlertRaised;

        public string LogPath => _logPath;

        public AlertBroker(string logPath = "alerts.log", SignatureWhitelist? whitelist = null)
            : this(logPath, whitelist, DefaultDedupeCooldown)
        {
        }

        /// <summary>Test-only seam — lets tests use a short cooldown instead of waiting an hour.</summary>
        internal AlertBroker(string logPath, SignatureWhitelist? whitelist, TimeSpan dedupeCooldown)
        {
            _logPath        = logPath;
            _whitelist      = whitelist ?? new SignatureWhitelist();
            _dedupeCooldown = dedupeCooldown;
        }

        public void Submit(Alert alert)
        {
            // Efficiency gate: paths already verified and whitelisted in a prior scan are
            // dropped here before dedup/logging so they never appear in the alert list.
            // High-trust rules (see TrustPolicy) bypass this — their finding is the verdict,
            // and a valid signature on the path doesn't change that.
            if (!TrustPolicy.HighTrustRuleIds.Contains(alert.RuleId) &&
                !string.IsNullOrEmpty(alert.ExecutablePath) &&
                _whitelist.IsWhitelisted(alert.ExecutablePath))
                return;

            // Include path when available so the same rule firing on two different binaries
            // produces two distinct alerts rather than silently deduplicating the second one.
            string fingerprint = string.IsNullOrEmpty(alert.ExecutablePath)
                ? $"{alert.RuleId}:{alert.Description}"
                : $"{alert.RuleId}:{alert.ExecutablePath}";
            Alert? toFire = null;
            DateTime now = DateTime.UtcNow;

            lock (_lock)
            {
                if (_lastSeen.TryGetValue(fingerprint, out var last) && now - last < _dedupeCooldown)
                    return;

                _lastSeen[fingerprint] = now;
                _alerts.Add(alert);
                WriteLog(alert);
                toFire = alert;
            }

            AlertRaised?.Invoke(toFire);
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
