using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Engine
{
    public class AlertBroker : IAlertSink
    {
        private readonly List<Alert> _alerts = new();
        private readonly HashSet<string> _seen = new();
        private readonly string _logPath;
        private readonly SignatureWhitelist _whitelist;
        private readonly object _lock = new();

        public event Action<Alert>? AlertRaised;

        public AlertBroker(string logPath = "alerts.log", SignatureWhitelist? whitelist = null)
        {
            _logPath   = logPath;
            _whitelist = whitelist ?? new SignatureWhitelist();
        }

        public void Submit(Alert alert)
        {
            // Efficiency gate: paths already verified and whitelisted in a prior scan are
            // dropped here before dedup/logging so they never appear in the alert list.
            if (!string.IsNullOrEmpty(alert.ExecutablePath) &&
                _whitelist.IsWhitelisted(alert.ExecutablePath))
                return;

            string fingerprint = $"{alert.RuleId}:{alert.Description}";
            Alert? toFire = null;

            lock (_lock)
            {
                if (!_seen.Add(fingerprint)) return;
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
            catch (Exception ex) { Console.WriteLine($"Log write failed: {ex.Message}"); }
        }
    }
}
