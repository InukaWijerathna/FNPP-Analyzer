using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using FNPPScanner.Models;

namespace FNPPScanner.Engine
{
    public class AlertBroker : IAlertSink
    {
        private readonly List<Alert> _alerts = new();
        private readonly HashSet<string> _seen = new();
        private readonly string _logPath;
        private readonly object _lock = new();

        public event Action<Alert>? AlertRaised;

        public AlertBroker(string logPath = "alerts.log") => _logPath = logPath;

        public void Submit(Alert alert)
        {
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

        private void WriteLog(Alert alert)
        {
            try { File.AppendAllText(_logPath, JsonSerializer.Serialize(alert) + Environment.NewLine); }
            catch (Exception ex) { Console.WriteLine($"Log write failed: {ex.Message}"); }
        }
    }
}
