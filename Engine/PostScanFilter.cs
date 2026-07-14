using System.Collections.Generic;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Engine
{
    public sealed record FilterResult(
        IReadOnlyList<Alert> Visible,
        IReadOnlyList<Alert> Suppressed,
        IReadOnlyList<string> NewlyWhitelisted
    );

    /// <summary>
    /// Signature-based filter that sits between alert producers (RuleEngine, the
    /// real-time ProcessCreationWatcher) and the AlertBroker. Filtering happens at
    /// submit time — before the broker stores the alert or fires its event — so an
    /// alert's Suppressed flag and final severity are settled by the time anything
    /// displays it, and real-time alerts get the exact same treatment as scan alerts.
    ///
    /// For each alert that carries an ExecutablePath, unless its RuleId is in
    /// <see cref="TrustPolicy.HighTrustRuleIds"/>:
    ///   - Already whitelisted (content hash still matches) → dropped entirely.
    ///   - Valid Authenticode → path+hash added to whitelist; forwarded marked Suppressed.
    ///   - No/invalid signature → forwarded; Medium escalated to High.
    ///
    /// Alerts without a path, and alerts from high-trust rules, pass through unchanged.
    /// </summary>
    public class PostScanFilter : IAlertSink
    {
        private readonly SignatureWhitelist _whitelist;
        private readonly IAlertSink _next;
        private readonly List<string> _newlyWhitelisted = new();
        private readonly object _lock = new();

        public PostScanFilter(SignatureWhitelist whitelist, IAlertSink next)
        {
            _whitelist = whitelist;
            _next      = next;
        }

        public void Submit(Alert alert)
        {
            string path = alert.ExecutablePath;

            if (string.IsNullOrEmpty(path) || TrustPolicy.HighTrustRuleIds.Contains(alert.RuleId))
            {
                _next.Submit(alert);
                return;
            }

            if (_whitelist.IsWhitelisted(path))
                return; // verified before and unchanged on disk — drop silently

            var status = AuthenticodeVerifier.Verify(path);

            if (status == SignatureStatus.Valid)
            {
                if (_whitelist.Add(path))
                    lock (_lock) _newlyWhitelisted.Add(path);

                // Stored (visible greyed-out in the Alerts view) but never raised live.
                alert.Suppressed = true;
                _next.Submit(alert);
                return;
            }

            // Unsigned or invalid binary — escalate Medium → High to raise urgency
            var final = (status == SignatureStatus.NotSigned || status == SignatureStatus.Invalid)
                     && alert.Severity == AlertSeverity.Medium
                ? alert.WithSeverity(AlertSeverity.High)
                : alert;

            _next.Submit(final);
        }

        /// <summary>
        /// Partitions one cycle's stored alerts into visible/suppressed and drains the
        /// paths whitelisted since the last call — used for the end-of-scan summary.
        /// </summary>
        public FilterResult CollectResult(IReadOnlyList<Alert> cycleAlerts)
        {
            var visible    = new List<Alert>();
            var suppressed = new List<Alert>();
            foreach (var alert in cycleAlerts)
                (alert.Suppressed ? suppressed : visible).Add(alert);

            return new FilterResult(visible, suppressed, DrainNewlyWhitelisted());
        }

        public IReadOnlyList<string> DrainNewlyWhitelisted()
        {
            lock (_lock)
            {
                var drained = _newlyWhitelisted.ToArray();
                _newlyWhitelisted.Clear();
                return drained;
            }
        }
    }
}
