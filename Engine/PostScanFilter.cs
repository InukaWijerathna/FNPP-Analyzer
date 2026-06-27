using System.Collections.Generic;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Engine
{
    public sealed record FilterResult(
        IReadOnlyList<Alert> Visible,
        IReadOnlyList<Alert> Suppressed,
        IReadOnlyList<string> NewlyWhitelisted
    );

    public class PostScanFilter
    {
        private readonly SignatureWhitelist _whitelist;

        public PostScanFilter(SignatureWhitelist whitelist) => _whitelist = whitelist;

        /// <summary>
        /// Processes alerts raised during one scan cycle.
        ///
        /// For each alert that carries an ExecutablePath, unless its RuleId is in
        /// <see cref="TrustPolicy.HighTrustRuleIds"/>:
        ///   - Already whitelisted  → suppress (drop from display).
        ///   - Valid Authenticode   → add to whitelist, suppress.
        ///   - No/invalid signature → keep; escalate Medium to High.
        ///
        /// Alerts without a path, and alerts from a high-trust rule, are passed through unchanged.
        /// </summary>
        public FilterResult Process(IReadOnlyList<Alert> newAlerts)
        {
            var visible          = new List<Alert>();
            var suppressed       = new List<Alert>();
            var newlyWhitelisted = new List<string>();

            foreach (var alert in newAlerts)
            {
                string path = alert.ExecutablePath;

                if (string.IsNullOrEmpty(path) || TrustPolicy.HighTrustRuleIds.Contains(alert.RuleId))
                {
                    visible.Add(alert);
                    continue;
                }

                if (_whitelist.IsWhitelisted(path))
                {
                    alert.Suppressed = true;
                    suppressed.Add(alert);
                    continue;
                }

                var status = AuthenticodeVerifier.Verify(path);

                if (status == SignatureStatus.Valid)
                {
                    if (_whitelist.Add(path))
                        newlyWhitelisted.Add(path);

                    alert.Suppressed = true;
                    suppressed.Add(alert);
                }
                else
                {
                    // Unsigned or invalid binary — escalate Medium → High to raise urgency
                    var final = (status == SignatureStatus.NotSigned || status == SignatureStatus.Invalid)
                             && alert.Severity == AlertSeverity.Medium
                        ? alert.WithSeverity(AlertSeverity.High)
                        : alert;

                    visible.Add(final);
                }
            }

            return new FilterResult(visible, suppressed, newlyWhitelisted);
        }
    }
}
