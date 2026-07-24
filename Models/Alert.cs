using System;

namespace FNPPAnalyzer.Models
{
    public class Alert
    {
        public Guid Id { get; init; } = Guid.NewGuid();
        public DateTime Timestamp { get; init; } = DateTime.UtcNow;
        public AlertSeverity Severity { get; init; }
        public AlertType Type { get; init; }
        public string Title { get; init; } = string.Empty;
        public string Description { get; init; } = string.Empty;
        public string SourceProcess { get; init; } = string.Empty;
        public string RuleId { get; init; } = string.Empty;
        public string ExecutablePath { get; init; } = string.Empty;
        public object? Metadata { get; init; }

        /// <summary>
        /// Optional stable dedup identity for alerts whose Description embeds volatile
        /// values (counts, timestamps). Without it, path-less alerts fall back to
        /// deduplicating on the full Description — which never matches when the
        /// description changes every cycle.
        /// </summary>
        public string? DedupeKey { get; init; }

        /// <summary>Set by PostScanFilter when the path is Authenticode-valid and whitelisted.</summary>
        public bool Suppressed { get; set; }

        public Alert WithSeverity(AlertSeverity severity) => new Alert
        {
            Id             = Id,
            Timestamp      = Timestamp,
            Severity       = severity,
            Type           = Type,
            Title          = Title,
            Description    = Description,
            SourceProcess  = SourceProcess,
            RuleId         = RuleId,
            ExecutablePath = ExecutablePath,
            Metadata       = Metadata,
            DedupeKey      = DedupeKey
        };
    }
}
