namespace FNPPAnalyzer.Models
{
    public class DetectionEvent
    {
        public string RuleId { get; init; } = string.Empty;
        public string RuleName { get; init; } = string.Empty;
        public AlertSeverity Severity { get; init; }
        public AlertType Type { get; init; }
        public string Description { get; init; } = string.Empty;
        public string ExecutablePath { get; init; } = string.Empty;
        public object? Metadata { get; init; }

        /// <summary>See <see cref="Alert.DedupeKey"/> — copied onto the alert by RuleEngine.</summary>
        public string? DedupeKey { get; init; }
    }
}
