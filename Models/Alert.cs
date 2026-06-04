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
        public object? Metadata { get; init; }
    }
}
