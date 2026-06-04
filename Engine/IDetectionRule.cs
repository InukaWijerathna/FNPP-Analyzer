using System.Collections.Generic;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Engine
{
    public interface IDetectionRule
    {
        string RuleId { get; }
        string Name { get; }
        string Description { get; }
        IReadOnlyList<DetectionEvent> Evaluate(ScanContext context);
    }
}
