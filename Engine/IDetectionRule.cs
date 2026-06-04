using System.Collections.Generic;
using FNPPScanner.Models;

namespace FNPPScanner.Engine
{
    public interface IDetectionRule
    {
        string RuleId { get; }
        string Name { get; }
        string Description { get; }
        IReadOnlyList<DetectionEvent> Evaluate(ScanContext context);
    }
}
