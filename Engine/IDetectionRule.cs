using System.Collections.Generic;
using WinEDR_MVP.Models;

namespace WinEDR_MVP.Engine
{
    public interface IDetectionRule
    {
        string RuleId { get; }
        string Name { get; }
        string Description { get; }
        IReadOnlyList<DetectionEvent> Evaluate(ScanContext context);
    }
}
