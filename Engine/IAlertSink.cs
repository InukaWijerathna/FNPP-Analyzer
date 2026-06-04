using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Engine
{
    public interface IAlertSink
    {
        void Submit(Alert alert);
    }
}
