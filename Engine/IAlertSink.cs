using FNPPScanner.Models;

namespace FNPPScanner.Engine
{
    public interface IAlertSink
    {
        void Submit(Alert alert);
    }
}
