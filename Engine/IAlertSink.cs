using WinEDR_MVP.Models;

namespace WinEDR_MVP.Engine
{
    public interface IAlertSink
    {
        void Submit(Alert alert);
    }
}
