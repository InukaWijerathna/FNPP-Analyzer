namespace FNPPAnalyzer.Engine
{
    /// <summary>
    /// Lock shared by every background Console.Error write (rule/engine error logging) and
    /// the TUI's live progress-bar rendering in Program.cs. Without it, a diagnostic write
    /// firing mid-scan can land between Spectre.Console's cursor-position writes and corrupt
    /// the rendered output — the same hazard the alert-display code already guards against.
    /// </summary>
    public static class ConsoleSync
    {
        public static readonly object Lock = new();
    }
}
