namespace FNPPAnalyzer.Models
{
    public enum AlertSeverity { Low, Medium, High }

    public enum AlertType
    {
        MAL,    // Malware
        TROJ,   // Trojan
        BACK,   // Backdoor
        RECON,  // Reconnaissance
        RANSOM, // Ransomware
        INFO    // Informational
    }
}
