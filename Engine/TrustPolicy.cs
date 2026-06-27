using System;
using System.Collections.Generic;

namespace FNPPAnalyzer.Engine
{
    /// <summary>
    /// Rules whose finding IS the verdict — a valid (or stolen-but-valid) code-signing
    /// certificate doesn't change the fact that a system process is running from the wrong
    /// path, or that a file hashes to a known-malicious sample. Alerts from these rules
    /// bypass the signature whitelist entirely: AlertBroker never drops them as already
    /// whitelisted, and PostScanFilter never suppresses or whitelists them based on signature.
    /// </summary>
    public static class TrustPolicy
    {
        public static readonly HashSet<string> HighTrustRuleIds = new(StringComparer.OrdinalIgnoreCase)
        {
            "PROC-001", // System Process Masquerading
            "FILE-003", // Known Malware Hash
        };
    }
}
