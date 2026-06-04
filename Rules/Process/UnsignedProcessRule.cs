using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using FNPPAnalyzer.Config;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Rules.Process
{
    // PROC-006: Detects unsigned executables running from Windows system directories.
    // Uses WinVerifyTrust (Authenticode) — the correct Windows API for signature verification.
    // Scoped to processes whose names are in TrustedSystemProcesses config; legitimate
    // OEM drivers in DriverStore/SystemApps are excluded to prevent false positives.
    public class UnsignedProcessRule : IDetectionRule
    {
        public string RuleId => "PROC-006";
        public string Name => "Unsigned System Process";
        public string Description => "Detects unsigned executables running from Windows system directories.";

        // Legitimate OEM/driver paths — always skip, they contain third-party signed binaries
        private static readonly string[] ExcludedPrefixes =
        [
            @"C:\Windows\System32\DriverStore\",
            @"C:\Windows\SysWOW64\DriverStore\",
            @"C:\Windows\SystemApps\",
            @"C:\Windows\WinSxS\",
        ];

        private static readonly string[] SystemPrefixes =
        [
            @"C:\Windows\System32\",
            @"C:\Windows\SysWOW64\",
            @"C:\Windows\",
        ];

        private readonly AppConfig _config;

        public UnsignedProcessRule(AppConfig config) => _config = config;

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();
            var checked_ = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var proc in context.Processes)
            {
                try
                {
                    // Only check processes whose name appears in TrustedSystemProcesses —
                    // everything else (OEM tools, third-party utilities) is expected to vary.
                    string procName = proc.ProcessName.ToLower();
                    if (!_config.TrustedSystemProcesses.Contains(procName + ".exe")) continue;

                    string? path = proc.MainModule?.FileName;
                    if (string.IsNullOrEmpty(path) || !checked_.Add(path)) continue;

                    // Skip DriverStore, SystemApps, WinSxS — OEM / packaged-app territory
                    bool excluded = false;
                    foreach (var prefix in ExcludedPrefixes)
                        if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        { excluded = true; break; }
                    if (excluded) continue;

                    bool inSystem = false;
                    foreach (var prefix in SystemPrefixes)
                        if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        { inSystem = true; break; }
                    if (!inSystem) continue;

                    if (!IsAuthenticodeSigned(path))
                        events.Add(new DetectionEvent
                        {
                            RuleId = RuleId,
                            RuleName = Name,
                            Severity = AlertSeverity.High,
                            Type = AlertType.MAL,
                            Description = $"Unsigned executable in system path: {proc.ProcessName} ({path})",
                            Metadata = new { ProcessId = proc.Id, Path = path }
                        });
                }
                catch { }
            }
            return events;
        }

        // ── WinVerifyTrust P/Invoke ───────────────────────────────────────────────────

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint  cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint  cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint  dwUIChoice;           // 2 = WTD_UI_NONE
            public uint  fdwRevocationChecks;  // 0 = WTD_REVOKE_NONE
            public uint  dwUnionChoice;        // 1 = WTD_CHOICE_FILE
            public IntPtr pInfo;               // points to WINTRUST_FILE_INFO
            public uint  dwStateAction;        // 1 = WTD_STATEACTION_VERIFY
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint  dwProvFlags;          // 0x10 = WTD_CACHE_ONLY_URL_RETRIEVAL
            public uint  dwUIContext;
            public IntPtr pSignatureSettings;
        }

        private static readonly Guid ActionGenericVerifyV2 =
            new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

        [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(IntPtr hWnd, ref Guid pgActionID,
            ref WINTRUST_DATA pWVTData);

        private static bool IsAuthenticodeSigned(string filePath)
        {
            if (!File.Exists(filePath)) return true;

            IntPtr pathPtr     = IntPtr.Zero;
            IntPtr fileInfoPtr = IntPtr.Zero;

            try
            {
                pathPtr = Marshal.StringToHGlobalUni(filePath);

                var fileInfo = new WINTRUST_FILE_INFO
                {
                    cbStruct       = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                    pcwszFilePath  = pathPtr,
                    hFile          = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };

                fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                var trust = new WINTRUST_DATA
                {
                    cbStruct            = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData      = IntPtr.Zero,
                    dwUIChoice          = 2,    // WTD_UI_NONE
                    fdwRevocationChecks = 0,    // WTD_REVOKE_NONE
                    dwUnionChoice       = 1,    // WTD_CHOICE_FILE
                    pInfo               = fileInfoPtr,
                    dwStateAction       = 1,    // WTD_STATEACTION_VERIFY
                    hWVTStateData       = IntPtr.Zero,
                    pwszURLReference    = IntPtr.Zero,
                    dwProvFlags         = 0x10, // WTD_CACHE_ONLY_URL_RETRIEVAL (no network)
                    dwUIContext         = 0,
                    pSignatureSettings  = IntPtr.Zero
                };

                var actionId = ActionGenericVerifyV2;
                uint result;
                try
                {
                    result = WinVerifyTrust(IntPtr.Zero, ref actionId, ref trust);
                }
                finally
                {
                    // Must always close, even if the verify call throws
                    trust.dwStateAction = 2; // WTD_STATEACTION_CLOSE
                    WinVerifyTrust(IntPtr.Zero, ref actionId, ref trust);
                }

                return result == 0; // S_OK = valid Authenticode signature present
            }
            catch
            {
                return true; // if we can't check, assume signed (avoid false positives)
            }
            finally
            {
                if (fileInfoPtr != IntPtr.Zero) Marshal.FreeHGlobal(fileInfoPtr);
                if (pathPtr     != IntPtr.Zero) Marshal.FreeHGlobal(pathPtr);
            }
        }
        // ─────────────────────────────────────────────────────────────────────────────
    }
}
