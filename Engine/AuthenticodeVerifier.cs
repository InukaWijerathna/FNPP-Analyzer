using System;
using System.IO;
using System.Runtime.InteropServices;

namespace FNPPAnalyzer.Engine
{
    public enum SignatureStatus { Valid, Invalid, NotSigned, Unknown }

    public static class AuthenticodeVerifier
    {
        // 0x800B0100 TRUST_E_NOSIGNATURE   — no signature embedded
        // 0x800B0112 TRUST_E_SUBJECT_NOT_TRUSTED — signature present but not trusted
        // 0x800B010E TRUST_E_EXPLICIT_DISTRUST   — explicitly untrusted
        private const uint TRUST_E_NOSIGNATURE        = 0x800B0100;
        private const uint TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0112;
        private const uint TRUST_E_EXPLICIT_DISTRUST   = 0x800B010E;

        public static SignatureStatus Verify(string filePath)
        {
            if (!File.Exists(filePath)) return SignatureStatus.Unknown;

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
                    dwProvFlags         = 0x10, // WTD_CACHE_ONLY_URL_RETRIEVAL — no network
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
                    // Must always call CLOSE to free the provider state, even on exception
                    trust.dwStateAction = 2; // WTD_STATEACTION_CLOSE
                    WinVerifyTrust(IntPtr.Zero, ref actionId, ref trust);
                }

                return result switch
                {
                    0                          => SignatureStatus.Valid,
                    TRUST_E_NOSIGNATURE        => SignatureStatus.NotSigned,
                    TRUST_E_SUBJECT_NOT_TRUSTED => SignatureStatus.NotSigned,
                    TRUST_E_EXPLICIT_DISTRUST   => SignatureStatus.Invalid,
                    _                           => SignatureStatus.Invalid
                };
            }
            catch
            {
                return SignatureStatus.Unknown;
            }
            finally
            {
                if (fileInfoPtr != IntPtr.Zero) Marshal.FreeHGlobal(fileInfoPtr);
                if (pathPtr     != IntPtr.Zero) Marshal.FreeHGlobal(pathPtr);
            }
        }

        // ── WinTrust P/Invoke ─────────────────────────────────────────────────────

        private static readonly Guid ActionGenericVerifyV2 =
            new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint   cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint   cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint   dwUIChoice;
            public uint   fdwRevocationChecks;
            public uint   dwUnionChoice;
            public IntPtr pInfo;
            public uint   dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint   dwProvFlags;
            public uint   dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(IntPtr hWnd, ref Guid pgActionID,
            ref WINTRUST_DATA pWVTData);
    }
}
