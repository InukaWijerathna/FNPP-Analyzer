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

            var embedded = VerifyEmbedded(filePath);
            if (embedded != SignatureStatus.NotSigned) return embedded;

            // No embedded Authenticode signature — most stock Windows binaries are signed
            // via a catalog file instead (confirmed via Get-AuthenticodeSignature for
            // notepad.exe, cmd.exe, explorer.exe: all Valid/Catalog), and WTD_CHOICE_FILE
            // never checks the catalog database. Fall back to an explicit catalog lookup
            // before concluding the file is genuinely unsigned.
            return VerifyCatalog(filePath);
        }

        // ── Embedded (WTD_CHOICE_FILE) verification ─────────────────────────────────

        private static SignatureStatus VerifyEmbedded(string filePath)
        {
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

                return RunWinVerifyTrust(WTD_CHOICE_FILE, fileInfoPtr);
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

        // ── Catalog (WTD_CHOICE_CATALOG) verification ───────────────────────────────

        // Subsystem GUID Windows itself uses for catalog-admin lookups during driver/file
        // signature verification (DRIVER_ACTION_VERIFY) — not specific to drivers despite
        // the name; it's the standard subsystem for CryptCATAdminAcquireContext2 callers.
        private static readonly Guid DriverActionVerify = new("F750E6C3-38EE-11D1-85E5-00C04FC295EE");

        private static SignatureStatus VerifyCatalog(string filePath)
        {
            IntPtr hCatAdmin      = IntPtr.Zero;
            IntPtr hFile          = INVALID_HANDLE_VALUE;
            IntPtr hCatInfo       = IntPtr.Zero;
            IntPtr pHash          = IntPtr.Zero;
            IntPtr pathPtr        = IntPtr.Zero;
            IntPtr tagPtr         = IntPtr.Zero;
            IntPtr catalogPathPtr = IntPtr.Zero;
            IntPtr catalogInfoPtr = IntPtr.Zero;

            try
            {
                var subsystem = DriverActionVerify;
                if (!CryptCATAdminAcquireContext2(out hCatAdmin, ref subsystem, "SHA256", IntPtr.Zero, 0))
                    return SignatureStatus.NotSigned;

                hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero,
                    OPEN_EXISTING, 0, IntPtr.Zero);
                if (hFile == INVALID_HANDLE_VALUE) return SignatureStatus.Unknown;

                uint hashSize = 0;
                CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashSize, IntPtr.Zero, 0);
                if (hashSize == 0) return SignatureStatus.NotSigned;

                pHash = Marshal.AllocHGlobal((int)hashSize);
                if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashSize, pHash, 0))
                    return SignatureStatus.Unknown;

                hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pHash, hashSize, 0, IntPtr.Zero);
                if (hCatInfo == IntPtr.Zero)
                    return SignatureStatus.NotSigned; // no catalog contains this hash — genuinely unsigned

                var catInfo = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                if (!CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0))
                    return SignatureStatus.Unknown;

                byte[] hashBytes = new byte[hashSize];
                Marshal.Copy(pHash, hashBytes, 0, (int)hashSize);
                string memberTag = Convert.ToHexString(hashBytes); // ToHexString is uppercase, as required

                pathPtr        = Marshal.StringToHGlobalUni(filePath);
                tagPtr         = Marshal.StringToHGlobalUni(memberTag);
                catalogPathPtr = Marshal.StringToHGlobalUni(catInfo.wszCatalogFile);

                var catalogInfo = new WINTRUST_CATALOG_INFO
                {
                    cbStruct              = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                    pcwszCatalogFilePath  = catalogPathPtr,
                    pcwszMemberTag        = tagPtr,
                    pcwszMemberFilePath   = pathPtr,
                    hMemberFile           = hFile,
                    pbCalculatedFileHash  = pHash,
                    cbCalculatedFileHash  = hashSize,
                    hCatAdmin             = hCatAdmin
                };

                catalogInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
                Marshal.StructureToPtr(catalogInfo, catalogInfoPtr, false);

                return RunWinVerifyTrust(WTD_CHOICE_CATALOG, catalogInfoPtr);
            }
            catch
            {
                return SignatureStatus.Unknown;
            }
            finally
            {
                if (catalogInfoPtr != IntPtr.Zero) Marshal.FreeHGlobal(catalogInfoPtr);
                if (catalogPathPtr != IntPtr.Zero) Marshal.FreeHGlobal(catalogPathPtr);
                if (tagPtr != IntPtr.Zero) Marshal.FreeHGlobal(tagPtr);
                if (pathPtr != IntPtr.Zero) Marshal.FreeHGlobal(pathPtr);
                if (hCatInfo != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                if (hCatAdmin != IntPtr.Zero) CryptCATAdminReleaseContext(hCatAdmin, 0);
                if (hFile != IntPtr.Zero && hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
                if (pHash != IntPtr.Zero) Marshal.FreeHGlobal(pHash);
            }
        }

        // ── Shared WinVerifyTrust call + result mapping ─────────────────────────────

        private static SignatureStatus RunWinVerifyTrust(uint unionChoice, IntPtr pInfo)
        {
            var trust = new WINTRUST_DATA
            {
                cbStruct            = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData      = IntPtr.Zero,
                dwUIChoice          = 2,    // WTD_UI_NONE
                fdwRevocationChecks = 0,    // WTD_REVOKE_NONE
                dwUnionChoice       = unionChoice,
                pInfo               = pInfo,
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

        // ── WinTrust / CryptCATAdmin P/Invoke ────────────────────────────────────────

        private const uint WTD_CHOICE_FILE    = 1;
        private const uint WTD_CHOICE_CATALOG = 2;

        private const uint GENERIC_READ     = 0x80000000;
        private const uint FILE_SHARE_READ  = 0x1;
        private const uint OPEN_EXISTING    = 3;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_CATALOG_INFO
        {
            public uint   cbStruct;
            public uint   dwCatalogVersion;
            public IntPtr pcwszCatalogFilePath;
            public IntPtr pcwszMemberTag;
            public IntPtr pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public uint   cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CATALOG_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] // MAX_PATH
            public string wszCatalogFile;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(IntPtr hWnd, ref Guid pgActionID,
            ref WINTRUST_DATA pWVTData);

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptCATAdminAcquireContext2(
            out IntPtr phCatAdmin, ref Guid pgSubsystem, string? pwszHashAlgorithm,
            IntPtr pStrongHashPolicy, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle2(
            IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, IntPtr pbHash, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
            IntPtr hCatAdmin, IntPtr pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptCATCatalogInfoFromContext(
            IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseCatalogContext(
            IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFile(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
            uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
    }
}
