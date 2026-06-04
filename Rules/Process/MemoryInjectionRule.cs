using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using FNPPAnalyzer.Config;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Models;

namespace FNPPAnalyzer.Rules.Process
{
    // PROC-007: Detect shellcode/DLL injection by scanning process memory for
    // committed, private, executable regions — the classic signature of
    // VirtualAllocEx + WriteProcessMemory + CreateRemoteThread injection.
    //
    // Scoped to TrustedSystemProcesses (svchost, lsass, etc.) because those
    // should NEVER have private RWX memory; flagging every process would
    // generate false positives from Chrome/JVM JIT regions.
    public class MemoryInjectionRule : IDetectionRule
    {
        public string RuleId => "PROC-007";
        public string Name => "Memory Injection Detected";
        public string Description => "Detects RWX private memory regions in system processes — classic shellcode injection indicator.";

        // VirtualQueryEx page-protection constants
        private const uint PAGE_EXECUTE           = 0x10;
        private const uint PAGE_EXECUTE_READ      = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;

        // Any executable protection
        private const uint EXEC_MASK = PAGE_EXECUTE | PAGE_EXECUTE_READ
                                     | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

        // Classic injection: executable AND writable (no NX after write — shellcode pattern)
        private const uint RWX_MASK = PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

        private const uint MEM_COMMIT  = 0x1000;
        private const uint MEM_PRIVATE = 0x20000; // not backed by a file / shared section

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ           = 0x0010;

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint   AllocationProtect;
            public IntPtr RegionSize;
            public uint   State;
            public uint   Protect;
            public uint   Type;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualQueryEx(
            IntPtr hProcess, IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        private readonly AppConfig _config;

        public MemoryInjectionRule(AppConfig config) => _config = config;

        public IReadOnlyList<DetectionEvent> Evaluate(ScanContext context)
        {
            var events = new List<DetectionEvent>();

            foreach (var proc in context.Processes)
            {
                // Only scan processes that are listed as trusted system processes.
                // These should have no private executable memory outside their loaded modules.
                string name = proc.ProcessName.ToLowerInvariant() + ".exe";
                bool isSystemProc = _config.TrustedSystemProcesses
                    .Exists(p => string.Equals(p, name, StringComparison.OrdinalIgnoreCase) ||
                                 string.Equals(p, proc.ProcessName, StringComparison.OrdinalIgnoreCase));
                if (!isSystemProc) continue;

                IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id);
                if (hProcess == IntPtr.Zero) continue;

                try
                {
                    ScanProcessMemory(proc.Id, proc.ProcessName, hProcess, events);
                }
                finally { CloseHandle(hProcess); }
            }

            return events;
        }

        private static void ScanProcessMemory(
            int pid, string procName, IntPtr hProcess, List<DetectionEvent> events)
        {
            long   address = 0;
            uint   mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
            long   suspiciousBytes = 0;
            int    regions = 0;
            const int MaxRegions = 50_000; // hard cap — prevents runaway on pathological processes

            while (regions++ < MaxRegions &&
                   VirtualQueryEx(hProcess, (IntPtr)address, out var mbi, mbiSize) != 0)
            {
                long regionSize = (long)mbi.RegionSize;

                // Zero-size region would cause an infinite loop — shouldn't happen but guard anyway
                if (regionSize <= 0) break;

                // Advance cursor using 64-bit arithmetic to avoid (int) truncation on large regions
                long nextAddress = (long)mbi.BaseAddress + regionSize;

                // Past the end of the 64-bit user-mode address space → done
                if (nextAddress <= 0) break;
                address = nextAddress;

                // Only interested in committed, private, RWX regions
                bool committed = (mbi.State   & MEM_COMMIT)  != 0;
                bool priv      = (mbi.Type    & MEM_PRIVATE) != 0;
                bool rwx       = (mbi.Protect & RWX_MASK)    != 0;

                if (!committed || !priv || !rwx) continue;

                suspiciousBytes += regionSize;
            }

            // Only raise an alert if total suspicious memory exceeds 4 KB
            // (avoids noise from tiny guard pages that some loaders allocate).
            if (suspiciousBytes < 4096) return;

            events.Add(new DetectionEvent
            {
                RuleId      = "PROC-007",
                RuleName    = "Memory Injection Detected",
                Severity    = AlertSeverity.High,
                Type        = AlertType.MAL,
                Description = $"{procName} (PID {pid}) has {suspiciousBytes / 1024} KB of private RWX memory — possible shellcode injection",
                Metadata    = new { ProcessId = pid, ProcessName = procName, SuspiciousKB = suspiciousBytes / 1024 }
            });
        }
    }
}
