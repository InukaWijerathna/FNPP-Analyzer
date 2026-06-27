# FNPP Analyzer

A Windows host-based threat detector that monitors running processes, network connections, file activity, and registry persistence for malicious behaviour. Runs entirely in the terminal with an interactive TUI.

```
╔══════════════════════════════════════════════════╗
║   ███████╗███╗   ██╗██████╗ ██████╗              ║
║   ██╔════╝████╗  ██║██╔══██╗██╔══██╗             ║
║   █████╗  ██╔██╗ ██║██████╔╝██████╔╝             ║
║   ██╔══╝  ██║╚██╗██║██╔═══╝ ██╔═══╝              ║
║   ██║     ██║ ╚████║██║     ██║                  ║
║   ╚═╝     ╚═╝  ╚═══╝╚═╝     ╚═╝                  ║
║             A N A L Y Z E R                      ║
╚══════════════════════════════════════════════════╝
```

## Requirements

- Windows 10/11
- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- Administrator privileges (recommended for full process inspection)

## Build & Run

```powershell
git clone https://github.com/InukaWijerathna/FNPP-Analyzer
cd FNPP-Analyzer

dotnet build FNPPAnalyzer.csproj
dotnet run --project FNPPAnalyzer.csproj
```

Or build a standalone executable:

```powershell
dotnet publish FNPPAnalyzer.csproj -c Release -r win-x64 --self-contained
```

> Run as Administrator for full `SeDebugPrivilege` access. Without it, some process details (command lines, parent PIDs) may be unavailable.

## Interface

Navigation is via arrow keys and Enter. No typing required.

```
  FNPP Analyzer  IDLE  │  Alerts: 0  │  Log: alerts.log

──────────────────── Main Menu ────────────────────
? Select an option:
  > 1.  Scan Now        (run a single detection cycle)
    2.  Live Monitor    (start continuous scanning)
    3.  Stop Monitor    (stop continuous scanning)
    4.  Alerts          (view all recorded alerts)
    5.  Status          (scanner state & statistics)
    6.  Reload Rules    (reload IOCs, whitelist & YARA rules)
    7.  Clear
    8.  Open Log File   (open alerts.log)
    9.  Quit
```

| Command | Description |
|---|---|
| Scan Now | Runs one detection pass immediately |
| Live Monitor | Starts background scanning on a 30-second interval |
| Stop Monitor | Cancels the background scan |
| Alerts | Shows all recorded alerts in a table |
| Status | Shows scanner state, interval, and alert count |
| Reload Rules | Re-reads `whitelist.json`, `iocs.json`, and recompiles `YaraRules/*.yar` without restarting |
| Open Log File | Opens `alerts.log` in the default associated application; shows a message instead if no log file has been created yet |

## Detection Rules

| Rule ID | Category | What it detects |
|---|---|---|
| PROC-001 | Process | System process name masquerading (e.g. `svchost` from wrong path) |
| PROC-002 | Process | Executables/scripts running from user-writable directories |
| PROC-003 | Process | Scripts launched from untrusted paths (sub-finding of PROC-002) |
| PROC-004 | Process | Shell interpreters spawned by Office applications or browsers |
| PROC-005 | Process | Living-off-the-land binary (LOLBin) abuse |
| PROC-006 | Process | Unsigned executables running from Windows system directories |
| PROC-007 | Process | RWX private memory regions — shellcode/DLL injection indicator |
| NET-001 | Network | Outbound connections to suspicious ports |
| NET-002 | Network | Port-scan behaviour (many distinct remote ports in a short window) |
| NET-003 | Network | Connection-count bursts |
| NET-004 | Network | Tor circuit / untrusted-process external connections |
| FILE-001 | File | Double-extension files (e.g. `report.pdf.exe`) |
| FILE-002 | File | Hidden executables in untrusted directories |
| FILE-003 | File | Known malicious file hashes (SHA-256, extendable via `iocs.json`) |
| FILE-004 | File | Suspicious PE import table entries (injection, keylogging, ransomware APIs, etc.) |
| FILE-005 | File | YARA rule matches against process executables and untrusted-directory files |
| PERS-001 | Persistence | Suspicious entries in Windows startup registry keys |
| PERS-002 | Persistence | Scheduled tasks with untrusted or missing executables |

## YARA Rules

FILE-005 scans running process executables and files under the configured untrusted
directories against compiled [YARA](https://virustotal.github.io/yara/) rules using
[dnYara](https://github.com/airbus-cert/dnYara). On startup the scanner compiles every
`.yar`/`.yara` file found in the `YaraRulesPath` directory (default: `YaraRules/`,
shipped with a baseline `malware_indicators.yar` set covering Mimikatz, Cobalt Strike,
ransomware notes, encoded PowerShell, process-hollowing API combos, etc.).

Drop additional `.yar`/`.yara` files into that folder to extend coverage, then use
**Reload Rules** from the main menu to recompile without restarting. Each matched rule
becomes a `FILE-005` alert; severity and alert
type are read from the rule's `meta.severity` (`Low`/`Medium`/`High`) and `meta.type`
(`MAL`/`TROJ`/`BACK`/`RECON`/`RANSOM`/`INFO`), defaulting to `Medium`/`MAL` when omitted:

```yara
rule Example_Indicator
{
    meta:
        severity = "High"
        type = "TROJ"
    strings:
        $s1 = "evil string"
    condition:
        $s1
}
```

## Alerts

Alerts are deduplicated and written to `alerts.log` (one JSON object per line) in the working directory. They also appear inline in the terminal as they fire during live monitoring.

Severity levels: `HIGH` · `MEDIUM` · `LOW`

**Deduplication:** repeated alerts for the same rule + path are suppressed for 1 hour, then re-raised if the condition is still occurring — a single past detection doesn't silence that exact finding forever.

**Signature-based suppression:** when an alert carries an `ExecutablePath`, a valid Authenticode signature on that file auto-whitelists the path (suppressing it going forward); an unsigned or invalid signature escalates a `MEDIUM` alert to `HIGH`. Two rules are exempt from this entirely — **PROC-001** (System Process Masquerading) and **FILE-003** (Known Malware Hash) — because their finding *is* the verdict: a valid (or stolen-but-valid) certificate doesn't excuse a system process running from the wrong path, or a file matching a known-malicious hash. Alerts from those two rules are never suppressed by the whitelist and never added to it.

## Configuration

On first run, a `config.json` is generated with default values. Edit it to customise trusted process names, execution paths, and per-rule enable/disable, thresholds, and severity overrides.

```json
{
  "TrustedSystemProcesses": ["svchost.exe", "explorer.exe", ...],
  "TrustedExecutionPaths":  ["C:\\Windows\\System32", ...],
  "UntrustedExecutionPaths": ["Downloads", "Temp", ...],
  "YaraRulesPath": "YaraRules",
  "Rules": {
    "FILE-001": { "Enabled": false },
    "NET-003":  { "Enabled": true, "Threshold": 200, "Severity": "Medium" }
  }
}
```

`Rules` entries are keyed by the specific **leaf** rule ID shown in the [Detection Rules](#detection-rules) table (`FILE-001`, `PROC-002`, `NET-003`, …) — not the rule's display name. Each entry supports:

- `Enabled` — set to `false` to drop that finding entirely (it's filtered out before reaching the alert log or display).
- `Severity` — overrides the alert's severity (`Low`/`Medium`/`High`) regardless of what the rule itself assigned.
- `Threshold` — only consulted by `NET-003` (connection-count burst threshold); ignored by every other rule.

A few rules (`FileScannerRule` → `FILE-001`/`FILE-002`, `SuspiciousExecutionRule` → `PROC-002`/`PROC-003`, `SuspiciousNetworkActivityRule` → `NET-001`..`NET-004`) implement more than one rule ID internally — `Enabled`/`Severity` still apply per leaf ID as shown above, it's just that disabling every leaf ID under one of these doesn't skip that rule's scan work, only its output.
