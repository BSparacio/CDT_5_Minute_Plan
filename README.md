# CDT_5_Minute_Plan

A PowerShell hardening script for Windows Server 2019 SMB servers competing in an **Attack/Defense (A/D) Capture the Flag (CTF)** environment. All controls are derived from the **CIS Microsoft Windows Server 2019 Benchmark v4.0.0** and are applied directly through Windows Registry writes, making the script reliable, repeatable, and free of WMI session-state issues.

---

## Overview

`HardenSMB.ps1` applies 14 sections of layered security controls to a Windows Server 2019 SMB server. It targets the most commonly exploited SMB attack surfaces in CTF environments including EternalBlue, NTLM relay, credential dumping via Mimikatz, anonymous null session enumeration, and red team pre-baked persistence mechanisms.

All hardening changes are written directly to the Windows Registry rather than through WMI-backed cmdlets such as `Set-SmbServerConfiguration`. This design choice ensures the script is **idempotent** — running it once produces the same system state as running it ten times — and avoids the `Data of this type is not supported` WMI session degradation that occurs when those cmdlets are called repeatedly in the same PowerShell session.

At the end of every run, the script produces a **dynamic summary** that reports only what actually occurred during that execution. No section is marked as passed unless its registry writes or system calls actually succeeded.

---

## Hard Constraints

These two constraints are built into every decision the script makes and are verified at the end of every run:

| Constraint | Reason |
|---|---|
| **Port 445 must remain open** | The grey team scoring system connects over port 445 to verify uptime. Blocking it causes immediate scoring loss. |
| **The GREYTEAM account must not be modified** | The grey team uses this account for authenticated SMB access during uptime checks. Any change to it will break scoring. |

---

## Requirements

| Requirement | Details |
|---|---|
| **Operating System** | Windows Server 2019 |
| **PowerShell Version** | 5.1 or later (included by default) |
| **Privileges** | Must be run as Administrator — the script enforces this with `#Requires -RunAsAdministrator` and exits immediately if the check fails |
| **Execution Policy** | Must permit running local `.ps1` files (see [Running the Script](#running-the-script)) |
| **Git** | Required only if cloning from GitHub — optional if transferring the file manually |

---

## Getting the Script

### Clone from GitHub

On any machine with Git installed, open a terminal and run:

```bash
git clone https://github.com/BSparacio/CDT_5_Minute_Plan.git
```

To pull updates during the competition:

```bash
cd ctf-blueteam-tools
git pull
```

## Running the Script

### Step 1 — Open an elevated PowerShell window

Right-click the PowerShell icon and select **Run as Administrator**, or run the following from any elevated prompt:

### Step 2 — Set execution policy (if needed)

If the system blocks `.ps1` execution, adjust the policy for the current session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Step 3 — Navigate to the script and run it

```powershell
cd C:\Scripts
.\HardenSMB.ps1
```

### Optional — Capture output to a log file

To save the full terminal output while still seeing it on screen:

```powershell
.\HardenSMB.ps1 | Tee-Object -FilePath C:\Scripts\harden_log.txt
```

---

## What the Script Does

### Helper Functions and Result Tracking

The script defines six internal helper functions used throughout every section:

| Function | Purpose |
|---|---|
| `Write-Banner` | Prints a cyan section header to the terminal |
| `Write-Step` | Prints a yellow step description |
| `Write-Success` | Prints a green `[+]` line and optionally registers a PASS result |
| `Write-Warn` | Prints a magenta `[!]` line and optionally registers a WARN result |
| `Write-Fail` | Prints a red `[X]` line and optionally registers a FAIL result |
| `Write-Info` | Prints a gray `[-]` informational line (not tracked) |

The central result tracking mechanism is `$script:Results`, a generic `List[PSCustomObject]` that persists for the lifetime of the script. Every major hardening step registers its outcome here via `Add-Result`, which accepts a `Section`, `Description`, `Status` (`PASS`, `WARN`, `FAIL`, or `SKIP`), and a `Detail` string. The dynamic summary at the end reads exclusively from this list.

The `Set-RegValue` helper is used by almost every section. It wraps a registry write, creates the key path if it does not exist, and calls `Write-Success` or `Write-Fail` based on the result. It targets the registry directly rather than going through WMI, which is the reason the script remains stable across repeated runs.

```powershell
function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "DWord", [string]$Description = "")
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Success "$Description"
    } catch {
        Write-Fail "Could not set $Name at $Path - $_"
    }
}
```

---

### Pre-Flight Checks

Before applying any changes the script performs three checks:

1. **Administrator verification** — Uses the Windows principal identity API to confirm elevation. Exits with a non-zero code immediately if not running as Administrator.

2. **GREYTEAM account check** — Calls `Get-LocalUser -Name "GREYTEAM"`. If found, registers a PASS and documents the account's enabled state. If not found, registers a WARN noting it may be a domain account. The account is never modified in either case.

3. **SMB baseline snapshot** — Reads the current state of SMBv1, SMBv2, packet signing, and encryption directly from `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` and prints it before any changes are made. Also prints all current SMB shares via `Get-SmbShare` and any active sessions via `Get-SmbSession`.

---

### Section 1 — Disable SMBv1

> **CIS:** 18.4.2, 18.4.3 | **Threat:** EternalBlue (MS17-010 / CVE-2017-0144)

SMBv1 enables unauthenticated remote code execution. This section disables it using three independent methods so that undoing any single one does not re-enable the protocol:

| Method | Registry / Command |
|---|---|
| Server-side disable | `HKLM:\...\LanmanServer\Parameters` → `SMB1 = 0` |
| Client driver disable | `HKLM:\...\Services\mrxsmb10` → `Start = 4` (Disabled) |
| Windows Feature removal | `Disable-WindowsOptionalFeature -FeatureName "SMB1Protocol"` |

Immediately after, `SMB2 = 1` is explicitly written to the LanmanServer Parameters key to guarantee SMBv2 and SMBv3 remain enabled for scoring traffic.

---

### Section 2 — SMB Packet Signing

> **CIS:** 2.3.8.1, 2.3.8.2, 2.3.9.2, 2.3.9.3 | **Threat:** NTLM Relay (CVE-2025-55234, CVE-2025-33073, CVE-2025-58726)

SMB packet signing cryptographically binds each packet to its session. Without it, an attacker on the same network can intercept an NTLM authentication and relay it to a different server to authenticate as the victim. This section enables and requires signing on both the server and client sides:

| Key | Value | Effect |
|---|---|---|
| `LanmanServer\Parameters\RequireSecuritySignature` | `1` | Server requires all clients to sign |
| `LanmanServer\Parameters\EnableSecuritySignature` | `1` | Server will sign if client requests it |
| `LanmanWorkstation\Parameters\RequireSecuritySignature` | `1` | Client requires all servers to sign |
| `LanmanWorkstation\Parameters\EnableSecuritySignature` | `1` | Client will sign if server requests it |
| `LanmanWorkstation\Parameters\EnablePlainTextPassword` | `0` | Blocks cleartext credential transmission |

---

### Section 3 — NTLM Hardening

> **CIS:** 2.3.11.1, 2.3.11.2, 2.3.11.5, 2.3.11.7, 2.3.11.9, 2.3.11.10, 2.3.11.11, 2.3.11.13

LM and NTLMv1 hashes are trivially crackable. This section enforces NTLMv2 across all authentication and prevents LM hashes from ever being stored:

| Registry Value | Setting | Meaning |
|---|---|---|
| `Lsa\LmCompatibilityLevel` | `5` | Send NTLMv2 only — refuse LM and NTLMv1 |
| `Lsa\NoLMHash` | `1` | Do not store LAN Manager hash in SAM |
| `Lsa\MSV1_0\NTLMMinClientSec` | `537395200` | Require NTLMv2 + 128-bit encryption (client) |
| `Lsa\MSV1_0\NTLMMinServerSec` | `537395200` | Require NTLMv2 + 128-bit encryption (server) |
| `Lsa\UseMachineId` | `1` | Use computer identity for NTLM (not null) |
| `Lsa\MSV1_0\AllowNullSessionFallback` | `0` | Disable NULL session fallback |
| `Lsa\MSV1_0\AuditReceivingNTLMTraffic` | `2` | Audit all incoming NTLM traffic |
| `Lsa\MSV1_0\RestrictSendingNTLMTraffic` | `1` | Audit all outgoing NTLM traffic |

---

### Section 4 — Anonymous Access Lockdown

> **CIS:** 2.3.10.1, 2.3.10.2, 2.3.10.3, 2.3.10.5, 2.3.10.7, 2.3.10.10, 2.3.10.12

Null session enumeration lets unauthenticated attackers list users, shares, and group memberships without credentials. Port 445 remains open — only unauthenticated connections are blocked:

| Registry Value | Setting | Meaning |
|---|---|---|
| `Lsa\TurnOffAnonymousBlock` | `0` | Block anonymous SID/Name translation |
| `Lsa\RestrictAnonymousSAM` | `1` | No anonymous SAM account enumeration |
| `Lsa\RestrictAnonymous` | `1` | No anonymous share/SAM enumeration |
| `Lsa\EveryoneIncludesAnonymous` | `0` | Everyone group excludes anonymous users |
| `LanmanServer\Parameters\RestrictNullSessAccess` | `1` | Block anonymous named pipe and share access |
| `LanmanServer\Parameters\NullSessionShares` | `""` | No shares accessible anonymously |
| `LanmanServer\Parameters\NullSessionPipes` | `""` | No named pipes accessible anonymously |

---

### Section 5 — Credential Protection

> **CIS:** 18.4.1, 18.4.6, 18.4.8 | **Threat:** Mimikatz, Pass-the-Hash

Because the red team had pre-competition access to the system, credential theft tools are likely already present. This section directly counters them:

**WDigest Disable** — Sets `UseLogonCredential = 0` under the WDigest key. WDigest caches plaintext credentials in memory when enabled. Disabling it means `sekurlsa::wdigest` in Mimikatz returns nothing.

**LSA Protection (RunAsPPL)** — Sets `RunAsPPL = 1` and `RunAsPPLBoot = 1` under `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`. This elevates LSASS to a Protected Process Light, blocking code injection and credential dumping. **A reboot is required to fully activate this control.** The summary reports it as WARN as a reminder.

**UAC Network Logon Restriction** — Sets `LocalAccountTokenFilterPolicy = 0` to enforce UAC token filtering on local accounts authenticating over the network, blocking pass-the-hash attacks using local administrator credentials.

**WDigest Security Provider Cleanup** — Removes `wdigest` from the `SecurityProviders` string in the registry as a secondary enforcement measure.

---

### Section 6 — Anti-Relay: Disable LLMNR and NetBIOS

> **CIS:** 18.4.7, 18.5.2, 18.5.3, 18.5.4, 18.5.6 | **Threat:** Responder, NTLM Relay

LLMNR and NetBIOS broadcasts are the primary mechanism tools like Responder use to intercept NTLM authentication. When DNS resolution fails, Windows broadcasts over these protocols. Responder responds, captures the NTLM exchange, and relays it elsewhere. This section removes those broadcasts entirely:

| Change | Registry Key / Value |
|---|---|
| Disable LLMNR | `HKLM:\SOFTWARE\Policies\...\DNSClient\EnableMulticast = 0` |
| Set NetBT to P-node (no broadcast) | `NetBT\Parameters\NodeType = 2` |
| Prevent NetBIOS name hijacking | `NetBT\Parameters\NoNameReleaseOnDemand = 1` |
| Disable IPv4 source routing | `Tcpip\Parameters\DisableIPSourceRouting = 2` |
| Disable IPv6 source routing | `Tcpip6\Parameters\DisableIPSourceRouting = 2` |
| Disable ICMP redirect override | `Tcpip\Parameters\EnableICMPRedirect = 0` |

---

### Section 7 — Account Lockout Policy

> **CIS:** 1.2.1, 1.2.2, 1.2.4 | **Threat:** Credential brute-force

Configures lockout policy via the built-in `net accounts` command:

```
Threshold : 5 invalid attempts
Duration  : 30 minutes locked
Window    : 30 minutes observation period
```

This does not affect the GREYTEAM account during normal scoring — the counter only increments on a wrong password. A correct authentication attempt from the grey team scoring system never triggers it.

---

### Section 8 — Advanced Audit Policy

> **CIS:** Section 17 (17.1.1, 17.2.4–17.2.6, 17.3.1–17.3.2, 17.5.1, 17.5.4–17.5.6, 17.6.1–17.6.2, 17.6.4, 17.7.1–17.7.2, 17.8.1, 17.9.1, 17.9.3)

Enables 18 advanced audit policy subcategories using `auditpol`, giving real-time visibility into attacks through the Windows Security event log:

| Subcategory | Events Captured |
|---|---|
| Credential Validation | Success + Failure |
| Logon | Success + Failure |
| Account Lockout | Failure |
| Process Creation | Success |
| File Share | Success + Failure |
| Detailed File Share | Failure |
| Sensitive Privilege Use | Success + Failure |
| User Account Management | Success + Failure |
| Audit Policy Change | Success + Failure |
| System Integrity | Success + Failure |

Also enables the `Microsoft-Windows-SMBServer/Audit` event log via `wevtutil`, which fires:
- **Event ID 3021** — client connected without SMB signing (relay attempt indicator)
- **Event IDs 3024–3026** — client lacks Extended Protection for Authentication

---

### Section 9 — Firewall Hardening

> **CIS:** 9.1.x, 9.2.x, 9.3.x | **Note:** Port 445 is NOT blocked

Enables the Windows Firewall on all three profiles (Domain, Private, Public) and configures 16 MB log files for each recording both dropped and allowed connections.

Adds inbound block rules for common red team lateral movement ports:

| Rule | Port | Protocol | Reason |
|---|---|---|---|
| Block Telnet | 23 | TCP | Cleartext credential pivot tool |
| Block RPC | 135 | TCP | Lateral movement via RPC endpoint mapper |
| Block NetBIOS NS | 137 | UDP | NetBIOS name service — LLMNR/relay enabler |
| Block NetBIOS DGM | 138 | UDP | NetBIOS datagram — relay enabler |
| Block NetBIOS SSN | 139 | TCP | Legacy SMBv1 session service |
| Block WinRM HTTP | 5985 | TCP | Remote PowerShell execution |
| Block WinRM HTTPS | 5986 | TCP | Remote PowerShell execution |
| Block Meterpreter | 4444 | TCP | Common Metasploit default port |

Also adds an **outbound** block rule for port 443 to disrupt Cobalt Strike and similar C2 beacons that use HTTPS for callback traffic.

Rules that already exist are detected with `Get-NetFirewallRule` and skipped, preventing duplicate entries across repeated runs.

---

### Section 10 — Red Team Persistence Hunting

> **Note:** This section scans only — it does not auto-delete anything

Because the red team had pre-competition access, this section hunts for common persistence mechanisms and prints findings for manual review. Automatic deletion is intentionally avoided because removing an unknown entry could break grey team scoring mechanisms.

**What is scanned:**

| Target | Method |
|---|---|
| Scheduled tasks | `Get-ScheduledTask` — flags non-Microsoft tasks that are not Disabled |
| Non-standard services | `Get-WmiObject Win32_Service` — flags services outside Windows/Microsoft/Program Files paths |
| Autorun registry keys | `Run` and `RunOnce` keys under both HKLM and HKCU |
| Suspicious files | `.exe`, `.dll`, `.ps1`, `.bat`, `.vbs`, `.py`, `.rb`, `.sh` in `%TEMP%`, `%SystemRoot%\Temp`, `%ProgramData%`, and Startup folders |
| Suspicious named pipes | Compares active pipes against a whitelist of known Windows system pipes — unknown pipes may indicate C2 |

**Any findings require a manual decision** — review the output and determine whether each entry is legitimate before removing it.

---

### Section 11 — Disable High-Risk Services

Stops and disables five services that are commonly abused for lateral movement and credential theft and have no role on a dedicated SMB file server:

| Service | Name | Threat |
|---|---|---|
| Print Spooler | `Spooler` | PrinterBug / SpoolSample forces outbound NTLM auth coercion enabling relay attacks |
| WebDAV Client | `WebClient` | PetitPotam and related authentication coercion techniques |
| Remote Registry | `RemoteRegistry` | Allows remote registry reads — enables enumeration and tampering |
| Windows Remote Management | `WinRM` | Remote PowerShell execution channel for lateral movement |
| Telnet | `TlntSvr` | Transmits credentials in cleartext |

---

### Section 12 — Additional CIS Hardening

> **CIS:** 2.3.9.1, 2.3.9.4, 2.3.9.5, 2.3.13.1, 18.4.4, 18.4.5, 18.5.1, 18.5.8, 18.10.8.2, 18.10.8.3

Applies a collection of independent controls:

| Control | Registry Key | Value | Reason |
|---|---|---|---|
| Certificate Padding | `Cryptography\Wintrust\Config\EnableCertPaddingCheck` | `1` | Prevents hash collision attacks on signatures |
| SEHOP | `Session Manager\kernel\DisableExceptionChainValidation` | `0` | Blocks SEH overwrite exploit technique |
| Disable Auto Logon | `Winlogon\AutoAdminLogon` | `0` | Prevents automatic administrator login |
| Disable AutoPlay | `Policies\Explorer\NoDriveTypeAutoRun` | `255` | Blocks autoplay on all drive types |
| Disable AutoRun | `Policies\Explorer\NoAutorun` | `1` | Prevents autorun.inf execution |
| Disable logon-screen shutdown | `Policies\System\ShutdownWithoutLogon` | `0` | Requires login to shut down |
| SMB idle timeout | `LanmanServer\Parameters\AutoDisconnect` | `15` | Disconnects idle SMB sessions after 15 minutes |
| Forced logoff on expiry | `LanmanServer\Parameters\EnableForcedLogoff` | `1` | Disconnects clients when logon hours expire |
| SPN validation | `LanmanServer\Parameters\SmbServerNameHardeningLevel` | `1` | Mitigates Ghost SPN / CVE-2025-58726 Kerberos relay |
| Safe DLL Search Mode | `Session Manager\SafeDllSearchMode` | `1` | Prevents DLL hijacking via search order |

---

### Section 13 — GREYTEAM Access Verification

After all hardening is applied, this section performs a final safety check to confirm scoring will continue to function:

1. Re-checks the GREYTEAM account with `Get-LocalUser -Name "GREYTEAM"` and registers the result
2. Prints all current SMB shares with `Get-SmbShare` to confirm none were accidentally removed
3. Reads `LanmanServer\Parameters\SMB2` from the registry to confirm SMBv2 is still enabled
4. Runs `netstat -an` to confirm port 445 is actively listening
5. Reads `RequireSecuritySignature` to confirm signing is still in the required state

Each of these checks feeds into the dynamic summary so the operator can see at a glance whether the scoring-critical components are intact.

---

### Section 14 — Dynamic Summary

Reads the `$script:Results` list populated throughout the run and prints a formatted report grouped by section. Each entry shows its actual recorded status:

```
  [SMBv1]
    [+] SMBv1 server disabled
        LanmanServer SMB1 registry key set to 0
    [+] SMBv1 client driver disabled
        mrxsmb10 Start value set to 4 (Disabled)
    [!] SMBv1 Windows Feature disabled
        Feature was enabled and has been disabled - reboot recommended

  [Credentials]
    [+] WDigest disabled (anti-Mimikatz)
        UseLogonCredential=0 - cleartext passwords will not be cached in memory
    [!] LSA Protection (RunAsPPL) enabled
        Registry set to RunAsPPL=1 - requires reboot to fully activate

----------------------------------------------------------------------
  PASSED:  12    WARNED:   3    FAILED:   0    SKIPPED:   0
----------------------------------------------------------------------

======================================================================
  SCORING SAFETY CHECK
  [+] Port 445 / SMBv2: CONFIRMED OPEN
  [!] GREYTEAM account: Not found as local user - may be domain account
======================================================================
```

No section is reported as PASS unless it actually succeeded. The summary accurately reflects the real state of the system.

---

## Terminal Output Key

| Symbol | Color | Meaning |
|---|---|---|
| `[*]` | Yellow | A step is starting |
| `[+]` | Green | A change succeeded or a check passed |
| `[!]` | Magenta | A warning — requires attention but not a failure |
| `[-]` | Gray | Informational message — not tracked |
| `[X]` | Red | A change failed |

---

## Dynamic Summary Example

```
======================================================================
  HARDENING COMPLETE - DYNAMIC SUMMARY
======================================================================

  [Pre-Flight]
    [+] GREYTEAM account present
        Not found as local user - may be domain account, verify manually

  [SMBv1]
    [+] SMBv1 server disabled
        LanmanServer SMB1 registry key set to 0
    [+] SMBv1 client driver disabled
        mrxsmb10 Start value set to 4 (Disabled)
    [+] SMBv1 Windows Feature disabled
        Feature was already in disabled state

  [SMB Signing]
    [+] SMB packet signing required (server and client)
        RequireSecuritySignature=1 and EnableSecuritySignature=1 on LanmanServer and LanmanWorkstation

  [NTLM Hardening]
    [+] NTLMv2-only authentication enforced
        LmCompatibilityLevel=5, NTLMv2+128-bit required, LM hash storage disabled

  [Credentials]
    [+] WDigest disabled (anti-Mimikatz)
        UseLogonCredential=0 - cleartext passwords will not be cached in memory
    [!] LSA Protection (RunAsPPL) enabled
        Registry set to RunAsPPL=1 and RunAsPPLBoot=1 - requires reboot to fully activate

  [Services]
    [+] High-risk services disabled
        Disabled=5 (Print Spooler, WinRM, RemoteRegistry, WebClient, Telnet)

  [Verification]
    [+] SMBv2 active for scoring
        Registry SMB2 key confirms enabled - port 445 scoring traffic will work
    [+] GREYTEAM account untouched
        Account exists, Enabled=True

----------------------------------------------------------------------
  PASSED:  11    WARNED:   2    FAILED:   0    SKIPPED:   0
----------------------------------------------------------------------

======================================================================
  SCORING SAFETY CHECK
  [+] Port 445 / SMBv2: CONFIRMED OPEN
  [+] GREYTEAM account: Account exists, Enabled=True
======================================================================

Script completed at 2026-04-08 09:14:32
```

---

## Monitoring Commands

Run these in a separate elevated PowerShell window during the competition:

```powershell
# Who is connected over SMB right now
Get-SmbSession | Format-Table ClientComputerName, ClientUserName, NumOpens

# What files are open over SMB
Get-SmbOpenFile | Format-Table ClientComputerName, ClientUserName, Path

# Recent failed logon attempts (brute-force indicator)
Get-WinEvent -LogName Security -MaxEvents 50 |
    Where-Object { $_.Id -eq 4625 } |
    Select-Object TimeCreated, Message | Format-List

# Recent successful network logons
Get-WinEvent -LogName Security -MaxEvents 20 |
    Where-Object { $_.Id -eq 4624 } |
    Select-Object TimeCreated, Message | Format-List

# SMB signing violation events (relay attempt indicator — Event ID 3021)
Get-WinEvent -LogName "Microsoft-Windows-SMBServer/Audit" -MaxEvents 20

# Check for unexpected new services
Get-WmiObject Win32_Service |
    Where-Object { $_.PathName -notlike "*Windows*" } |
    Select-Object Name, State, PathName

# Kill a suspicious SMB session — DO NOT use on GREYTEAM
Get-SmbSession |
    Where-Object { $_.ClientUserName -eq "suspicioususer" } |
    Close-SmbSession
```

---

## Registry Keys Reference

All changes made by this script. Every key is under `HKEY_LOCAL_MACHINE` (`HKLM`).

| Registry Path | Value Name | Set To | Section |
|---|---|---|---|
| `...\LanmanServer\Parameters` | `SMB1` | `0` | §1 |
| `...\Services\mrxsmb10` | `Start` | `4` | §1 |
| `...\LanmanServer\Parameters` | `SMB2` | `1` | §1 |
| `...\LanmanServer\Parameters` | `RequireSecuritySignature` | `1` | §2 |
| `...\LanmanServer\Parameters` | `EnableSecuritySignature` | `1` | §2 |
| `...\LanmanWorkstation\Parameters` | `RequireSecuritySignature` | `1` | §2 |
| `...\LanmanWorkstation\Parameters` | `EnableSecuritySignature` | `1` | §2 |
| `...\LanmanWorkstation\Parameters` | `EnablePlainTextPassword` | `0` | §2 |
| `...\Control\Lsa` | `LmCompatibilityLevel` | `5` | §3 |
| `...\Control\Lsa` | `NoLMHash` | `1` | §3 |
| `...\Control\Lsa\MSV1_0` | `NTLMMinClientSec` | `537395200` | §3 |
| `...\Control\Lsa\MSV1_0` | `NTLMMinServerSec` | `537395200` | §3 |
| `...\Control\Lsa` | `UseMachineId` | `1` | §3 |
| `...\Control\Lsa\MSV1_0` | `AllowNullSessionFallback` | `0` | §3 |
| `...\Control\Lsa\MSV1_0` | `AuditReceivingNTLMTraffic` | `2` | §3 |
| `...\Control\Lsa\MSV1_0` | `RestrictSendingNTLMTraffic` | `1` | §3 |
| `...\Control\Lsa` | `TurnOffAnonymousBlock` | `0` | §4 |
| `...\Control\Lsa` | `RestrictAnonymousSAM` | `1` | §4 |
| `...\Control\Lsa` | `RestrictAnonymous` | `1` | §4 |
| `...\Control\Lsa` | `EveryoneIncludesAnonymous` | `0` | §4 |
| `...\LanmanServer\Parameters` | `RestrictNullSessAccess` | `1` | §4 |
| `...\LanmanServer\Parameters` | `NullSessionShares` | `""` | §4 |
| `...\LanmanServer\Parameters` | `NullSessionPipes` | `""` | §4 |
| `...\SecurityProviders\WDigest` | `UseLogonCredential` | `0` | §5 |
| `...\Control\Lsa` | `RunAsPPL` | `1` | §5 |
| `...\Control\Lsa` | `RunAsPPLBoot` | `1` | §5 |
| `...\Policies\System` | `LocalAccountTokenFilterPolicy` | `0` | §5 |
| `...\Policies\...\DNSClient` | `EnableMulticast` | `0` | §6 |
| `...\Services\NetBT\Parameters` | `NoNameReleaseOnDemand` | `1` | §6 |
| `...\Services\NetBT\Parameters` | `NodeType` | `2` | §6 |
| `...\Services\Tcpip\Parameters` | `DisableIPSourceRouting` | `2` | §6 |
| `...\Services\Tcpip6\Parameters` | `DisableIPSourceRouting` | `2` | §6 |
| `...\Services\Tcpip\Parameters` | `EnableICMPRedirect` | `0` | §6 |
| `...\Control\Lsa` | `SCENoApplyLegacyAuditPolicy` | `1` | §8 |
| `...\LanmanServer\Parameters` | `AuditSmb1Access` | `1` | §8 |
| `...\Cryptography\Wintrust\Config` | `EnableCertPaddingCheck` | `1` | §12 |
| `...\Session Manager\kernel` | `DisableExceptionChainValidation` | `0` | §12 |
| `...\NT\CurrentVersion\Winlogon` | `AutoAdminLogon` | `0` | §12 |
| `...\Policies\Explorer` | `NoDriveTypeAutoRun` | `255` | §12 |
| `...\Policies\Explorer` | `NoAutorun` | `1` | §12 |
| `...\Policies\System` | `ShutdownWithoutLogon` | `0` | §12 |
| `...\LanmanServer\Parameters` | `AutoDisconnect` | `15` | §12 |
| `...\LanmanServer\Parameters` | `EnableForcedLogoff` | `1` | §12 |
| `...\LanmanServer\Parameters` | `SmbServerNameHardeningLevel` | `1` | §12 |
| `...\Session Manager` | `SafeDllSearchMode` | `1` | §12 |

---

## Important Warnings

> **Do not block port 445.** The script intentionally omits any inbound block rule for port 445. Adding one will prevent the grey team scoring system from connecting and will immediately cost uptime points.

> **Do not modify the GREYTEAM account.** Do not change its password, disable it, rename it, or delete it. The grey team uses it for authenticated SMB access during uptime verification.

> **LSA Protection requires a reboot.** The `RunAsPPL` registry value is set during the run, but the protection does not take effect until the system reboots. The summary reports this as WARN to remind you. If possible, reboot the VM before the competition begins.

> **Section 10 findings require manual review.** The persistence hunting section prints suspicious scheduled tasks, services, autorun keys, files, and named pipes but does not delete anything automatically. Review each finding and decide whether it is legitimate or malicious before removing it. Automatic deletion risks removing something the grey team scoring system depends on.

> **The script is idempotent.** Re-running it at any point during the competition is safe. All writes go to the same registry keys with the same values. If the red team has undone any of your hardening, re-running the script will restore it.

---

*Based on CIS Microsoft Windows Server 2019 Benchmark v4.0.0 — Built for A/D CTF Blue Team Defense*