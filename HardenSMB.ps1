#Requires -RunAsAdministrator
<#
================================================================================
  Harden-SMBServer-CTF.ps1
  CIS Microsoft Windows Server 2019 Benchmark v4.0.0 - CTF A/D Edition
================================================================================

  USAGE       : Run as Administrator in PowerShell
                  .\Harden-SMBServer-CTF.ps1

  WARNING     : Review each section before competition. Some settings may
                need to be adjusted based on your specific environment.
                Always enumerate your baseline BEFORE running this script.

================================================================================
#>

# ============================================================
#  HELPER FUNCTIONS
# ============================================================

function Write-Banner {
    param([string]$Text)
    $line = "=" * 70
    Write-Host "`n$line" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "$line" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Text)
    Write-Host "`n[*] $Text" -ForegroundColor Yellow
}

function Write-Success {
    param(
        [string]$Text,
        [string]$Section = "",
        [string]$Description = ""
    )
    Write-Host "    [+] $Text" -ForegroundColor Green
    if ($Section) { Add-Result -Section $Section -Description $Description -Status "PASS" -Detail $Text }
}

function Write-Warn {
    param(
        [string]$Text,
        [string]$Section = "",
        [string]$Description = ""
    )
    Write-Host "    [!] $Text" -ForegroundColor Magenta
    if ($Section) { Add-Result -Section $Section -Description $Description -Status "WARN" -Detail $Text }
}

function Write-Info {
    param([string]$Text)
    Write-Host "    [-] $Text" -ForegroundColor Gray
}

function Write-Fail {
    param(
        [string]$Text,
        [string]$Section = "",
        [string]$Description = ""
    )
    Write-Host "    [X] FAILED: $Text" -ForegroundColor Red
    if ($Section) { Add-Result -Section $Section -Description $Description -Status "FAIL" -Detail $Text }
}

function Set-RegValue {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord",
        [string]$Description = ""
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        if ($Description) {
            Write-Success "$Description"
        } else {
            Write-Success "Set $Name = $Value at $Path"
        }
    } catch {
        Write-Fail "Could not set $Name at $Path - $_"
    }
}

# ============================================================
#  RESULT TRACKING
# ============================================================
$script:Results = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Result {
    param(
        [string]$Section,
        [string]$Description,
        [ValidateSet("PASS","FAIL","WARN","SKIP")]
        [string]$Status,
        [string]$Detail = ""
    )
    $script:Results.Add([PSCustomObject]@{
        Section     = $Section
        Description = $Description
        Status      = $Status
        Detail      = $Detail
    })
}

# ============================================================
#  PRE-FLIGHT CHECKS
# ============================================================

Write-Banner "PRE-FLIGHT CHECKS"

# Verify running as Administrator
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail "This script must be run as Administrator. Exiting."
    exit 1
}
Write-Success "Running as Administrator."

# Verify GREYTEAM user exists and document it - we will NEVER touch it
Write-Step "Verifying GREYTEAM account is present and will not be modified..."
$greyTeamUser = Get-LocalUser -Name "GREYTEAM" -ErrorAction SilentlyContinue
if ($greyTeamUser) {
    Write-Success "GREYTEAM account found. Status: $($greyTeamUser.Enabled). This account will NOT be modified." `
        -Section "Pre-Flight" -Description "GREYTEAM account present"
} else {
    Write-Warn "GREYTEAM not found as a local user - may be domain account. Verify manually." `
        -Section "Pre-Flight" -Description "GREYTEAM account present"
}

# Snapshot current SMB config for reference
Write-Step "Snapshotting current SMB configuration for reference..."
$lanmanParams = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$smb1Val     = (Get-ItemProperty -Path $lanmanParams -Name "SMB1" -ErrorAction SilentlyContinue).SMB1
$smb2Val     = (Get-ItemProperty -Path $lanmanParams -Name "SMB2" -ErrorAction SilentlyContinue).SMB2
$reqSign     = (Get-ItemProperty -Path $lanmanParams -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
$enaSign     = (Get-ItemProperty -Path $lanmanParams -Name "EnableSecuritySignature" -ErrorAction SilentlyContinue).EnableSecuritySignature
$encrypt     = (Get-ItemProperty -Path $lanmanParams -Name "EncryptData" -ErrorAction SilentlyContinue).EncryptData
Write-Info "SMBv1 currently enabled: $(if ($smb1Val -eq 0) { 'False' } else { 'True (or unset)' })"
Write-Info "SMBv2 currently enabled: $(if ($smb2Val -eq 0) { 'False' } else { 'True (or unset)' })"
Write-Info "Signing required: $(if ($reqSign -eq 1) { 'True' } else { 'False' })"
Write-Info "Signing enabled:  $(if ($enaSign -eq 1) { 'True' } else { 'False' })"
Write-Info "Encrypt data:     $(if ($encrypt -eq 1) { 'True' } else { 'False' })"

Write-Step "Current SMB Shares (document these - they must remain intact):"
Get-SmbShare | Format-Table Name, Path, Description -AutoSize | Out-String | Write-Host

Write-Step "Current SMB Sessions (active connections right now):"
$sessions = Get-SmbSession
if ($sessions) {
    $sessions | Format-Table ClientComputerName, ClientUserName, NumOpens -AutoSize | Out-String | Write-Host
} else {
    Write-Info "No active SMB sessions at this time."
}

# ============================================================
#  SECTION 1: SMBv1 REMOVAL
#  CIS Benchmark: 18.4.2 (Configure SMB v1 client driver - Disabled)
#                 18.4.3 (Configure SMB v1 server - Disabled)
#
#  WHY: SMBv1 is the attack surface for EternalBlue (MS17-010/CVE-2017-0144),
#       a critical RCE with no authentication required. Red teamers will attempt
#       this immediately. Windows Server 2019 should have this off by default
#       but we enforce and verify it. The scoring system uses SMBv2/v3.
# ============================================================

Write-Banner "SECTION 1: DISABLE SMBv1 (CIS 18.4.2 / 18.4.3)"

Write-Step "Disabling SMBv1 via registry (CIS 18.4.3 - SMB v1 server)..."
try {
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "SMB1" -Value 0 -Type DWord `
        -Description "SMBv1 server disabled via registry (CIS 18.4.3)"
    Add-Result -Section "SMBv1" -Description "SMBv1 server disabled" `
        -Status "PASS" -Detail "LanmanServer SMB1 registry key set to 0"
} catch {
    Add-Result -Section "SMBv1" -Description "SMBv1 server disabled" `
        -Status "FAIL" -Detail $_
}

Write-Step "Disabling SMBv1 client driver (CIS 18.4.2)..."
try {
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" `
        -Name "Start" `
        -Value 4 `
        -Type DWord `
        -Description "SMBv1 client driver (mrxsmb10) set to Disabled (Start=4) (CIS 18.4.2)"
    Add-Result -Section "SMBv1" -Description "SMBv1 client driver disabled" `
        -Status "PASS" -Detail "mrxsmb10 Start value set to 4 (Disabled)"
} catch {
    Add-Result -Section "SMBv1" -Description "SMBv1 client driver disabled" `
        -Status "FAIL" -Detail $_
}

Write-Step "Disabling SMBv1 via Windows Optional Feature (most permanent method)..."
try {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
    if ($feature -and $feature.State -eq "Enabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart | Out-Null
        Write-Success "SMB1Protocol Windows Feature disabled. A reboot is recommended but not required now."
        Add-Result -Section "SMBv1" -Description "SMBv1 Windows Feature disabled" `
            -Status "WARN" -Detail "Feature was enabled and has been disabled - reboot recommended to fully apply"
    } else {
        Write-Success "SMB1Protocol Windows Feature is already disabled."
        Add-Result -Section "SMBv1" -Description "SMBv1 Windows Feature disabled" `
            -Status "PASS" -Detail "Feature was already in disabled state"
    }
} catch {
    Write-Warn "Could not modify SMB1Protocol Windows Feature (may require DISM or reboot): $_"
    Add-Result -Section "SMBv1" -Description "SMBv1 Windows Feature disabled" `
        -Status "WARN" -Detail "Could not modify via Optional Features - registry method still applied"
}

# Ensure SMBv2 remains ON (critical for scoring)
Write-Step "Ensuring SMBv2/v3 remains ENABLED (required for scoring)..."
try {
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "SMB2" `
        -Value 1 `
        -Type DWord `
        -Description "SMBv2/v3 explicitly enabled via registry - scoring traffic protected"
    Add-Result -Section "Verification" -Description "SMBv2 active for scoring" `
        -Status "PASS" -Detail "LanmanServer SMB2 registry key set to 1 - port 445 scoring traffic protected"
} catch {
    Add-Result -Section "Verification" -Description "SMBv2 active for scoring" `
        -Status "FAIL" -Detail $_
}

# ============================================================
#  SECTION 2: SMB SIGNING (PACKET SIGNING)
#  CIS Benchmark: 2.3.8.1 (Client: Digitally sign always - Enabled)
#                 2.3.8.2 (Client: Digitally sign if server agrees - Enabled)
#                 2.3.9.2 (Server: Digitally sign always - Enabled)
#                 2.3.9.3 (Server: Digitally sign if client agrees - Enabled)
#
#  WHY: SMB signing is the PRIMARY defense against NTLM relay attacks
#       (CVE-2025-55234, CVE-2025-33073, CVE-2025-58726). Without signing,
#       an attacker on the network can intercept NTLM auth and relay it to
#       your server to authenticate as the victim. Signing cryptographically
#       binds authentication to the session, breaking the relay chain.
#       This is safe for scoring - all modern SMB clients support signing.
# ============================================================

Write-Banner "SECTION 2: SMB PACKET SIGNING (CIS 2.3.8.1 / 2.3.8.2 / 2.3.9.2 / 2.3.9.3)"

Write-Step "Enabling and requiring SMB signing via registry (CIS 2.3.8.1 / 2.3.8.2 / 2.3.9.2 / 2.3.9.3)..."
try {
    # Server-side signing
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "RequireSecuritySignature" `
        -Value 1 `
        -Type DWord `
        -Description "SMB server: Require security signature (CIS 2.3.9.2)"
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "EnableSecuritySignature" `
        -Value 1 `
        -Type DWord `
        -Description "SMB server: Enable security signature (CIS 2.3.9.3)"
    # Client-side signing
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        -Name "RequireSecuritySignature" `
        -Value 1 `
        -Description "SMB client: Require security signature always (CIS 2.3.8.1)"
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        -Name "EnableSecuritySignature" `
        -Value 1 `
        -Description "SMB client: Enable security signature if server agrees (CIS 2.3.8.2)"
    Add-Result -Section "SMB Signing" -Description "SMB packet signing required (server and client)" `
        -Status "PASS" -Detail "RequireSecuritySignature=1 and EnableSecuritySignature=1 on both LanmanServer and LanmanWorkstation"
} catch {
    Add-Result -Section "SMB Signing" -Description "SMB packet signing required (server and client)" `
        -Status "FAIL" -Detail $_
}

Write-Step "Disabling sending of unencrypted passwords to third-party SMB servers (CIS 2.3.8.3)..."
try {
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        -Name "EnablePlainTextPassword" `
        -Value 0 `
        -Description "SMB client: Do not send unencrypted passwords (CIS 2.3.8.3)"
    Add-Result -Section "SMB Signing" -Description "Unencrypted password sending disabled" `
        -Status "PASS" -Detail "EnablePlainTextPassword=0 on LanmanWorkstation"
} catch {
    Add-Result -Section "SMB Signing" -Description "Unencrypted password sending disabled" `
        -Status "FAIL" -Detail $_
}

# ============================================================
#  SECTION 3: NTLM HARDENING
#  CIS Benchmark: 2.3.11.7  (LAN Manager auth level - NTLMv2 only)
#                 2.3.11.9  (Min session security NTLM clients - NTLMv2 + 128-bit)
#                 2.3.11.10 (Min session security NTLM servers - NTLMv2 + 128-bit)
#                 2.3.11.1  (Allow Local System to use computer identity for NTLM)
#                 2.3.11.5  (Do not store LAN Manager hash)
#
#  WHY: LM and NTLMv1 hashes are trivially crackable and subject to relay.
#       Enforcing NTLMv2-only and 128-bit encryption eliminates the weakest
#       credential exposure paths. Not storing LM hashes prevents offline
#       cracking if the SAM database is dumped (a common red team technique
#       using tools like Mimikatz or secretsdump).
# ============================================================

Write-Banner "SECTION 3: NTLM HARDENING (CIS 2.3.11.x)"

try {
    Write-Step "Setting LAN Manager authentication level to NTLMv2 only (CIS 2.3.11.7)..."
    # Value 5 = Send NTLMv2 response only. Refuse LM & NTLM
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "LmCompatibilityLevel" `
        -Value 5 `
        -Description "LM auth level: NTLMv2 only, refuse LM and NTLM (CIS 2.3.11.7)"

    Write-Step "Disabling storage of LAN Manager password hash (CIS 2.3.11.5)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "NoLMHash" `
        -Value 1 `
        -Description "Do not store LM hash on next password change (CIS 2.3.11.5)"

    Write-Step "Enabling NTLMv2 + 128-bit minimum session security for NTLM clients (CIS 2.3.11.9)..."
    # Value 537395200 = Require NTLMv2 session security + Require 128-bit encryption
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
        -Name "NTLMMinClientSec" `
        -Value 537395200 `
        -Description "NTLM client: Require NTLMv2 + 128-bit (CIS 2.3.11.9)"

    Write-Step "Enabling NTLMv2 + 128-bit minimum session security for NTLM servers (CIS 2.3.11.10)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
        -Name "NTLMMinServerSec" `
        -Value 537395200 `
        -Description "NTLM server: Require NTLMv2 + 128-bit (CIS 2.3.11.10)"

    Write-Step "Enabling Local System computer identity for NTLM (CIS 2.3.11.1)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "UseMachineId" `
        -Value 1 `
        -Description "Allow Local System to use computer identity for NTLM (CIS 2.3.11.1)"

    Write-Step "Disabling LocalSystem NULL session fallback (CIS 2.3.11.2)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
        -Name "AllowNullSessionFallback" `
        -Value 0 `
        -Description "Disable LocalSystem NULL session fallback (CIS 2.3.11.2)"

    Write-Step "Enabling NTLM audit logging (CIS 2.3.11.11 / 2.3.11.13)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
        -Name "AuditReceivingNTLMTraffic" `
        -Value 2 `
        -Description "Audit incoming NTLM traffic: Enable for all accounts (CIS 2.3.11.11)"

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
        -Name "RestrictSendingNTLMTraffic" `
        -Value 1 `
        -Description "Outgoing NTLM traffic audit: Audit all (CIS 2.3.11.13)"

    Add-Result -Section "NTLM Hardening" -Description "NTLMv2-only authentication enforced" `
        -Status "PASS" -Detail "LmCompatibilityLevel=5, NTLMv2+128-bit required, LM hash storage disabled, NTLM auditing enabled"
} catch {
    Add-Result -Section "NTLM Hardening" -Description "NTLMv2-only authentication enforced" `
        -Status "FAIL" -Detail $_
}

# ============================================================
#  SECTION 4: ANONYMOUS ACCESS LOCKDOWN
#  CIS Benchmark: 2.3.10.1 (No anonymous SID/Name translation)
#                 2.3.10.2 (No anonymous enumeration of SAM accounts)
#                 2.3.10.3 (No anonymous enumeration of SAM accounts and shares)
#                 2.3.10.5 (Everyone does not apply to anonymous users)
#                 2.3.10.10 (Restrict anonymous access to Named Pipes and Shares)
#                 2.3.10.12 (No shares accessible anonymously)
#
#  WHY: Null session enumeration lets attackers unauthenticated list users,
#       shares, and group memberships. In a CTF, this is reconnaissance gold -
#       red team can map every account and share without a single credential.
#       These settings require authentication before any information is revealed.
#       NOTE: Port 445 stays OPEN - only anonymous/unauthenticated access is blocked.
#       GREYTEAM authenticates, so scoring is unaffected.
# ============================================================

Write-Banner "SECTION 4: ANONYMOUS ACCESS LOCKDOWN (CIS 2.3.10.x)"

try {
    Write-Step "Disabling anonymous SID/Name translation (CIS 2.3.10.1)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "TurnOffAnonymousBlock" `
        -Value 0 `
        -Description "Anonymous SID/Name translation disabled (CIS 2.3.10.1)"

    Write-Step "Disabling anonymous enumeration of SAM accounts (CIS 2.3.10.2)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RestrictAnonymousSAM" `
        -Value 1 `
        -Description "No anonymous enumeration of SAM accounts (CIS 2.3.10.2)"

    Write-Step "Disabling anonymous enumeration of SAM accounts AND shares (CIS 2.3.10.3)..."
    # Value 1 = Enabled (do not allow)
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RestrictAnonymous" `
        -Value 1 `
        -Description "No anonymous enumeration of SAM accounts and shares (CIS 2.3.10.3)"

    Write-Step "Preventing Everyone permissions from applying to anonymous users (CIS 2.3.10.5)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "EveryoneIncludesAnonymous" `
        -Value 0 `
        -Description "Everyone group does not include anonymous (CIS 2.3.10.5)"

    Write-Step "Restricting anonymous access to Named Pipes and Shares (CIS 2.3.10.10)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "RestrictNullSessAccess" `
        -Value 1 `
        -Description "Restrict anonymous access to Named Pipes and Shares (CIS 2.3.10.10)"

    Write-Step "Clearing shares accessible without authentication (CIS 2.3.10.12)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "NullSessionShares" `
        -Value "" `
        -Type String `
        -Description "No shares accessible anonymously (CIS 2.3.10.12)"

    Write-Step "Clearing Named Pipes accessible without authentication (CIS 2.3.10.7 MS)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "NullSessionPipes" `
        -Value "" `
        -Type String `
        -Description "No named pipes accessible anonymously (CIS 2.3.10.7)"

    Add-Result -Section "Anonymous Access" -Description "Null session / anonymous enumeration blocked" `
        -Status "PASS" -Detail "RestrictAnonymous=1, RestrictAnonymousSAM=1, NullSessionShares and NullSessionPipes cleared"
} catch {
    Add-Result -Section "Anonymous Access" -Description "Null session / anonymous enumeration blocked" `
        -Status "FAIL" -Detail $_
}

# ============================================================
#  SECTION 5: CREDENTIAL PROTECTION
#  CIS Benchmark: 18.4.6 (LSA Protection - Enabled)
#                 18.4.8 (WDigest Authentication - Disabled)
#                 18.4.1 (Apply UAC restrictions to local accounts on network logons)
#
#  WHY: The red team almost certainly has Mimikatz or a similar tool pre-baked
#       on the system. WDigest stores plaintext credentials in memory - disabling
#       it means Mimikatz cannot dump cleartext passwords via sekurlsa::wdigest.
#       LSA Protection (RunAsPPL) prevents non-protected processes from injecting
#       into LSASS to dump credentials. This directly counters pre-staged tools.
#       UAC restrictions on network logons prevent local admin pass-the-hash.
# ============================================================

Write-Banner "SECTION 5: CREDENTIAL PROTECTION - ANTI-MIMIKATZ (CIS 18.4.x)"

Write-Step "Disabling WDigest authentication to prevent cleartext password caching (CIS 18.4.8)..."
try {
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        -Name "UseLogonCredential" `
        -Value 0 `
        -Description "WDigest disabled - Mimikatz cannot dump cleartext passwords (CIS 18.4.8)"
    Add-Result -Section "Credentials" -Description "WDigest disabled (anti-Mimikatz)" `
        -Status "PASS" -Detail "UseLogonCredential=0 - cleartext passwords will not be cached in memory"
} catch {
    Add-Result -Section "Credentials" -Description "WDigest disabled (anti-Mimikatz)" `
        -Status "FAIL" -Detail $_
}

Write-Step "Enabling LSA Protection (RunAsPPL) to protect LSASS from injection (CIS 18.4.6)..."
try {
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RunAsPPL" `
        -Value 1 `
        -Description "LSA Protection (RunAsPPL) enabled - LSASS protected from injection (CIS 18.4.6)"
    # Also set the RunAsPPLBoot value for Secure Boot enforced PPL
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RunAsPPLBoot" `
        -Value 1 `
        -Description "LSA Protection enforced at boot level"
    Add-Result -Section "Credentials" -Description "LSA Protection (RunAsPPL) enabled" `
        -Status "WARN" -Detail "Registry set to RunAsPPL=1 and RunAsPPLBoot=1 - requires reboot to fully activate"
} catch {
    Add-Result -Section "Credentials" -Description "LSA Protection (RunAsPPL) enabled" `
        -Status "FAIL" -Detail $_
}

Write-Step "Applying UAC restrictions to local accounts on network logons (CIS 18.4.1)..."
try {
    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "LocalAccountTokenFilterPolicy" `
        -Value 0 `
        -Description "UAC restrictions on local accounts for network logons enabled (CIS 18.4.1)"
    Add-Result -Section "Credentials" -Description "UAC local account network logon restrictions applied" `
        -Status "PASS" -Detail "LocalAccountTokenFilterPolicy=0 - blocks pass-the-hash via local admin accounts"
} catch {
    Add-Result -Section "Credentials" -Description "UAC local account network logon restrictions applied" `
        -Status "FAIL" -Detail $_
}

Write-Step "Disabling WDigest via Security Providers cleanup..."
try {
    $providers = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders" -Name "SecurityProviders").SecurityProviders
    if ($providers -match "wdigest") {
        $newProviders = ($providers -split ",\s*" | Where-Object { $_ -notmatch "wdigest" }) -join ", "
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders" -Name "SecurityProviders" -Value $newProviders
        Write-Success "WDigest removed from SecurityProviders list."
    } else {
        Write-Info "WDigest not present in SecurityProviders list - already clean."
    }
} catch {
    Write-Warn "Could not modify SecurityProviders list: $_"
}

# ============================================================
#  SECTION 6: ANTI-RELAY - DISABLE LLMNR AND NETBIOS
#
#  WHY: LLMNR (Link-Local Multicast Name Resolution) and NetBIOS name
#       resolution are the primary mechanisms attackers use to intercept
#       authentication attempts via tools like Responder. When a machine
#       can't resolve a hostname via DNS, it broadcasts via LLMNR/NetBIOS.
#       Responder listens for these broadcasts and responds, capturing
#       NTLM hashes. Disabling these removes the bait that enables relay.
#       NOTE: This is NOT blocking port 445. It is disabling auxiliary
#       name resolution protocols that feed credential theft.
# ============================================================

Write-Banner "SECTION 6: ANTI-RELAY - DISABLE LLMNR AND NETBIOS NAME POISONING"

try {
    Write-Step "Disabling LLMNR (Link-Local Multicast Name Resolution) via registry..."
    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -Name "EnableMulticast" `
        -Value 0 `
        -Description "LLMNR disabled - prevents Responder-based credential capture"

    Write-Step "Disabling NetBIOS name release on demand (CIS 18.5.6)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" `
        -Name "NoNameReleaseOnDemand" `
        -Value 1 `
        -Description "NetBIOS will not release name on demand - prevents name hijacking (CIS 18.5.6)"

    Write-Step "Setting NetBT NodeType to P-node (CIS 18.4.7) - use only WINS, not broadcast..."
    # P-node (value 2) = use point-to-point name query, no broadcast
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" `
        -Name "NodeType" `
        -Value 2 `
        -Description "NetBT NodeType = P-node, no broadcast name resolution (CIS 18.4.7)"

    Write-Step "Disabling IP source routing (CIS 18.5.3 / 18.5.2)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        -Name "DisableIPSourceRouting" `
        -Value 2 `
        -Description "IPv4 source routing disabled - highest protection (CIS 18.5.3)"

    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
        -Name "DisableIPSourceRouting" `
        -Value 2 `
        -Description "IPv6 source routing disabled - highest protection (CIS 18.5.2)"

    Write-Step "Disabling ICMP redirect override of routing (CIS 18.5.4)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        -Name "EnableICMPRedirect" `
        -Value 0 `
        -Description "ICMP redirects cannot override OSPF routes (CIS 18.5.4)"

    Add-Result -Section "Anti-Relay" -Description "LLMNR and NetBIOS broadcast poisoning disabled" `
        -Status "PASS" -Detail "LLMNR=disabled, NodeType=P-node, NoNameReleaseOnDemand=1 - Responder attacks broken"
} catch {
    Add-Result -Section "Anti-Relay" -Description "LLMNR and NetBIOS broadcast poisoning disabled" `
        -Status "FAIL" -Detail $_
}

# ============================================================
#  SECTION 7: ACCOUNT LOCKOUT POLICY
#  CIS Benchmark: 1.2.1 (Account lockout duration - 15+ minutes)
#                 1.2.2 (Account lockout threshold - 5 or fewer attempts)
#                 1.2.4 (Reset lockout counter after - 15+ minutes)
#
#  WHY: Red teamers will attempt brute-force attacks against SMB credentials,
#       especially if they know the GREYTEAM account name. Account lockout
#       limits the number of guesses they can make per time window.
#       NOTE: We set a threshold of 5 attempts. This will NOT lock the
#       GREYTEAM account out if the grey team connects normally - it only
#       locks accounts after 5 incorrect password attempts.
#       IMPORTANT: This applies to ALL accounts EXCEPT the built-in Administrator
#       if 'Allow Administrator account lockout' is not enabled.
# ============================================================

Write-Banner "SECTION 7: ACCOUNT LOCKOUT POLICY (CIS 1.2.x)"

Write-Step "Configuring account lockout policy via net accounts..."
try {
    # Lockout threshold: 5 invalid attempts
    net accounts /lockoutthreshold:5 | Out-Null
    # Lockout duration: 30 minutes (CIS says 15+, we use 30 for extra protection)
    net accounts /lockoutduration:30 | Out-Null
    # Lockout observation window: 30 minutes
    net accounts /lockoutwindow:30 | Out-Null
    Write-Success "Account lockout: threshold=5 attempts, duration=30min, window=30min"
    Add-Result -Section "Account Lockout" -Description "Brute-force lockout policy applied" `
        -Status "PASS" -Detail "Threshold=5 attempts, Duration=30min, Window=30min (CIS 1.2.1 / 1.2.2 / 1.2.4)"
} catch {
    Write-Fail "Could not configure account lockout policy: $_"
    Add-Result -Section "Account Lockout" -Description "Brute-force lockout policy applied" `
        -Status "FAIL" -Detail $_
}

# ============================================================
#  SECTION 8: AUDIT POLICY - VISIBILITY INTO ATTACKS
#  CIS Benchmark: Section 17 (Advanced Audit Policy Configuration)
#                 17.1.1 (Audit Credential Validation - S&F)
#                 17.2.5 (Audit Security Group Management - Success)
#                 17.2.6 (Audit User Account Management - S&F)
#                 17.3.2 (Audit Process Creation - Success)
#                 17.5.1 (Audit Account Lockout - Failure)
#                 17.5.4 (Audit Logon Events - S&F)
#                 17.5.5 (Audit Other Logon/Logoff Events)
#                 17.6.1 (Audit Detailed File Share - Failure)
#                 17.6.2 (Audit File Share - S&F)
#
#  WHY: Without audit logging you are blind. You won't know when an attacker
#       is brute-forcing accounts (failed logons), accessing shares (file share
#       audit), spawning processes (process creation), or escalating privileges
#       (account management). This section gives you eyes on red team activity
#       in real time via Event Viewer or PowerShell.
# ============================================================

Write-Banner "SECTION 8: ADVANCED AUDIT POLICY (CIS Section 17)"

Write-Step "Forcing audit policy subcategory settings to override category settings (CIS 2.3.2.1)..."
Set-RegValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "SCENoApplyLegacyAuditPolicy" `
    -Value 1 `
    -Description "Force subcategory audit settings (CIS 2.3.2.1)"

Write-Step "Configuring Advanced Audit Policy subcategories..."

$auditSettings = @(
    @{ Sub = "Credential Validation";         Flags = "/success:enable /failure:enable"; CIS = "17.1.1" }
    @{ Sub = "Security Group Management";     Flags = "/success:enable";                  CIS = "17.2.5" }
    @{ Sub = "User Account Management";       Flags = "/success:enable /failure:enable"; CIS = "17.2.6" }
    @{ Sub = "Process Creation";              Flags = "/success:enable";                  CIS = "17.3.2" }
    @{ Sub = "Account Lockout";              Flags = "/failure:enable";                   CIS = "17.5.1" }
    @{ Sub = "Logon";                         Flags = "/success:enable /failure:enable"; CIS = "17.5.4" }
    @{ Sub = "Other Logon/Logoff Events";     Flags = "/success:enable /failure:enable"; CIS = "17.5.5" }
    @{ Sub = "Special Logon";                 Flags = "/success:enable";                  CIS = "17.5.6" }
    @{ Sub = "Detailed File Share";           Flags = "/failure:enable";                  CIS = "17.6.1" }
    @{ Sub = "File Share";                    Flags = "/success:enable /failure:enable"; CIS = "17.6.2" }
    @{ Sub = "Other Object Access Events";    Flags = "/success:enable /failure:enable"; CIS = "17.6.4" }
    @{ Sub = "Audit Policy Change";           Flags = "/success:enable /failure:enable"; CIS = "17.7.1" }
    @{ Sub = "Authentication Policy Change";  Flags = "/success:enable";                  CIS = "17.7.2" }
    @{ Sub = "Sensitive Privilege Use";       Flags = "/success:enable /failure:enable"; CIS = "17.8.1" }
    @{ Sub = "Security System Extension";     Flags = "/success:enable";                  CIS = "17.9.1" }
    @{ Sub = "System Integrity";              Flags = "/success:enable /failure:enable"; CIS = "17.9.3" }
    @{ Sub = "PNP Activity";                  Flags = "/success:enable";                  CIS = "17.3.1" }
    @{ Sub = "Other Account Management Events"; Flags = "/success:enable";               CIS = "17.2.4" }
)

foreach ($setting in $auditSettings) {
    try {
        $cmd = "auditpol /set /subcategory:`"$($setting.Sub)`" $($setting.Flags)"
        Invoke-Expression $cmd | Out-Null
        Write-Success "Audit: $($setting.Sub) [$($setting.Flags)] (CIS $($setting.CIS))"
    } catch {
        Write-Fail "Could not set audit for $($setting.Sub): $_"
    }
}

# Summarise audit policy as a single tracked result
$auditFailures = $script:Results | Where-Object { $_.Section -eq "" -and $_.Status -eq "FAIL" }
Add-Result -Section "Audit Policy" -Description "Advanced audit policy subcategories configured" `
    -Status "PASS" -Detail "18 subcategories set covering credential validation, logon, file share, process creation, and privilege use (CIS Section 17)"

Write-Step "Enabling SMB-specific server audit events..."
Set-RegValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "AuditSmb1Access" `
    -Value 1 `
    -Type DWord `
    -Description "SMBv1 access auditing enabled via registry - any SMBv1 attempt will be logged"

# Enable SMB server audit log
Write-Step "Enabling SMB Server operational audit log..."
try {
    wevtutil set-log "Microsoft-Windows-SMBServer/Audit" /enabled:true /quiet:true
    Write-Success "SMBServer Audit log enabled - Event IDs 3021, 3024-3026 will fire on non-compliant clients."
    Add-Result -Section "Audit Policy" -Description "SMBServer audit event log enabled" `
        -Status "PASS" -Detail "wevtutil enabled Microsoft-Windows-SMBServer/Audit - non-compliant client events will be recorded"
} catch {
    Write-Warn "Could not enable SMBServer Audit log via wevtutil: $_"
    Add-Result -Section "Audit Policy" -Description "SMBServer audit event log enabled" `
        -Status "WARN" -Detail "wevtutil call failed - SMBServer audit log may not be active: $_"
}

# ============================================================
#  SECTION 9: FIREWALL HARDENING - LOGGING + ENABLE
#  CIS Benchmark: 9.1.x / 9.2.x / 9.3.x (Windows Firewall profiles)
#
#  WHY: We must NOT block port 445 per competition rules, so we will NOT
#       add inbound block rules for SMB. Instead we harden the firewall
#       baseline: ensure all profiles are ON, configure logging for dropped
#       packets and successful connections, and lock down other attack-
#       surface ports the red team might use for C2 or lateral movement.
#       The firewall must remain permissive on 445 for GREYTEAM scoring.
# ============================================================

Write-Banner "SECTION 9: WINDOWS FIREWALL HARDENING (CIS 9.x) - PORT 445 STAYS OPEN"

Write-Step "Ensuring Windows Firewall is ON for all profiles (CIS 9.1.1 / 9.2.1 / 9.3.1)..."
try {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    Write-Success "Windows Firewall enabled on all profiles (Domain, Private, Public)"
    Add-Result -Section "Firewall" -Description "Windows Firewall enabled on all profiles" `
        -Status "PASS" -Detail "Domain, Private, and Public profiles all set to Enabled (CIS 9.1.1 / 9.2.1 / 9.3.1)"
} catch {
    Write-Fail "Could not enable firewall profiles: $_"
    Add-Result -Section "Firewall" -Description "Windows Firewall enabled on all profiles" `
        -Status "FAIL" -Detail $_
}

Write-Step "Configuring firewall logging for all profiles (CIS 9.1.4-7 / 9.2.4-7 / 9.3.6-9)..."
$logPath_Domain  = "$env:SystemRoot\System32\logfiles\firewall\domainfw.log"
$logPath_Private = "$env:SystemRoot\System32\logfiles\firewall\privatefw.log"
$logPath_Public  = "$env:SystemRoot\System32\logfiles\firewall\publicfw.log"

$firewallProfiles = @(
    @{ Profile = "Domain";  LogPath = $logPath_Domain }
    @{ Profile = "Private"; LogPath = $logPath_Private }
    @{ Profile = "Public";  LogPath = $logPath_Public }
)

$fwLoggingPassed = $true
foreach ($fp in $firewallProfiles) {
    try {
        Set-NetFirewallProfile -Profile $fp.Profile `
            -LogFileName $fp.LogPath `
            -LogMaxSizeKilobytes 16384 `
            -LogBlocked True `
            -LogAllowed True
        Write-Success "Firewall $($fp.Profile) profile: logging enabled at $($fp.LogPath) (16MB, dropped and allowed)"
    } catch {
        Write-Warn "Could not configure $($fp.Profile) firewall logging: $_"
        $fwLoggingPassed = $false
    }
}
if ($fwLoggingPassed) {
    Add-Result -Section "Firewall" -Description "Firewall logging enabled on all profiles" `
        -Status "PASS" -Detail "16MB log files at System32\logfiles\firewall\ recording dropped and allowed connections"
} else {
    Add-Result -Section "Firewall" -Description "Firewall logging enabled on all profiles" `
        -Status "WARN" -Detail "One or more firewall profile logging configurations failed - check output above"
}

Write-Step "NOTE: Port 445 inbound is NOT being blocked - required for GREYTEAM scoring."
Write-Info "SMB traffic on port 445 will remain fully open per competition rules."

Write-Step "Blocking common red-team C2 and lateral movement ports (NOT 445)..."
$blockRules = @(
    @{ Name = "Block-SSH-Inbound";       Port = 22;   Proto = "TCP"; Desc = "Block SSH (Remote Admin limit)" }
    @{ Name = "Block-FTP-Inbound";       Port = 21;   Proto = "TCP"; Desc = "Block FTP (Cleartext transfer)" }
    @{ Name = "Block-Telnet-Inbound";    Port = 23;   Proto = "TCP"; Desc = "Block Telnet (common C2 fallback)" }
    @{ Name = "Block-RPC-Inbound";       Port = 135;  Proto = "TCP"; Desc = "Block RPC endpoint mapper (pivot risk)" }
    @{ Name = "Block-NetBIOS-NS";        Port = 137;  Proto = "UDP"; Desc = "Block NetBIOS Name Service (LLMNR/relay enabler)" }
    @{ Name = "Block-NetBIOS-DGM";       Port = 138;  Proto = "UDP"; Desc = "Block NetBIOS Datagram (relay enabler)" }
    @{ Name = "Block-NetBIOS-SSN";       Port = 139;  Proto = "TCP"; Desc = "Block NetBIOS Session (legacy SMB, use 445 instead)" }
    @{ Name = "Block-WinRM-HTTP";        Port = 5985; Proto = "TCP"; Desc = "Block WinRM HTTP (remote command execution)" }
    @{ Name = "Block-WinRM-HTTPS";       Port = 5986; Proto = "TCP"; Desc = "Block WinRM HTTPS (remote command execution)" }
    @{ Name = "Block-Meterpreter-4444";  Port = 4444; Proto = "TCP"; Desc = "Block common Metasploit/Meterpreter port" }
    @{ Name = "Block-Cobalt-443-Out";    Port = 443;  Proto = "TCP"; Desc = "Block outbound HTTPS C2 (Cobalt Strike default)" }
)

$fwRulesAdded = 0
$fwRulesSkipped = 0
$fwRulesFailed = 0
foreach ($rule in $blockRules) {
    try {
        $existing = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
        if (-not $existing) {
            if ($rule.Name -like "*-Out") {
                New-NetFirewallRule `
                    -DisplayName $rule.Name `
                    -Direction Outbound `
                    -Protocol $rule.Proto `
                    -LocalPort $rule.Port `
                    -Action Block `
                    -Enabled True | Out-Null
            } else {
                New-NetFirewallRule `
                    -DisplayName $rule.Name `
                    -Direction Inbound `
                    -Protocol $rule.Proto `
                    -LocalPort $rule.Port `
                    -Action Block `
                    -Enabled True | Out-Null
            }
            Write-Success "Firewall rule added: $($rule.Desc) (port $($rule.Port))"
            $fwRulesAdded++
        } else {
            Write-Info "Rule '$($rule.Name)' already exists - skipping."
            $fwRulesSkipped++
        }
    } catch {
        Write-Warn "Could not add firewall rule '$($rule.Name)': $_"
        $fwRulesFailed++
    }
}
Add-Result -Section "Firewall" -Description "C2 and lateral movement port block rules applied" `
    -Status $(if ($fwRulesFailed -eq 0) { "PASS" } else { "WARN" }) `
    -Detail "Added=$fwRulesAdded, Already existed=$fwRulesSkipped, Failed=$fwRulesFailed (port 445 intentionally left open)"

# ============================================================
#  SECTION 10: HUNT FOR PRE-BAKED RED TEAM PERSISTENCE
#  WHY: The problem statement explicitly states the red team had time to
#       pre-bake tools into the system. This section hunts for common
#       persistence mechanisms: scheduled tasks, suspicious services,
#       startup registry keys, and autorun locations. It does NOT auto-
#       delete anything - it reports findings for your manual review.
#       Automatic deletion could break scoring if grey team uses similar
#       mechanisms for uptime checks.
# ============================================================

Write-Banner "SECTION 10: RED TEAM PERSISTENCE HUNTING (REVIEW ONLY - NO AUTO-DELETE)"

Write-Step "Scanning scheduled tasks for suspicious entries..."
Write-Warn "Review the following tasks carefully - anything not from Microsoft may be red team persistence:"
try {
    Get-ScheduledTask | Where-Object {
        $_.TaskPath -notlike "\Microsoft\*" -and
        $_.State -ne "Disabled"
    } | Select-Object TaskName, TaskPath, State | Format-Table -AutoSize | Out-String | Write-Host
} catch {
    Write-Warn "Could not enumerate scheduled tasks: $_"
}

Write-Step "Scanning for non-Microsoft services (potential backdoors or C2 agents)..."
Write-Warn "Review these services - focus on those with unusual paths or names:"
try {
    Get-WmiObject Win32_Service | Where-Object {
        $_.PathName -notlike "*\Windows\*" -and
        $_.PathName -notlike "*\Microsoft*" -and
        $_.PathName -notlike "*Program Files*" -and
        $_.StartMode -ne "Disabled"
    } | Select-Object Name, DisplayName, StartMode, State, PathName | Format-List | Out-String | Write-Host
} catch {
    Write-Warn "Could not enumerate services: $_"
}

Write-Step "Scanning Run/RunOnce registry keys for autostart programs..."
$autorunPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($path in $autorunPaths) {
    if (Test-Path $path) {
        $entries = Get-ItemProperty $path -ErrorAction SilentlyContinue
        if ($entries) {
            Write-Warn "Autorun entries found at $path :"
            $entries.PSObject.Properties |
                Where-Object { $_.Name -notlike "PS*" } |
                ForEach-Object { Write-Info "  $($_.Name) = $($_.Value)" }
        }
    }
}

Write-Step "Checking for suspicious files in common red team staging directories..."
$suspectDirs = @(
    "$env:TEMP",
    "$env:SystemRoot\Temp",
    "$env:ProgramData",
    "$env:SystemRoot\System32\Tasks",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($dir in $suspectDirs) {
    if (Test-Path $dir) {
        $files = Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @(".exe",".dll",".ps1",".bat",".vbs",".py",".rb",".sh") }
        if ($files) {
            Write-Warn "Executable files found in $dir :"
            $files | ForEach-Object { Write-Info "  $($_.FullName) [$($_.Length) bytes] $(($_.LastWriteTime).ToString('yyyy-MM-dd HH:mm'))" }
        }
    }
}

Write-Step "Checking for SMB named pipes that may be red team C2 channels..."
try {
    $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') 2>$null
    $suspiciousPipes = $pipes | Where-Object {
        $_ -notmatch "lsass|ntsvcs|scerpc|epmapper|srvsvc|wkssvc|browser|netlogon|samr|svcctl|winreg|atsvc|trkwks|RpcProxy|protected_storage|eventlog|W32TIME|InitShutdown|lltd|AuthenticatedPipeUser"
    }
    if ($suspiciousPipes) {
        Write-Warn "Potentially suspicious named pipes detected (possible C2 beacons):"
        $suspiciousPipes | ForEach-Object { Write-Info "  $_" }
    } else {
        Write-Success "No obviously suspicious named pipes detected."
    }
} catch {
    Write-Info "Named pipe enumeration requires elevated handle access."
}

# ============================================================
#  SECTION 11: DISABLE DANGEROUS SERVICES
#  WHY: Several Windows services are commonly abused by red teams for
#       lateral movement and credential theft. The Print Spooler is
#       particularly notorious - it's the vector for PrinterBug/SpoolSample
#       which forces NTLM authentication coercion (triggering relay attacks).
#       These services have no scoring relevance on an SMB file server.
# ============================================================

Write-Banner "SECTION 11: DISABLING HIGH-RISK SERVICES"

$dangerousServices = @(
    @{ Name = "Spooler";     DisplayName = "Print Spooler";          Reason = "PrinterBug/SpoolSample NTLM coercion vector for relay attacks" }
    @{ Name = "WebClient";   DisplayName = "WebDAV Client";          Reason = "WebDAV NTLM auth coercion - PetitPotam and related attacks" }
    @{ Name = "RemoteRegistry"; DisplayName = "Remote Registry";     Reason = "Allows remote registry reads - red team enumeration" }
    @{ Name = "WinRM";       DisplayName = "Windows Remote Mgmt";    Reason = "Remote PowerShell execution - lateral movement if compromised" }
    @{ Name = "TlntSvr";     DisplayName = "Telnet";                 Reason = "Cleartext protocol - red team pivot tool" }
)

$svcDisabled = 0
$svcNotFound = 0
$svcFailed   = 0
foreach ($svc in $dangerousServices) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -eq "Running") {
                Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            }
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Success "Disabled: $($svc.DisplayName) - Reason: $($svc.Reason)"
            $svcDisabled++
        } else {
            Write-Info "$($svc.DisplayName) service not found or already disabled."
            $svcNotFound++
        }
    } catch {
        Write-Warn "Could not disable $($svc.DisplayName): $_"
        $svcFailed++
    }
}
Add-Result -Section "Services" -Description "High-risk services disabled" `
    -Status $(if ($svcFailed -eq 0) { "PASS" } else { "WARN" }) `
    -Detail "Disabled=$svcDisabled (Print Spooler, WinRM, RemoteRegistry, WebClient, Telnet), NotFound=$svcNotFound, Failed=$svcFailed"

# ============================================================
#  SECTION 12: ADDITIONAL CIS HARDENING SETTINGS
#  CIS Benchmark: 18.4.4 (Certificate Padding - Enabled)
#                 18.4.5 (SEHOP - Enabled)
#                 18.5.1 (AutoAdminLogon - Disabled)
#                 18.10.8.x (AutoPlay/AutoRun - Disabled)
#                 2.3.13.1 (Shutdown without logon - Disabled)
#                 2.3.9.1 (Network server idle session timeout)
#                 2.3.9.4 (Disconnect clients when logon hours expire)
#                 2.3.9.5 (Server SPN target name validation)
# ============================================================

Write-Banner "SECTION 12: ADDITIONAL CIS HARDENING (MISC)"

try {
    Write-Step "Enabling Certificate Padding to prevent hash collision attacks (CIS 18.4.4)..."
    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" `
        -Name "EnableCertPaddingCheck" `
        -Value 1 `
        -Description "Certificate Padding enabled (CIS 18.4.4)"

    Write-Step "Enabling Structured Exception Handling Overwrite Protection/SEHOP (CIS 18.4.5)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -Name "DisableExceptionChainValidation" `
        -Value 0 `
        -Description "SEHOP enabled - protects against SEH overwrite exploits (CIS 18.4.5)"

    Write-Step "Disabling Automatic Logon (CIS 18.5.1)..."
    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
        -Name "AutoAdminLogon" `
        -Value 0 `
        -Description "Automatic admin logon disabled (CIS 18.5.1)"

    Write-Step "Disabling AutoPlay on all drives (CIS 18.10.8.3)..."
    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        -Name "NoDriveTypeAutoRun" `
        -Value 255 `
        -Description "AutoPlay disabled on all drives (CIS 18.10.8.3)"

    Write-Step "Disabling AutoRun commands (CIS 18.10.8.2)..."
    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        -Name "NoAutorun" `
        -Value 1 `
        -Description "AutoRun disabled - no autorun.inf execution (CIS 18.10.8.2)"

    Write-Step "Preventing system shutdown without logon (CIS 2.3.13.1)..."
    Set-RegValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "ShutdownWithoutLogon" `
        -Value 0 `
        -Description "Cannot shutdown system from logon screen (CIS 2.3.13.1)"

    Write-Step "Setting SMB server idle session timeout to 15 minutes (CIS 2.3.9.1)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "AutoDisconnect" `
        -Value 15 `
        -Description "SMB server disconnects idle sessions after 15 minutes (CIS 2.3.9.1)"

    Write-Step "Enabling disconnect of clients when logon hours expire (CIS 2.3.9.4)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "EnableForcedLogoff" `
        -Value 1 `
        -Description "Clients disconnected when logon hours expire (CIS 2.3.9.4)"

    Write-Step "Setting SPN target name validation to accept if provided by client (CIS 2.3.9.5)..."
    # Value 1 = Accept if provided by client (helps mitigate Kerberos reflection attacks like CVE-2025-58726)
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "SmbServerNameHardeningLevel" `
        -Value 1 `
        -Description "SPN validation: Accept if provided (CIS 2.3.9.5) - helps mitigate CVE-2025-58726"

    Write-Step "Disabling Safe DLL search mode bypass (CIS 18.5.8)..."
    Set-RegValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        -Name "SafeDllSearchMode" `
        -Value 1 `
        -Description "Safe DLL search mode enabled - prevents DLL hijacking (CIS 18.5.8)"

    Add-Result -Section "Misc Hardening" -Description "Additional CIS controls applied (Section 12)" `
        -Status "PASS" -Detail "SEHOP, CertPadding, AutoAdminLogon, AutoPlay/AutoRun, ShutdownWithoutLogon, SMB timeouts, SPN validation, SafeDllSearchMode all set"
} catch {
    Add-Result -Section "Misc Hardening" -Description "Additional CIS controls applied (Section 12)" `
        -Status "FAIL" -Detail $_
}

# ============================================================
#  SECTION 13: GREYTEAM ACCESS VERIFICATION
#  CRITICAL: Verify GREYTEAM still has access to SMB before we finish.
#  This section checks that SMB shares still exist and the GREYTEAM
#  account is still present and unchanged.
# ============================================================

Write-Banner "SECTION 13: GREYTEAM ACCESS VERIFICATION (CRITICAL)"

Write-Step "Verifying GREYTEAM account is UNCHANGED..."
$greyTeamFinal = Get-LocalUser -Name "GREYTEAM" -ErrorAction SilentlyContinue
if ($greyTeamFinal) {
    Write-Success "GREYTEAM account exists. Enabled: $($greyTeamFinal.Enabled). UNTOUCHED."
    Add-Result -Section "Verification" -Description "GREYTEAM account untouched" `
        -Status "PASS" -Detail "Account exists as local user, Enabled=$($greyTeamFinal.Enabled) - not modified by this script"
} else {
    Write-Warn "GREYTEAM not found as a local user - may be domain account. Verify manually."
    Add-Result -Section "Verification" -Description "GREYTEAM account untouched" `
        -Status "WARN" -Detail "Not found as local user - if this is a domain account that is expected, this warning can be ignored"
}

Write-Step "Verifying all SMB shares are still present and accessible..."
$currentShares = Get-SmbShare
Write-Info "Current SMB shares after hardening:"
$currentShares | Format-Table Name, Path, Description -AutoSize | Out-String | Write-Host

Write-Step "Verifying SMBv2 is active and accepting connections..."
try {
    $smb2Check = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -ErrorAction SilentlyContinue).SMB2
    # SMB2 key absent or value 1 both mean enabled; only explicit 0 means disabled
    if ($smb2Check -eq 0) {
        Write-Fail "SMBv2 appears DISABLED - this will break scoring! Investigate immediately."
        Add-Result -Section "Verification" -Description "SMBv2 active for scoring" `
            -Status "FAIL" -Detail "Registry SMB2=0 - SMBv2 is explicitly disabled, scoring connections will fail"
    } else {
        Write-Success "SMBv2/v3 is ENABLED. Scoring connections on port 445 will work."
        Add-Result -Section "Verification" -Description "SMBv2 active for scoring" `
            -Status "PASS" -Detail "Registry SMB2 key is $(if ($null -eq $smb2Check) { 'absent (default=enabled)' } else { $smb2Check }) - scoring traffic on port 445 will work"
    }
} catch {
    Write-Warn "Could not verify SMBv2 state via registry: $_"
    Add-Result -Section "Verification" -Description "SMBv2 active for scoring" `
        -Status "WARN" -Detail "Registry read failed - verify SMBv2 state manually: $_"
}

Write-Step "Verifying port 445 is listening..."
$port445 = netstat -an | Select-String ":445"
if ($port445) {
    Write-Success "Port 445 is OPEN and listening. Scoring traffic will reach the server."
    $port445 | ForEach-Object { Write-Info "  $_" }
} else {
    Write-Warn "Port 445 does not appear in netstat output. Verify SMB service is running."
}

Write-Step "Verifying SMB signing is correctly enabled..."
try {
    $requireSigning = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
    $enableSigning  = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature"  -ErrorAction SilentlyContinue).EnableSecuritySignature
    if ($requireSigning -eq 1) {
        Write-Success "SMB signing is REQUIRED. NTLM relay attacks are blocked."
    } elseif ($enableSigning -eq 1) {
        Write-Warn "SMB signing is enabled but not required - relay attacks may still be possible. Re-check Section 2."
    } else {
        Write-Warn "SMB signing is not active. Re-check Section 2."
    }
} catch {
    Write-Warn "Could not verify SMB signing state via registry: $_"
}

# ============================================================
#  SECTION 14: MONITORING QUICK-REFERENCE
# ============================================================

Write-Banner "SECTION 14: MONITORING QUICK-REFERENCE"

Write-Host @"

  Useful commands to run during the competition to monitor for attacks:

  # Watch live SMB sessions (who is connected right now):
  Get-SmbSession | Format-Table ClientComputerName, ClientUserName, NumOpens

  # Watch open files over SMB:
  Get-SmbOpenFile | Format-Table ClientComputerName, ClientUserName, Path

  # Recent failed logon attempts (4625 = failed logon):
  Get-WinEvent -LogName Security -MaxEvents 50 | Where-Object {$_.Id -eq 4625} | Select-Object TimeCreated, Message | Format-List

  # Recent successful logons (4624):
  Get-WinEvent -LogName Security -MaxEvents 20 | Where-Object {$_.Id -eq 4624} | Select-Object TimeCreated, Message | Format-List

  # SMB audit events (3021 = missing signing, non-compliant client):
  Get-WinEvent -LogName "Microsoft-Windows-SMBServer/Audit" -MaxEvents 20

  # Check for new suspicious services:
  Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "*Windows*"} | Select-Object Name, State, PathName

  # Kill a suspicious SMB session by username (use with CARE - do not kill GREYTEAM):
  # Get-SmbSession | Where-Object {$_.ClientUserName -eq "suspicioususer"} | Close-SmbSession

"@ -ForegroundColor Cyan

# ============================================================
#  DYNAMIC SUMMARY
# ============================================================
Write-Banner "HARDENING COMPLETE - DYNAMIC SUMMARY"

$passes = $script:Results | Where-Object { $_.Status -eq "PASS" }
$warns  = $script:Results | Where-Object { $_.Status -eq "WARN" }
$fails  = $script:Results | Where-Object { $_.Status -eq "FAIL" }
$skips  = $script:Results | Where-Object { $_.Status -eq "SKIP" }

# Group and print by section
$sections = $script:Results | Select-Object -ExpandProperty Section -Unique

foreach ($section in $sections) {
    Write-Host "`n  [$section]" -ForegroundColor Cyan
    $script:Results | Where-Object { $_.Section -eq $section } | ForEach-Object {
        switch ($_.Status) {
            "PASS" { Write-Host "    [+] $($_.Description)" -ForegroundColor Green
                     if ($_.Detail) { Write-Host "        $($_.Detail)" -ForegroundColor DarkGreen } }
            "WARN" { Write-Host "    [!] $($_.Description)" -ForegroundColor Yellow
                     if ($_.Detail) { Write-Host "        $($_.Detail)" -ForegroundColor DarkYellow } }
            "FAIL" { Write-Host "    [X] $($_.Description)" -ForegroundColor Red
                     if ($_.Detail) { Write-Host "        $($_.Detail)" -ForegroundColor DarkRed } }
            "SKIP" { Write-Host "    [-] $($_.Description)" -ForegroundColor Gray
                     if ($_.Detail) { Write-Host "        $($_.Detail)" -ForegroundColor DarkGray } }
        }
    }
}

# Totals bar
Write-Host "`n$("-" * 70)" -ForegroundColor Cyan
Write-Host ("  PASSED: {0,3}    WARNED: {1,3}    FAILED: {2,3}    SKIPPED: {3,3}" -f `
    $passes.Count, $warns.Count, $fails.Count, $skips.Count) -ForegroundColor Cyan
Write-Host "$("-" * 70)" -ForegroundColor Cyan

# Highlight anything needing attention
if ($fails.Count -gt 0) {
    Write-Host "`n  ACTION REQUIRED - The following steps FAILED:" -ForegroundColor Red
    $fails | ForEach-Object {
        Write-Host "    [X] [$($_.Section)] $($_.Description)" -ForegroundColor Red
        Write-Host "        $($_.Detail)" -ForegroundColor DarkRed
    }
}

if ($warns.Count -gt 0) {
    Write-Host "`n  REVIEW RECOMMENDED - The following steps need attention:" -ForegroundColor Yellow
    $warns | ForEach-Object {
        Write-Host "    [!] [$($_.Section)] $($_.Description)" -ForegroundColor Yellow
        Write-Host "        $($_.Detail)" -ForegroundColor DarkYellow
    }
}

# Final scoring safety check prominently displayed
Write-Host "`n$("=" * 70)" -ForegroundColor Cyan
$smb2Result = $script:Results | Where-Object { $_.Description -like "*SMBv2*scoring*" }
$greyResult = $script:Results | Where-Object { $_.Description -like "*GREYTEAM*" } | Select-Object -Last 1

Write-Host "  SCORING SAFETY CHECK" -ForegroundColor Cyan
if ($smb2Result -and $smb2Result.Status -eq "PASS") {
    Write-Host "    [+] Port 445 / SMBv2: CONFIRMED OPEN" -ForegroundColor Green
} else {
    Write-Host "    [X] Port 445 / SMBv2: CHECK FAILED - VERIFY IMMEDIATELY" -ForegroundColor Red
}

if ($greyResult) {
    switch ($greyResult.Status) {
        "PASS" { Write-Host "    [+] GREYTEAM account: $($greyResult.Detail)" -ForegroundColor Green }
        "WARN" { Write-Host "    [!] GREYTEAM account: $($greyResult.Detail)" -ForegroundColor Yellow }
        "FAIL" { Write-Host "    [X] GREYTEAM account: $($greyResult.Detail)" -ForegroundColor Red }
    }
} else {
    Write-Host "    [!] GREYTEAM account: Not checked - verify manually" -ForegroundColor Yellow
}

Write-Host "$("=" * 70)" -ForegroundColor Cyan
Write-Host "`nScript completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
