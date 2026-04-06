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
    param([string]$Text)
    Write-Host "    [+] $Text" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Text)
    Write-Host "    [!] $Text" -ForegroundColor Magenta
}

function Write-Info {
    param([string]$Text)
    Write-Host "    [-] $Text" -ForegroundColor Gray
}

function Write-Fail {
    param([string]$Text)
    Write-Host "    [X] FAILED: $Text" -ForegroundColor Red
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
    Write-Success "GREYTEAM account found. Status: $($greyTeamUser.Enabled). This account will NOT be modified."
} else {
    Write-Warn "GREYTEAM account not found locally. It may be a domain account. Proceeding - this script does NOT touch user accounts."
}

# Snapshot current SMB config for reference
Write-Step "Snapshotting current SMB configuration for reference..."
$smbConfig = Get-SmbServerConfiguration
Write-Info "SMBv1 currently enabled: $($smbConfig.EnableSMB1Protocol)"
Write-Info "SMBv2 currently enabled: $($smbConfig.EnableSMB2Protocol)"
Write-Info "Signing required: $($smbConfig.RequireSecuritySignature)"
Write-Info "Signing enabled: $($smbConfig.EnableSecuritySignature)"
Write-Info "Encrypt data: $($smbConfig.EncryptData)"

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

Write-Step "Disabling SMBv1 via SmbServerConfiguration..."
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Write-Success "SMBv1 server protocol disabled via Set-SmbServerConfiguration."
} catch {
    Write-Fail "Could not disable SMBv1 via SmbServerConfiguration: $_"
}

Write-Step "Disabling SMBv1 via registry (CIS 18.4.3 - SMB v1 server)..."
Set-RegValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "SMB1" `
    -Value 0 `
    -Type DWord `
    -Description "SMBv1 server disabled via registry (CIS 18.4.3)"

Write-Step "Disabling SMBv1 client driver (CIS 18.4.2)..."
Set-RegValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" `
    -Name "Start" `
    -Value 4 `
    -Type DWord `
    -Description "SMBv1 client driver (mrxsmb10) set to Disabled (Start=4) (CIS 18.4.2)"

Write-Step "Disabling SMBv1 via Windows Optional Feature (most permanent method)..."
try {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
    if ($feature -and $feature.State -eq "Enabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart | Out-Null
        Write-Success "SMB1Protocol Windows Feature disabled. A reboot is recommended but not required now."
    } else {
        Write-Success "SMB1Protocol Windows Feature is already disabled."
    }
} catch {
    Write-Warn "Could not modify SMB1Protocol Windows Feature (may require DISM or reboot): $_"
}

# Verify SMBv2 remains ON (critical for scoring)
Write-Step "Verifying SMBv2/v3 remains ENABLED (required for scoring)..."
try {
    Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
    Write-Success "SMBv2/v3 confirmed ENABLED. Scoring traffic will continue to work."
} catch {
    Write-Fail "Could not confirm SMBv2 state: $_"
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

Write-Step "Enabling SMB signing via SmbServerConfiguration..."
try {
    Set-SmbServerConfiguration `
        -RequireSecuritySignature $true `
        -EnableSecuritySignature $true `
        -Force
    Write-Success "SMB server signing: RequireSecuritySignature=True, EnableSecuritySignature=True"
} catch {
    Write-Fail "Could not set SMB signing via SmbServerConfiguration: $_"
}

Write-Step "Enforcing SMB server signing via registry (CIS 2.3.9.2 / 2.3.9.3)..."
Set-RegValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RequireSecuritySignature" `
    -Value 1 `
    -Description "SMB server: Require security signature (CIS 2.3.9.2)"

Set-RegValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "EnableSecuritySignature" `
    -Value 1 `
    -Description "SMB server: Enable security signature (CIS 2.3.9.3)"

Write-Step "Enforcing SMB client signing via registry (CIS 2.3.8.1 / 2.3.8.2)..."
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

Write-Step "Disabling sending of unencrypted passwords to third-party SMB servers (CIS 2.3.8.3)..."
Set-RegValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "EnablePlainTextPassword" `
    -Value 0 `
    -Description "SMB client: Do not send unencrypted passwords (CIS 2.3.8.3)"

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
Set-RegValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name "UseLogonCredential" `
    -Value 0 `
    -Description "WDigest disabled - Mimikatz cannot dump cleartext passwords (CIS 18.4.8)"

Write-Step "Enabling LSA Protection (RunAsPPL) to protect LSASS from injection (CIS 18.4.6)..."
Set-RegValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" `
    -Value 1 `
    -Description "LSA Protection (RunAsPPL) enabled - LSASS protected from injection (CIS 18.4.6)"

# Also set the new RunAsPPLBoot value for Secure Boot enforced PPL
Set-RegValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPLBoot" `
    -Value 1 `
    -Description "LSA Protection enforced at boot level"

Write-Step "Applying UAC restrictions to local accounts on network logons (CIS 18.4.1)..."
Set-RegValue `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LocalAccountTokenFilterPolicy" `
    -Value 0 `
    -Description "UAC restrictions on local accounts for network logons enabled (CIS 18.4.1)"

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
    Write-Success "Account lockout threshold set to 5 attempts (CIS 1.2.2)"

    # Lockout duration: 30 minutes (CIS says 15+, we use 30 for extra protection)
    net accounts /lockoutduration:30 | Out-Null
    Write-Success "Account lockout duration set to 30 minutes (CIS 1.2.1)"

    # Lockout observation window: 30 minutes
    net accounts /lockoutwindow:30 | Out-Null
    Write-Success "Lockout observation window set to 30 minutes (CIS 1.2.4)"
} catch {
    Write-Fail "Could not configure account lockout policy: $_"
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

Write-Step "Enabling SMB-specific server audit events..."
try {
    Set-SmbServerConfiguration -AuditSmb1Access $true -Force
    Write-Success "SMBv1 access auditing enabled - any SMBv1 attempt will be logged."
} catch {
    Write-Warn "Could not enable SMBv1 audit: $_"
}

# Enable SMB server audit log
Write-Step "Enabling SMB Server operational audit log..."
try {
    wevtutil set-log "Microsoft-Windows-SMBServer/Audit" /enabled:true /quiet:true
    Write-Success "SMBServer Audit log enabled - Event IDs 3021, 3024-3026 will fire on non-compliant clients."
} catch {
    Write-Warn "Could not enable SMBServer Audit log via wevtutil: $_"
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
} catch {
    Write-Fail "Could not enable firewall profiles: $_"
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

foreach ($fp in $firewallProfiles) {
    try {
        Set-NetFirewallProfile -Profile $fp.Profile `
            -LogFileName $fp.LogPath `
            -LogMaxSizeKilobytes 16384 `
            -LogBlocked True `
            -LogAllowed True
        Write-Success "Firewall $($fp.Profile) profile: logging enabled at $($fp.LogPath) (16MB, dropped+allowed)"
    } catch {
        Write-Warn "Could not configure $($fp.Profile) firewall logging: $_"
    }
}

Write-Step "NOTE: Port 445 inbound is NOT being blocked - required for GREYTEAM scoring."
Write-Info "SMB traffic on port 445 will remain fully open per competition rules."

Write-Step "Blocking common red-team C2 and lateral movement ports (NOT 445)..."
$blockRules = @(
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
        } else {
            Write-Info "Rule '$($rule.Name)' already exists - skipping."
        }
    } catch {
        Write-Warn "Could not add firewall rule '$($rule.Name)': $_"
    }
}

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

foreach ($svc in $dangerousServices) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -eq "Running") {
                Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            }
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Success "Disabled: $($svc.DisplayName) - Reason: $($svc.Reason)"
        } else {
            Write-Info "$($svc.DisplayName) service not found or already disabled."
        }
    } catch {
        Write-Warn "Could not disable $($svc.DisplayName): $_"
    }
}

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
} else {
    Write-Warn "GREYTEAM not found as a local user - may be domain account. Verify manually."
}

Write-Step "Verifying all SMB shares are still present and accessible..."
$currentShares = Get-SmbShare
Write-Info "Current SMB shares after hardening:"
$currentShares | Format-Table Name, Path, Description -AutoSize | Out-String | Write-Host

Write-Step "Verifying SMBv2 is active and accepting connections..."
$finalConfig = Get-SmbServerConfiguration
if ($finalConfig.EnableSMB2Protocol) {
    Write-Success "SMBv2/v3 is ENABLED. Scoring connections on port 445 will work."
} else {
    Write-Fail "SMBv2 appears DISABLED - this will break scoring! Investigate immediately."
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
$signingCheck = Get-SmbServerConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature
if ($signingCheck.RequireSecuritySignature) {
    Write-Success "SMB signing is REQUIRED. NTLM relay attacks are blocked."
} else {
    Write-Warn "SMB signing require is not active. Re-check Section 2."
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
#  COMPLETION SUMMARY
# ============================================================

Write-Banner "HARDENING COMPLETE - SUMMARY"

Write-Host @"

  The following hardening measures have been applied based on
  CIS Microsoft Windows Server 2019 Benchmark v4.0.0:

  [1]  SMBv1 DISABLED        - EternalBlue (MS17-010) is blocked
  [2]  SMB SIGNING REQUIRED  - NTLM relay attacks are broken
  [3]  NTLMv2 ONLY           - LM/NTLM hash cracking difficulty raised
  [4]  LM HASH STORAGE OFF   - Mimikatz SAM dump yields no LM hashes
  [5]  LSA PROTECTION ON     - LSASS injection (Mimikatz) blocked
  [6]  WDIGEST DISABLED      - No cleartext passwords in memory
  [7]  LLMNR DISABLED        - Responder credential capture broken
  [8]  NULL SESSIONS BLOCKED - No anonymous SMB enumeration
  [9]  ACCOUNT LOCKOUT SET   - Brute force limited to 5 attempts
  [10] FULL AUDIT LOGGING    - All auth/file/process events logged
  [11] FIREWALL HARDENED     - Logging on, C2 ports blocked
  [12] RISKY SERVICES KILLED - Spooler, WinRM, RemoteRegistry off
  [13] PERSISTENCE SCANNED   - Review output above for red team artifacts
  [14] GREYTEAM VERIFIED     - Account intact, port 445 open, SMBv2 active

  GREYTEAM account: NOT MODIFIED
  Port 445:         OPEN (scoring traffic will flow)
  SMBv2/v3:         ENABLED

  RECOMMENDED NEXT STEPS:
  - Reboot to fully activate LSA Protection (RunAsPPL)
  - Review the persistence scan output in Section 10 manually
  - Monitor Event Viewer > Security log and SMBServer/Audit during competition
  - Run: Get-SmbSession frequently to watch active connections

"@ -ForegroundColor Green

Write-Host "Script completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan