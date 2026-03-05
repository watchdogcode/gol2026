##############################################################################################
#This sample script is not supported under any Microsoft standard support program or service.
#This sample script is provided AS IS without warranty of any kind.
#Microsoft further disclaims all implied warranties including, without limitation, any implied
#warranties of merchantability or of fitness for a particular purpose. The entire risk arising
#out of the use or performance of the sample script and documentation remains with you. In no
#event shall Microsoft, its authors, or anyone else involved in the creation, production, or
#delivery of the scripts be liable for any damages whatsoever (including, without limitation,
#damages for loss of business profits, business interruption, loss of business information,
#or other pecuniary loss) arising out of the use of or inability to use the sample script or
#documentation, even if Microsoft has been advised of the possibility of such damages.
##############################################################################################
<#
.SYNOPSIS
    Creates a transport rule in Exchange Online to quarantine emails
    with attachments whose content cannot be inspected.

.DESCRIPTION
    This script creates a Transport Rule that redirects messages to hosted
    quarantine when any attachment content cannot be inspected (e.g.,
    password-protected, encrypted, or corrupted files).

.NOTES
    Requires: ExchangeOnlineManagement module and an active session (Connect-ExchangeOnline).
    Author  : Ernesto Cobos Roqueñí
    Date    : 24/February/2026
    Version : 1.1

.EXAMPLE
    .\Quarantine-UninspectableAttachments.ps1

#>

#Requires -Modules ExchangeOnlineManagement

# ── Validate / establish Exchange Online session ──
try {
    $null = Get-AcceptedDomain -ErrorAction Stop | Select-Object -First 1
    Write-Host "Exchange Online session active." -ForegroundColor DarkGray
} catch {
    Write-Host "No active Exchange Online session. Connecting..." -ForegroundColor Yellow
    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Host "Connected to Exchange Online." -ForegroundColor Green
    }
    catch {
        Write-Host "[X] Could not connect to Exchange Online: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

# ── Rule variables ──
$ruleName        = "Quarantine Attachments Can't be inspected"
$ruleDescription = "If the message has any attachment whose content can't be inspected, redirect the message to hosted quarantine. Audit severity: High."

# ── Check if the rule already exists ──
$existingRule = Get-TransportRule -Identity $ruleName -ErrorAction SilentlyContinue
if ($existingRule) {
    Write-Host "Rule '$ruleName' already exists (State: $($existingRule.State)). Skipping creation." -ForegroundColor Yellow
    Write-Host "To modify it use: Set-TransportRule -Identity '$ruleName' ..." -ForegroundColor Cyan
    return
}

# ── Create the transport rule ──
$ruleParams = @{
    Name                 = $ruleName
    Comments             = $ruleDescription
    AttachmentIsUnsupported = $true
    Quarantine           = $true
    Mode                 = "Enforce"
    Priority             = 1
    RuleErrorAction      = "Defer"
    SetAuditSeverity     = "High"
    StopRuleProcessing   = $true
}

try {
    New-TransportRule @ruleParams -ErrorAction Stop
    Write-Host "`nRule '$ruleName' created successfully in Enforce mode." -ForegroundColor Green
} catch {
    Write-Host "`nFailed to create rule: $_" -ForegroundColor Red
}

<#
  ══════════════════════════════════════════════════════════════
  RECOMMENDATIONS
  ══════════════════════════════════════════════════════════════

  1. TEST MODE FIRST
     Change -Mode "Enforce" to -Mode "AuditAndNotify" to
     verify which messages would match before quarantining.

  2. RULE PRIORITY
     Use -Priority 0 if you want this rule evaluated before
     other existing transport rules.

  3. EXCEPTIONS
     Consider adding exceptions for trusted senders:
       -ExceptIfFrom "trusted-partner@company.com"
       -ExceptIfSenderDomainIs "trusteddomain.com"

  4. POST-IMPLEMENTATION MONITORING
     Review quarantined messages regularly:
       Get-QuarantineMessage -StartReceivedDate (Get-Date).AddDays(-7) |
         Where-Object { $_.QuarantineTypes -eq "TransportRule" }

  5. NOTIFY ADMINS
     Consider adding -GenerateIncidentReport and
     -IncidentReportContent to alert admins when triggered.

  6. DOCUMENTATION
     Record the rule in your security CMDB/wiki with:
     - Creation date, justification, and associated ticket.
     - Owner responsible for periodic review.
  ══════════════════════════════════════════════════════════════
#>
