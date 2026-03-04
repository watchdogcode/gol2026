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
    Creates a transport rule in Exchange Online to block emails
    sent to *.onmicrosoft.com domains.

.DESCRIPTION
    This script prompts for the short tenant name (e.g., contoso) and creates
    a Transport Rule that silently deletes messages whose "To" header matches
    @<tenant>.onmicrosoft.com or @<tenant>.mail.onmicrosoft.com.

.NOTES
    Requires: ExchangeOnlineManagement module and an active session (Connect-ExchangeOnline).
    Author  : SecOps Team
    Date    : 2026-02-24

.EXAMPLE
    .\Block-OnMicrosoftEmails.ps1

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

# ── Prompt for domain ──
do {
    $admdomain = $(Write-Host "Please, enter the domain to block" -F Green -NoNewLine) + $(Write-Host " (ex: If your domain is contoso.onmicrosoft.com, just type contoso)  " -F yellow -NoNewLine) + 
$(Write-Host "domain: " -F Green -NoNewLine; Read-Host)
    $admdomain = $admdomain.Trim()
} while ([string]::IsNullOrWhiteSpace($admdomain))

# ── Rule variables ──
$ruleName        = "Block emails sent to $admdomain.onmicrosoft.com"
$pattern1        = "@$admdomain\.onmicrosoft\.com"
$pattern2        = "@$admdomain\.mail\.onmicrosoft\.com"
$ruleDescription = "Blocks messages whose 'To' header matches '$pattern1' or '$pattern2'. Action: delete without notifying sender or recipient. Audit severity: High."

# ── Check if the rule already exists ──
$existingRule = Get-TransportRule -Identity $ruleName -ErrorAction SilentlyContinue
if ($existingRule) {
    Write-Host "Rule '$ruleName' already exists (State: $($existingRule.State)). Skipping creation." -ForegroundColor Yellow
    Write-Host "To modify it use: Set-TransportRule -Identity '$ruleName' ..." -ForegroundColor Cyan
    return
}

# ── Create the transport rule ──
$ruleParams = @{
    Name                      = $ruleName
    Comments                  = $ruleDescription
    HeaderMatchesMessageHeader = "To"
    HeaderMatchesPatterns     = @($pattern1, $pattern2)
    DeleteMessage             = $true
    Mode                      = "Enforce"
    RuleErrorAction           = "Defer"
    SetAuditSeverity          = "High"
    StopRuleProcessing        = $false
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
     verify which messages would match before blocking.

  2. RULE PRIORITY
     Use -Priority 0 if you want this rule evaluated before
     other existing transport rules.

  3. EXCEPTIONS
     Consider adding -ExceptIfFrom or -ExceptIfSentTo to
     exclude service accounts or critical mailboxes:
       -ExceptIfFrom "noreply@company.com"

  4. POST-IMPLEMENTATION MONITORING
     Review the Message Trace after enabling the rule:
       Get-MessageTrace -StartDate (Get-Date).AddHours(-24) -EndDate (Get-Date) |
         Where-Object { $_.Status -eq "FilteredAsSpam" -or $_.Status -eq "Failed" }

  5. SENDER NOTIFICATION (OPTIONAL)
     If you prefer to reject instead of silently deleting:
       Remove -DeleteMessage $true and use:
       -RejectMessageReasonText "Delivery to onmicrosoft.com addresses is not permitted."
       -RejectMessageEnhancedStatusCode "5.7.1"

  6. LIMITED SCOPE
     This rule only inspects the "To" header. If you also
     need to block CC/BCC, add additional rules or use
     -AnyOfToHeader / -AnyOfToCCHeader instead.

  7. DOCUMENTATION
     Record the rule in your security CMDB/wiki with:
     - Creation date, justification, and associated ticket.
     - Owner responsible for periodic review.
  ══════════════════════════════════════════════════════════════
#>

