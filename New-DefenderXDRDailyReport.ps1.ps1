<#
.SYNOPSIS
    Daily Security Operations Report Generator using Microsoft 365 Defender API.
    Automates KQL Advanced Hunting queries for MDO, MDE, MDI, and MDA.

.DESCRIPTION
    This script authenticates against the M365 Defender API, executes a defined set of 
    daily hunting queries, and generates a professional HTML executive report.

.PARAMETER TimeWindowHours
    Time window in hours for the analysis (Default: 24).

.PARAMETER OutputPath
    Full path for the output HTML file.

.PARAMETER AuthMode
    Authentication method: 'Secret', 'Interactive', 'DeviceCode'.
    For 'Secret', ensure $ClientId, $TenantId, and $ClientSecret are set (or env vars).

.NOTES
    API Endpoint: https://api.security.microsoft.com
    Required Permission: AdvancedHunting.Read.All
#>

param(
    [int]$TimeWindowHours = 24,
    [string]$OutputPath = "$PSScriptRoot\Daily_SecOps_Report_$(Get-Date -Format 'yyyyMMdd').html",
    [string]$TenantId = $env:AZURE_TENANT_ID,
    [string]$ClientId = $env:AZURE_CLIENT_ID,
    [string]$ClientSecret = $env:AZURE_CLIENT_SECRET,
    [ValidateSet("Secret", "Interactive", "DeviceCode")]
    [string]$AuthMode = "Secret",
    [bool]$SendMail = $false,
    [string]$SmtpServer,
    [string]$From,
    [string]$To,
    [string]$Subject = "Daily Security Report - M365 Defender",
    [int]$TimeoutSec = 120,
    [bool]$FailFast = $false
)

# --- CONFIGURATION & GLOBALS ---
$ErrorActionPreference = "Stop"
$ApiBaseUrl = "https://api.security.microsoft.com/api"
$ResourceUrl = "https://api.security.microsoft.com"
$ReportDate = Get-Date
$StartDate = $ReportDate.AddHours(-$TimeWindowHours)

# --- LOGGING FUNCTION ---
function Write-Log {
    param([string]$Message, [string]$Level="INFO")
    $Color = switch($Level) { "INFO" {"Cyan"} "WARN" {"Yellow"} "ERROR" {"Red"} default {"White"} }
    Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] [$Level] $Message" -ForegroundColor $Color
}

# --- AUTHENTICATION ---
function Get-M365Token {
    Write-Log "Acquiring Access Token via $AuthMode..."
    
    try {
        if ($AuthMode -eq "Secret") {
            if (-not ($TenantId -and $ClientId -and $ClientSecret)) {
                throw "For 'Secret' auth, TenantId, ClientId, and ClientSecret are required."
            }
            $Body = @{
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = $ClientSecret
                scope         = "$ResourceUrl/.default"
            }
            $TokenReq = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $Body -ErrorAction Stop
            return $TokenReq.access_token
        }
        elseif ($AuthMode -in @("Interactive", "DeviceCode")) {
            # Attempt to use Az or Mg modules if available for interactive flows
            if (Get-Module -ListAvailable -Name "Az.Accounts") {
                Write-Log "Using Az.Accounts for interactive token..."
                $TokenData = Get-AzAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop
                return $TokenData.Token
            }
            elseif (Get-Module -ListAvailable -Name "Microsoft.Graph.Authentication") {
                Write-Log "Using Microsoft.Graph for interactive token..."
                # Connect if not connected
                if (-not (Get-MgContext)) { Connect-MgGraph -Scopes "AdvancedHunting.Read.All" -NoWelcome }
                $TokenData = Get-MgAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop
                return $TokenData
            }
            else {
                throw "Modules 'Az.Accounts' or 'Microsoft.Graph.Authentication' not found. Required for Interactive/DeviceCode auth."
            }
        }
    }
    catch {
        Write-Log "Authentication Failed: $_" -Level ERROR
        throw $_
    }
}

# --- API EXECUTION ---
function Invoke-HuntingQuery {
    param(
        [string]$Token,
        [string]$Query,
        [string]$Name
    )

    $Uri = "$ApiBaseUrl/advancedhunting/run"
    $Headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
    }
    
    # Inject TimeWindow
    $FinalQuery = $Query -replace "ago\(24h\)", "ago($($TimeWindowHours)h)"
    $Body = @{ Query = $FinalQuery } | ConvertTo-Json -Compress

    $Retries = 0
    $MaxRetries = 3
    
    do {
        try {
            $Sw = [System.Diagnostics.Stopwatch]::StartNew()
            $Response = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $Body -TimeoutSec $TimeoutSec -ErrorAction Stop
            $Sw.Stop()
            
            Write-Log "Query ['$Name'] executed in $($Sw.ElapsedMilliseconds)ms. Rows: $($Response.Results.Count)"
            
            return @{
                Name = $Name
                Results = $Response.Results
                Stats = $Response.Stats
                Error = $null
            }
        }
        catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            if ($StatusCode -eq 429 -or $StatusCode -ge 500) {
                $Retries++
                $Wait = [math]::Pow(2, $Retries)
                Write-Log "API Error $StatusCode. Retrying in $Wait seconds..." -Level WARN
                Start-Sleep -Seconds $Wait
            }
            else {
                Write-Log "Query ['$Name'] Failed: $_" -Level ERROR
                if ($FailFast) { throw $_ }
                return @{ Name = $Name; Results = @(); Error = $_.Exception.Message }
            }
        }
    } while ($Retries -lt $MaxRetries)

    return @{ Name = $Name; Results = @(); Error = "Max retries exceeded" }
}

# --- KQL DEFINITIONS ---
$Queries = @{
    "MDO_Campaigns" = @"
EmailEvents
| where Timestamp >= ago(24h)
| where ThreatTypes has_any ("Phish","Malware")
| where DeliveryAction == "Delivered"
| summarize Events=count(), Targets=dcount(RecipientEmailAddress) by Subject, SenderFromDomain
| top 10 by Events desc
"@

    "MDO_TopUrls" = @"
EmailUrlInfo
| where Timestamp >= ago(24h)
| summarize Hits=count() by UrlDomain
| top 20 by Hits desc
"@

    "MDO_TopUsers" = @"
EmailEvents
| where Timestamp >= ago(24h) and ThreatTypes has "Phish"
| summarize Attempts=count() by RecipientEmailAddress
| top 20 by Attempts desc
"@

    "MDE_AlertsBySev" = @"
AlertInfo
| where Timestamp >= ago(24h) and ServiceSource == "MicrosoftDefenderForEndpoint"
| summarize Count=count() by Severity
| order by Count desc
"@

    "MDI_HighRiskUsers" = @"
EntraIdSignInEvents
| where Timestamp >= ago(24h)
| where RiskLevelAggregated in (50, 100)
| summarize Events=count() by 
AccountUpn, RiskLevelAggregated
| top 25 by Events desc
"@

    "MDE_Health" = @"
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
| project Timestamp, DeviceName, OSPlatform, ExposureLevel, OnboardingStatus
| where OnboardingStatus !in ("Onboarded","Unknown") or ExposureLevel in ("High","Medium")
| top 50 by Timestamp desc
"@

    "MDI_BruteForce" = @"
IdentityLogonEvents
| where Timestamp >= ago(24h)
| summarize Fails=countif(ActionType == "LogonFailed"), Success=countif(ActionType == "LogonSuccess"), LastSeen=max(Timestamp) by AccountUpn, IPAddress, Location
| where Fails >= 20 and Success > 0
| order by Fails desc
"@

    "MDI_AtypicalLocations" = @"
IdentityLogonEvents
| where Timestamp >= ago(24h)
| summarize Locations=dcount(Location), LastSeen=max(Timestamp) by AccountUpn
| where Locations >= 3
| order by Locations desc
"@

    "MDA_OAuth" = @"
CloudAppEvents
| where Timestamp >= ago(24h)
| where ActionType in ("Consent to application","Grant consent")
| summarize Consents=count(), Users=dcount(AccountId) by Application, ApplicationId
| top 20 by Consents desc
"@

    "MDA_ShadowIT" = @"
CloudAppEvents
| where Timestamp >= ago(24h)
| summarize Events=count(), Users=dcount(AccountId) by Application
| top 20 by Events desc
"@
}

# --- MAIN EXECUTION ---

# 1. Authenticate
$Token = Get-M365Token

# 2. Execute Queries
$Data = @{}
foreach ($Key in $Queries.Keys) {
    $Result = Invoke-HuntingQuery -Token $Token -Query $Queries[$Key] -Name $Key
    $Data[$Key] = $Result.Results
}

# 3. Calculate KPIs
$Kpi_TotalAlerts = ($Data["MDE_AlertsBySev"] | Measure-Object -Property Count -Sum).Sum
if (-not $Kpi_TotalAlerts) { $Kpi_TotalAlerts = 0 }

$Kpi_PhishDelivered = ($Data["MDO_Campaigns"] | Measure-Object -Property Events -Sum).Sum
if (-not $Kpi_PhishDelivered) { $Kpi_PhishDelivered = 0 }

$Kpi_CompromisedIdentities = $Data["MDI_BruteForce"].Count
$Kpi_HighRiskUsers = $Data["MDI_HighRiskUsers"].Count
$Kpi_NewOAuth = ($Data["MDA_OAuth"] | Measure-Object -Property Consents -Sum).Sum
if (-not $Kpi_NewOAuth) { $Kpi_NewOAuth = 0 }

# --- RANDOM DAILY KQL SELECTION ---
$MdoDailyQueries = @(
    @{ Title="High Severity MDO Alerts (Incidents Queue)"; Query="AlertInfo | where Timestamp > ago(24h) | where ServiceSource == 'MicrosoftDefenderForOffice365' and Severity == 'High' | summarize Count=count() by Title" },
    @{ Title="Delivered Phishing/Malware (False Negatives)"; Query="EmailEvents | where Timestamp > ago(24h) | where DeliveryAction == 'Delivered' and ThreatTypes has_any ('Phish','Malware') | project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, ThreatTypes" },
    @{ Title="Top Active Campaigns (Campaigns View)"; Query="EmailEvents | where Timestamp > ago(24h) | where isnotempty(CampaignId) | summarize Events=count(), Targets=dcount(RecipientEmailAddress) by CampaignId, Subject | top 5 by Events desc" },
    @{ Title="ZAP Activity (Automated Investigation)"; Query="EmailPostDeliveryEvents | where Timestamp > ago(24h) | where ActionType has 'ZAP' | summarize Count=count() by ActionTrigger, ActionResult" },
    @{ Title="Suspicious Delivered Attachments (Analysis)"; Query="EmailAttachmentInfo | where Timestamp > ago(24h) | join kind=inner (EmailEvents | where DeliveryAction == 'Delivered') on NetworkMessageId | where FileType in ('exe', 'ps1', 'vbs', 'iso', 'js') | project Timestamp, FileName, RecipientEmailAddress" }
)
$SelectedMdoQuery = $MdoDailyQueries | Get-Random

# 4. Generate HTML
function ConvertTo-HtmlTable {
    param($Rows, $Columns)
    if (-not $Rows -or $Rows.Count -eq 0) { return "<tr><td colspan='$($Columns.Count)' style='text-align:center; color:#666;'>No data found in period</td></tr>" }
    
    $Html = ""
    foreach ($Row in $Rows) {
        $Html += "<tr>"
        foreach ($Col in $Columns) {
            $Val = $Row.$Col
            if ($Val -is [DateTime]) { $Val = $Val.ToString("yyyy-MM-dd HH:mm") }
            $Html += "<td>$Val</td>"
        }
        $Html += "</tr>"
    }
    return $Html
}

$HtmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Daily Security Report</title>
    <style>
        :root {
            --primary-color: #0078d4;
            --secondary-color: #2b2b2b;
            --bg-color: #f0f2f5;
            --card-bg: #ffffff;
            --text-color: #323130;
            --border-color: #e1dfdd;
            --danger-color: #a80000;
        }
        body { 
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif; 
            background-color: var(--bg-color); 
            color: var(--text-color); 
            margin: 0; 
            padding: 0; 
            line-height: 1.5;
        }
        .header {
            background-color: var(--primary-color);
            color: white;
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
        .header .meta { font-size: 0.9em; opacity: 0.9; text-align: right; }
        
        .container { 
            max-width: 1200px; 
            margin: 30px auto; 
            padding: 0 20px; 
        }
        
        h2 { 
            color: var(--secondary-color); 
            margin-top: 40px; 
            margin-bottom: 15px; 
            font-size: 18px; 
            border-left: 4px solid var(--primary-color); 
            padding-left: 12px; 
            display: flex;
            align-items: center;
        }

        /* KPI Grid */
        .kpi-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .kpi-card { 
            background: var(--card-bg); 
            padding: 25px 20px; 
            border-radius: 8px; 
            text-align: center; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.05); 
            transition: transform 0.2s ease;
            border-top: 4px solid transparent;
        }
        .kpi-card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .kpi-card.alert { border-top-color: var(--primary-color); }
        .kpi-card.danger { border-top-color: var(--danger-color); }
        
        .kpi-val { font-size: 3em; font-weight: 700; color: var(--secondary-color); line-height: 1; margin-bottom: 5px; }
        .kpi-label { font-size: 0.85em; color: #605e5c; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
        
        /* Tables */
        .table-container {
            background: var(--card-bg);
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            overflow: hidden;
            margin-bottom: 30px;
        }
        table { width: 100%; border-collapse: collapse; font-size: 0.95em; }
        th { background-color: #f8f9fa; color: #605e5c; text-align: left; padding: 12px 15px; font-weight: 600; border-bottom: 2px solid var(--border-color); }
        td { border-bottom: 1px solid var(--border-color); padding: 12px 15px; color: var(--text-color); }
        tr:last-child td { border-bottom: none; }
        tr:hover { background-color: #f8f9fa; }
        
        /* Recommendations */
        .recs { 
            background-color: #e6f2ff; 
            padding: 20px; 
            border-radius: 8px; 
            border: 1px solid #cce4ff;
        }
        .recs ul { margin: 0; padding-left: 20px; }
        .recs li { margin-bottom: 8px; line-height: 1.6; }
        
        /* Daily Activities */
        .activities { 
            background-color: var(--card-bg); 
            border-radius: 8px; 
            padding: 20px; 
            margin-bottom: 30px; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            border-left: 5px solid var(--primary-color);
        }
        .activities h4 { margin-top: 0; margin-bottom: 15px; color: var(--secondary-color); font-size: 1.1em; }
        .activities ul { margin: 0; padding-left: 20px; }
        .activities li { margin-bottom: 8px; font-size: 1em; color: var(--text-color); }
        .activities li a { color: var(--primary-color); text-decoration: none; font-weight: 500; }
        .activities li a:hover { text-decoration: underline; }
        
        .footer { text-align: center; margin-top: 50px; color: #8a8886; font-size: 0.85em; padding-bottom: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Daily Security Operations Report</h1>
        <div class="meta">
            <div><strong>Period:</strong> $($StartDate.ToString("yyyy-MM-dd HH:mm")) - $($ReportDate.ToString("yyyy-MM-dd HH:mm"))</div>
            <div style="font-size: 0.85em; margin-top: 4px;">Tenant ID: $TenantId</div>
        </div>
    </div>

    <div class="container">
        <!-- KPIs -->
        <div class="kpi-grid">
            <div class="kpi-card alert">
                <div class="kpi-val">$Kpi_TotalAlerts</div>
                <div class="kpi-label">Total Alerts (MDE)</div>
            </div>
            <div class="kpi-card $(if($Kpi_PhishDelivered -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$Kpi_PhishDelivered</div>
                <div class="kpi-label">Phish Delivered</div>
            </div>
            <div class="kpi-card $(if($Kpi_HighRiskUsers -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$Kpi_HighRiskUsers</div>
                <div class="kpi-label">High Risk Users</div>
            </div>
            <div class="kpi-card $(if($Kpi_CompromisedIdentities -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$Kpi_CompromisedIdentities</div>
                <div class="kpi-label">Identity Brute Force</div>
            </div>
            <div class="kpi-card alert">
                <div class="kpi-val">$Kpi_NewOAuth</div>
                <div class="kpi-label">New OAuth Consents</div>
            </div>
        </div>

        <!-- MDO Section -->
        <h2>MDO: Email & Collaboration</h2>
        <div class="activities">
            <h4>Daily Activities</h4>
            <ul>
                <li><a href="https://security.microsoft.com/incidents">Monitor email and collaboration incidents and alerts.</a>
                    <div style="margin-top:8px; padding:10px; background:#f8f9fa; border-left:3px solid #0078d4; font-family:Consolas, monospace; font-size:0.85em; color:#333;">
                        <div style="font-weight:bold; color:#0078d4; margin-bottom:5px;">💡 Recommended KQL: $($SelectedMdoQuery.Title)</div>
                        <div style="white-space:pre-wrap;">$($SelectedMdoQuery.Query)</div>
                    </div>
                </li>
                <li><a href="https://security.microsoft.com/campaigns">Evaluate phishing and malware campaigns that were delivered.</a></li>
                <li><a href="https://security.microsoft.com/action-center/pending">Review pending or incomplete automated actions (AIR).</a></li>
                <li><a href="https://security.microsoft.com/submissions">Triage suspicious messages reported by users.</a></li>
                <li><a href="https://security.microsoft.com/alerts">Manage alerts with classification and necessary remediations.</a></li>
            </ul>
        </div>
        
        <h3>Top Phishing Campaigns Delivered</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Subject</th><th>SenderDomain</th><th>Events</th><th>Targets</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["MDO_Campaigns"] @("Subject","SenderFromDomain","Events","Targets"))</tbody>
            </table>
        </div>
        
        <h3>Top Targeted Users (Phishing)</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Recipient</th><th>Attempts</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["MDO_TopUsers"] @("RecipientEmailAddress","Attempts"))</tbody>
            </table>
        </div>

        <!-- MDE Section -->
        <h2>MDE: Endpoint Security</h2>
        <h3>Alerts by Severity</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Severity</th><th>Count</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["MDE_AlertsBySev"] @("Severity","Count"))</tbody>
            </table>
        </div>

        <!-- MDI Section -->
        <h2>MDI: Identity Security</h2>
        <h3>Potential Brute Force Success</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Account</th><th>IP Address</th><th>Location</th><th>Fails</th><th>Success</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["MDI_BruteForce"] @("AccountUpn","IPAddress","Location","Fails","Success"))</tbody>
            </table>
        </div>

        <h3>Users with High Risk Sign-ins</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Account</th><th>Risk Level</th><th>Events</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["MDI_HighRiskUsers"] @("UserPrincipalName","RiskLevelAggregated","Events"))</tbody>
            </table>
        </div>

        <!-- MDA Section -->
        <h2>MDA: Cloud Apps & Shadow IT</h2>
        <h3>New OAuth Consents</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Application</th><th>AppId</th><th>Consents</th><th>Users</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["MDA_OAuth"] @("Application","ApplicationId","Consents","Users"))</tbody>
            </table>
        </div>

        <!-- Recommendations -->
        <h2>Daily Recommendations & Actions</h2>
        <div class="recs">
            <ul>
                <li><strong>MDO:</strong> Review the $(if($Kpi_PhishDelivered -gt 0){"<b>$Kpi_PhishDelivered</b> delivered phishing campaigns"}else{"phishing campaigns"}) and validate ZAP effectiveness. Check top targeted users for awareness training.</li>
                <li><strong>MDI:</strong> Investigate the <b>$Kpi_HighRiskUsers</b> users with high risk sign-ins. Reset passwords or enforce MFA for risky sessions.</li>
                <li><strong>MDI:</strong> Analyze the <b>$Kpi_CompromisedIdentities</b> accounts with brute force success. Reset passwords and enforce MFA if not present.</li>
                <li><strong>MDA:</strong> Audit the <b>$Kpi_NewOAuth</b> new OAuth consents. Revoke permissions for suspicious or unverified publishers.</li>
            </ul>
        </div>
        
        <div class="footer">
            Generated by Automated Security Operations | Microsoft 365 Defender
        </div>
    </div>
</body>
</html>
"@

# 5. Save Output
try {
    $Dir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
    $HtmlContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Log "Report saved to: $OutputPath"
}
catch {
    Write-Log "Failed to save report: $_" -Level ERROR
}

# 6. Send Mail (Optional)
if ($SendMail) {
    if ($SmtpServer -and $From -and $To) {
        try {
            Write-Log "Sending email to $To..."
            Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To -Subject $Subject -Body $HtmlContent -BodyAsHtml -Priority High
            Write-Log "Email sent successfully."
        }
        catch {
            Write-Log "Failed to send email: $_" -Level ERROR
        }
    } else {
        Write-Log "Email skipped. Missing SMTP parameters." -Level WARN
    }
}
