<#
.SYNOPSIS
    New-DefenderXDRWeeklyReport.ps1
    Generates a Weekly Executive Threat Report using Microsoft Defender XDR Advanced Hunting API.

.DESCRIPTION
    Automates weekly security operations tasks for MDO, MDE, MDI, and MDA.
    Extracts KPIs, trends, and actionable insights into a standalone HTML report.

.PARAMETER TimeWindowDays
    Analysis period in days (7, 14, or 30). Default: 7.

.PARAMETER OutputPath
    Path to save the HTML report.

.PARAMETER AuthMode
    Authentication method: 'DeviceCode' (default), 'Interactive', 'Secret', 'Certificate'.

.PARAMETER TenantId
    Azure AD Tenant ID (Required).

.PARAMETER ClientId
    App Registration Client ID (Required).

.PARAMETER ClientSecret
    Client Secret (Required if AuthMode is 'Secret').

.PARAMETER CertThumbprint
    Certificate Thumbprint (Required if AuthMode is 'Certificate').

.PARAMETER SendMail
    Switch to send the report via email.

.EXAMPLE
    .\New-DefenderXDRWeeklyReport.ps1 -TenantId "xxx" -ClientId "yyy" -AuthMode DeviceCode

.NOTES
    Requires 'AdvancedHunting.Read.All' permission.
#>

param(
    [ValidateSet(7, 14, 30)]
    [int]$TimeWindowDays = 7,

    [string]$OutputPath = 'C:\Reports\DefenderXDR_Weekly.html',

    [ValidateSet('DeviceCode', 'Interactive', 'Secret', 'Certificate')]
    [string]$AuthMode = 'DeviceCode',

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [string]$ClientSecret,
    [string]$CertThumbprint,

    [bool]$SendMail = $false,
    [string]$SmtpServer,
    [string]$To,
    [string]$Subject = "Defender XDR - Weekly Threat Report",

    [string]$ProxyUrl,
    [int]$TimeoutSec = 120,
    [switch]$FailFast
)

# --- CONFIGURATION ---
$ErrorActionPreference = "Stop"
$ApiBaseUrl = "https://api.security.microsoft.com/api"
$Scope = "https://api.security.microsoft.com/.default"
$Authority = "https://login.microsoftonline.com/$TenantId"

if ($ProxyUrl) {
    [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($ProxyUrl)
}

# --- AUTHENTICATION ---
function New-AuthToken {
    Write-Host "[-] Authenticating via $AuthMode..." -ForegroundColor Cyan
    
    try {
        if ($AuthMode -eq 'Secret') {
            if (-not $ClientSecret) { throw "ClientSecret is required for Secret auth." }
            $Body = @{
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = $ClientSecret
                scope         = $Scope
            }
            $Response = Invoke-RestMethod -Method Post -Uri "$Authority/oauth2/v2.0/token" -Body $Body -ErrorAction Stop
            return $Response.access_token
        }
        elseif ($AuthMode -eq 'Certificate') {
            # Basic implementation assuming certificate is in CurrentUser\My
            if (-not $CertThumbprint) { throw "CertThumbprint is required for Certificate auth." }
            $Cert = Get-Item "Cert:\CurrentUser\My\$CertThumbprint"
            
            # Create JWT Client Assertion (Simplified for PS without external modules)
            # NOTE: For production without modules, Secret is preferred. 
            # Fallback to MSAL.PS or Az if available for Cert, otherwise throw.
            if (Get-Module -ListAvailable -Name "MSAL.PS") {
                Import-Module MSAL.PS
                $Token = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -ClientCertificate $Cert -Scopes $Scope
                return $Token.AccessToken
            }
            throw "Certificate auth requires MSAL.PS module or manual JWT construction. Please use Secret or DeviceCode."
        }
        elseif ($AuthMode -eq 'DeviceCode') {
            $CodeReq = Invoke-RestMethod -Method Post -Uri "$Authority/oauth2/v2.0/devicecode" -Body @{
                client_id = $ClientId
                scope     = $Scope
            }
            
            Write-Host "    [!] To sign in, use a web browser to open the page $($CodeReq.verification_uri) and enter the code: $($CodeReq.user_code)" -ForegroundColor Yellow
            
            $Expires = (Get-Date).AddSeconds($CodeReq.expires_in)
            while ((Get-Date) -lt $Expires) {
                try {
                    $TokenReq = Invoke-RestMethod -Method Post -Uri "$Authority/oauth2/v2.0/token" -Body @{
                        grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                        client_id  = $ClientId
                        device_code = $CodeReq.device_code
                    } -ErrorAction Stop
                    return $TokenReq.access_token
                }
                catch {
                    $Err = $_.Exception.Response.GetResponseStream()
                    $Reader = New-Object System.IO.StreamReader($Err)
                    $ErrBody = $Reader.ReadToEnd() | ConvertFrom-Json
                    if ($ErrBody.error -eq "authorization_pending") {
                        Start-Sleep -Seconds 5
                    } else {
                        throw $_
                    }
                }
            }
            throw "Device code flow timed out."
        }
        elseif ($AuthMode -eq 'Interactive') {
            # Requires Az or Mg module
            if (Get-Module -ListAvailable -Name "Az.Accounts") {
                Connect-AzAccount -Tenant $TenantId -ErrorAction Stop | Out-Null
                return (Get-AzAccessToken -ResourceUrl "https://api.security.microsoft.com").Token
            }
            throw "Interactive auth requires 'Az.Accounts' module."
        }
    }
    catch {
        Write-Error "Authentication failed: $_"
        exit 1
    }
}

# --- API EXECUTOR ---
function Invoke-DefenderAhQuery {
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
    $FinalQuery = $Query -replace "ago\(TimeWindowDays\*d\)", "ago($($TimeWindowDays)d)"
    $Body = @{ Query = $FinalQuery } | ConvertTo-Json -Compress

    $Retries = 0
    $MaxRetries = 3
    
    do {
        try {
            $Sw = [System.Diagnostics.Stopwatch]::StartNew()
            $Response = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $Body -TimeoutSec $TimeoutSec -ErrorAction Stop
            $Sw.Stop()
            
            Write-Host "    [+] Query '$Name' ($($Sw.ElapsedMilliseconds)ms) - Rows: $($Response.Results.Count)" -ForegroundColor Gray
            
            return @{
                Name = $Name
                Results = $Response.Results
                Error = $null
            }
        }
        catch {
            $StatusCode = 0
            if ($_.Exception.Response) { $StatusCode = $_.Exception.Response.StatusCode.value__ }
            
            if ($StatusCode -eq 429 -or $StatusCode -ge 500) {
                $Retries++
                $Wait = [math]::Pow(2, $Retries)
                Write-Warning "    [!] API Error $StatusCode. Retrying in $Wait seconds..."
                Start-Sleep -Seconds $Wait
            }
            else {
                Write-Error "    [x] Query '$Name' Failed: $($_.Exception.Message)"
                if ($FailFast) { throw $_ }
                return @{ Name = $Name; Results = @(); Error = $_.Exception.Message }
            }
        }
    } while ($Retries -lt $MaxRetries)

    return @{ Name = $Name; Results = @(); Error = "Max retries exceeded" }
}

# --- KQL QUERIES ---
$Queries = @{
    # MDO
    "MDO_Trend" = @"
EmailEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| summarize Incidents=count(), Phish=countif(ThreatTypes has 'Phish'), Malware=countif(ThreatTypes has 'Malware') by bin(Timestamp, 1d)
| order by Timestamp asc
"@

    "MDO_Campaigns" = @"
EmailEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ThreatTypes has_any ('Phish', 'Malware')
| summarize Count=count(), Targets=dcount(RecipientEmailAddress) by Subject, SenderFromDomain
| top 20 by Count desc
"@

    "MDO_TopUsers" = @"
EmailEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ThreatTypes has_any ('Phish', 'Malware')
| summarize Attacks=count() by RecipientEmailAddress
| top 20 by Attacks desc
"@

    # MDE
    "MDE_Severity" = @"
AlertInfo
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ServiceSource == 'MicrosoftDefenderForEndpoint'
| summarize Count=count() by Severity
| order by Count desc
"@

    "MDE_HostsRisk" = @"
AlertInfo
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ServiceSource == 'MicrosoftDefenderForEndpoint'
| where Severity in ('High', 'Critical')
| join kind=inner (AlertEvidence | where Timestamp between (ago(TimeWindowDays*d) .. now()) | where EntityType == 'Machine') on AlertId
| summarize AlertCount=dcount(AlertId), MaxSev=max(Severity) by DeviceName, DeviceId
| where AlertCount >= 3
| top 25 by AlertCount desc
"@

    "MDE_Health" = @"
DeviceInfo
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| summarize arg_max(Timestamp, OSPlatform, SensorHealthState, DeviceId) by DeviceName
| project DeviceName, OS=OSPlatform, Health=SensorHealthState, LastSeen=Timestamp, DeviceId
| top 25 by LastSeen desc
"@

    # MDI
    "MDI_Spray" = @"
IdentityLogonEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ActionType == 'LogonFailed'
| summarize Failures=count(), DistinctIPs=dcount(IPAddress) by AccountUpn, Location
| where Failures >= 10
| top 25 by Failures desc
"@

    "MDI_Atypical" = @"
IdentityLogonEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| summarize Countries=dcount(Location), LastSeen=max(Timestamp) by AccountUpn
| where Countries >= 3
| top 25 by Countries desc
"@

    # MDA
    "MDA_OAuth" = @"
CloudAppEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ActionType in ('Consent to application', 'Grant consent')
| summarize Consents=count(), Users=dcount(AccountId) by Application, ApplicationId
| top 20 by Consents desc
"@

    "MDA_Apps" = @"
CloudAppEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| summarize Events=count(), Users=dcount(AccountId) by Application
| top 20 by Events desc
"@
}

# --- MAIN EXECUTION ---
Write-Host "Starting Weekly Defender XDR Report Generation..." -ForegroundColor Green
Write-Host "Time Window: Last $TimeWindowDays days" -ForegroundColor Gray

# 1. Authenticate
$Token = New-AuthToken

# 2. Execute Queries
$Data = @{}
foreach ($Key in $Queries.Keys) {
    $Result = Invoke-DefenderAhQuery -Token $Token -Query $Queries[$Key] -Name $Key
    $Data[$Key] = $Result.Results
}

# 3. Calculate KPIs
$KPI_MDO_Phish = ($Data["MDO_Trend"] | Measure-Object -Property Phish -Sum).Sum
$KPI_MDO_Malware = ($Data["MDO_Trend"] | Measure-Object -Property Malware -Sum).Sum
$KPI_MDE_Alerts = ($Data["MDE_Severity"] | Measure-Object -Property Count -Sum).Sum
$KPI_MDE_RiskyHosts = $Data["MDE_HostsRisk"].Count
$KPI_MDI_Spray = $Data["MDI_Spray"].Count
$KPI_MDA_OAuth = ($Data["MDA_OAuth"] | Measure-Object -Property Consents -Sum).Sum

if (-not $KPI_MDO_Phish) { $KPI_MDO_Phish = 0 }
if (-not $KPI_MDO_Malware) { $KPI_MDO_Malware = 0 }
if (-not $KPI_MDE_Alerts) { $KPI_MDE_Alerts = 0 }
if (-not $KPI_MDA_OAuth) { $KPI_MDA_OAuth = 0 }

# --- STATUS CALCULATION (CISO View) ---
$GlobalStatus = if ($KPI_MDE_RiskyHosts -gt 0 -or $KPI_MDO_Phish -gt 50) { "Critical" } elseif ($KPI_MDE_Alerts -gt 20) { "Warning" } else { "Healthy" }
$StatusColor = switch ($GlobalStatus) { "Critical" { "#d13438" } "Warning" { "#ffaa44" } "Healthy" { "#107c10" } }

# 4. Generate HTML
function New-HtmlTable {
    param($Rows, $Cols)
    if (-not $Rows -or $Rows.Count -eq 0) { return "<tr><td colspan='$($Cols.Count)' style='text-align:center; color:#888; padding:15px;'>No data available for this period.</td></tr>" }
    $Html = ""
    foreach ($Row in $Rows) {
        $Html += "<tr>"
        foreach ($Col in $Cols) {
            $Val = $Row.$Col
            
            # UI/UX: Deep Links & Formatting
            if ($Col -eq "DeviceName" -and $Row.DeviceId) {
                $Val = "<a href='https://security.microsoft.com/machines/$($Row.DeviceId)' target='_blank' title='View Device in Defender'>$Val</a>"
            }
            elseif ($Col -in @("AccountUpn", "RecipientEmailAddress") -and $Val) {
                $Val = "<a href='https://security.microsoft.com/users/sec/UserPage?user=$Val' target='_blank' title='View User in Defender'>$Val</a>"
            }
            elseif ($Val -is [DateTime]) { $Val = $Val.ToString("yyyy-MM-dd HH:mm") }
            
            $Html += "<td>$Val</td>"
        }
        $Html += "</tr>"
    }
    return $Html
}

$HtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Defender XDR - Weekly Threat Report</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; color: #323130; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: #fff; padding: 40px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); border-radius: 8px; }
        
        /* Header */
        .header { border-bottom: 3px solid #0078d4; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; color: #0078d4; font-size: 28px; }
        .meta { text-align: right; font-size: 0.9em; color: #605e5c; }
        .status-badge { padding: 5px 15px; border-radius: 4px; color: white; font-weight: bold; text-transform: uppercase; font-size: 0.9em; }
        
        /* Executive Summary */
        .summary { background: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 5px solid #0078d4; margin-bottom: 30px; }
        .summary h3 { margin-top: 0; color: #201f1e; }
        .summary ul { margin: 0; padding-left: 20px; }
        .summary li { margin-bottom: 8px; font-size: 1.05em; }

        /* KPI Grid */
        .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }
        .card { background: #fff; padding: 20px; border-radius: 6px; border: 1px solid #e1dfdd; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .card-val { font-size: 36px; font-weight: 700; color: #0078d4; margin-bottom: 5px; }
        .card-label { font-size: 12px; text-transform: uppercase; color: #605e5c; font-weight: 600; letter-spacing: 0.5px; }
        .card.danger .card-val { color: #d13438; }
        .card.success .card-val { color: #107c10; }
        
        /* Sections */
        h2 { color: #201f1e; border-left: 4px solid #0078d4; padding-left: 12px; margin-top: 40px; font-size: 20px; }
        h3 { color: #605e5c; font-size: 16px; margin-top: 25px; margin-bottom: 10px; }
        
        /* Tables */
        table { width: 100%; border-collapse: collapse; font-size: 14px; margin-bottom: 20px; }
        th { background: #f3f2f1; text-align: left; padding: 10px; border-bottom: 2px solid #e1dfdd; color: #605e5c; }
        td { padding: 10px; border-bottom: 1px solid #e1dfdd; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f0f0f0; transition: background 0.2s; }
        a { text-decoration: none; color: #0078d4; font-weight: 500; }
        a:hover { text-decoration: underline; }

        /* Checklist */
        .checklist { background: #e6f2ff; padding: 20px; border-radius: 6px; margin-top: 40px; }
        .checklist h3 { margin-top: 0; color: #005a9e; }
        .checklist ul { list-style: none; padding: 0; }
        .checklist li { padding: 8px 0; border-bottom: 1px solid #cce4ff; display: flex; align-items: flex-start; }
        .checklist li:before { content: "☐"; margin-right: 10px; font-weight: bold; color: #0078d4; }
        
        .footer { margin-top: 50px; text-align: center; color: #8a8886; font-size: 12px; border-top: 1px solid #e1dfdd; padding-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>Defender XDR – Weekly Threat Report</h1>
                <div style="margin-top:5px; color:#605e5c;">Weekly Security Operations & Threat Protection</div>
            </div>
            <div class="meta">
                <div class="status-badge" style="background-color: $StatusColor; display:inline-block; margin-bottom:10px;">$GlobalStatus</div><br>
                <strong>Tenant:</strong> $TenantId<br>
                <strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm")<br>
                <strong>Period:</strong> Last $TimeWindowDays Days
            </div>
        </div>

        <div class="summary">
            <h3>Executive Summary</h3>
            <ul>
                <li><strong>$KPI_MDO_Phish</strong> phishing emails and <strong>$KPI_MDO_Malware</strong> malware attempts detected this week.</li>
                <li><strong>$KPI_MDE_Alerts</strong> total endpoint alerts recorded; <strong>$KPI_MDE_RiskyHosts</strong> hosts require immediate attention (Multi-Alert/High Sev).</li>
                <li><strong>$KPI_MDI_Spray</strong> identities showed signs of password spray or brute force attacks.</li>
                <li><strong>$KPI_MDA_OAuth</strong> new OAuth consents granted to applications.</li>
            </ul>
        </div>

        <div class="kpi-grid">
            <div class="card $(if($KPI_MDE_Alerts -eq 0){'success'})">
                <div class="card-val">$KPI_MDE_Alerts</div>
                <div class="card-label">Total Endpoint Alerts</div>
            </div>
            <div class="card $(if($KPI_MDO_Phish -eq 0){'success'}else{'danger'})">
                <div class="card-val">$KPI_MDO_Phish</div>
                <div class="card-label">Phishing Attempts</div>
            </div>
            <div class="card $(if($KPI_MDE_RiskyHosts -eq 0){'success'}else{'danger'})">
                <div class="card-val">$KPI_MDE_RiskyHosts</div>
                <div class="card-label">Critical Hosts (≥3 Alerts)</div>
            </div>
            <div class="card $(if($KPI_MDI_Spray -eq 0){'success'}else{'danger'})">
                <div class="card-val">$KPI_MDI_Spray</div>
                <div class="card-label">Identity Spray Attacks</div>
            </div>
            <div class="card $(if($KPI_MDA_OAuth -eq 0){'success'})">
                <div class="card-val">$KPI_MDA_OAuth</div>
                <div class="card-label">New OAuth Consents</div>
            </div>
        </div>

        <!-- MDO -->
        <h2>MDO: Email & Collaboration</h2>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
            <div>
                <h3>Top Active Campaigns</h3>
                <table>
                    <thead><tr><th>Subject</th><th>Sender Domain</th><th>Count</th><th>Targets</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDO_Campaigns"] @("Subject","SenderFromDomain","Count","Targets"))</tbody>
                </table>
            </div>
            <div>
                <h3>Top Targeted Users</h3>
                <table>
                    <thead><tr><th>User Email</th><th>Attacks</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDO_TopUsers"] @("RecipientEmailAddress","Attacks"))</tbody>
                </table>
            </div>
        </div>

        <!-- MDE -->
        <h2>MDE: Endpoint Security</h2>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
            <div>
                <h3>Alerts by Severity</h3>
                <table>
                    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDE_Severity"] @("Severity","Count"))</tbody>
                </table>
            </div>
            <div>
                <h3>Hosts with Multiple High/Critical Alerts</h3>
                <table>
                    <thead><tr><th>Device Name</th><th>Alert Count</th><th>Max Severity</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDE_HostsRisk"] @("DeviceName","AlertCount","MaxSev"))</tbody>
                </table>
            </div>
        </div>
        <h3>Device Health Status (Top 25)</h3>
        <table>
            <thead><tr><th>Device Name</th><th>OS</th><th>Health State</th><th>Last Seen</th></tr></thead>
            <tbody>$(New-HtmlTable $Data["MDE_Health"] @("DeviceName","OS","Health","LastSeen"))</tbody>
        </table>

        <!-- MDI -->
        <h2>MDI: Identity Security</h2>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
            <div>
                <h3>Password Spray / Brute Force</h3>
                <table>
                    <thead><tr><th>Account</th><th>Location</th><th>Failures</th><th>IPs</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDI_Spray"] @("AccountUpn","Location","Failures","DistinctIPs"))</tbody>
                </table>
            </div>
            <div>
                <h3>Atypical Locations (Travel)</h3>
                <table>
                    <thead><tr><th>Account</th><th>Countries</th><th>Last Seen</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDI_Atypical"] @("AccountUpn","Countries","LastSeen"))</tbody>
                </table>
            </div>
        </div>

        <!-- MDA -->
        <h2>MDA: Cloud Apps & Shadow IT</h2>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
            <div>
                <h3>New OAuth Consents</h3>
                <table>
                    <thead><tr><th>App Name</th><th>App ID</th><th>Consents</th><th>Users</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDA_OAuth"] @("Application","ApplicationId","Consents","Users"))</tbody>
                </table>
            </div>
            <div>
                <h3>New Apps Discovered (Shadow IT)</h3>
                <table>
                    <thead><tr><th>Application</th><th>Events</th><th>Users</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDA_Apps"] @("Application","Events","Users"))</tbody>
                </table>
            </div>
        </div>

        <!-- Recommendations -->
        <div class="checklist">
            <h3>Weekly Operational Checklist</h3>
            <ul>
                <li><strong>MDO:</strong> Review top phishing campaigns and adjust Safe Links/Attachments policies. Check "Top Targeted Users" for potential compromise or training needs.</li>
                <li><strong>MDE:</strong> Investigate hosts with ≥3 High/Critical alerts. Isolate devices if active threats are confirmed. Validate EDR sensor health.</li>
                <li><strong>MDI:</strong> Review accounts with high failure rates (Spray) and enforce MFA or password resets. Investigate atypical travel patterns.</li>
                <li><strong>MDA:</strong> Audit new OAuth consents. Revoke permissions for unverified or suspicious applications. Review Shadow IT usage.</li>
            </ul>
        </div>

        <div class="footer">
            Source: Defender XDR – Advanced Hunting & Reporting (Weekly Ops) | Generated at $(Get-Date -Format "HH:mm")
        </div>
    </div>
</body>
</html>
"@

# 5. Save Report
try {
    $Dir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
    $HtmlContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Host "[-] Report saved to: $OutputPath" -ForegroundColor Cyan
}
catch {
    Write-Error "Failed to save report: $_"
}

# 6. Send Email (Optional)
if ($SendMail) {
    if ($SmtpServer -and $To) {
        try {
            Write-Host "[-] Sending email to $To..." -ForegroundColor Cyan
            Send-MailMessage -SmtpServer $SmtpServer -From "DefenderReport@$env:COMPUTERNAME" -To $To -Subject $Subject -Body $HtmlContent -BodyAsHtml -Priority High
            Write-Host "    [+] Email sent." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to send email: $_"
        }
    } else {
        Write-Warning "Email skipped. Missing SmtpServer or To parameter."
    }
}

# --- APPENDIX: MANUAL QUERIES ---
<#
    APPENDIX: KQL Queries for Manual Execution in Defender Portal
    
    // MDO: Trend
    EmailEvents | where Timestamp > ago(7d) | summarize Count=count() by bin(Timestamp, 1d), ThreatTypes
    
    // MDE: Risky Hosts
    AlertInfo | where Timestamp > ago(7d) | where ServiceSource == 'MicrosoftDefenderForEndpoint' 
    | summarize AlertCount=count(), MaxSev=max(Severity) by DeviceName | where AlertCount >= 3
    
    // MDI: Spray
    IdentityLogonEvents | where Timestamp > ago(7d) | where ActionType == 'LogonFailed' 
    | summarize Failures=count() by AccountUpn, Location | where Failures >= 10
    
    // MDA: OAuth
    CloudAppEvents | where Timestamp > ago(7d) | where ActionType in ('Consent to application', 'Grant consent')
#>
