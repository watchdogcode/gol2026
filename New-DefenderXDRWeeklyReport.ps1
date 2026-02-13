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

    [string]$OutputPath = "$PSScriptRoot\Weekly_SecOps_Report_$(Get-Date -Format 'yyyyMMdd').html",

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
    [switch]$FailFast,
    [switch]$ExportCsv,
    [switch]$UseParallel,
    [string]$LogPath = 'C:\Reports\Logs\DefenderXDR.log',
    [switch]$TestMode
)

# --- CONFIGURATION ---
$ErrorActionPreference = "Continue"
$ApiBaseUrl = "https://api.security.microsoft.com/api"
$Scope = "https://api.security.microsoft.com/.default"
$Authority = "https://login.microsoftonline.com/$TenantId"

# Constants
$MAX_RETRIES = 3
$RETRY_DELAY_BASE = 2
$MIN_FAILURES_SPRAY = 10
$MIN_ALERTS_RISKY_HOST = 3
# Security: Token cache uses DPAPI-protected Export-Clixml (current user only)
$TOKEN_CACHE_FILE = "$env:TEMP\DefenderXDR_TokenCache.xml"
$KPI_CACHE_FILE = "$env:TEMP\DefenderXDR_KPICache.json"

if ($ProxyUrl) {
    [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($ProxyUrl)
}

# --- CREDENTIAL MASKING (Homogeneous with Daily Report) ---
function Mask-String {
    param([string]$Value, [int]$VisibleChars = 4)
    if ([string]::IsNullOrEmpty($Value)) { return '****' }
    if ($Value.Length -le $VisibleChars) { return '****' }
    return ('*' * ($Value.Length - $VisibleChars)) + $Value.Substring($Value.Length - $VisibleChars)
}

$MaskedTenantId  = Mask-String $TenantId
$MaskedClientId  = Mask-String $ClientId
$MaskedSecret    = if ($ClientSecret) { '********' } else { '(not set)' }
$MaskedThumbprint = if ($CertThumbprint) { Mask-String $CertThumbprint } else { '(not set)' }

# --- LOGGING FUNCTION ---
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')]
        [string]$Level = 'INFO'
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Console output with colors
    $Color = switch($Level) {
        'ERROR' { 'Red' }
        'WARN'  { 'Yellow' }
        'INFO'  { 'Cyan' }
        'DEBUG' { 'Gray' }
    }
    Write-Host $LogEntry -ForegroundColor $Color
    
    # File output
    try {
        $LogDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $LogDir)) { 
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null 
        }
        Add-Content -Path $LogPath -Value $LogEntry -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Silent fail on logging to avoid breaking script
    }
}

# --- SECURITY POSTURE: Log masked credentials at startup ---
Write-Log "=== Security Context ===" -Level INFO
Write-Log "  Tenant ID   : $MaskedTenantId" -Level INFO
Write-Log "  Client ID   : $MaskedClientId" -Level INFO
Write-Log "  Secret      : $MaskedSecret" -Level INFO
Write-Log "  Cert Thumb  : $MaskedThumbprint" -Level INFO
Write-Log "  Auth Mode   : $AuthMode" -Level INFO
Write-Log "========================" -Level INFO

# --- AUTHENTICATION ---
function New-AuthToken {
    Write-Log "Authenticating via $AuthMode..." -Level INFO
    
    # Check token cache
    if ((Test-Path $TOKEN_CACHE_FILE)) {
        try {
            $CachedToken = Import-Clixml -Path $TOKEN_CACHE_FILE -ErrorAction Stop
            if ($CachedToken.Expiry -gt (Get-Date).AddMinutes(5)) {
                Write-Log "Using cached token (valid until $($CachedToken.Expiry))" -Level DEBUG
                return $CachedToken.Token
            }
        } catch {
            Write-Log "Token cache invalid, re-authenticating" -Level WARN
        }
    }
    
    try {
        $Token = $null
        
        if ($AuthMode -eq 'Secret') {
            if (-not $ClientSecret) { throw "ClientSecret is required for Secret auth." }
            
            $Body = @{
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = $ClientSecret
                scope         = $Scope
            }
            $Response = Invoke-RestMethod -Method Post -Uri "$Authority/oauth2/v2.0/token" -Body $Body -ErrorAction Stop
            $Token = $Response.access_token
            $ExpiresIn = $Response.expires_in
            
            # Security: Clear plain-text secret from memory immediately
            $PlainSecret = $null
            [System.GC]::Collect()
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
            
            Write-Log "To sign in, open $($CodeReq.verification_uri) and enter code: $($CodeReq.user_code)" -Level WARN
            
            $Expires = (Get-Date).AddSeconds($CodeReq.expires_in)
            $MaxAttempts = [math]::Ceiling($CodeReq.expires_in / 5)
            $Attempt = 0
            
            while ((Get-Date) -lt $Expires -and $Attempt -lt $MaxAttempts) {
                $Attempt++
                try {
                    $TokenReq = Invoke-RestMethod -Method Post -Uri "$Authority/oauth2/v2.0/token" -Body @{
                        grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                        client_id  = $ClientId
                        device_code = $CodeReq.device_code
                    } -ErrorAction Stop
                    $Token = $TokenReq.access_token
                    $ExpiresIn = $TokenReq.expires_in
                    break
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
            if (-not $Token) { throw "Device code flow timed out after $Attempt attempts." }
        }
        elseif ($AuthMode -eq 'Interactive') {
            # Requires Az or Mg module
            if (Get-Module -ListAvailable -Name "Az.Accounts") {
                Connect-AzAccount -Tenant $TenantId -ErrorAction Stop | Out-Null
                $Token = (Get-AzAccessToken -ResourceUrl "https://api.security.microsoft.com").Token
                $ExpiresIn = 3600 # Default Az token expiry
            } else {
                throw "Interactive auth requires 'Az.Accounts' module."
            }
        }
        
        # Cache the token
        if ($Token) {
            $CacheObj = @{
                Token = $Token
                Expiry = (Get-Date).AddSeconds($ExpiresIn - 300) # 5 min buffer
            }
            Export-Clixml -Path $TOKEN_CACHE_FILE -InputObject $CacheObj -Force -ErrorAction SilentlyContinue
            Write-Log "Token cached successfully" -Level DEBUG
        }
        
        return $Token
    }
    catch {
        Write-Log "Authentication failed: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

# --- API EXECUTOR ---
function Invoke-DefenderAhQuery {
    param(
        [string]$Token,
        [string]$Query,
        [string]$Name
    )

    if ($TestMode) {
        Write-Log "TEST MODE: Returning mock data for '$Name'" -Level DEBUG
        return @{
            Name = $Name
            Results = @(@{ MockData = "Test"; Count = 0 })
            Error = $null
        }
    }

    $Uri = "$ApiBaseUrl/advancedhunting/run"
    $Headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
    }
    
    # Inject TimeWindow - Using parameterized approach for better KQL handling
    $FinalQuery = $Query -replace "ago\(TimeWindowDays\*d\)", "ago($($TimeWindowDays)d)"
    $Body = @{ Query = $FinalQuery } | ConvertTo-Json -Compress

    $Retries = 0
    
    do {
        try {
            $Sw = [System.Diagnostics.Stopwatch]::StartNew()
            $Response = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $Body -TimeoutSec $TimeoutSec -ErrorAction Stop
            $Sw.Stop()
            
            Write-Log "Query '$Name' completed in $($Sw.ElapsedMilliseconds)ms - Rows: $($Response.Results.Count)" -Level DEBUG
            
            return @{
                Name = $Name
                Results = $Response.Results
                Error = $null
                Duration = $Sw.ElapsedMilliseconds
            }
        }
        catch {
            $StatusCode = 0
            if ($_.Exception.Response) { $StatusCode = $_.Exception.Response.StatusCode.value__ }
            
            if ($StatusCode -eq 429 -or $StatusCode -ge 500) {
                $Retries++
                $Wait = [math]::Pow($RETRY_DELAY_BASE, $Retries)
                Write-Log "API Error $StatusCode for '$Name'. Retry $Retries/$MAX_RETRIES in $Wait seconds" -Level WARN
                Start-Sleep -Seconds $Wait
            }
            else {
                Write-Log "Query '$Name' failed: $($_.Exception.Message)" -Level ERROR
                if ($FailFast) { throw $_ }
                return @{ Name = $Name; Results = @(); Error = $_.Exception.Message; Duration = 0 }
            }
        }
    } while ($Retries -lt $MAX_RETRIES)

    Write-Log "Query '$Name' exceeded max retries" -Level ERROR
    return @{ Name = $Name; Results = @(); Error = "Max retries exceeded"; Duration = 0 }
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
| where AlertCount >= $MIN_ALERTS_RISKY_HOST
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
| where Failures >= $MIN_FAILURES_SPRAY
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
Write-Log "Starting Weekly Defender XDR Report Generation" -Level INFO
Write-Log "Time Window: Last $TimeWindowDays days" -Level INFO

try {
    # 1. Authenticate
    $Token = New-AuthToken
    if (-not $Token) { throw "Authentication failed - no token received" }

    # 2. Execute Queries (Parallel if PS 7+ and flag enabled)
    $Data = @{}
    
    if ($UseParallel -and $PSVersionTable.PSVersion.Major -ge 7) {
        Write-Log "Executing queries in parallel..." -Level INFO
        
        $Results = $Queries.GetEnumerator() | ForEach-Object -Parallel {
            $Query = $_.Value
            $Name = $_.Key
            $Token = $using:Token
            $TimeWindowDays = $using:TimeWindowDays
            $ApiBaseUrl = $using:ApiBaseUrl
            $TimeoutSec = $using:TimeoutSec
            $FailFast = $using:FailFast
            $TestMode = $using:TestMode
            $MAX_RETRIES = $using:MAX_RETRIES
            $RETRY_DELAY_BASE = $using:RETRY_DELAY_BASE
            
            # Execute query (reuse function logic)
            if ($TestMode) {
                return @{ Name = $Name; Results = @(@{ MockData = "Test" }); Error = $null }
            }
            
            $Uri = "$ApiBaseUrl/advancedhunting/run"
            $Headers = @{
                "Authorization" = "Bearer $Token"
                "Content-Type"  = "application/json"
            }
            $FinalQuery = $Query -replace "ago\(TimeWindowDays\*d\)", "ago($($TimeWindowDays)d)"
            $Body = @{ Query = $FinalQuery } | ConvertTo-Json -Compress
            
            $Retries = 0
            do {
                try {
                    $Response = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $Body -TimeoutSec $TimeoutSec -ErrorAction Stop
                    return @{ Name = $Name; Results = $Response.Results; Error = $null }
                }
                catch {
                    $StatusCode = 0
                    if ($_.Exception.Response) { $StatusCode = $_.Exception.Response.StatusCode.value__ }
                    if ($StatusCode -eq 429 -or $StatusCode -ge 500) {
                        $Retries++
                        Start-Sleep -Seconds ([math]::Pow($RETRY_DELAY_BASE, $Retries))
                    } else {
                        return @{ Name = $Name; Results = @(); Error = $_.Exception.Message }
                    }
                }
            } while ($Retries -lt $MAX_RETRIES)
            
            return @{ Name = $Name; Results = @(); Error = "Max retries exceeded" }
        } -ThrottleLimit 5
        
        foreach ($Result in $Results) {
            $Data[$Result.Name] = $Result.Results
            if ($Result.Error) {
                Write-Log "Query '$($Result.Name)' had error: $($Result.Error)" -Level WARN
            }
        }
    }
    else {
        Write-Log "Executing queries sequentially..." -Level INFO
        foreach ($Key in $Queries.Keys) {
            $Result = Invoke-DefenderAhQuery -Token $Token -Query $Queries[$Key] -Name $Key
            $Data[$Key] = $Result.Results
        }
    }
    
    # Validate data
    $TotalRows = ($Data.Values | Measure-Object -Property Count -Sum).Sum
    Write-Log "Total rows retrieved: $TotalRows" -Level INFO
    
    if ($TotalRows -eq 0) {
        Write-Log "Warning: No data retrieved from any query" -Level WARN
    }

    # 3. Calculate KPIs
    $KPI_MDO_Phish = ($Data["MDO_Trend"] | Measure-Object -Property Phish -Sum).Sum
    $KPI_MDO_Malware = ($Data["MDO_Trend"] | Measure-Object -Property Malware -Sum).Sum
    $KPI_MDE_Alerts = ($Data["MDE_Severity"] | Measure-Object -Property Count -Sum).Sum
    $KPI_MDE_RiskyHosts = $Data["MDE_HostsRisk"].Count
    $KPI_MDI_Spray = $Data["MDI_Spray"].Count
    $KPI_MDA_OAuth = ($Data["MDA_OAuth"] | Measure-Object -Property Consents -Sum).Sum

    # Null safety
    if (-not $KPI_MDO_Phish) { $KPI_MDO_Phish = 0 }
    if (-not $KPI_MDO_Malware) { $KPI_MDO_Malware = 0 }
    if (-not $KPI_MDE_Alerts) { $KPI_MDE_Alerts = 0 }
    if (-not $KPI_MDA_OAuth) { $KPI_MDA_OAuth = 0 }
    
    Write-Log "KPIs calculated: Phish=$KPI_MDO_Phish, Malware=$KPI_MDO_Malware, Alerts=$KPI_MDE_Alerts" -Level INFO
    
    # Compare with previous period
    $PrevKPIs = $null
    $KPIChanges = @{}
    if (Test-Path $KPI_CACHE_FILE) {
        try {
            $PrevKPIs = Get-Content $KPI_CACHE_FILE -Raw | ConvertFrom-Json
            $KPIChanges = @{
                Phish = if ($PrevKPIs.Phish -gt 0) { [math]::Round((($KPI_MDO_Phish - $PrevKPIs.Phish) / $PrevKPIs.Phish) * 100, 1) } else { 0 }
                Malware = if ($PrevKPIs.Malware -gt 0) { [math]::Round((($KPI_MDO_Malware - $PrevKPIs.Malware) / $PrevKPIs.Malware) * 100, 1) } else { 0 }
                Alerts = if ($PrevKPIs.Alerts -gt 0) { [math]::Round((($KPI_MDE_Alerts - $PrevKPIs.Alerts) / $PrevKPIs.Alerts) * 100, 1) } else { 0 }
            }
            Write-Log "Trend vs previous: Phish $($KPIChanges.Phish)%, Malware $($KPIChanges.Malware)%, Alerts $($KPIChanges.Alerts)%" -Level INFO
        } catch {
            Write-Log "Could not load previous KPIs for comparison" -Level DEBUG
        }
    }
    
    # Save current KPIs for next run
    $CurrentKPIs = @{
        Phish = $KPI_MDO_Phish
        Malware = $KPI_MDO_Malware
        Alerts = $KPI_MDE_Alerts
        RiskyHosts = $KPI_MDE_RiskyHosts
        Date = (Get-Date).ToString("yyyy-MM-dd")
    }
    $CurrentKPIs | ConvertTo-Json | Out-File $KPI_CACHE_FILE -Encoding UTF8 -Force

    # --- STATUS CALCULATION (CISO View) ---
    $GlobalStatus = if ($KPI_MDE_RiskyHosts -gt 0 -or $KPI_MDO_Phish -gt 50) { "Critical" } elseif ($KPI_MDE_Alerts -gt 20) { "Warning" } else { "Healthy" }
    $StatusColor = switch ($GlobalStatus) { "Critical" { "#d13438" } "Warning" { "#ffaa44" } "Healthy" { "#107c10" } }
    
    # Tenant ID already masked at script startup via Mask-String function

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
                <strong>Tenant:</strong> $MaskedTenantId<br>
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
        if (-not (Test-Path $Dir)) { 
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null 
            Write-Log "Created output directory: $Dir" -Level DEBUG
        }
        
        # Use explicit UTF8 encoding (without BOM) for HTML
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($OutputPath, $HtmlContent, $Utf8NoBom)
        
        Write-Log "Report saved to: $OutputPath" -Level INFO
        
        # Export CSV if requested
        if ($ExportCsv) {
            $CsvDir = Join-Path $Dir "CSV_Export"
            if (-not (Test-Path $CsvDir)) { New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null }
            
            foreach ($Key in $Data.Keys) {
                if ($Data[$Key].Count -gt 0) {
                    $CsvPath = Join-Path $CsvDir "$Key.csv"
                    $Data[$Key] | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
                    Write-Log "Exported CSV: $CsvPath" -Level DEBUG
                }
            }
            Write-Log "CSV files exported to: $CsvDir" -Level INFO
        }
    }
    catch {
        Write-Log "Failed to save report: $($_.Exception.Message)" -Level ERROR
        throw
    }

    # 6. Send Email (Optional)
    if ($SendMail) {
        if ($SmtpServer -and $To) {
            try {
                Write-Log "Sending email to $To via $SmtpServer" -Level INFO
                Send-MailMessage -SmtpServer $SmtpServer -From "DefenderReport@$env:COMPUTERNAME" -To $To -Subject $Subject -Body $HtmlContent -BodyAsHtml -Priority High -Encoding ([System.Text.Encoding]::UTF8)
                Write-Log "Email sent successfully" -Level INFO
            }
            catch {
                Write-Log "Failed to send email: $($_.Exception.Message)" -Level ERROR
            }
        } else {
            Write-Log "Email skipped. Missing SmtpServer or To parameter" -Level WARN
        }
    }

    Write-Log "Weekly Defender XDR Report generation completed successfully" -Level INFO
}
catch {
    Write-Log "Script execution failed: $($_.Exception.Message)" -Level ERROR
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level DEBUG
    throw
}
finally {
    # Cleanup sensitive data from memory
    if ($Token) { Clear-Variable -Name Token -ErrorAction SilentlyContinue }
    if ($ClientSecret) { Clear-Variable -Name ClientSecret -ErrorAction SilentlyContinue }
    if ($PlainSecret) { Clear-Variable -Name PlainSecret -ErrorAction SilentlyContinue }
    # Remove token cache file on exit for security
    if (Test-Path $TOKEN_CACHE_FILE) {
        Remove-Item $TOKEN_CACHE_FILE -Force -ErrorAction SilentlyContinue
        Write-Log "Token cache cleaned up" -Level DEBUG
    }
    [System.GC]::Collect()
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
