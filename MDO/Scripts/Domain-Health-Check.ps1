<#
.SYNOPSIS
    Domain Health Check - Verifies DNS authentication records (SPF, DKIM, DMARC, MTA-STS).
.DESCRIPTION
    Checks required PowerShell modules, installs them if missing, and generates
    an HTML report with the domain's email authentication configuration.
.NOTES
    Date:    2026-02-20
    Version: 2.5
    Requires: Administrator privileges

    .\Domain-Health-Check.ps1
    Prompts for a domain and generates a health check HTML report.
 
.DISCLAIMER
    The sample scripts are not supported under any Microsoft standard support program or service.
    The sample scripts are provided AS IS without warranty of any kind. Microsoft further disclaims all
    implied warranties including, without limitation, any implied warranties of merchantability or of
    fitness for a particular purpose. The entire risk arising out of the use or performance of the
    sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or
    anyone else involved in the creation, production, or delivery of the scripts be liable for any
    damages whatsoever (including, without limitation, damages for loss of business profits, business
    interruption, loss of business information, or other pecuniary loss) arising out of the use of or
    inability to use the sample scripts or documentation, even if Microsoft has been advised of the
    possibility of such damages.
#>
# 1. Script Requirements
#Requires -RunAsAdministrator
Clear-DnsClientCache
Set-StrictMode -Version Latest
Write-Host "Reviewing requirements..." -ForegroundColor Yellow
Write-Host "PowerShell Running as Administrator OK" -ForegroundColor Green
$requiredModules = @('DomainHealthChecker', 'EmailAuthChecker')
$totalModules = $requiredModules.Count
for ($i = 0; $i -lt $totalModules; $i++) {
    $mod = $requiredModules[$i]
    $percent = [math]::Round((($i) / $totalModules) * 100)
    Write-Progress -Activity "Checking required modules" -Status "Verifying $mod ($($i+1)/$totalModules)" -PercentComplete $percent

    if (Get-Module -ListAvailable -Name $mod) {
        Write-Host "$mod Module installed OK" -ForegroundColor Green
    } else {
        Write-Host "$mod Module does not exist; " -ForegroundColor Red -NoNewline
        Write-Host "Downloading and installing now..." -ForegroundColor Yellow
        Write-Progress -Activity "Checking required modules" -Status "Installing $mod ($($i+1)/$totalModules)..." -PercentComplete $percent
        try {
            Install-Module $mod -Force -Confirm:$false -ErrorAction Stop
            Write-Host "$mod module installed successfully" -ForegroundColor Green
        } catch {
            Write-Progress -Activity "Checking required modules" -Completed
            Write-Host "ERROR: Failed to install $mod - $_" -ForegroundColor Red
            exit 1
        }
    }
    # Import the module explicitly after confirming it's available
    Import-Module $mod -ErrorAction SilentlyContinue
}
Write-Progress -Activity "Checking required modules" -Completed
Write-Host "All module checks completed." -ForegroundColor Green
$folder = "C:\Scripts\MDO"
if (-not (Test-Path $folder)) {
    New-Item -Path $folder -ItemType Directory
    Write-Host "Folder for reports, created at $folder" -ForegroundColor Green
} 
else {
    Write-Host "Folder for reports already exists at $folder" -ForegroundColor Green
}

# 2. Domain Information
$domain = $(Write-Host "Please, enter the domain to analize" -F Green -NoNewLine) + $(Write-Host " (ex: microsoft.com) " -F yellow -NoNewLine) + 
$(Write-Host "domain: " -F Green -NoNewLine; Read-Host)


# Validate domain input
if ([string]::IsNullOrWhiteSpace($domain)) {
    Write-Host "ERROR: No domain provided. Exiting." -ForegroundColor Red
    exit 1
}
if ($domain -notmatch '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
    Write-Host "ERROR: Invalid domain format '$domain'. Exiting." -ForegroundColor Red
    exit 1
}

# Variable to generate the report name with the domain and date
$date = Get-Date
$date2 = Get-Date -Format "ddMMyyHHmmss"
$Filehtml = "DomainHealthCheck_${domain}_${date2}.html"

Write-Host ""
Write-Host "Checking MX, SPF, DKIM, DMARC & MTA-STS for domain: " -ForegroundColor Cyan -NoNewline
Write-Host ( $domain) -ForegroundColor Yellow

#MX variables
$MX = Resolve-DnsName -Name $domain -Type MX -ErrorAction SilentlyContinue


# Domain Health Check variables
$DHC = Invoke-SpfDkimDmarc -Name $domain
$DHCName = $DHC.Name
$DHCSpfRecord = $DHC.SpfRecord
$DHCSpfAdvisory = $DHC.SpfAdvisory
$DHCSPFRecordLength = $DHC.SpfRecordLength
$DHCSPFRecordDnsLookupCount = $DHC.SpfRecordDnsLookupCount
$DHCDmarcRecord = $DHC.DmarcRecord
$DHCDmarcAdvisory = $DHC.DmarcAdvisory
$DHCDkimRecord = $DHC.DkimRecord
$DHCDkimSelector = $DHC.DkimSelector
$DHCDkimAdvisory = $DHC.DkimAdvisory
$DHCMtaRecord = $DHC.MtaRecord
$DHCMtaAdvisory = $DHC.MtaAdvisory 

#SPF
$ResplveDNSName = Resolve-DnsName -Name $domain -Type TXT -ErrorAction SilentlyContinue |
Where-Object { ($_.Strings -join '') -match '^\s*v=spf1\b' } |
Select-Object Name, Type, TTL, @{Name='String';Expression={$_.Strings -join ''}}

$SPFTTL = $ResplveDNSName.TTL -join ',' 

#DMAR
$DMARC = Resolve-DnsName -Name _dmarc.$domain -Type TXT -ErrorAction SilentlyContinue
if ($null -ne $DMARC) {
    $DMARCTTL = $DMARC.TTL -join ','
} else {
    $DMARCTTL = 'N/A'
}

$MTA = Resolve-DnsName -Name "_mta-sts.$domain" -Type TXT -ErrorAction SilentlyContinue |   Select-Object Name, Type, TTL, @{Name="TXT"; Expression = { $_.Strings -join "" } }

# DKIM Check (CNAME o TXT)
function New-ResultObject {
  param(
    [string]$Selector,
    [string]$Name,
    [string]$Type,
    [Nullable[int]]$TTL,
    [string]$String
  )
  [pscustomobject]@{
    Selector = $Selector
    Name     = $Name
    Type     = $Type
    TTL      = $TTL
    String   = $String
  }
}
function Test-ResolveDnsNameAvailable {
  return (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)
}
function Get-SelectorFromFqdn {
  param([string]$Fqdn)
  # Try to extract the format selector: <selector>._domainkey.<domain>
  $m = [regex]::Match($Fqdn, '^(?<sel>[^.]+)\._domainkey\.', 'IgnoreCase')
  if ($m.Success) { return $m.Groups['sel'].Value }
  # Fallback: first label
  return ($Fqdn.Split('.')[0])
}
function Resolve-CnameDkim {
  param([string]$Fqdn)
  $selector = Get-SelectorFromFqdn -Fqdn $Fqdn
  $cname = Resolve-DnsName -Name $Fqdn -Type CNAME -ErrorAction SilentlyContinue
  $out = @()
  foreach ($r in @($cname)) {
    if (-not $r) { continue }
    $target = ''
    try { $target = $r.NameHost } catch { $target = '' }
    if (-not [string]::IsNullOrWhiteSpace($target)) {
      $out += (New-ResultObject -Selector $selector -Name $r.Name -Type $r.Type -TTL $r.TTL -String $target)
    }
  }
  return ,$out
}
function Resolve-TxtDkim {
  param([string]$Fqdn)
  $selector = Get-SelectorFromFqdn -Fqdn $Fqdn
  $txt = Resolve-DnsName -Name $Fqdn -Type TXT -ErrorAction SilentlyContinue
  $out = @()
  foreach ($r in @($txt)) {
    if (-not $r) { continue }
    $joined = ''
    try { $joined = ($r.Strings -join '') } catch { $joined = '' }
    # Only consider TXT that really looks like DKIM
    if ($joined -match '(?i)\bv=DKIM1\b' -or $joined -match '(?i)\bp=') {
      $out += (New-ResultObject -Selector $selector -Name $r.Name -Type $r.Type -TTL $r.TTL -String $joined)
    }
  }
  return ,$out
}
function Get-DkimRecordsAnyProvider {
  param([string]$domain)

  # Common multi-vendor selectors
  $selectors = @(
    "selector1","selector2",            # Microsoft 365 common
    "s1","s2",                          # SendGrid common
    "k1","k2",                          # Mailchimp common
    "default","dkim",                   # Generic
    "google1","google2",                # Google
    "google",                           # Google Workspace sometimes
    "mail","m1","m2",                   # Generic
    "smtp","smtpapi",                   # Generic / gateways
    "mandrill",                         # Mandrill
    "sendgrid","sg",                    # SendGrid
    "mg",                               # Mailgun
    "mimecast","pp","proofpoint"        # Gateways common
  )

  $results = @()
  foreach ($s in $selectors) {
    $fqdn = "$s._domainkey.$domain"
    # 1) First CNAME
    $c = Resolve-CnameDkim -Fqdn $fqdn
    if (@($c).Count -gt 0) {
      $results += $c
      continue
    }
    # 2) If there is no CNAME, look for TXT
    $t = Resolve-TxtDkim -Fqdn $fqdn
    if (@($t).Count -gt 0) {
      $results += $t
      continue
    }
  }
  # Deduplicate
  return @($results) | Sort-Object Selector, Name, Type, String -Unique
}
# ===== MAIN =====
if (-not (Test-ResolveDnsNameAvailable)) {
  Write-Error "Resolve-DnsName is not available in this session. Use Windows PowerShell 5.1+ or an environment that includes the cmdlet."
  exit 1
}
$dkim = @(Get-DkimRecordsAnyProvider -Domain $domain)

# ========== HTML REPORT ==========

# TTL badge helper
function Get-TtlClass {
    param($ttlValue)
    if ([string]::IsNullOrWhiteSpace($ttlValue) -or $ttlValue -eq "N/A" -or $ttlValue -eq 0) { return "bg-danger text-white px-2 rounded fw-bold" }
    try { if ([int]$ttlValue -le 3600) { return "bg-success text-white px-2 rounded fw-bold" } } catch {}
    return "bg-danger text-white px-2 rounded fw-bold"
}

# Dashboard status badges
$spfSt  = if ($DHCSpfAdvisory -eq "An SPF-record is configured and the policy is sufficiently strict.") { "bg-success" } else { "bg-danger" }
$dkSt   = if ($dkim.Count -gt 0) { "bg-success" } else { "bg-danger" }
$dmSt   = if ($DHCDmarcRecord -match "p=reject" -or $DHCDmarcRecord -match "p=quarantine") { "bg-success" } else { "bg-danger" }
$mtaSt  = if ($DHCMtaRecord -and $DHCMtaRecord -ne "yourinfo") { "bg-success" } else { "bg-danger" }

$spfAdv   = $DHCSpfAdvisory
$dkimAdv  = if ($dkim.Count -gt 0) { "DKIM selectors found" } else { "No DKIM selectors detected" }
$dmarcAdv = if ($DHCDmarcRecord -match "p=none") { "DMARC policy in monitoring mode (p=none)" } elseif ([string]::IsNullOrWhiteSpace($DHCDmarcRecord) -or $DHCDmarcRecord -eq "yourinfo") { "No DMARC record detected" } else { "DMARC policy is enforcing" }
$dmarcAdvSt = if ($dmarcAdv -match 'p=none' -or $dmarcAdv -match 'No DMARC') { 'bg-danger' } else { 'bg-success' }
$dmarcAdvClass = if ($DHCDmarcAdvisory -match 'will prevent abuse' -and $DHCDmarcAdvisory -match 'subdomain policy does not prevent abuse') { 'bg-warning-custom' } elseif ($DHCDmarcAdvisory -match 'will prevent abuse') { 'bg-success text-white' } elseif ($DHCDmarcAdvisory -match 'p=reject' -or $DHCDmarcAdvisory -match 'p=quarantine') { 'bg-success text-white' } elseif ($DHCDmarcAdvisory -match 'does not prevent abuse') { 'bg-danger text-white' } else { 'bg-danger text-white' }
$mtaAdv   = if ($DHCMtaRecord -and $DHCMtaRecord -ne "yourinfo") { "MTA-STS DNS record found" } else { "MTA-STS DNS record not found" }

$mtaTTLValue = if ($null -ne $MTA) { $MTA.TTL } else { "N/A" }

# Extract numeric length from SPFRecordLength (may be string)
$spfLengthNum = 0
if ($DHCSPFRecordLength -match '(\d+)') { $spfLengthNum = [int]$Matches[1] }

# Extract numeric lookup count from string like "7/10 (OK)"
$spfLookupsNum = 0
if ($DHCSPFRecordDnsLookupCount -match '^(\d+)') { $spfLookupsNum = [int]$Matches[1] }

# SPF Includes resolution
$spfIncludes = @()
if ($DHCSpfRecord -match 'include:') {
    $includeMatches = [regex]::Matches($DHCSpfRecord, 'include:([^\s]+)')
    foreach ($inc in $includeMatches) {
        $incDomain = $inc.Groups[1].Value
        $incResult = Resolve-DnsName -Name $incDomain -Type TXT -ErrorAction SilentlyContinue |
            Where-Object { ($_.Strings -join '') -match '^\s*v=spf1\b' } |
            Select-Object Name, TTL, @{Name='SPF'; Expression = { $_.Strings -join ' ' } }
        if ($incResult) {
            $spfIncludes += [pscustomobject]@{
                Name = $incResult.Name
                TTL  = $incResult.TTL
                SPF  = $incResult.SPF
            }
        } else {
            $spfIncludes += [pscustomobject]@{
                Name = $incDomain
                TTL  = 'N/A'
                SPF  = 'TXT record not found, inaccessible or use macros'
            }
        }
    }
}

# SPF Includes Table
$spfIncludesTable = ""
if ($spfIncludes.Count -gt 0) {
    $incRows = foreach ($inc in $spfIncludes) {
        "<tr><td class='ps-3'>$($inc.Name)</td><td><span class='$(Get-TtlClass $inc.TTL)'>$($inc.TTL)</span></td><td style='word-break:break-all;'><code style='font-size:0.8rem;'>$($inc.SPF)</code></td></tr>"
    }
    $spfIncludesTable = @"
<div class='mt-3'>
    <strong>&#128269; SPF Include Lookups:</strong>
    <table class='table table-sm mt-2'>
        <thead><tr><th class='ps-3 small fw-bold'>Include Domain</th><th class='small fw-bold'>TTL</th><th class='small fw-bold'>SPF Record</th></tr></thead>
        <tbody>$($incRows -join '')</tbody>
    </table>
</div>
"@
}

# MX Rows
$mxRows = ""
foreach ($record in $MX) {
    $mxRows += "<tr><td>$($record.NameExchange)</td><td>$($record.Preference)</td><td><span class='$(Get-TtlClass $record.TTL)'>$($record.TTL)</span></td><td>$($record.Type)</td></tr>"
}

# DKIM Table
$dkimTable = ""
if ($dkim.Count -gt 0) {
    $dkRows = foreach ($dk in $dkim) { "<tr><td class='ps-4'><strong>$($dk.Selector)</strong></td><td style='max-width:420px;word-break:break-all;'><code style='font-size:0.7rem;'>$($dk.String)</code></td><td>$($dk.Type)</td><td><span class='$(Get-TtlClass $dk.TTL)'>$($dk.TTL)</span></td></tr>" }
    $dkimTable = @"
<table class='table table-sm mt-2'>
    <thead><tr><th class='ps-4 small fw-bold'>Selector</th><th class='small fw-bold'>Key / Host</th><th class='small fw-bold'>Type</th><th class='small fw-bold'>TTL</th></tr></thead>
    <tbody>$($dkRows -join '')</tbody>
</table>
"@
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Domain Health Check - $domain</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f4f7f9; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .hero { background-color: #0078d4; color: white; padding: 30px; border-bottom: 4px solid #005a9e; }
        .hero h1 { font-size: 1.5rem; font-weight: 400; margin-bottom: 5px; opacity: 0.9; }
        .hero p { font-size: 1.35rem; font-weight: 600; margin-top: 0; }
        .logo-img { max-height: 35px; filter: brightness(0) invert(1); }
        .stat-number { font-size: 2.5rem; font-weight: 800; }
        .table-card { background: white; border: 1px solid #e1e4e8; border-radius: 8px; padding: 25px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .section-divider { border-bottom: 2px solid #0078d4; color: #0078d4; font-weight: bold; margin: 25px 0 15px 0; font-size: 1.25rem; }
        .record-box { background-color: #f8f9fa; border: 1px solid #ddd; padding: 12px; border-radius: 4px; display: block; word-break: break-all; font-family: 'Consolas', monospace; font-size: 0.95rem; margin-top: 5px; border-left: 5px solid #0078d4; }
        .badge-advisory { display: block; padding: 8px; border-radius: 4px; font-weight: 600; margin-bottom: 10px; width: fit-content; text-transform: uppercase; font-size: 0.8rem; }
        .bg-warning-custom { background-color: #FAFD55 !important; color: #000 !important; }
    </style>
</head>
<body>

    <!-- Hero Header -->
    <div class="hero text-center">
        <img src="https://dco.microsoft.com/Images/microsoft-white-logo.png" alt="Microsoft" class="logo-img mb-2">
        <h1>Domain Health Security Report</h1>
        <p>Analysis for: <strong>$domain</strong> | <span style="font-size:0.85rem;">$date</span></p>
        <p><em>&ldquo;Technology enables security, but discipline makes it effective&rdquo;</em></p>
    </div>

    <div class="container-fluid px-5">

        <!-- Dashboard Cards -->
        <div class="row g-3 mt-3 text-center">
            <div class="col"><div class="card p-3 $spfSt text-white">SPF<div class="stat-number">$(if($spfSt -eq 'bg-success'){'PASS'}else{'FAIL'})</div></div></div>
            <div class="col"><div class="card p-3 $dkSt text-white">DKIM<div class="stat-number">$(if($dkSt -eq 'bg-success'){'PASS'}else{'FAIL'})</div></div></div>
            <div class="col"><div class="card p-3 $dmSt text-white">DMARC<div class="stat-number">$(if($dmSt -eq 'bg-success'){'PASS'}else{'FAIL'})</div></div></div>
            <div class="col"><div class="card p-3 $mtaSt text-white">MTA-STS<div class="stat-number">$(if($mtaSt -eq 'bg-success'){'PASS'}else{'FAIL'})</div></div></div>
        </div>

        <div class="table-card">

            <!-- 1. MX RECORDS -->
            <div class="section-divider">&#128236; 1. MX Records for $DHCName</div>
            <table class="table table-sm">
                <thead><tr><th class="small fw-bold">Hostname</th><th class="small fw-bold">Preference</th><th class="small fw-bold">TTL</th><th class="small fw-bold">Type</th></tr></thead>
                <tbody>$mxRows</tbody>
            </table>

            <!-- 2. SPF RECORD -->
            <div class="section-divider">&#128737;&#65039; 2. SPF Record for $DHCName</div>
            <span class="badge-advisory $spfSt text-white">$spfAdv</span>
            <strong>Current SPF Record:</strong><code class="record-box">$DHCSpfRecord</code>
            <div class="mt-2">
                <strong>Length:</strong> <span class="badge $(if($spfLengthNum -gt 255){'bg-danger'}else{'bg-success'})">$DHCSPFRecordLength / 255</span> |
                <strong>Lookups:</strong> <span class="badge $(if($spfLookupsNum -gt 10){'bg-danger text-white'}elseif($spfLookupsNum -ge 8){'bg-warning text-dark'}else{'bg-success text-white'})">$DHCSPFRecordDnsLookupCount</span> |
                <strong>TTL:</strong> <span class="$(Get-TtlClass $SPFTTL)">$SPFTTL</span>
            </div>
            $spfIncludesTable

            <!-- 3. DKIM DETAILS -->
            <div class="section-divider">&#128273; 3. DKIM Details for $DHCName</div>
            <span class="badge-advisory $dkSt text-white">$dkimAdv</span>
            <div class="mb-2">
                <strong>Selector:</strong> $DHCDkimSelector<br>
                <strong>Dkim Record:</strong><code class="record-box" style="font-size:0.7rem;">$DHCDkimRecord</code>
                <strong>Advisory:</strong> $DHCDkimAdvisory
            </div>
            $dkimTable

            <!-- 4. DMARC POLICY -->
            <div class="section-divider">&#128678; 4. DMARC Policy for $DHCName</div>
            <span class="badge-advisory $dmarcAdvClass">$DHCDmarcAdvisory</span>
            <strong>Current DMARC:</strong><code class="record-box">$DHCDmarcRecord</code>
            <div class="mt-2">
                <strong>TTL:</strong> <span class="$(Get-TtlClass $DMARCTTL)">$DMARCTTL</span>
            </div>
            <div class="mt-2">
                <span class="badge-advisory $dmarcAdvSt text-white">$dmarcAdv</span>
            </div>

            <!-- 5. MTA-STS -->
            <div class="section-divider">&#127760; 5. MTA-STS Policy for $DHCName</div>
            <span class="badge-advisory $mtaSt text-white">$mtaAdv</span>
            <div class="bg-light border rounded p-3 mt-2">
                <div style="border-bottom:1px solid #eee;padding:8px 0;"><strong style="width:160px;display:inline-block;">MTA Record:</strong> $DHCMtaRecord</div>
                <div style="border-bottom:1px solid #eee;padding:8px 0;"><strong style="width:160px;display:inline-block;">Advisory:</strong> $DHCMtaAdvisory</div>
                <div style="padding:8px 0;"><strong style="width:160px;display:inline-block;">DNS TTL:</strong> <span class="$(Get-TtlClass $mtaTTLValue)">$mtaTTLValue</span></div>
            </div>

        </div><!-- /table-card -->

        <!-- Note -->
        <div class="alert alert-secondary text-center mt-4">
            &#128161; <strong>Note:</strong> Security advisory issues and character limits (SPF Length &gt; 255) are highlighted in <span class="text-danger fw-bold">Red</span>.
        </div>

        <!-- Action Items & Microsoft Recommendations -->
        <div class="card shadow-sm border-primary mb-4">
            <div class="card-header text-white" style="background-color: #0078d4;">&#128221; Action Items &amp; Microsoft Recommendations</div>
            <div class="card-body">
                <ul>
                    <li><strong>Reduce SPF record length (max 255 chars)</strong> - <a href="https://www.rfc-editor.org/rfc/rfc7208" target="_blank">RFC 7208</a></li>
                    <li><strong>SPF Record Syntax</strong> - <a href="http://www.open-spf.org/SPF_Record_Syntax/" target="_blank">open-spf.org</a></li>
                    <li><strong>Implement DKIM record</strong> - <a href="https://dkim.org/" target="_blank">dkim.org</a></li>
                    <li><strong>List of DKIM selectors</strong> - <a href="https://www.syskeo.com/en/resources/dkim" target="_blank">syskeo.com</a></li>
                    <li><strong>Upgrade DMARC policy from 'none' to 'reject'</strong> - <a href="https://www.rfc-editor.org/rfc/rfc7489.html" target="_blank">RFC 7489</a></li>
                    <li><strong>DMARC Record Syntax: Every Tag and Parameter Explained</strong> - <a href="https://dmarccreator.com/resources/dmarc-record-syntax-tags" target="_blank">dmarccreator.com</a></li>
                    <li><strong>SMTP MTA Strict Transport Security (MTA-STS)</strong> - <a href="https://www.rfc-editor.org/rfc/rfc8461" target="_blank">RFC 8461</a></li>
                    <li><strong>Implement MTA-STS</strong> - <a href="https://learn.microsoft.com/en-us/purview/enhancing-mail-flow-with-mta-sts" target="_blank">Microsoft Configuration Guide</a></li>
                    <li><strong>DNS Propagation and TTL Explained</strong> - <a href="https://www.whatsmyiplive.com/blog/dns-propagation-and-ttl.html" target="_blank">whatsmyiplive.com</a></li>
                    <li><strong>Double check with EmailAuthChecker: Start-EmailAuthChecker</strong> - <a href="https://www.linkedin.com/posts/abdullah-al-zmaili-57496128_i-am-excited-to-share-that-i-have-developed-activity-7358838297034407936-tM70" target="_blank">Introducing EmailAuthChecker</a></li>
                </ul>
            </div>
        </div>

        <!-- Microsoft Official Documentation -->
        <div class="card shadow-sm border-info mb-4">
            <div class="card-header text-white" style="background-color: #0078d4;">&#128218; Microsoft Official Documentation</div>
            <div class="card-body">
                <div class="list-group">
                    <a href="https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-spf-configure" class="list-group-item list-group-item-action" target="_blank">&#128279; SPF Setup Guide</a>
                    <a href="https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure#scenario-parked-domains" class="list-group-item list-group-item-action" target="_blank">&#128279; SPF Setup Parked Domains</a>
                    <a href="https://learn.microsoft.com/en-us/microsoft-365/admin/get-help-with-domains/create-dns-records-at-any-dns-hosting-provider?view=o365-worldwide&tabs=domain-connect" class="list-group-item list-group-item-action" target="_blank">&#128279; Connect your domain by adding DNS records</a>
                    <a href="https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dkim-configure" class="list-group-item list-group-item-action" target="_blank">&#128279; DKIM Setup Guide</a>
                    <a href="https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dmarc-configure" class="list-group-item list-group-item-action" target="_blank">&#128279; DMARC Setup Guide</a>
                    <a href="https://learn.microsoft.com/en-us/purview/enhancing-mail-flow-with-mta-sts" class="list-group-item list-group-item-action" target="_blank">&#128279; MTA-STS Enhancing mail flow</a>
                    <a href="https://learn.microsoft.com/en-us/defender-office-365/email-authentication-arc-configure" class="list-group-item list-group-item-action" target="_blank">&#128279; Configure trusted ARC sealers</a>
                    <a href="https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dmarc-configure#use-the-microsoft-365-admin-center-to-add-dmarc-txt-records-for-onmicrosoftcom-domains-in-microsoft-365" class="list-group-item list-group-item-action" target="_blank">&#128279; DMARC TXT records for *.onmicrosoft.com</a>
                    <a href="https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dmarc-configure#dmarc-txt-records-for-parked-domains-in-microsoft-365" class="list-group-item list-group-item-action" target="_blank">&#128279; DMARC TXT records for parked domains</a>
                    <a href="https://mha.azurewebsites.net/" class="list-group-item list-group-item-action" target="_blank">&#128279; Message Header Analyzer</a>
                </div>
            </div>
        </div>
     
        <!-- Footer -->
        <div class="text-center py-4"><p>Internal Tools 2026</p></div>

    </div><!-- /container -->
</body>
</html>
"@

# Output the HTML report
$reportPath = "C:\Scripts\MDO\$Filehtml"
$dir = [System.IO.Path]::GetDirectoryName($reportPath)
if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
$html | Out-File -FilePath $reportPath -Encoding utf8 -Force
Invoke-Item $reportPath