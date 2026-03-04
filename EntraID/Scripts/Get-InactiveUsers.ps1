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
		Get users via Microsoft Graph based on lack of sign-in activity

	.DESCRIPTION
        This script will retrieve a list of users who have not signed in for at least a specified number of days.
        Requires Microsoft Entra P1 or P2 license in the tenant.
        Requires the signed in user to have User.Read.All (or higher) delegated scope.
            Permissions: https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http#permissions
        Requires the signed in user to have AuditLog.Read.All delegated scope and a sufficient Entra role. (Reports Reader is least privileged role.)
            Permissions: https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0&tabs=http#permissions

    .PARAMETER SignInType
        Filter users on the type of sign-in: interactive (successful or unsuccessful), non-interactive (successful or unsuccessful),
        or successful (for either type). Valid values are Interactive, NonInteractive, and Successful.
        Successful is the default.

    .PARAMETER MemberDaysOfInactivity
        The number of days of sign-in inactivity for a member user to be returned. Default value is 30.
        Note: Users with a null value for the date/time of the sign-in type will not be returned.

    .PARAMETER GuestDaysOfInactivity
        The number of days of sign-in inactivity for a guest user to be returned. Default value is 90.
        Cannot be less than MemberDaysOfInactivity if members are included.
        Note: Users with a null value for the date/time of the sign-in type will not be returned.
    
    .PARAMETER CloudEnvironment
        Cloud instance of the tenant. Possible values are Commercial, USGovGCC, USGovGCCHigh, USGovDoD, and China.
        Default value is Commercial.

    .PARAMETER UserType
        Filter users based on their type. Valid values are Member and Guest. Default is both.

    .PARAMETER DoNotExportToCSV
        Switch to skip exporting the results to CSV and instead output the result objects to the host.
        
	.NOTES
        Version 1.0
        March 4, 2026

    .ORIGINAL_SOURCE
    https://github.com/o365soa/Scripts

	.LINK
		about_functions_advanced   
#>
#Requires -Modules @{ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0'}
[CmdletBinding()]
param (
    [ValidateSet('Interactive','NonInteractive','Successful')]$SignInType = 'Successful',
    [int]$MemberDaysOfInactivity = 45,
    [int]$GuestDaysOfInactivity = 90,
    [ValidateSet("Member", "Guest")][string[]]$UserType = @("Member", "Guest"),
    [ValidateSet("Commercial", "USGovGCC", "USGovGCCHigh", "USGovDoD", "China")][string]$CloudEnvironment="Commercial",
    [switch]$DoNotExportToCSV
)

if ($UserType -contains 'Member' -and $GuestDaysOfInactivity -lt $MemberDaysOfInactivity) {
    Write-Error -Message "GuestDaysOfInactivity cannot be less than MemberDaysOfInactivity when UserType includes Members."
    exit
}

# ─────────────────────────────────────────────
# Carpeta de reportes
# ─────────────────────────────────────────────
$reportDir = "C:\Scripts\EntraID"
if (-not (Test-Path $reportDir)) {
    New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
    Write-Host "Carpeta creada: $reportDir" -ForegroundColor DarkGray
}
else {
    Write-Host "Carpeta de reportes existe: $reportDir" -ForegroundColor DarkGray
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath   = Join-Path $reportDir "EntraID-InactiveUsers_$timestamp.csv"
$htmlPath  = Join-Path $reportDir "EntraID-InactiveUsers_$timestamp.html"

# Start-Transcript -Path "Transcript-inactiveusers.txt" -Append
switch ($CloudEnvironment) {
    "Commercial"   {$cloud = "Global"}
    "USGovGCC"     {$cloud = "Global"}
    "USGovGCCHigh" {$cloud = "USGov"}
    "USGovDoD"     {$cloud = "USGovDoD"}
    "China"        {$cloud = "China"}            
}

if (-not(Get-MgContext)) {
    Write-Host -ForegroundColor Green "$(Get-Date) Connecting to Microsoft Graph..."
    Connect-MgGraph -ContextScope CurrentUser -Environment $cloud -NoWelcome
}

$neededScopes = @()
# Supported scope for Users API from least to most privileged
$supportedScopes = @('User.Read.All', 'User.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All')
foreach ($scope in (Get-MgContext).Scopes) {
    if ($scope -in $supportedScopes) {
        $userScopeInCurrentContext = $true
        break
    }
}
if ((-not($userScopeInCurrentContext))) {
    $neededScopes += 'User.Read.All'
}
# Supported scope for Sign-ins API
if ((Get-MgContext).Scopes -notcontains 'AuditLog.Read.All') {
    $neededScopes += 'AuditLog.Read.All'
}

if ($neededScopes) {
    Write-Host -ForegroundColor Green "$(Get-Date) Reconnecting to Microsoft Graph and requesting new scopes..."
    Connect-MgGraph -ContextScope CurrentUser -Scopes $neededScopes -Environment $cloud -NoWelcome
}

if ($UserType -contains 'Member') {
    $targetdate = (Get-Date).ToUniversalTime().AddDays(-$MemberDaysOfInactivity).ToString("o")
} else {
    $targetdate = (Get-Date).ToUniversalTime().AddDays(-$GuestDaysOfInactivity).ToString("o")
}
# Used for client-side filtering of results for guest users
$guestTargetDate = (Get-Date).ToUniversalTime().AddDays(-$GuestDaysOfInactivity)

$result = New-Object -TypeName System.Collections.ArrayList
switch ($SignInType) {
    Interactive {$siFilter = 'signInActivity/lastSignInDateTime'}
    NonInteractive {$siFilter = 'signInActivity/lastNonInteractiveSignInDateTime'}
    Successful {$siFilter = 'signInActivity/lastSuccessfulSignInDateTime'}
}

# Filtering on signInActivity cannot be used with any other filterable properties, so filtering on userType is performed client-side
# https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts
$apiUrl = "/v1.0/users?`$filter=$siFilter lt $($targetdate)&`$select=accountEnabled,id,userType,signInActivity,userprincipalname"
Write-Verbose "Initial URL: $apiUrl"
$typeMessage = @()
if ($UserType -contains 'Member') {
    $typeMessage += "member users with $MemberDaysOfInactivity+ days"
}
if ($UserType -contains 'Guest') {
    $typeMessage += "guest users with $GuestDaysOfInactivity+ days"
}
Write-Host -ForegroundColor Green "$(Get-Date) Getting $($typeMessage -join ' and ') of sign-in inactivity..."
do {
    # Get data via Graph and continue paging until complete
    $response = Invoke-MgGraphRequest -Method GET $apiUrl -OutputType PSObject
    $apiUrl = $($response."@odata.nextLink")
    if ($apiUrl) { Write-Verbose "@odata.nextLink: $apiUrl" }
    $result.AddRange($response.value) | Out-Null
}
until ($null -eq $response."@odata.nextLink")

if ($result.Count -gt 0) {
    # Processing user data to prepare export
    #Write-Host -ForegroundColor Green "$(Get-Date) Processing $($result.Count) returned users..."

    $return=@()
    foreach ($item in $result) {
        if (($UserType -contains 'Member' -and $item.userType -eq 'Member') -or 
            ($UserType -contains 'Guest' -and $item.userType -eq 'Guest' -and $item.'signInActivity'.$($siFilter.SubString($siFilter.IndexOf('/')+1)) -lt $guestTargetDate)) {

            if ($null -ne $item.userPrincipalName -and $item.accountEnabled -eq $true) {
                $return += New-Object -TypeName PSObject -Property @{
                    UserPrincipalName = $item.userPrincipalName
                    LastSuccessfulSignIn = $item.signInActivity.lastSuccessfulSignInDateTime
                    LastInteractiveSignIn = $item.signInActivity.lastSignInDateTime
                    LastNonInteractiveSignIn = $item.signInActivity.lastNonInteractiveSignInDateTime
                    UserType = $item.userType
                }
            }
        }
    }

    if ($return.Count -gt 0) {
        # ─────────────────────────────────────────────
        # Contadores de resumen
        # ─────────────────────────────────────────────
        $countMembers = ($return | Where-Object { $_.UserType -eq 'Member' }).Count
        $countGuests  = ($return | Where-Object { $_.UserType -eq 'Guest'  }).Count
        $countTotal   = $return.Count

        # Export to CSV unless opted out
        if ($DoNotExportToCSV -eq $false) {
            Write-Host -ForegroundColor Green "$(Get-Date) Exporting CSV: $csvPath"
            $return | Select-Object -Property UserPrincipalName,UserType,LastSuccessfulSignIn,LastInteractiveSignIn,LastNonInteractiveSignIn | Export-CSV $csvPath -NoTypeInformation -Encoding utf8BOM
        }

        if ($DoNotExportToCSV -eq $true) {
            $return
        }

        # ─────────────────────────────────────────────
        # Exportar a HTML
        # ─────────────────────────────────────────────
        $htmlHead = @"
<style>
    body   { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 20px; background: #f5f5f5; color: #333; }
    h1     { color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 8px; }
    h2     { color: #005a9e; margin-top: 30px; }
    table  { border-collapse: collapse; width: 100%; margin-top: 10px; font-size: 13px; }
    th     { background: #0078d4; color: #fff; padding: 10px; text-align: left; }
    td     { border: 1px solid #ddd; padding: 8px; color: #333; }
    tr:nth-child(even) { background: #e9e9e9; }
    tr:nth-child(odd)  { background: #fff; }
    .member  { color: #0078d4; font-weight: bold; }
    .guest   { color: #ca5010; font-weight: bold; }
    .summary { background: #0078d4; color: #fff; padding: 12px 20px; border-radius: 6px; display: inline-block; margin: 5px; }
</style>
"@

        try {
            $tenantDetail = Get-MgOrganization | Select-Object -First 1
            $tenantName   = $tenantDetail.DisplayName
        } catch {
            $tenantName   = "N/A"
        }
        $tenantId = (Get-MgContext).TenantId

        $htmlBody = @"
<h1>Reporte de Usuarios Inactivos - Microsoft Entra ID <em style="font-size: 0.75em; font-weight: normal; margin-left: 80px;">&ldquo;La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad&rdquo;</em></h1>
<p>Tenant: $tenantName | Tenant ID: $tenantId | Generado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<p>Tipo de inicio de sesión evaluado: <strong>$SignInType</strong> | Inactividad miembros: <strong>$MemberDaysOfInactivity días</strong> | Inactividad invitados: <strong>$GuestDaysOfInactivity días</strong></p>

<div>
    <span class="summary">Miembros: $countMembers</span>
    <span class="summary">Invitados: $countGuests</span>
    <span class="summary">Total: $countTotal</span>
</div>

<h2>Detalle de Usuarios Inactivos</h2>
"@

        $htmlTable = $return |
            Select-Object -Property UserPrincipalName,UserType,LastSuccessfulSignIn,LastInteractiveSignIn,LastNonInteractiveSignIn |
            ConvertTo-Html -Fragment | Out-String

        # Colorear tipos de usuario en HTML
        $htmlTable = $htmlTable -replace '<td>Member</td>', '<td class="member">Member</td>'
        $htmlTable = $htmlTable -replace '<td>Guest</td>',  '<td class="guest">Guest</td>'

        $htmlFooter = '<footer style="text-align: center; margin-top: 40px; padding: 15px 0; border-top: 2px solid #0078d4; color: #555; font-size: 13px;">chiringuito365.com&reg; | Internal Tools 2026</footer>'

        $fullHtml = ConvertTo-Html -Head $htmlHead -Body ($htmlBody + $htmlTable + $htmlFooter) -Title "Inactive Users Report" | Out-String

        try {
            $fullHtml | Out-File -FilePath $htmlPath -Encoding UTF8
            Write-Host -ForegroundColor Green "$(Get-Date) Reporte HTML exportado: $htmlPath"
            Invoke-Item $htmlPath
        }
        catch {
            Write-Host -ForegroundColor Red "$(Get-Date) Error al exportar HTML: $($_.Exception.Message)"
        }
    } else {
        Write-Host -ForegroundColor Green "$(Get-Date) No users match the search criteria."
    }
} else {
    Write-Host -ForegroundColor Green "$(Get-Date) No users were returned based on the search criteria."
}

Write-Host -ForegroundColor Green "$(Get-Date) Script has completed."
# Stop-Transcript
