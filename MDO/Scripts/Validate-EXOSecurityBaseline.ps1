##############################################################################################
# This sample script is not supported under any Microsoft standard support program or service.
# This sample script is provided AS IS without warranty of any kind.
# Microsoft further disclaims all implied warranties including, without limitation, any implied
# warranties of merchantability or of fitness for a particular purpose. The entire risk arising
# out of the use or performance of the sample script and documentation remains with you. In no
# event shall Microsoft, its authors, or anyone else involved in the creation, production, or
# delivery of the scripts be liable for any damages whatsoever (including, without limitation,
# damages for loss of business profits, business interruption, loss of business information,
# or other pecuniary loss) arising out of the use of or inability to use the sample script or
# documentation, even if Microsoft has been advised of the possibility of such damages.
##############################################################################################
<#
.SYNOPSIS
    Valida la línea base de seguridad en Exchange Online y genera un dashboard HTML.

.DESCRIPTION
    Este script verifica las configuraciones recomendadas del documento
    "Línea base para mejorar la postura de seguridad en Exchange Online":

    1. Reglas básicas de flujo de correo – Microsoft 365
       - Block emails to *.onmicrosoft.com
       - Quarantine Attachments Can't be inspected

    2. RejectDirectSend en Exchange Online
       - Get-OrganizationConfig | Select RejectDirectSend  (esperado: $true)

    3. Estándares SPF, DKIM, DMARC y MTA-STS
       - Consulta DNS para todos los dominios aceptados del tenant

    4. Conditional Access – Bloqueo de autenticación legacy
       - Microsoft Graph: política habilitada con bloqueo de "Other clients"

    5. AutoForwarding Controls
       - Outbound spam filter policy
       - Remote domain
       - Mail flow rule
       - Exchange role assignment policy

    Genera un reporte HTML tipo dashboard con semáforos de cumplimiento.

.NOTES
    Requiere privilegios para:
        - Exchange Online
        - Microsoft Graph (Policy.Read.All, Directory.Read.All)

    Requiere módulos:
        - ExchangeOnlineManagement
        - Microsoft.Graph.Identity.SignIns
        - DomainHealthChecker (opcional)

    Autor  : Ernesto Cobos Roqueñí, Arturo Mandujano
    Fecha  : 22/junio/2026
    Versión: 1.2

    Referencia:
    https://github.com/watchdogcode/gol2026/blob/main/MDO/L%C3%ADnea%20base%20para%20mejorar%20la%20postura%20de%20seguridad%20en%20Exchange%20online.md
#>

#Requires -Version 5.1

# ─────────────────────────────────────────────
# Configuración general
# ─────────────────────────────────────────────
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────
# Funciones auxiliares
# ─────────────────────────────────────────────
function Ensure-Module {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Host "Instalando módulo $Name..." -ForegroundColor Yellow
        Install-Module -Name $Name -Force -Scope CurrentUser -AllowClobber
    }

    if (-not (Get-Module -Name $Name)) {
        Import-Module $Name -ErrorAction Stop
    }
}

function ConvertTo-FlatString {
    param([object]$Value)

    if ($null -eq $Value) { return "" }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return ($Value | ForEach-Object { $_.ToString() }) -join "; "
    }

    return $Value.ToString()
}

function ConvertTo-HtmlText {
    param([AllowNull()][object]$Text)

    if ($null -eq $Text) { return "" }

    return [System.Net.WebUtility]::HtmlEncode((ConvertTo-FlatString $Text))
}

function Ensure-ExchangeConnection {
    [CmdletBinding()]
    param()

    Ensure-Module -Name ExchangeOnlineManagement

    try {
        $exoConn = Get-ConnectionInformation -ErrorAction Stop | Where-Object { $_.State -eq 'Connected' }
        if (-not $exoConn) {
            throw "No hay sesión activa de Exchange Online."
        }
        Write-Host "Sesión activa de Exchange Online detectada." -ForegroundColor DarkGray
    }
    catch {
        Write-Host "Conectando a Exchange Online..." -ForegroundColor Yellow
        try {
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
            Write-Host "Conexión a Exchange Online establecida exitosamente." -ForegroundColor Green
        }
        catch {
            Write-Host "No fue posible conectarse a Exchange Online: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }
}

function Ensure-GraphConnection {
    [CmdletBinding()]
    param()

    Ensure-Module -Name Microsoft.Graph.Identity.SignIns

    $requiredScopes = @(
        "Policy.Read.All",
        "Directory.Read.All"
    )

    $needReconnect = $false
    $ctx = $null

    try {
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $ctx -or -not $ctx.Account) {
            $needReconnect = $true
        }
        else {
            foreach ($scope in $requiredScopes) {
                if (-not ($ctx.Scopes -contains $scope)) {
                    $needReconnect = $true
                    break
                }
            }
        }
    }
    catch {
        $needReconnect = $true
    }

    if ($needReconnect) {
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        catch { }

        Write-Host "Conectando a Microsoft Graph..." -ForegroundColor Yellow
        try {
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop | Out-Null
            $ctx = Get-MgContext -ErrorAction SilentlyContinue

            if (-not $ctx -or -not $ctx.Account) {
                throw "No se obtuvo una sesión válida en Microsoft Graph después de Connect-MgGraph."
            }

            foreach ($scope in $requiredScopes) {
                if (-not ($ctx.Scopes -contains $scope)) {
                    throw "La sesión de Graph no contiene el scope requerido: $scope"
                }
            }

            Write-Host "Conexión a Microsoft Graph establecida exitosamente." -ForegroundColor Green
        }
        catch {
            throw "No fue posible autenticarse en Microsoft Graph. Detalle: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "Sesión activa de Microsoft Graph detectada." -ForegroundColor DarkGray
    }
}

function Test-LegacyAuthBlock {
    [CmdletBinding()]
    param()

    try {
        Ensure-GraphConnection

        $pols = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop

        foreach ($p in $pols) {
            if ($p.State -ne 'enabled') { continue }

            $clientTypes  = @($p.Conditions.ClientAppTypes) | ForEach-Object { $_.ToString().ToLower() }
            $grantBuiltIn = @($p.GrantControls.BuiltInControls) | ForEach-Object { $_.ToString().ToLower() }

            if (($clientTypes -contains 'other') -and ($grantBuiltIn -contains 'block')) {
                return [PSCustomObject]@{
                    DisplayName = $p.DisplayName
                    Id          = $p.Id
                    State       = $p.State
                    ClientApps  = ($clientTypes -join ', ')
                    Controls    = ($grantBuiltIn -join ', ')
                }
            }
        }

        return $null
    }
    catch {
        return [PSCustomObject]@{
            Error = "Graph connection failed: $($_.Exception.Message)"
        }
    }
}

# ─────────────────────────────────────────────
# Funciones auxiliares - AutoForwarding
# ─────────────────────────────────────────────
function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Control,
        [Parameter(Mandatory)][string]$ObjectName,
        [Parameter(Mandatory)][string]$Status,   # pass | fail | warn | info
        [Parameter(Mandatory)][string]$Finding,
        [string]$CurrentValue = "",
        [string]$RecommendedValue = "",
        [string]$Notes = ""
    )

    [PSCustomObject]@{
        Control          = $Control
        ObjectName       = $ObjectName
        Status           = $Status
        Finding          = $Finding
        CurrentValue     = $CurrentValue
        RecommendedValue = $RecommendedValue
        Notes            = $Notes
    }
}

function Test-AnyPropertyValue {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string[]]$PropertyNames
    )

    foreach ($prop in $PropertyNames) {
        if ($Object.PSObject.Properties.Name -contains $prop) {
            $val = $Object.$prop
            if ($null -ne $val) {
                if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
                    if (@($val).Count -gt 0) { return $true }
                }
                else {
                    if (-not [string]::IsNullOrWhiteSpace([string]$val)) { return $true }
                }
            }
        }
    }

    return $false
}

function Get-SafeString {
    param([object]$Value)

    if ($null -eq $Value) { return "" }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return (@($Value) -join "; ")
    }

    return [string]$Value
}

# ─────────────────────────────────────────────
# Validación de módulos y conexiones
# ─────────────────────────────────────────────
Ensure-ExchangeConnection

# ─────────────────────────────────────────────
# Carpeta de reportes
# ─────────────────────────────────────────────
$reportDir = "C:\Scripts\SecurityBaseline"
if (-not (Test-Path $reportDir)) {
    New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
}
Write-Host "Carpeta de reportes: $reportDir" -ForegroundColor DarkGray

$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$orgConfig  = Get-OrganizationConfig
$tenantName = $orgConfig.DisplayName
$htmlPath   = Join-Path $reportDir "SecurityBaseline_$timestamp.html"

Write-Host "Analizando líneas base recomendadas..." -ForegroundColor Yellow

# ═════════════════════════════════════════════
# SECCIÓN 1: Reglas básicas de flujo de correo
# ═════════════════════════════════════════════
try {
    $allRules = Get-TransportRule -ResultSize Unlimited | Sort-Object Priority
}
catch {
    $allRules = @()
}

# --- Regla 1: Block emails to *.onmicrosoft.com ---
$blockOnMicrosoftRule = $allRules | Where-Object {
    $_.Comments -like "*Blocks messages whose 'To' header matches*"
}

if ($blockOnMicrosoftRule) {
    $blockOnMicrosoftStatus  = "Implementada"
    $blockOnMicrosoftClass   = "pass"
    $blockOnMicrosoftState   = ConvertTo-FlatString $blockOnMicrosoftRule.State
    $blockOnMicrosoftName    = ConvertTo-FlatString $blockOnMicrosoftRule.Name
    $blockOnMicrosoftMode    = ConvertTo-FlatString $blockOnMicrosoftRule.Mode
    $blockOnMicrosoftDetails = "Regla: $blockOnMicrosoftName | Estado: $blockOnMicrosoftState | Modo: $blockOnMicrosoftMode"
}
else {
    $blockOnMicrosoftStatus  = "Recomendación no implementada"
    $blockOnMicrosoftClass   = "fail"
    $blockOnMicrosoftState   = "N/A"
    $blockOnMicrosoftName    = "N/A"
    $blockOnMicrosoftMode    = "N/A"
    $blockOnMicrosoftDetails = "No se encontró ninguna regla cuyo Comments contenga: Blocks messages whose 'To' header matches"
}

# --- Regla 2: Quarantine Attachments Can't be inspected ---
$quarantineRule = $allRules | Where-Object {
    $_.Comments -like "*content can't be inspected*"
}

if ($quarantineRule) {
    $quarantineStatus  = "Implementada"
    $quarantineClass   = "pass"
    $quarantineState   = ConvertTo-FlatString $quarantineRule.State
    $quarantineName    = ConvertTo-FlatString $quarantineRule.Name
    $quarantineMode    = ConvertTo-FlatString $quarantineRule.Mode
    $quarantineDetails = "Regla: $quarantineName | Estado: $quarantineState | Modo: $quarantineMode"
}
else {
    $quarantineStatus  = "Recomendación no implementada"
    $quarantineClass   = "fail"
    $quarantineState   = "N/A"
    $quarantineName    = "N/A"
    $quarantineMode    = "N/A"
    $quarantineDetails = "No se encontró ninguna regla cuyo Comments contenga: content can't be inspected"
}

# ═════════════════════════════════════════════
# SECCIÓN 2: RejectDirectSend
# ═════════════════════════════════════════════
$rejectDirectSend = $orgConfig.RejectDirectSend

if ($rejectDirectSend -eq $true) {
    $rejectDSStatus  = "Implementada"
    $rejectDSClass   = "pass"
    $rejectDSDetails = "Set-OrganizationConfig -RejectDirectSend `$true está configurado correctamente."
}
else {
    $rejectDSStatus  = "Recomendación no implementada"
    $rejectDSClass   = "fail"
    $rejectDSDetails = "RejectDirectSend está en `$false. Se recomienda ejecutar: Set-OrganizationConfig -RejectDirectSend `$true"
}

# ═════════════════════════════════════════════
# SECCIÓN 3: Estándares SPF, DKIM, DMARC, MTA-STS
# ═════════════════════════════════════════════
$hasDHC = $false
try {
    if (Get-Module -ListAvailable -Name DomainHealthChecker) {
        Import-Module DomainHealthChecker -ErrorAction SilentlyContinue
        if (Get-Command -Name Invoke-SpfDkimDmarc -ErrorAction SilentlyContinue) {
            $hasDHC = $true
        }
    }
    else {
        try {
            Install-Module DomainHealthChecker -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
            Import-Module DomainHealthChecker -ErrorAction Stop
            if (Get-Command -Name Invoke-SpfDkimDmarc -ErrorAction SilentlyContinue) {
                $hasDHC = $true
            }
        }
        catch { }
    }
}
catch { }

try {
    $acceptedDomains = Get-AcceptedDomain | Sort-Object DomainName
}
catch {
    $acceptedDomains = @()
}

$domainResults = @()

foreach ($ad in $acceptedDomains) {
    $domain = $ad.DomainName.ToString()

    # SPF
    $spfRecord   = ""
    $spfStatus   = "fail"
    $spfAdvisory = "No encontrado"

    try {
        $spfTxt = Resolve-DnsName -Name $domain -Type TXT -ErrorAction SilentlyContinue |
            Where-Object { ($_.Strings -join '') -match '^\s*v=spf1\b' }

        if ($spfTxt) {
            $spfRecord = ($spfTxt.Strings -join '')
            if ($spfRecord -match '(^|\s)-all(\s|$)') {
                $spfStatus   = "pass"
                $spfAdvisory = "SPF con -all (hard fail) — Correcto"
            }
            elseif ($spfRecord -match '(^|\s)~all(\s|$)') {
                $spfStatus   = "warn"
                $spfAdvisory = "SPF con ~all (soft fail) — Se recomienda -all"
            }
            else {
                $spfStatus   = "warn"
                $spfAdvisory = "SPF encontrado pero sin -all"
            }
        }
    }
    catch { }

    # DKIM
    $dkimRecord   = ""
    $dkimStatus   = "fail"
    $dkimAdvisory = "No encontrado"

    try {
        foreach ($sel in @("selector1", "selector2")) {
            $dkimCheck = Resolve-DnsName -Name "$sel._domainkey.$domain" -Type CNAME -ErrorAction SilentlyContinue
            if ($dkimCheck) {
                $dkimRecord   = "$sel → $($dkimCheck.NameHost)"
                $dkimStatus   = "pass"
                $dkimAdvisory = "DKIM CNAME encontrado para $sel"
                break
            }
        }
    }
    catch { }

    # DMARC
    $dmarcRecord   = ""
    $dmarcStatus   = "fail"
    $dmarcAdvisory = "No encontrado"

    try {
        $dmarcTxt = Resolve-DnsName -Name "_dmarc.$domain" -Type TXT -ErrorAction SilentlyContinue
        if ($dmarcTxt) {
            $dmarcRecord = ($dmarcTxt.Strings -join '')
            if ($dmarcRecord -match 'p=reject') {
                $dmarcStatus   = "pass"
                $dmarcAdvisory = "DMARC con p=reject — Óptimo"
            }
            elseif ($dmarcRecord -match 'p=quarantine') {
                $dmarcStatus   = "warn"
                $dmarcAdvisory = "DMARC con p=quarantine — Se recomienda p=reject"
            }
            elseif ($dmarcRecord -match 'p=none') {
                $dmarcStatus   = "warn"
                $dmarcAdvisory = "DMARC con p=none — Solo monitoreo, se recomienda p=reject"
            }
            else {
                $dmarcStatus   = "warn"
                $dmarcAdvisory = "DMARC encontrado pero sin política clara"
            }
        }
    }
    catch { }

    # MTA-STS
    $mtaRecord   = ""
    $mtaStatus   = "fail"
    $mtaAdvisory = "No encontrado"

    try {
        $mtaTxt = Resolve-DnsName -Name "_mta-sts.$domain" -Type TXT -ErrorAction SilentlyContinue
        if ($mtaTxt) {
            $mtaRecord = ($mtaTxt.Strings -join '')
            if ($mtaRecord -match 'v=STSv1') {
                $mtaStatus   = "pass"
                $mtaAdvisory = "MTA-STS configurado"
            }
            else {
                $mtaStatus   = "warn"
                $mtaAdvisory = "Registro encontrado pero sin v=STSv1"
            }
        }
    }
    catch { }

    # Enriquecimiento opcional con DomainHealthChecker
    if ($hasDHC) {
        try {
            $dhc = Invoke-SpfDkimDmarc -Name $domain -ErrorAction SilentlyContinue
            if ($dhc) {
                if ($dhc.SpfAdvisory)   { $spfAdvisory   = $dhc.SpfAdvisory }
                if ($dhc.DkimAdvisory)  { $dkimAdvisory  = $dhc.DkimAdvisory }
                if ($dhc.DmarcAdvisory) { $dmarcAdvisory = $dhc.DmarcAdvisory }
                if ($dhc.MtaAdvisory)   { $mtaAdvisory   = $dhc.MtaAdvisory }

                if ($dhc.DkimRecord -and $dhc.DkimRecord -ne "yourDkimRecord") {
                    $dkimRecord = $dhc.DkimRecord
                    $dkimStatus = "pass"
                }
            }
        }
        catch { }
    }

    $domainResults += [PSCustomObject]@{
        Domain         = $domain
        DomainType     = $ad.DomainType
        Default        = $ad.Default
        SPFRecord      = $spfRecord
        SPFStatus      = $spfStatus
        SPFAdvisory    = $spfAdvisory
        DKIMRecord     = $dkimRecord
        DKIMStatus     = $dkimStatus
        DKIMAdvisory   = $dkimAdvisory
        DMARCRecord    = $dmarcRecord
        DMARCStatus    = $dmarcStatus
        DMARCAdvisory  = $dmarcAdvisory
        MTARecord      = $mtaRecord
        MTAStatus      = $mtaStatus
        MTAAdvisory    = $mtaAdvisory
    }
}

# ═════════════════════════════════════════════
# SECCIÓN 4: Conditional Access - Bloqueo de autenticación legacy
# ═════════════════════════════════════════════
$legacyAuthPolicy  = Test-LegacyAuthBlock
$legacyAuthStatus  = "No evaluado"
$legacyAuthClass   = "fail"
$legacyAuthDetails = "No se evaluó la política de Conditional Access."

if ($legacyAuthPolicy -and $legacyAuthPolicy.PSObject.Properties.Name -contains 'Error' -and $legacyAuthPolicy.Error) {
    $legacyAuthStatus  = "Error"
    $legacyAuthClass   = "warn"
    $legacyAuthDetails = $legacyAuthPolicy.Error
}
elseif ($null -ne $legacyAuthPolicy) {
    $legacyAuthStatus  = "Encontrada"
    $legacyAuthClass   = "pass"
    $legacyAuthDetails = "Política: $($legacyAuthPolicy.DisplayName) (ID: $($legacyAuthPolicy.Id)) | ClientApps: $($legacyAuthPolicy.ClientApps) | Controls: $($legacyAuthPolicy.Controls)"
}
else {
    $legacyAuthStatus  = "No encontrada"
    $legacyAuthClass   = "fail"
    $legacyAuthDetails = "No se encontró política habilitada que bloquee autenticación legacy."
}

# ═════════════════════════════════════════════
# SECCIÓN 5: AutoForwarding Controls
# ═════════════════════════════════════════════
Write-Host "Validando controles de auto-forwarding..." -ForegroundColor Yellow

$autoForwardResults = New-Object System.Collections.Generic.List[object]

# 5.1 Outbound spam filter policy
try {
    $outboundPolicies = Get-HostedOutboundSpamFilterPolicy
}
catch {
    $outboundPolicies = @()
    $autoForwardResults.Add((Add-Result -Control "Outbound spam filter policy" `
        -ObjectName "General" `
        -Status "warn" `
        -Finding "No fue posible obtener Hosted Outbound Spam Filter Policies." `
        -CurrentValue "" `
        -RecommendedValue "Validar manualmente" `
        -Notes $_.Exception.Message))
}

try {
    $outboundRules = Get-HostedOutboundSpamFilterRule -ErrorAction Stop
}
catch {
    $outboundRules = @()
}

foreach ($policy in $outboundPolicies) {
    $autoForwardingMode = $null
    if ($policy.PSObject.Properties.Name -contains "AutoForwardingMode") {
        $autoForwardingMode = [string]$policy.AutoForwardingMode
    }

    $isDefault = $false
    if ($policy.PSObject.Properties.Name -contains "IsDefault") {
        $isDefault = [bool]$policy.IsDefault
    }

    $appliedRules = @(
        $outboundRules |
        Where-Object {
            ($_.PSObject.Properties.Name -contains "HostedOutboundSpamFilterPolicy") -and
            ($_.HostedOutboundSpamFilterPolicy -eq $policy.Name) -and
            (
                ($_.PSObject.Properties.Name -notcontains "State") -or
                ($_.State -eq "Enabled")
            )
        }
    )

    $isApplied = $isDefault -or ($appliedRules.Count -gt 0)

    if (-not $isApplied) {
        $autoForwardResults.Add((Add-Result -Control "Outbound spam filter policy" `
            -ObjectName $policy.Name `
            -Status "info" `
            -Finding "Política encontrada pero no parece aplicada actualmente." `
            -CurrentValue "AutoForwardingMode=$autoForwardingMode" `
            -RecommendedValue "Off o Automatic" `
            -Notes "Se reporta como informativa porque no se detectó regla activa asociada y no es la política default."))
        continue
    }

    if ($autoForwardingMode -eq "On") {
        $autoForwardResults.Add((Add-Result -Control "Outbound spam filter policy" `
            -ObjectName $policy.Name `
            -Status "fail" `
            -Finding "La política permite automatic external forwarding." `
            -CurrentValue "AutoForwardingMode=On" `
            -RecommendedValue "Off o Automatic" `
            -Notes "Esto permite reenvío automático externo para el scope cubierto por la política."))
    }
    elseif ($autoForwardingMode -in @("Off","Automatic")) {
        $autoForwardResults.Add((Add-Result -Control "Outbound spam filter policy" `
            -ObjectName $policy.Name `
            -Status "pass" `
            -Finding "La política no permite automatic external forwarding." `
            -CurrentValue "AutoForwardingMode=$autoForwardingMode" `
            -RecommendedValue "Off o Automatic" `
            -Notes "Microsoft trata Automatic como bloqueado en el estado actual del servicio."))
    }
    else {
        $autoForwardResults.Add((Add-Result -Control "Outbound spam filter policy" `
            -ObjectName $policy.Name `
            -Status "warn" `
            -Finding "No fue posible interpretar el valor de AutoForwardingMode." `
            -CurrentValue "AutoForwardingMode=$autoForwardingMode" `
            -RecommendedValue "Off o Automatic" `
            -Notes "Revisar manualmente la política."))
    }
}

# 5.2 Remote domain
try {
    $remoteDomains = Get-RemoteDomain
}
catch {
    $remoteDomains = @()
    $autoForwardResults.Add((Add-Result -Control "Remote domain" `
        -ObjectName "General" `
        -Status "warn" `
        -Finding "No fue posible obtener Remote Domains." `
        -CurrentValue "" `
        -RecommendedValue "Validar manualmente" `
        -Notes $_.Exception.Message))
}

foreach ($rd in $remoteDomains) {
    $autoForwardEnabled = $null
    if ($rd.PSObject.Properties.Name -contains "AutoForwardEnabled") {
        $autoForwardEnabled = [bool]$rd.AutoForwardEnabled
    }

    $domainName = if ($rd.PSObject.Properties.Name -contains "DomainName") { $rd.DomainName } else { $rd.Name }

    if ($autoForwardEnabled -eq $true) {
        $autoForwardResults.Add((Add-Result -Control "Remote domain" `
            -ObjectName $rd.Name `
            -Status "fail" `
            -Finding "El remote domain permite auto-forwarding." `
            -CurrentValue "Domain=$domainName | AutoForwardEnabled=True" `
            -RecommendedValue "AutoForwardEnabled=False" `
            -Notes "Si este dominio es externo y no es una excepción de negocio controlada, representa exposición."))
    }
    elseif ($autoForwardEnabled -eq $false) {
        $autoForwardResults.Add((Add-Result -Control "Remote domain" `
            -ObjectName $rd.Name `
            -Status "pass" `
            -Finding "El remote domain bloquea auto-forwarding." `
            -CurrentValue "Domain=$domainName | AutoForwardEnabled=False" `
            -RecommendedValue "AutoForwardEnabled=False" `
            -Notes "Configuración correcta para evitar reenvío automático hacia ese dominio remoto."))
    }
    else {
        $autoForwardResults.Add((Add-Result -Control "Remote domain" `
            -ObjectName $rd.Name `
            -Status "warn" `
            -Finding "No fue posible interpretar AutoForwardEnabled." `
            -CurrentValue "Domain=$domainName" `
            -RecommendedValue "AutoForwardEnabled=False" `
            -Notes "Revisar manualmente esta entrada."))
    }
}

# 5.3 Mail flow rules
try {
    $transportRules = Get-TransportRule -ResultSize Unlimited
}
catch {
    $transportRules = @()
    $autoForwardResults.Add((Add-Result -Control "Mail flow rule" `
        -ObjectName "General" `
        -Status "warn" `
        -Finding "No fue posible obtener Transport Rules." `
        -CurrentValue "" `
        -RecommendedValue "Validar manualmente" `
        -Notes $_.Exception.Message))
}

$forwardingActionProps = @(
    "RedirectMessageTo",
    "BlindCopyTo",
    "AddToRecipients",
    "CopyTo"
)

$protectiveRules = @()
$riskyForwardingRules = @()

foreach ($rule in $transportRules) {
    if ($rule.PSObject.Properties.Name -contains "State") {
        if ($rule.State -ne "Enabled") { continue }
    }

    $messageTypes = @()
    if ($rule.PSObject.Properties.Name -contains "MessageTypeMatches") {
        $messageTypes = @($rule.MessageTypeMatches | ForEach-Object { [string]$_ })
    }

    $sentToScope = if ($rule.PSObject.Properties.Name -contains "SentToScope") { [string]$rule.SentToScope } else { "" }

    # Reglas de riesgo
    $hasForwardingAction = Test-AnyPropertyValue -Object $rule -PropertyNames $forwardingActionProps
    if ($hasForwardingAction) {
        $riskyForwardingRules += $rule
    }

    # Reglas protectoras
    $isAutoForwardRule = $false
    foreach ($mt in $messageTypes) {
        if ($mt -match "AutoForward") {
            $isAutoForwardRule = $true
            break
        }
    }

    $hasBlockingAction = $false
    if (($rule.PSObject.Properties.Name -contains "DeleteMessage") -and ($rule.DeleteMessage -eq $true)) {
        $hasBlockingAction = $true
    }
    if (($rule.PSObject.Properties.Name -contains "RejectMessageEnhancedStatusCode") -and (-not [string]::IsNullOrWhiteSpace([string]$rule.RejectMessageEnhancedStatusCode))) {
        $hasBlockingAction = $true
    }
    if (($rule.PSObject.Properties.Name -contains "RejectMessageReasonText") -and (-not [string]::IsNullOrWhiteSpace([string]$rule.RejectMessageReasonText))) {
        $hasBlockingAction = $true
    }

    if ($isAutoForwardRule -and ($sentToScope -match "NotInOrganization|Outside")) {
        $protectiveRules += [PSCustomObject]@{
            Name               = $rule.Name
            Priority           = $rule.Priority
            SentToScope        = $sentToScope
            HasBlockingAction  = $hasBlockingAction
            MessageTypeMatches = ($messageTypes -join "; ")
        }
    }
}

if ($riskyForwardingRules.Count -gt 0) {
    foreach ($rr in $riskyForwardingRules) {
        $actions = @()
        foreach ($p in $forwardingActionProps) {
            if ($rr.PSObject.Properties.Name -contains $p) {
                $v = $rr.$p
                if ($null -ne $v) {
                    if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
                        if (@($v).Count -gt 0) { $actions += "$p=$(Get-SafeString $v)" }
                    }
                    else {
                        if (-not [string]::IsNullOrWhiteSpace([string]$v)) { $actions += "$p=$(Get-SafeString $v)" }
                    }
                }
            }
        }

        $autoForwardResults.Add((Add-Result -Control "Mail flow rule" `
            -ObjectName $rr.Name `
            -Status "fail" `
            -Finding "La regla tiene acciones de forwarding/redirect y debe revisarse." `
            -CurrentValue ($actions -join " | ") `
            -RecommendedValue "No usar acciones de redirección/reenvío salvo excepción justificada." `
            -Notes "Regla activa con acciones que pueden facilitar forwarding automático."))
    }
}

if ($protectiveRules.Count -eq 0) {
    $autoForwardResults.Add((Add-Result -Control "Mail flow rule" `
        -ObjectName "Protective rule for AutoForward" `
        -Status "warn" `
        -Finding "No se detectó una regla activa específica para mensajes de tipo AutoForward hacia fuera de la organización." `
        -CurrentValue "0 reglas protectoras" `
        -RecommendedValue "Al menos 1 regla protectora para MessageTypeMatches=AutoForward y destino externo" `
        -Notes "Esta ausencia no significa por sí sola que exista forwarding, pero reduce visibilidad/defensa adicional."))
}
else {
    foreach ($pr in $protectiveRules) {
        $status = if ($pr.HasBlockingAction) { "pass" } else { "warn" }
        $finding = if ($pr.HasBlockingAction) {
            "Existe regla protectora para AutoForward externo con acción de bloqueo."
        }
        else {
            "Existe regla para AutoForward externo, pero no se detectó claramente una acción de bloqueo."
        }

        $autoForwardResults.Add((Add-Result -Control "Mail flow rule" `
            -ObjectName $pr.Name `
            -Status $status `
            -Finding $finding `
            -CurrentValue "MessageTypeMatches=$($pr.MessageTypeMatches) | SentToScope=$($pr.SentToScope) | Priority=$($pr.Priority)" `
            -RecommendedValue "Regla activa para AutoForward externo con acción de rechazo o eliminación" `
            -Notes "Validación adicional orientada a hardening y visibilidad."))
    }
}

# 5.4 Exchange role assignment policy
try {
    $mailboxes = Get-Mailbox -RecipientTypeDetails UserMailbox,SharedMailbox -ResultSize Unlimited
}
catch {
    try {
        $mailboxes = Get-Mailbox -ResultSize Unlimited
    }
    catch {
        $mailboxes = @()
        $autoForwardResults.Add((Add-Result -Control "Role assignment policy" `
            -ObjectName "General" `
            -Status "warn" `
            -Finding "No fue posible obtener buzones para validar RoleAssignmentPolicy." `
            -CurrentValue "" `
            -RecommendedValue "Validar manualmente" `
            -Notes $_.Exception.Message))
    }
}

if ($mailboxes.Count -gt 0) {
    $assignedPolicySummary = $mailboxes |
        Group-Object -Property RoleAssignmentPolicy |
        Sort-Object Count -Descending

    foreach ($policyGroup in $assignedPolicySummary) {
        $policyName = [string]$policyGroup.Name
        $mbxCount   = [int]$policyGroup.Count

        if ([string]::IsNullOrWhiteSpace($policyName)) {
            $autoForwardResults.Add((Add-Result -Control "Role assignment policy" `
                -ObjectName "(Sin policy asignada)" `
                -Status "warn" `
                -Finding "Se detectaron buzones sin RoleAssignmentPolicy explícita en la propiedad consultada." `
                -CurrentValue "Mailboxes=$mbxCount" `
                -RecommendedValue "Validar asignación efectiva de policy" `
                -Notes "Revisar manualmente si estos buzones heredan por plan/licencia."))
            continue
        }

        try {
            $roleAssignments = Get-ManagementRoleAssignment -RoleAssignee $policyName -ErrorAction Stop |
                Select-Object -ExpandProperty Role -Unique
        }
        catch {
            $autoForwardResults.Add((Add-Result -Control "Role assignment policy" `
                -ObjectName $policyName `
                -Status "warn" `
                -Finding "No fue posible obtener los roles asignados a la policy." `
                -CurrentValue "Mailboxes=$mbxCount" `
                -RecommendedValue "Revisar manualmente" `
                -Notes $_.Exception.Message))
            continue
        }

        $exposedParams = @()
        $rolesChecked  = @()

        foreach ($role in $roleAssignments) {
            $rolesChecked += $role

            try {
                $entry = Get-ManagementRoleEntry "$role\Set-Mailbox" -ErrorAction Stop
                $params = @($entry.Parameters)

                foreach ($p in @("ForwardingAddress","ForwardingSmtpAddress","DeliverToMailboxAndForward")) {
                    if ($params -contains $p) {
                        $exposedParams += "$role->$p"
                    }
                }
            }
            catch {
                # No todos los roles tienen entrada Set-Mailbox
            }
        }

        $exposedParams = $exposedParams | Select-Object -Unique

        if ($exposedParams.Count -gt 0) {
            $autoForwardResults.Add((Add-Result -Control "Role assignment policy" `
                -ObjectName $policyName `
                -Status "fail" `
                -Finding "La policy expone parámetros de Set-Mailbox que permiten configurar SMTP forwarding." `
                -CurrentValue ($exposedParams -join " | ") `
                -RecommendedValue "Quitar ForwardingAddress, ForwardingSmtpAddress y DeliverToMailboxAndForward de la experiencia disponible al usuario" `
                -Notes "Buzones con esta policy asignada: $mbxCount"))
        }
        else {
            $autoForwardResults.Add((Add-Result -Control "Role assignment policy" `
                -ObjectName $policyName `
                -Status "pass" `
                -Finding "No se detectaron parámetros de forwarding expuestos en Set-Mailbox para esta policy." `
                -CurrentValue "Roles inspeccionados: $($rolesChecked.Count)" `
                -RecommendedValue "Sin exposición de parámetros de forwarding" `
                -Notes "Buzones con esta policy asignada: $mbxCount"))
        }
    }
}

# ─────────────────────────────────────────────
# Contadores para el dashboard
# ─────────────────────────────────────────────
$totalChecks = 0
$passChecks  = 0
$failChecks  = 0
$warnChecks  = 0
$infoChecks  = 0

foreach ($c in @($blockOnMicrosoftClass, $quarantineClass, $rejectDSClass, $legacyAuthClass)) {
    $totalChecks++
    switch ($c) {
        "pass" { $passChecks++ }
        "fail" { $failChecks++ }
        "warn" { $warnChecks++ }
        "info" { $infoChecks++ }
    }
}

foreach ($dr in $domainResults) {
    foreach ($st in @($dr.SPFStatus, $dr.DKIMStatus, $dr.DMARCStatus, $dr.MTAStatus)) {
        $totalChecks++
        switch ($st) {
            "pass" { $passChecks++ }
            "fail" { $failChecks++ }
            "warn" { $warnChecks++ }
            "info" { $infoChecks++ }
        }
    }
}

foreach ($afr in $autoForwardResults) {
    $totalChecks++
    switch ($afr.Status) {
        "pass" { $passChecks++ }
        "fail" { $failChecks++ }
        "warn" { $warnChecks++ }
        "info" { $infoChecks++ }
    }
}

$compliancePercent = if ($totalChecks -gt 0) {
    [math]::Round(($passChecks / $totalChecks) * 100, 1)
}
else { 0 }

# ─────────────────────────────────────────────
# Resumen específico de AutoForwarding
# ─────────────────────────────────────────────
$afPassCount = @($autoForwardResults | Where-Object { $_.Status -eq "pass" }).Count
$afFailCount = @($autoForwardResults | Where-Object { $_.Status -eq "fail" }).Count
$afWarnCount = @($autoForwardResults | Where-Object { $_.Status -eq "warn" }).Count
$afInfoCount = @($autoForwardResults | Where-Object { $_.Status -eq "info" }).Count

$afOverallStatus = if ($afFailCount -gt 0) { "FAIL" }
elseif ($afWarnCount -gt 0) { "WARN" }
else { "PASS" }

$afOverallClass = if ($afOverallStatus -eq "PASS") { "pass" } elseif ($afOverallStatus -eq "WARN") { "warn" } else { "fail" }
$afOverallIcon  = if ($afOverallStatus -eq "PASS") { "✅" } elseif ($afOverallStatus -eq "WARN") { "⚠️" } else { "❌" }

# ─────────────────────────────────────────────
# Generar HTML Dashboard
# ─────────────────────────────────────────────
$htmlHead = @"
<style>
    * { box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; padding: 20px; background: #f0f2f5; color: #333; }
    .header { background: linear-gradient(135deg, #0078d4, #005a9e); color: #fff; padding: 30px; border-radius: 10px; margin-bottom: 25px; display: flex; align-items: center; justify-content: space-between; }
    .header-text { flex: 1; }
    .header-logo { flex-shrink: 0; margin-left: 30px; }
    .header-logo img { height: 50px; filter: brightness(0) invert(1); }
    .header h1 { margin: 0 0 5px 0; font-size: 24px; }
    .header p { margin: 5px 0; opacity: 0.95; font-size: 14px; }
    .header .quote { font-style: italic; opacity: 0.85; margin-top: 10px; font-size: 17px; }

    .dashboard { display: flex; gap: 15px; margin-bottom: 25px; flex-wrap: wrap; }
    .card { background: #fff; border-radius: 10px; padding: 20px; flex: 1; min-width: 180px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }
    .card .number { font-size: 36px; font-weight: bold; margin: 10px 0; }
    .card .label { font-size: 13px; color: #666; text-transform: uppercase; letter-spacing: 1px; }
    .card.total .number { color: #0078d4; }
    .card.pass .number { color: #107c10; }
    .card.fail .number { color: #d13438; }
    .card.warn .number { color: #ff8c00; }
    .card.info .number { color: #5c2d91; }
    .card.percent .number { color: #0078d4; }

    .section { background: #fff; border-radius: 10px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    .section h2 { color: #0078d4; margin-top: 0; border-bottom: 2px solid #0078d4; padding-bottom: 8px; font-size: 18px; }
    .section h3 { color: #005a9e; margin-top: 20px; font-size: 15px; }

    table { border-collapse: collapse; width: 100%; margin-top: 10px; font-size: 13px; }
    th { background: #0078d4; color: #fff; padding: 10px 12px; text-align: left; }
    td { border: 1px solid #e0e0e0; padding: 8px 12px; vertical-align: top; }
    tr:nth-child(even) { background: #f8f9fa; }
    tr:nth-child(odd) { background: #fff; }

    .badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; color: #fff; }
    .badge.pass { background: #107c10; }
    .badge.fail { background: #d13438; }
    .badge.warn { background: #ff8c00; }
    .badge.info { background: #5c2d91; }

    .status-row { display: flex; align-items: center; padding: 12px 15px; border-radius: 8px; margin-bottom: 8px; }
    .status-row.pass { background: #f0fff0; border-left: 4px solid #107c10; }
    .status-row.fail { background: #fff5f5; border-left: 4px solid #d13438; }
    .status-row.warn { background: #fffaf0; border-left: 4px solid #ff8c00; }
    .status-row.info { background: #f7f3ff; border-left: 4px solid #5c2d91; }
    .status-row .icon { font-size: 20px; margin-right: 12px; }
    .status-row .info { flex: 1; }
    .status-row .info .title { font-weight: bold; font-size: 14px; }
    .status-row .info .detail { font-size: 12px; color: #666; margin-top: 3px; word-break: break-word; }

    .ref-link { font-size: 12px; color: #0078d4; text-decoration: none; }
    .ref-link:hover { text-decoration: underline; }

    footer { text-align: center; margin-top: 30px; padding: 15px 0; border-top: 2px solid #0078d4; color: #555; font-size: 13px; }
    code { white-space: pre-wrap; word-break: break-all; }
</style>
"@

$htmlBody = @"
<div class="header">
    <div class="header-text">
        <h1>🛡 Validación de Línea Base de Seguridad — Exchange Online</h1>
        <p><strong>Tenant:</strong> $(ConvertTo-HtmlText $tenantName) &nbsp;|&nbsp; <strong>Generado:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p class="quote">“La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad”</p>
    </div>
    <div class="header-logo">
        <img src="https://cdn.theatlantic.com/assets/marketing/prod/logos/2024/03/MS-Security_logo_horiz_c-gray_rgb_1_O3yRRKf.png" alt="Microsoft Security">
    </div>
</div>
"@

$htmlBody += @"
<div class="dashboard">
    <div class="card total">
        <div class="label">Verificaciones</div>
        <div class="number">$totalChecks</div>
    </div>
    <div class="card pass">
        <div class="label">Cumple</div>
        <div class="number">$passChecks</div>
    </div>
    <div class="card fail">
        <div class="label">No Cumple</div>
        <div class="number">$failChecks</div>
    </div>
    <div class="card warn">
        <div class="label">Advertencia</div>
        <div class="number">$warnChecks</div>
    </div>
    <div class="card info">
        <div class="label">Info</div>
        <div class="number">$infoChecks</div>
    </div>
    <div class="card percent">
        <div class="label">Cumplimiento</div>
        <div class="number">${compliancePercent}%</div>
    </div>
</div>
"@

# ─── Sección 1: Reglas de flujo de correo ───
$blockIcon      = if ($blockOnMicrosoftClass -eq "pass") { "✅" } else { "❌" }
$quarantineIcon = if ($quarantineClass -eq "pass") { "✅" } else { "❌" }

$htmlBody += @"
<div class="section">
    <h2>1. Reglas básicas de flujo de correo — Microsoft 365</h2>
    <p style="font-size:13px; color:#666;">Se verifican las reglas de transporte recomendadas para proteger contra correos a dominios onmicrosoft.com y adjuntos no inspeccionables.</p>

    <div class="status-row $blockOnMicrosoftClass">
        <div class="icon">$blockIcon</div>
        <div class="info">
            <div class="title">Block emails to *.onmicrosoft.com</div>
            <div class="detail">Estado: <span class="badge $blockOnMicrosoftClass">$(ConvertTo-HtmlText $blockOnMicrosoftStatus)</span></div>
            <div class="detail">$(ConvertTo-HtmlText $blockOnMicrosoftDetails)</div>
            <div class="detail">Busca en Comments: <em>"Blocks messages whose 'To' header matches"</em></div>
        </div>
    </div>

    <div class="status-row $quarantineClass">
        <div class="icon">$quarantineIcon</div>
        <div class="info">
            <div class="title">Quarantine Attachments Can't be inspected</div>
            <div class="detail">Estado: <span class="badge $quarantineClass">$(ConvertTo-HtmlText $quarantineStatus)</span></div>
            <div class="detail">$(ConvertTo-HtmlText $quarantineDetails)</div>
            <div class="detail">Busca en Comments: <em>"If the message has any attachment whose content can't be inspected"</em></div>
        </div>
    </div>

    <h3>Todas las reglas de transporte del tenant</h3>
    <table>
        <tr>
            <th>Prioridad</th>
            <th>Nombre</th>
            <th>Estado</th>
            <th>Modo</th>
            <th>Última Modificación</th>
            <th>Comments (extracto)</th>
        </tr>
"@

foreach ($rule in $allRules) {
    $stateClass = if ($rule.State -eq 'Enabled') { 'pass' } else { 'fail' }

    $commentsText = ConvertTo-FlatString $rule.Comments
    if ([string]::IsNullOrWhiteSpace($commentsText)) {
        $commentsExcerpt = "&mdash;"
    }
    else {
        $shortText = if ($commentsText.Length -gt 100) { $commentsText.Substring(0,100) + "..." } else { $commentsText }
        $commentsExcerpt = ConvertTo-HtmlText $shortText
    }

    $htmlBody += "<tr>"
    $htmlBody += "<td style='text-align:center'>$(ConvertTo-HtmlText $rule.Priority)</td>"
    $htmlBody += "<td>$(ConvertTo-HtmlText $rule.Name)</td>"
    $htmlBody += "<td><span class='badge $stateClass'>$(ConvertTo-HtmlText $rule.State)</span></td>"
    $htmlBody += "<td>$(ConvertTo-HtmlText $rule.Mode)</td>"
    $htmlBody += "<td>$(ConvertTo-HtmlText $rule.WhenChanged)</td>"
    $htmlBody += "<td style='font-size:11px'>$commentsExcerpt</td>"
    $htmlBody += "</tr>"
}

$htmlBody += "</table>"
$htmlBody += '<p style="font-size:11px; margin-top:10px;"><a class="ref-link" href="https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules" target="_blank">🔗 Referencia: Mail flow rules in Exchange Online</a></p>'
$htmlBody += "</div>"

# ─── Sección 2: RejectDirectSend ───
$rejectIcon = if ($rejectDSClass -eq "pass") { "✅" } else { "❌" }

$htmlBody += @"
<div class="section">
    <h2>2. RejectDirectSend en Exchange Online</h2>
    <p style="font-size:13px; color:#666;">Direct Send permite enviar correos a buzones internos del tenant de forma anónima por SMTP puerto 25. Habilitando RejectDirectSend se bloquea este vector de ataque.</p>

    <div class="status-row $rejectDSClass">
        <div class="icon">$rejectIcon</div>
        <div class="info">
            <div class="title">RejectDirectSend = $(ConvertTo-HtmlText $rejectDirectSend)</div>
            <div class="detail">Estado: <span class="badge $rejectDSClass">$(ConvertTo-HtmlText $rejectDSStatus)</span></div>
            <div class="detail">$(ConvertTo-HtmlText $rejectDSDetails)</div>
        </div>
    </div>

    <table style="margin-top:15px;">
        <tr>
            <th>Propiedad</th>
            <th>Valor Actual</th>
            <th>Valor Recomendado</th>
            <th>Resultado</th>
        </tr>
        <tr>
            <td><code>RejectDirectSend</code></td>
            <td><strong>$(ConvertTo-HtmlText $rejectDirectSend)</strong></td>
            <td><strong>True</strong></td>
            <td><span class="badge $rejectDSClass">$(if ($rejectDSClass -eq 'pass') { 'Cumple' } else { 'No Cumple' })</span></td>
        </tr>
    </table>

    <p style="font-size:11px; margin-top:10px;">
        <a class="ref-link" href="https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig#-rejectdirectsend" target="_blank">🔗 Referencia: Set-OrganizationConfig -RejectDirectSend</a>
    </p>
</div>
"@

# ─── Sección 3: SPF, DKIM, DMARC, MTA-STS ───
$spfPassCount   = ($domainResults | Where-Object { $_.SPFStatus   -eq "pass" } | Measure-Object).Count
$dkimPassCount  = ($domainResults | Where-Object { $_.DKIMStatus  -eq "pass" } | Measure-Object).Count
$dmarcPassCount = ($domainResults | Where-Object { $_.DMARCStatus -eq "pass" } | Measure-Object).Count
$mtaPassCount   = ($domainResults | Where-Object { $_.MTAStatus   -eq "pass" } | Measure-Object).Count
$totalDomains   = ($domainResults | Measure-Object).Count

$htmlBody += @"
<div class="section">
    <h2>3. Estándares SPF, DKIM, DMARC y MTA-STS</h2>
    <p style="font-size:13px; color:#666;">Verificación DNS de los estándares de autenticación de correo para todos los dominios aceptados del tenant.</p>

    <div class="dashboard" style="margin-bottom:15px;">
        <div class="card" style="min-width:120px;"><div class="label">Dominios</div><div class="number" style="color:#0078d4;">$totalDomains</div></div>
        <div class="card" style="min-width:120px;"><div class="label">SPF OK</div><div class="number" style="color:#107c10;">$spfPassCount/$totalDomains</div></div>
        <div class="card" style="min-width:120px;"><div class="label">DKIM OK</div><div class="number" style="color:#107c10;">$dkimPassCount/$totalDomains</div></div>
        <div class="card" style="min-width:120px;"><div class="label">DMARC OK</div><div class="number" style="color:#107c10;">$dmarcPassCount/$totalDomains</div></div>
        <div class="card" style="min-width:120px;"><div class="label">MTA-STS OK</div><div class="number" style="color:#107c10;">$mtaPassCount/$totalDomains</div></div>
    </div>

    <table>
        <tr>
            <th>Dominio</th>
            <th>Tipo</th>
            <th>SPF</th>
            <th>DKIM</th>
            <th>DMARC</th>
            <th>MTA-STS</th>
        </tr>
"@

foreach ($dr in $domainResults) {
    $defaultMark = if ($dr.Default) { ' <span style="font-size:10px; color:#0078d4;">(Default)</span>' } else { '' }

    $htmlBody += "<tr>"
    $htmlBody += "<td><strong>$(ConvertTo-HtmlText $dr.Domain)</strong>$defaultMark</td>"
    $htmlBody += "<td>$(ConvertTo-HtmlText $dr.DomainType)</td>"
    $htmlBody += "<td><span class='badge $($dr.SPFStatus)'>$(ConvertTo-HtmlText $dr.SPFStatus.ToUpper())</span></td>"
    $htmlBody += "<td><span class='badge $($dr.DKIMStatus)'>$(ConvertTo-HtmlText $dr.DKIMStatus.ToUpper())</span></td>"
    $htmlBody += "<td><span class='badge $($dr.DMARCStatus)'>$(ConvertTo-HtmlText $dr.DMARCStatus.ToUpper())</span></td>"
    $htmlBody += "<td><span class='badge $($dr.MTAStatus)'>$(ConvertTo-HtmlText $dr.MTAStatus.ToUpper())</span></td>"
    $htmlBody += "</tr>"
}

$htmlBody += "</table>"
$htmlBody += "<h3>Detalle por dominio</h3>"

foreach ($dr in $domainResults) {
    $htmlBody += @"
    <table style="margin-bottom:15px;">
        <tr><th colspan="3" style="background:#005a9e;">$(ConvertTo-HtmlText $dr.Domain)</th></tr>
        <tr>
            <td style="width:100px;"><strong>SPF</strong></td>
            <td style="width:80px;"><span class="badge $($dr.SPFStatus)">$(ConvertTo-HtmlText $dr.SPFStatus.ToUpper())</span></td>
            <td style="font-size:11px;">$(ConvertTo-HtmlText $dr.SPFAdvisory)<br/><code style="font-size:10px;">$(ConvertTo-HtmlText $dr.SPFRecord)</code></td>
        </tr>
        <tr>
            <td><strong>DKIM</strong></td>
            <td><span class="badge $($dr.DKIMStatus)">$(ConvertTo-HtmlText $dr.DKIMStatus.ToUpper())</span></td>
            <td style="font-size:11px;">$(ConvertTo-HtmlText $dr.DKIMAdvisory)<br/><code style="font-size:10px;">$(ConvertTo-HtmlText $dr.DKIMRecord)</code></td>
        </tr>
        <tr>
            <td><strong>DMARC</strong></td>
            <td><span class="badge $($dr.DMARCStatus)">$(ConvertTo-HtmlText $dr.DMARCStatus.ToUpper())</span></td>
            <td style="font-size:11px;">$(ConvertTo-HtmlText $dr.DMARCAdvisory)<br/><code style="font-size:10px;">$(ConvertTo-HtmlText $dr.DMARCRecord)</code></td>
        </tr>
        <tr>
            <td><strong>MTA-STS</strong></td>
            <td><span class="badge $($dr.MTAStatus)">$(ConvertTo-HtmlText $dr.MTAStatus.ToUpper())</span></td>
            <td style="font-size:11px;">$(ConvertTo-HtmlText $dr.MTAAdvisory)<br/><code style="font-size:10px;">$(ConvertTo-HtmlText $dr.MTARecord)</code></td>
        </tr>
    </table>
"@
}

# ─── Sección 4: Conditional Access - Bloqueo Autenticación Legacy ───
$legacyIcon = if ($legacyAuthClass -eq "pass") { "✅" } elseif ($legacyAuthClass -eq "warn") { "⚠️" } else { "❌" }

$htmlBody += @"
<div class="section">
    <h2>4. Conditional Access — Bloqueo de Autenticación Legacy</h2>
    <p style="font-size:13px; color:#666;">Verifica si existe una política habilitada que bloquee clientes legacy (Other clients) mediante un control de acceso de tipo <strong>block</strong>.</p>

    <div class="status-row $legacyAuthClass">
        <div class="icon">$legacyIcon</div>
        <div class="info">
            <div class="title">Política que bloquea autenticación legacy</div>
            <div class="detail">Estado: <span class="badge $legacyAuthClass">$(ConvertTo-HtmlText $legacyAuthStatus)</span></div>
            <div class="detail">$(ConvertTo-HtmlText $legacyAuthDetails)</div>
            <div class="detail">Referencia: <a class="ref-link" href="https://learn.microsoft.com/azure/active-directory/conditional-access/legacy-auth" target="_blank">Legacy authentication and Conditional Access</a></div>
        </div>
    </div>
</div>
"@

$htmlBody += '<p style="font-size:11px; margin-top:10px;">'
$htmlBody += '<a class="ref-link" href="https://www.rfc-editor.org/rfc/rfc7208" target="_blank">🔗 SPF RFC 7208</a> &nbsp;|&nbsp; '
$htmlBody += '<a class="ref-link" href="https://dkim.org/" target="_blank">🔗 DKIM</a> &nbsp;|&nbsp; '
$htmlBody += '<a class="ref-link" href="https://www.rfc-editor.org/rfc/rfc7489.html" target="_blank">🔗 DMARC RFC 7489</a> &nbsp;|&nbsp; '
$htmlBody += '<a class="ref-link" href="https://www.rfc-editor.org/rfc/rfc8461" target="_blank">🔗 MTA-STS RFC 8461</a>'
$htmlBody += '</p>'
$htmlBody += "</div>"

# ─── Sección 5: AutoForwarding ───
$htmlBody += @"
<div class="section">
    <h2>5. AutoForwarding Controls</h2>
    <p style="font-size:13px; color:#666;">Valida que no exista auto-forwarding permitido en los controles clave de Exchange Online: Outbound spam filter policy, Remote domain, Mail flow rule y Exchange role assignment policy.</p>

    <div class="status-row $afOverallClass">
        <div class="icon">$afOverallIcon</div>
        <div class="info">
            <div class="title">Resultado general de AutoForwarding</div>
            <div class="detail">Estado: <span class="badge $afOverallClass">$afOverallStatus</span></div>
            <div class="detail">PASS: $afPassCount | FAIL: $afFailCount | WARN: $afWarnCount | INFO: $afInfoCount</div>
        </div>
    </div>

    <div class="dashboard" style="margin-bottom:15px;">
        <div class="card total" style="min-width:120px;"><div class="label">Checks AF</div><div class="number">$($autoForwardResults.Count)</div></div>
        <div class="card pass" style="min-width:120px;"><div class="label">Pass AF</div><div class="number">$afPassCount</div></div>
        <div class="card fail" style="min-width:120px;"><div class="label">Fail AF</div><div class="number">$afFailCount</div></div>
        <div class="card warn" style="min-width:120px;"><div class="label">Warn AF</div><div class="number">$afWarnCount</div></div>
        <div class="card info" style="min-width:120px;"><div class="label">Info AF</div><div class="number">$afInfoCount</div></div>
    </div>

    <table>
        <tr>
            <th>Control</th>
            <th>Objeto</th>
            <th>Status</th>
            <th>Finding</th>
            <th>Valor actual</th>
            <th>Valor recomendado</th>
            <th>Notas</th>
        </tr>
"@

foreach ($af in ($autoForwardResults | Sort-Object Control, Status, ObjectName)) {
    $htmlBody += "<tr>"
    $htmlBody += "<td>$(ConvertTo-HtmlText $af.Control)</td>"
    $htmlBody += "<td>$(ConvertTo-HtmlText $af.ObjectName)</td>"
    $htmlBody += "<td><span class='badge $($af.Status)'>$(ConvertTo-HtmlText $($af.Status.ToUpper()))</span></td>"
    $htmlBody += "<td>$(ConvertTo-HtmlText $af.Finding)</td>"
    $htmlBody += "<td style='font-size:11px'><code>$(ConvertTo-HtmlText $af.CurrentValue)</code></td>"
    $htmlBody += "<td style='font-size:11px'><code>$(ConvertTo-HtmlText $af.RecommendedValue)</code></td>"
    $htmlBody += "<td style='font-size:11px'>$(ConvertTo-HtmlText $af.Notes)</td>"
    $htmlBody += "</tr>"
}

$htmlBody += @"
    </table>

    <p style="font-size:11px; margin-top:10px;">
        Este bloque conserva el criterio original del validador: en mail flow rules no agrega un PASS cuando no existen reglas activas con acciones de forwarding/redirect; solo reporta riesgo real y la presencia/ausencia de reglas protectoras específicas para AutoForward.
    </p>
</div>
"@

# ─── Referencia ───
$htmlBody += @"
<div class="section">
    <h2>Referencia</h2>
    <p>Este reporte valida las configuraciones definidas en el documento:</p>
    <p><a class="ref-link" style="font-size:14px;" href="https://github.com/watchdogcode/gol2026/blob/main/MDO/L%C3%ADnea%20base%20para%20mejorar%20la%20postura%20de%20seguridad%20en%20Exchange%20online.md" target="_blank">🔗 Línea base para mejorar la postura de seguridad en Exchange Online</a></p>
</div>
"@

$htmlFooter = '<footer>chiringuito365.com® | Internal Tools 2026</footer>'

$htmlReport = ConvertTo-Html -Head $htmlHead -Body ($htmlBody + $htmlFooter) -Title "Security Baseline Validation - Exchange Online"

$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($htmlPath, ($htmlReport -join "`r`n"), $utf8Bom)

# ─────────────────────────────────────────────
# Resumen final en consola
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "================ RESUMEN GENERAL ================" -ForegroundColor Cyan
Write-Host ("Verificaciones : {0}" -f $totalChecks)
Write-Host ("PASS          : {0}" -f $passChecks)
Write-Host ("FAIL          : {0}" -f $failChecks)
Write-Host ("WARN          : {0}" -f $warnChecks)
Write-Host ("INFO          : {0}" -f $infoChecks)
Write-Host ("Cumplimiento  : {0}%" -f $compliancePercent)
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "================ AUTOFORWARDING ================" -ForegroundColor Cyan
Write-Host ("Overall : {0}" -f $afOverallStatus)
Write-Host ("PASS    : {0}" -f $afPassCount)
Write-Host ("FAIL    : {0}" -f $afFailCount)
Write-Host ("WARN    : {0}" -f $afWarnCount)
Write-Host ("INFO    : {0}" -f $afInfoCount)
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Reporte HTML generado: $htmlPath" -ForegroundColor Green

# Abrir el reporte HTML
Invoke-Item $htmlPath