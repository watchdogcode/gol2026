<#
.SYNOPSIS
    Obtiene un reporte detallado de todas las políticas de Conditional Access del tenant.

.DESCRIPTION
    Este script recopila la configuración completa de cada política de Conditional Access
    en Microsoft Entra ID (Azure AD), incluyendo:
    - Información general (nombre, estado, fecha de creación/modificación)
    - Condiciones (usuarios, grupos, aplicaciones, plataformas, ubicaciones, riesgo)
    - Controles de acceso (Grant / Session)
    
    Genera tres salidas:
    1. Reporte en consola con formato visual
    2. Exportación a CSV con todos los campos relevantes
    3. Exportación a HTML con formato de tabla

.NOTES
    Requiere el módulo Microsoft.Graph con los scopes adecuados:
        Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All"

    Autor  : Ernesto Cobos Roueñí
    Fecha  : 2026-03-04
    Versión: 1.2
#>

# ─────────────────────────────────────────────
# Validación de módulo Microsoft Graph
# ─────────────────────────────────────────────
$requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.SignIns")

foreach ($mod in $requiredModules) {
    if (Get-Module -ListAvailable -Name $mod) {
        Write-Host "Módulo $mod instalado correctamente." -ForegroundColor DarkGray
    }
    else {
        Write-Host "[X] Módulo $mod no encontrado. " -ForegroundColor Red -NoNewline
        Write-Host "Descargando e instalando..." -ForegroundColor Yellow
        Install-Module $mod -Force -Scope CurrentUser
    }
}

# ─────────────────────────────────────────────
# Conexión a Microsoft Graph
# ─────────────────────────────────────────────
$requiredScopes = @("Policy.Read.All", "Directory.Read.All")

try {
    $context = Get-MgContext -ErrorAction Stop
    if ($null -eq $context) { throw "No conectado" }

    $missingScopes = $requiredScopes | Where-Object { $_ -notin $context.Scopes }
    if ($missingScopes) {
        Write-Host "Faltan scopes: $($missingScopes -join ', '). Reconectando..." -ForegroundColor Yellow
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome
    }
    else {
        Write-Host "Ya existe una sesión activa de Microsoft Graph." -ForegroundColor DarkGray
    }
}
catch {
    Write-Host "Conectando a Microsoft Graph..." -ForegroundColor Yellow
    try {
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        Write-Host "Conexión establecida exitosamente." -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] No se pudo conectar a Microsoft Graph." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return
    }
}

# ─────────────────────────────────────────────
# Carpeta de reportes
# ─────────────────────────────────────────────
$reportDir = "C:\Scripts\ConditionalAccess"
if (-not (Test-Path $reportDir)) {
    New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
    Write-Host "Carpeta creada: $reportDir" -ForegroundColor DarkGray
}
else {
    Write-Host "Carpeta de reportes existe: $reportDir" -ForegroundColor DarkGray
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath   = Join-Path $reportDir "ConditionalAccess_$timestamp.csv"
$htmlPath  = Join-Path $reportDir "ConditionalAccess_$timestamp.html"

# ─────────────────────────────────────────────
# Funciones auxiliares
# ─────────────────────────────────────────────
function ConvertTo-FlatString {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return ($Value | ForEach-Object { $_.ToString() }) -join "; "
    }
    return $Value.ToString()
}

function Get-PolicyStateText {
    param([string]$State)
    switch ($State) {
        "enabled"                { return "Habilitada" }
        "disabled"               { return "Deshabilitada" }
        "enabledForReportingButNotEnforced" { return "Solo reporte" }
        default                  { return $State }
    }
}

function Resolve-UserOrGroup {
    <#
    .SYNOPSIS
        Intenta resolver un ID de usuario o grupo a su DisplayName.
    #>
    param([string]$Id)

    if ([string]::IsNullOrWhiteSpace($Id)) { return $Id }

    # Valores especiales de Conditional Access
    switch ($Id) {
        "All"              { return "Todos los usuarios" }
        "GuestsOrExternalUsers" { return "Invitados o usuarios externos" }
        "None"             { return "Ninguno" }
        default {
            try {
                $obj = Get-MgDirectoryObject -DirectoryObjectId $Id -ErrorAction Stop
                return $obj.AdditionalProperties.displayName ?? $Id
            }
            catch {
                return $Id
            }
        }
    }
}

function Resolve-Application {
    <#
    .SYNOPSIS
        Intenta resolver un AppId a su DisplayName.
    #>
    param([string]$AppId)

    if ([string]::IsNullOrWhiteSpace($AppId)) { return $AppId }

    switch ($AppId) {
        "All"             { return "Todas las aplicaciones" }
        "Office365"       { return "Office 365" }
        "MicrosoftAdminPortals" { return "Portales de administración de Microsoft" }
        "None"            { return "Ninguna" }
        default {
            try {
                $sp = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -Top 1 -ErrorAction Stop
                if ($sp) { return $sp.DisplayName }
                return $AppId
            }
            catch {
                return $AppId
            }
        }
    }
}

function Resolve-NamedLocation {
    <#
    .SYNOPSIS
        Intenta resolver un ID de ubicación nombrada a su DisplayName.
    #>
    param([string]$LocationId)

    if ([string]::IsNullOrWhiteSpace($LocationId)) { return $LocationId }

    switch ($LocationId) {
        "All"              { return "Todas las ubicaciones" }
        "AllTrusted"       { return "Todas las ubicaciones de confianza" }
        default {
            try {
                $loc = Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $LocationId -ErrorAction Stop
                return $loc.DisplayName ?? $LocationId
            }
            catch {
                return $LocationId
            }
        }
    }
}

# ─────────────────────────────────────────────
# Obtener políticas de Conditional Access
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "Generando Reporte de Políticas de Conditional Access..." -ForegroundColor Cyan

try {
    $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
}
catch {
    Write-Host "[ERROR] No se pudieron obtener las políticas de Conditional Access." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    return
}

if (-not $policies -or $policies.Count -eq 0) {
    Write-Host "[i] No se encontraron políticas de Conditional Access en el tenant." -ForegroundColor Yellow
    return
}

# ─────────────────────────────────────────────
# Contadores de resumen
# ─────────────────────────────────────────────
$countEnabled   = ($policies | Where-Object { $_.State -eq "enabled" }).Count
$countDisabled  = ($policies | Where-Object { $_.State -eq "disabled" }).Count
$countReport    = ($policies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }).Count

# ─────────────────────────────────────────────
# Procesar cada política
# ─────────────────────────────────────────────
$reportData = [System.Collections.Generic.List[PSObject]]::new()
$policyIndex = 0

foreach ($policy in $policies) {
    $policyIndex++
    $stateText  = Get-PolicyStateText -State $policy.State

    # --- Condiciones: Usuarios ---
    $cond = $policy.Conditions

    $includeUsers  = ConvertTo-FlatString ($cond.Users.IncludeUsers  | ForEach-Object { Resolve-UserOrGroup $_ })
    $excludeUsers  = ConvertTo-FlatString ($cond.Users.ExcludeUsers  | ForEach-Object { Resolve-UserOrGroup $_ })
    $includeGroups = ConvertTo-FlatString ($cond.Users.IncludeGroups | ForEach-Object { Resolve-UserOrGroup $_ })
    $excludeGroups = ConvertTo-FlatString ($cond.Users.ExcludeGroups | ForEach-Object { Resolve-UserOrGroup $_ })
    $includeRoles  = ConvertTo-FlatString ($cond.Users.IncludeRoles  | ForEach-Object { Resolve-UserOrGroup $_ })
    $excludeRoles  = ConvertTo-FlatString ($cond.Users.ExcludeRoles  | ForEach-Object { Resolve-UserOrGroup $_ })

    # --- Condiciones: Aplicaciones ---
    $includeApps = ConvertTo-FlatString ($cond.Applications.IncludeApplications | ForEach-Object { Resolve-Application $_ })
    $excludeApps = ConvertTo-FlatString ($cond.Applications.ExcludeApplications | ForEach-Object { Resolve-Application $_ })
    $includeActions = ConvertTo-FlatString $cond.Applications.IncludeUserActions

    # --- Condiciones: Plataformas ---
    $includePlatforms = ConvertTo-FlatString $cond.Platforms.IncludePlatforms
    $excludePlatforms = ConvertTo-FlatString $cond.Platforms.ExcludePlatforms

    # --- Condiciones: Ubicaciones ---
    $includeLocations = ConvertTo-FlatString ($cond.Locations.IncludeLocations | ForEach-Object { Resolve-NamedLocation $_ })
    $excludeLocations = ConvertTo-FlatString ($cond.Locations.ExcludeLocations | ForEach-Object { Resolve-NamedLocation $_ })

    # --- Condiciones: Riesgo ---
    $signInRisk = ConvertTo-FlatString $cond.SignInRiskLevels
    $userRisk   = ConvertTo-FlatString $cond.UserRiskLevels

    # --- Condiciones: Client App Types ---
    $clientAppTypes = ConvertTo-FlatString $cond.ClientAppTypes

    # --- Controles de acceso: Grant ---
    $grantControls       = $policy.GrantControls
    $grantOperator       = $grantControls.Operator
    $builtInControls     = ConvertTo-FlatString $grantControls.BuiltInControls
    $customControls      = ConvertTo-FlatString $grantControls.CustomAuthenticationFactors
    $termsOfUse          = ConvertTo-FlatString $grantControls.TermsOfUse
    $authStrength        = $grantControls.AuthenticationStrength.DisplayName

    # --- Controles de sesión ---
    $sessionControls = $policy.SessionControls

    $sessionItems = @()
    if ($sessionControls.ApplicationEnforcedRestrictions.IsEnabled) {
        $sessionItems += "Restricciones de aplicación"
    }
    if ($sessionControls.CloudAppSecurity.IsEnabled) {
        $sessionItems += "Cloud App Security ($($sessionControls.CloudAppSecurity.CloudAppSecurityType))"
    }
    if ($sessionControls.PersistentBrowser.IsEnabled) {
        $sessionItems += "Navegador persistente ($($sessionControls.PersistentBrowser.Mode))"
    }
    if ($sessionControls.SignInFrequency.IsEnabled) {
        $sessionItems += "Frecuencia de inicio ($($sessionControls.SignInFrequency.Value) $($sessionControls.SignInFrequency.Type))"
    }
    if ($sessionControls.ContinuousAccessEvaluation.Mode) {
        $sessionItems += "CAE ($($sessionControls.ContinuousAccessEvaluation.Mode))"
    }
    if ($sessionControls.DisableResilienceDefaults -eq $true) {
        $sessionItems += "Resiliencia deshabilitada"
    }

    $sessionControlsFlat = ConvertTo-FlatString $sessionItems

    # --- Agregar al reporte ---
    $reportData.Add([PSCustomObject]@{
        Nombre               = $policy.DisplayName
        Estado               = $stateText
        ID                   = $policy.Id
        Creada               = $policy.CreatedDateTime
        Modificada           = $policy.ModifiedDateTime
        IncluirUsuarios      = $includeUsers
        ExcluirUsuarios      = $excludeUsers
        IncluirGrupos        = $includeGroups
        ExcluirGrupos        = $excludeGroups
        IncluirRoles         = $includeRoles
        ExcluirRoles         = $excludeRoles
        IncluirApps          = $includeApps
        ExcluirApps          = $excludeApps
        AccionesUsuario      = $includeActions
        IncluirPlataformas   = $includePlatforms
        ExcluirPlataformas   = $excludePlatforms
        IncluirUbicaciones   = $includeLocations
        ExcluirUbicaciones   = $excludeLocations
        RiesgoDeInicio       = $signInRisk
        RiesgoDeUsuario      = $userRisk
        TiposAppCliente      = $clientAppTypes
        OperadorGrant        = $grantOperator
        ControlesGrant       = $builtInControls
        AuthStrength         = $authStrength
        ControlesSesion      = $sessionControlsFlat
    })
}

# ─────────────────────────────────────────────
# Exportar a CSV
# ─────────────────────────────────────────────
try {
    $reportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8BOM
    Write-Host "[OK] Reporte CSV exportado: $csvPath" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Error al exportar CSV: $($_.Exception.Message)" -ForegroundColor Red
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
    .enabled   { color: #107c10; font-weight: bold; }
    .disabled  { color: #d13438; font-weight: bold; }
    .report    { color: #ca5010; font-weight: bold; }
    .summary   { background: #0078d4; color: #fff; padding: 12px 20px; border-radius: 6px; display: inline-block; margin: 5px; }
</style>
"@

$tenantDetail = Get-MgOrganization | Select-Object -First 1
$tenantName   = $tenantDetail.DisplayName
$tenantId     = (Get-MgContext).TenantId

$htmlBody = @"
<h1>Reporte de Políticas de Conditional Access</h1>
<p>Tenant: $tenantName | Tenant ID: $tenantId | Generado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

<div>
    <span class="summary">Habilitadas: $countEnabled</span>
    <span class="summary">Deshabilitadas: $countDisabled</span>
    <span class="summary">Solo reporte: $countReport</span>
    <span class="summary">Total: $($policies.Count)</span>
</div>

<h2>Detalle de Políticas</h2>
"@

$htmlTable = $reportData | ConvertTo-Html -Fragment | Out-String

# Colorear estados en HTML
$htmlTable = $htmlTable -replace "<td>Habilitada</td>",    '<td class="enabled">Habilitada</td>'
$htmlTable = $htmlTable -replace "<td>Deshabilitada</td>", '<td class="disabled">Deshabilitada</td>'
$htmlTable = $htmlTable -replace "<td>Solo reporte</td>",  '<td class="report">Solo reporte</td>'

$htmlFooter = '<footer style="text-align: center; margin-top: 40px; padding: 15px 0; border-top: 2px solid #0078d4; color: #555; font-size: 13px;">chiringuito365.com&reg; | Internal Tools 2026</footer>'

$fullHtml = ConvertTo-Html -Head $htmlHead -Body ($htmlBody + $htmlTable + $htmlFooter) -Title "Conditional Access Report" | Out-String

try {
    $fullHtml | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "[OK] Reporte HTML exportado: $htmlPath" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Error al exportar HTML: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Reporte generado exitosamente." -ForegroundColor Green
