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
    Valida la configuración de Zero-hour Auto Purge (ZAP) en el tenant de Microsoft 365.

.DESCRIPTION
    Este script revisa la configuración de ZAP (Zero-hour Auto Purge) en todas las políticas
    relevantes del tenant para asegurar que cumple con las mejores prácticas de Microsoft:

    - Anti-Spam  (HostedContentFilterPolicy) : SpamZapEnabled, PhishZapEnabled
    - Anti-Malware (MalwareFilterPolicy)      : ZapEnabled
    - Anti-Phishing (AntiPhishPolicy)         : ZapEnabled (disponible en tenants con MDO)
    - Configuración global de transporte      : Validaciones de exclusiones ZAP
    - Cuarentena                              : Políticas de cuarentena asociadas a acciones ZAP

    Genera un reporte HTML tipo dashboard con el estado de cumplimiento, detalle por política
    y recomendaciones de remediación.

.NOTES
    Requiere conexión previa a Exchange Online:
        Connect-ExchangeOnline

    Autor  : Ernesto Cobos Roqueñí
    Fecha  : 13/Marzo/2026
    Versión: 1.0
#>

# ─────────────────────────────────────────────
# Validación de módulo y carpeta de reportes
# ─────────────────────────────────────────────
if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
    Write-Host "Módulo ExchangeOnlineManagement instalado correctamente." -ForegroundColor DarkGray
}
else {
    Write-Host "[X] Módulo ExchangeOnlineManagement no encontrado. " -ForegroundColor Red -NoNewline
    Write-Host "Descargando e instalando..." -ForegroundColor Yellow
    Install-Module ExchangeOnlineManagement -Force -Scope CurrentUser
}

$reportDir = "C:\Scripts\MDO"
if (-not (Test-Path $reportDir)) {
    New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
    Write-Host "Carpeta creada: $reportDir" -ForegroundColor DarkGray
}
else {
    Write-Host "Carpeta de reportes existe: $reportDir" -ForegroundColor DarkGray
}

# ─────────────────────────────────────────────
# Colores y formato
# ─────────────────────────────────────────────
function Write-Status {
    param(
        [string]$Setting,
        [string]$CurrentValue,
        [string]$RecommendedValue,
        [string]$Status  # PASS, WARN, FAIL, INFO
    )

    $null = $script:htmlRows.Add([pscustomobject]@{
        Section       = $script:currentSection
        PolicyName    = $script:currentPolicyName
        Setting       = $Setting
        CurrentValue  = $CurrentValue
        Recommended   = $RecommendedValue
        Status        = $Status
    })
}

# ─────────────────────────────────────────────
# Contadores globales y tracking de políticas
# ─────────────────────────────────────────────
$script:totalChecks = 0
$script:passCount   = 0
$script:warnCount   = 0
$script:failCount   = 0

$script:policyResults    = @{}
$script:currentPolicyKey = $null
$script:currentPolicyName = $null
$script:currentSection   = $null

$script:htmlRows = [System.Collections.ArrayList]::new()

function Set-CurrentPolicy {
    param([string]$Section, [string]$PolicyName)
    $script:currentPolicyKey  = "$Section|$PolicyName"
    $script:currentPolicyName = $PolicyName
    $script:currentSection    = $Section
    if (-not $script:policyResults.ContainsKey($script:currentPolicyKey)) {
        $script:policyResults[$script:currentPolicyKey] = @{ Pass = 0; Fail = 0; Warn = 0 }
    }
}

function Test-Setting {
    param(
        [string]$Setting,
        $CurrentValue,
        $RecommendedValue
    )

    $script:totalChecks++

    $currentStr     = if ($null -eq $CurrentValue) { "<null>" } else { "$CurrentValue" }
    $recommendedStr = "$RecommendedValue"

    if ("$CurrentValue" -eq "$RecommendedValue") {
        $script:passCount++
        if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
            $script:policyResults[$script:currentPolicyKey].Pass++
        }
        Write-Status -Setting $Setting -CurrentValue $currentStr -RecommendedValue $recommendedStr -Status 'PASS'
    }
    else {
        $script:failCount++
        if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
            $script:policyResults[$script:currentPolicyKey].Fail++
        }
        Write-Status -Setting $Setting -CurrentValue $currentStr -RecommendedValue $recommendedStr -Status 'FAIL'
    }
}

function Test-SettingWarn {
    param(
        [string]$Setting,
        $CurrentValue,
        $RecommendedValue
    )

    $script:totalChecks++

    $currentStr     = if ($null -eq $CurrentValue) { "<null>" } else { "$CurrentValue" }
    $recommendedStr = "$RecommendedValue"

    if ("$CurrentValue" -eq "$RecommendedValue") {
        $script:passCount++
        if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
            $script:policyResults[$script:currentPolicyKey].Pass++
        }
        Write-Status -Setting $Setting -CurrentValue $currentStr -RecommendedValue $recommendedStr -Status 'PASS'
    }
    else {
        $script:warnCount++
        if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
            $script:policyResults[$script:currentPolicyKey].Warn++
        }
        Write-Status -Setting $Setting -CurrentValue $currentStr -RecommendedValue $recommendedStr -Status 'WARN'
    }
}

# ─────────────────────────────────────────────
# Conexión a Exchange Online
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "Validando conexion a Exchange Online..." -ForegroundColor DarkGray

try {
    $null = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "  Conexion a Exchange Online activa." -ForegroundColor Green
}
catch {
    Write-Host "  No hay conexion activa a Exchange Online. Conectando..." -ForegroundColor Yellow
    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Host "  Conexion a Exchange Online establecida." -ForegroundColor Green
    }
    catch {
        Write-Host "[X] No se pudo conectar a Exchange Online: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

$timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$tenantName = (Get-OrganizationConfig).DisplayName

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " Validación de ZAP (Zero-hour Auto Purge)"     -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Fecha : $timestamp" -ForegroundColor DarkGray
Write-Host "Tenant: $tenantName" -ForegroundColor DarkGray
Write-Host ""

# ═════════════════════════════════════════════
# 1. ANTI-SPAM — ZAP para Spam y Phish
# ═════════════════════════════════════════════
Write-Host "1. Validando ZAP en politicas Anti-Spam..." -ForegroundColor Yellow

$spamPolicies = Get-HostedContentFilterPolicy

foreach ($policy in $spamPolicies) {
    Set-CurrentPolicy -Section "Anti-Spam ZAP" -PolicyName $policy.Name

    # SpamZapEnabled — debe estar habilitado (True)
    Test-Setting -Setting "SpamZapEnabled"  -CurrentValue $policy.SpamZapEnabled  -RecommendedValue "True"

    # PhishZapEnabled — debe estar habilitado (True)
    Test-Setting -Setting "PhishZapEnabled" -CurrentValue $policy.PhishZapEnabled -RecommendedValue "True"

    # Verificar que las acciones asociadas a ZAP sean efectivas
    # ZAP mueve/cuarentena según estas acciones — si la acción es "NoAction", ZAP no sirve de nada
    $script:totalChecks++
    if ($policy.SpamAction -eq "NoAction") {
        $script:failCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Fail++ }
        Write-Status -Setting "SpamAction (acción ZAP para spam)" `
                     -CurrentValue $policy.SpamAction `
                     -RecommendedValue "MoveToJmf o Quarantine" `
                     -Status 'FAIL'
    }
    else {
        $script:passCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "SpamAction (acción ZAP para spam)" `
                     -CurrentValue "$($policy.SpamAction)" `
                     -RecommendedValue "MoveToJmf o Quarantine" `
                     -Status 'PASS'
    }

    $script:totalChecks++
    if ($policy.PhishSpamAction -eq "NoAction") {
        $script:failCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Fail++ }
        Write-Status -Setting "PhishSpamAction (acción ZAP para phish)" `
                     -CurrentValue $policy.PhishSpamAction `
                     -RecommendedValue "Quarantine" `
                     -Status 'FAIL'
    }
    else {
        $script:passCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "PhishSpamAction (acción ZAP para phish)" `
                     -CurrentValue "$($policy.PhishSpamAction)" `
                     -RecommendedValue "Quarantine" `
                     -Status 'PASS'
    }

    $script:totalChecks++
    if ($policy.HighConfidencePhishAction -eq "NoAction") {
        $script:failCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Fail++ }
        Write-Status -Setting "HighConfidencePhishAction (acción ZAP para phish HC)" `
                     -CurrentValue $policy.HighConfidencePhishAction `
                     -RecommendedValue "Quarantine" `
                     -Status 'FAIL'
    }
    else {
        $script:passCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "HighConfidencePhishAction (acción ZAP para phish HC)" `
                     -CurrentValue "$($policy.HighConfidencePhishAction)" `
                     -RecommendedValue "Quarantine" `
                     -Status 'PASS'
    }

    $script:totalChecks++
    if ($policy.HighConfidenceSpamAction -eq "NoAction") {
        $script:failCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Fail++ }
        Write-Status -Setting "HighConfidenceSpamAction (acción ZAP para spam HC)" `
                     -CurrentValue $policy.HighConfidenceSpamAction `
                     -RecommendedValue "Quarantine" `
                     -Status 'FAIL'
    }
    else {
        $script:passCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "HighConfidenceSpamAction (acción ZAP para spam HC)" `
                     -CurrentValue "$($policy.HighConfidenceSpamAction)" `
                     -RecommendedValue "Quarantine" `
                     -Status 'PASS'
    }

    # Verificar si hay AllowedSenders/Domains que podrían excluir mensajes de ZAP
    $script:totalChecks++
    if ($policy.AllowedSenders.Count -gt 0 -or $policy.AllowedSenderDomains.Count -gt 0) {
        $script:warnCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
        Write-Status -Setting "AllowedSenders/Domains (excluyen ZAP)" `
                     -CurrentValue "Senders: $($policy.AllowedSenders.Count), Domains: $($policy.AllowedSenderDomains.Count)" `
                     -RecommendedValue "0 — las listas allow impiden acciones de ZAP" `
                     -Status 'WARN'
    }
    else {
        $script:passCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "AllowedSenders/Domains" -CurrentValue "Ninguno" -RecommendedValue "0" -Status 'PASS'
    }
}

Write-Host "  Anti-Spam ZAP validado." -ForegroundColor Green

# ═════════════════════════════════════════════
# 2. ANTI-MALWARE — ZAP para Malware
# ═════════════════════════════════════════════
Write-Host "2. Validando ZAP en politicas Anti-Malware..." -ForegroundColor Yellow

$malwarePolicies = Get-MalwareFilterPolicy

foreach ($policy in $malwarePolicies) {
    Set-CurrentPolicy -Section "Anti-Malware ZAP" -PolicyName $policy.Name

    # ZapEnabled — debe estar habilitado (True)
    Test-Setting -Setting "ZapEnabled" -CurrentValue $policy.ZapEnabled -RecommendedValue "True"

    # EnableFileFilter amplifica la efectividad de ZAP al bloquear tipos peligrosos
    Test-SettingWarn -Setting "EnableFileFilter (complementa ZAP)" -CurrentValue $policy.EnableFileFilter -RecommendedValue "True"

    # QuarantineTag — debe estar configurado para que ZAP pueda actuar
    $script:totalChecks++
    if ($policy.QuarantineTag) {
        $script:passCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "QuarantineTag (destino ZAP)" -CurrentValue $policy.QuarantineTag -RecommendedValue "Configurado" -Status 'PASS'
    }
    else {
        $script:warnCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
        Write-Status -Setting "QuarantineTag (destino ZAP)" -CurrentValue "<no configurado>" -RecommendedValue "Configurar" -Status 'WARN'
    }
}

Write-Host "  Anti-Malware ZAP validado." -ForegroundColor Green

# ═════════════════════════════════════════════
# 3. ANTI-PHISHING — ZAP para suplantación
# ═════════════════════════════════════════════
Write-Host "3. Validando configuracion Anti-Phishing relevante a ZAP..." -ForegroundColor Yellow

$phishPolicies = Get-AntiPhishPolicy

foreach ($policy in $phishPolicies) {
    Set-CurrentPolicy -Section "Anti-Phishing (impacto ZAP)" -PolicyName $policy.Name

    # Enabled — si la politica está deshabilitada, ZAP no puede actuar con base en sus detecciones
    Test-Setting -Setting "Enabled" -CurrentValue $policy.Enabled -RecommendedValue "True"

    # EnableSpoofIntelligence — mejora detección que luego ZAP puede usar
    Test-Setting -Setting "EnableSpoofIntelligence" -CurrentValue $policy.EnableSpoofIntelligence -RecommendedValue "True"

    # AuthenticationFailAction — acción cuando falla autenticación (spoofing), ZAP la respeta
    Test-Setting -Setting "AuthenticationFailAction" -CurrentValue $policy.AuthenticationFailAction -RecommendedValue "MoveToJmf"

    # HonorDmarcPolicy — ZAP respeta DMARC reject/quarantine
    Test-SettingWarn -Setting "HonorDmarcPolicy" -CurrentValue $policy.HonorDmarcPolicy -RecommendedValue "True"
}

Write-Host "  Anti-Phishing (impacto ZAP) validado." -ForegroundColor Green

# ═════════════════════════════════════════════
# 4. REGLAS DE TRANSPORTE — Excepciones a ZAP
# ═════════════════════════════════════════════
Write-Host "4. Buscando reglas de transporte que puedan afectar ZAP..." -ForegroundColor Yellow

Set-CurrentPolicy -Section "Reglas de Transporte" -PolicyName "Excepciones ZAP"

$transportRules = Get-TransportRule -ResultSize Unlimited

# Buscar reglas que establezcan SCL=-1 (bypass filtering = bypass ZAP)
$sclBypassRules = @($transportRules | Where-Object { $_.SetSCL -eq -1 })

$script:totalChecks++
if ($sclBypassRules.Count -gt 0) {
    $script:warnCount++
    if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
    $ruleNames = ($sclBypassRules | ForEach-Object { $_.Name }) -join '; '
    Write-Status -Setting "Reglas con SCL=-1 (bypass ZAP)" `
                 -CurrentValue "$($sclBypassRules.Count) regla(s): $ruleNames" `
                 -RecommendedValue "0 — SCL=-1 evita que ZAP actúe" `
                 -Status 'WARN'
}
else {
    $script:passCount++
    if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
    Write-Status -Setting "Reglas con SCL=-1 (bypass ZAP)" -CurrentValue "Ninguna" -RecommendedValue "0" -Status 'PASS'
}

# Buscar reglas que establezcan HeaderContains X-MS-Exchange-Organization-SkipSafeLinksProcessing o similar
$skipProcessingRules = @($transportRules | Where-Object {
    $_.SetHeaderName -match 'X-MS-Exchange-Organization-SkipSafe|X-MS-Exchange-Organization-AuthAs' -or
    $_.SetHeaderValue -match 'Internal'
})

$script:totalChecks++
if ($skipProcessingRules.Count -gt 0) {
    $script:warnCount++
    if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
    $ruleNames = ($skipProcessingRules | ForEach-Object { $_.Name }) -join '; '
    Write-Status -Setting "Reglas con headers que omiten protección" `
                 -CurrentValue "$($skipProcessingRules.Count) regla(s): $ruleNames" `
                 -RecommendedValue "0 — pueden interferir con acciones de ZAP" `
                 -Status 'WARN'
}
else {
    $script:passCount++
    if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
    Write-Status -Setting "Reglas con headers que omiten protección" -CurrentValue "Ninguna" -RecommendedValue "0" -Status 'PASS'
}

Write-Host "  Reglas de transporte validadas." -ForegroundColor Green

# ═════════════════════════════════════════════
# 5. POLÍTICAS DE CUARENTENA — Acciones ZAP
# ═════════════════════════════════════════════
Write-Host "5. Validando politicas de cuarentena asociadas a ZAP..." -ForegroundColor Yellow

Set-CurrentPolicy -Section "Cuarentena" -PolicyName "Políticas de cuarentena"

try {
    $quarantinePolicies = Get-QuarantinePolicy -ErrorAction Stop

    # Verificar que existan políticas de cuarentena configuradas
    $script:totalChecks++
    if ($quarantinePolicies.Count -gt 0) {
        $script:passCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "Políticas de cuarentena definidas" `
                     -CurrentValue "$($quarantinePolicies.Count) política(s)" `
                     -RecommendedValue "Al menos 1" `
                     -Status 'PASS'
    }
    else {
        $script:failCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Fail++ }
        Write-Status -Setting "Políticas de cuarentena definidas" `
                     -CurrentValue "0" `
                     -RecommendedValue "Configurar políticas de cuarentena" `
                     -Status 'FAIL'
    }

    # Verificar cada política de cuarentena
    foreach ($qPolicy in $quarantinePolicies) {
        Set-CurrentPolicy -Section "Cuarentena" -PolicyName $qPolicy.Name

        # EndUserQuarantinePermissionsValue — evitar que usuarios liberen mensajes de phish/malware
        # El valor 0 es más restrictivo (AdminOnlyAccessPolicy), 27 es moderado, valores altos son permisivos
        if ($null -ne $qPolicy.EndUserQuarantinePermissionsValue) {
            $script:totalChecks++
            if ([int]$qPolicy.EndUserQuarantinePermissionsValue -le 27) {
                $script:passCount++
                if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
                Write-Status -Setting "EndUserQuarantinePermissionsValue" `
                             -CurrentValue "$($qPolicy.EndUserQuarantinePermissionsValue)" `
                             -RecommendedValue "0-27 (restrictivo)" `
                             -Status 'PASS'
            }
            else {
                $script:warnCount++
                if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
                Write-Status -Setting "EndUserQuarantinePermissionsValue" `
                             -CurrentValue "$($qPolicy.EndUserQuarantinePermissionsValue)" `
                             -RecommendedValue "0-27 — valores altos permiten a usuarios liberar mensajes purgados por ZAP" `
                             -Status 'WARN'
            }
        }

        # ESNEnabled — notificaciones de cuarentena al usuario
        if ($null -ne $qPolicy.ESNEnabled) {
            Test-SettingWarn -Setting "ESNEnabled (notificaciones cuarentena)" -CurrentValue $qPolicy.ESNEnabled -RecommendedValue "True"
        }
    }
}
catch {
    $script:totalChecks++
    $script:warnCount++
    Write-Status -Setting "Acceso a políticas de cuarentena" `
                 -CurrentValue "No disponible: $($_.Exception.Message)" `
                 -RecommendedValue "Verificar permisos" `
                 -Status 'WARN'
}

Write-Host "  Políticas de cuarentena validadas." -ForegroundColor Green

# ═════════════════════════════════════════════
# 6. PRESET SECURITY POLICIES — Cobertura ZAP
# ═════════════════════════════════════════════
Write-Host "6. Validando Preset Security Policies (cobertura ZAP)..." -ForegroundColor Yellow

Set-CurrentPolicy -Section "Preset Security Policies" -PolicyName "Standard / Strict"

try {
    $eopPreset = Get-EOPProtectionPolicyRule -ErrorAction SilentlyContinue
    $atpPreset = Get-ATPProtectionPolicyRule -ErrorAction SilentlyContinue

    $script:totalChecks++
    if ($eopPreset) {
        $enabledEop = @($eopPreset | Where-Object { $_.State -eq 'Enabled' })
        if ($enabledEop.Count -gt 0) {
            $script:passCount++
            if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
            $names = ($enabledEop | ForEach-Object { $_.Name }) -join ', '
            Write-Status -Setting "EOP Preset Policies activas" `
                         -CurrentValue "$names" `
                         -RecommendedValue "Standard y/o Strict habilitadas" `
                         -Status 'PASS'
        }
        else {
            $script:warnCount++
            if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
            Write-Status -Setting "EOP Preset Policies activas" `
                         -CurrentValue "Ninguna habilitada" `
                         -RecommendedValue "Habilitar Standard o Strict — incluyen ZAP habilitado por defecto" `
                         -Status 'WARN'
        }
    }
    else {
        $script:totalChecks--
        # No preset rules found — not an error, just not configured
    }

    $script:totalChecks++
    if ($atpPreset) {
        $enabledAtp = @($atpPreset | Where-Object { $_.State -eq 'Enabled' })
        if ($enabledAtp.Count -gt 0) {
            $script:passCount++
            if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
            $names = ($enabledAtp | ForEach-Object { $_.Name }) -join ', '
            Write-Status -Setting "ATP Preset Policies activas" `
                         -CurrentValue "$names" `
                         -RecommendedValue "Standard y/o Strict habilitadas" `
                         -Status 'PASS'
        }
        else {
            $script:warnCount++
            if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
            Write-Status -Setting "ATP Preset Policies activas" `
                         -CurrentValue "Ninguna habilitada" `
                         -RecommendedValue "Habilitar Standard o Strict" `
                         -Status 'WARN'
        }
    }
    else {
        $script:totalChecks--
    }
}
catch {
    # Preset cmdlets not available — skip silently
}

Write-Host "  Preset Security Policies validadas." -ForegroundColor Green

# ═════════════════════════════════════════════
# RESUMEN EN CONSOLA
# ═════════════════════════════════════════════
Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " Resumen de Validación ZAP"                      -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "  Total verificaciones: $($script:totalChecks)"  -ForegroundColor White
Write-Host "  Correctas (PASS)   : $($script:passCount)"     -ForegroundColor Green
Write-Host "  Advertencias (WARN): $($script:warnCount)"     -ForegroundColor Yellow
Write-Host "  Fallidas (FAIL)    : $($script:failCount)"     -ForegroundColor Red

if ($script:totalChecks -gt 0) {
    $pct = [math]::Round(($script:passCount / $script:totalChecks) * 100, 1)
    Write-Host "  Cumplimiento       : $pct%" -ForegroundColor $(if ($pct -ge 80) { 'Green' } elseif ($pct -ge 60) { 'Yellow' } else { 'Red' })
}

# ═════════════════════════════════════════════
# GENERACION DE REPORTE HTML
# ═════════════════════════════════════════════

$safeTenantName   = $tenantName -replace '[\\/:*?"<>|]', '_'
$reportTimestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$date2             = Get-Date -Format "ddMMyyHHmmss"
$htmlFile          = "ZAP_Validation_${safeTenantName}_${date2}.html"

# Build section rows for the HTML detail table
$htmlDetailRows = ""
$lastSection = ""
foreach ($row in $script:htmlRows) {
    $statusClass = switch ($row.Status) {
        'PASS' { 'status-pass' }
        'WARN' { 'status-warn' }
        'FAIL' { 'status-fail' }
        'INFO' { 'status-info' }
        default { '' }
    }
    $statusIcon = switch ($row.Status) {
        'PASS' { '&#9989;' }
        'WARN' { '&#9888;&#65039;' }
        'FAIL' { '&#10060;' }
        'INFO' { '&#8505;&#65039;' }
        default { '' }
    }

    if ($row.Section -and $row.Section -ne $lastSection) {
        $htmlDetailRows += "<tr class='section-row'><td colspan='5'><strong>$($row.Section)</strong></td></tr>`n"
        $lastSection = $row.Section
    }

    $safeCurrentValue = [System.Web.HttpUtility]::HtmlEncode($row.CurrentValue)
    $safeRecommended  = [System.Web.HttpUtility]::HtmlEncode($row.Recommended)
    $safeSetting      = [System.Web.HttpUtility]::HtmlEncode($row.Setting)
    $safePolicyName   = [System.Web.HttpUtility]::HtmlEncode($row.PolicyName)

    $htmlDetailRows += @"
<tr>
    <td class='$statusClass'>$statusIcon $($row.Status)</td>
    <td class='policy-name'>$safePolicyName</td>
    <td><strong>$safeSetting</strong></td>
    <td><code>$safeCurrentValue</code></td>
    <td><code>$safeRecommended</code></td>
</tr>
"@
}

# Build policy summary rows
$policySummaryRows = ""
foreach ($key in $script:policyResults.Keys | Sort-Object) {
    $parts   = $key -split '\|', 2
    $section = $parts[0]
    $name    = $parts[1]
    $r       = $script:policyResults[$key]
    $total   = $r.Pass + $r.Fail + $r.Warn
    if ($total -gt 0) { $pctP = [math]::Round(($r.Pass / $total) * 100, 0) } else { $pctP = 0 }

    if ($pctP -ge 80) { $barColor = '#28a745' } elseif ($pctP -ge 60) { $barColor = '#ffc107' } else { $barColor = '#dc3545' }

    $policySummaryRows += @"
<tr>
    <td>$section</td>
    <td><strong>$name</strong></td>
    <td class='text-center'>$($r.Pass)</td>
    <td class='text-center'>$($r.Warn)</td>
    <td class='text-center'>$($r.Fail)</td>
    <td>
        <div class='progress' style='height:20px;'>
            <div class='progress-bar' style='width:${pctP}%;background-color:${barColor};' role='progressbar'>$pctP%</div>
        </div>
    </td>
</tr>
"@
}

# Dashboard card colors
if ($script:totalChecks -gt 0) {
    $overallPct = [math]::Round(($script:passCount / $script:totalChecks) * 100, 1)
}
else {
    $overallPct = 0
}
if ($overallPct -ge 80) { $overallColor = '#28a745' } elseif ($overallPct -ge 60) { $overallColor = '#ffc107' } else { $overallColor = '#dc3545' }

$htmlReport = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>ZAP Configuration Validation Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f4f7f9; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .hero { background-color: #0078d4; color: white; padding: 35px 20px; border-bottom: 4px solid #005a9e; text-align: center; }
        .hero h1 { font-size: 1.6rem; font-weight: 600; margin-bottom: 8px; }
        .hero p { font-size: 1.35rem; font-weight: 400; margin: 2px 0; opacity: 0.9; }
        .logo-img { max-height: 35px; filter: brightness(0) invert(1); margin-bottom: 10px; }
        .stat-number { font-size: 2.2rem; font-weight: 800; }
        .stat-label { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; opacity: 0.9; }
        .table-card { background: white; border: 1px solid #e1e4e8; border-radius: 8px; padding: 25px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .section-divider { border-bottom: 2px solid #0078d4; color: #0078d4; font-weight: bold; margin: 25px 0 15px 0; font-size: 1.15rem; padding-bottom: 5px; }
        .section-row td { background-color: #e8f4fd !important; font-size: 1rem; padding: 10px 15px !important; border-top: 2px solid #0078d4; }
        .status-pass { color: #28a745; font-weight: 700; }
        .status-warn { color: #d39e00; font-weight: 700; }
        .status-fail { color: #dc3545; font-weight: 700; }
        .status-info { color: #0078d4; font-weight: 700; }
        .policy-name { color: #6c757d; font-size: 0.8rem; }
        .detail-table th { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; background-color: #f8f9fa; }
        .detail-table td { font-size: 0.85rem; vertical-align: middle; }
        .detail-table code { font-size: 0.8rem; color: #333; background-color: #f0f0f0; padding: 2px 5px; border-radius: 3px; }
        .progress { border-radius: 10px; background-color: #e9ecef; }
        .progress-bar { border-radius: 10px; font-size: 0.75rem; font-weight: 600; }
        .card-stat { border-radius: 10px; color: white; padding: 20px; text-align: center; }
        .link-docs { color: #107c10; text-decoration: none; font-weight: 600; }
        .link-docs:hover { text-decoration: underline; color: #0b5e0b; }
        .task-link { transition: background-color 0.2s, transform 0.1s; }
        .task-link:hover { background-color: #e8f4fd; transform: translateX(4px); border-left: 4px solid #0078d4; }
        .zap-info { background: linear-gradient(135deg, #e8f4fd 0%, #f0f7ff 100%); border-left: 4px solid #0078d4; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .zap-info h5 { color: #0078d4; font-weight: 700; }
        .zap-info ul li { margin-bottom: 6px; font-size: 0.9rem; }
        @media print {
            .hero { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
            .card-stat { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        }
    </style>
</head>
<body>

    <!-- Hero Header -->
    <div class="hero">
        <img src="https://dco.microsoft.com/Images/microsoft-white-logo.png" alt="Microsoft" class="logo-img">
        <h1> Validación de ZAP (Zero-hour Auto Purge)</h1>
        <p style="font-size: 0.95rem;">Fecha: $reportTimestamp</p>
        <p style="font-size: 1.5rem;">Tenant: <strong>$tenantName</strong></p>
        <p><em>&ldquo;La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad&rdquo;</em></p>
    </div>

    <div class="container-fluid px-4">

        <!-- ZAP Info Box -->
        <div class="zap-info mt-4">
            <h5>&#9432; ¿Qué es ZAP (Zero-hour Auto Purge)?</h5>
            <p>ZAP es una función de protección en Microsoft 365 que <strong>retroactivamente</strong> detecta y neutraliza mensajes maliciosos
            que ya fueron entregados a los buzones de los usuarios. Actúa cuando el motor de filtrado actualiza sus firmas y reclasifica
            un mensaje previamente entregado como spam, phishing o malware.</p>
            <ul>
                <li><strong>Spam ZAP:</strong> Mueve mensajes reclasificados como spam a la carpeta Junk Email.</li>
                <li><strong>Phish ZAP:</strong> Envía mensajes reclasificados como phishing a cuarentena.</li>
                <li><strong>Malware ZAP:</strong> Envía mensajes con adjuntos maliciosos a cuarentena.</li>
            </ul>
            <p><strong>Importante:</strong> ZAP solo actúa sobre mensajes <em>no leídos</em> en la bandeja de entrada (excepto para malware de alta confianza).
            Las listas de remitentes permitidos (Allow lists) y las reglas de transporte con SCL=-1 <strong>pueden impedir</strong> que ZAP actúe.</p>
        </div>

        <!-- Dashboard Cards -->
        <div class="row g-3 mt-3 text-center">
            <div class="col">
                <div class="card-stat" style="background-color: #0078d4;">
                    <div class="stat-label">Total Verificaciones</div>
                    <div class="stat-number">$($script:totalChecks)</div>
                </div>
            </div>
            <div class="col">
                <div class="card-stat" style="background-color: $overallColor;">
                    <div class="stat-label">Cumplimiento ZAP</div>
                    <div class="stat-number">$overallPct%</div>
                </div>
            </div>
            <div class="col">
                <div class="card-stat" style="background-color: #28a745;">
                    <div class="stat-label">Correctas</div>
                    <div class="stat-number">$($script:passCount)</div>
                </div>
            </div>
            <div class="col">
                <div class="card-stat" style="background-color: #ffc107; color: #333;">
                    <div class="stat-label">Advertencias</div>
                    <div class="stat-number">$($script:warnCount)</div>
                </div>
            </div>
            <div class="col">
                <div class="card-stat" style="background-color: #dc3545;">
                    <div class="stat-label">Fallidas</div>
                    <div class="stat-number">$($script:failCount)</div>
                </div>
            </div>
        </div>

        <!-- Policy Summary -->
        <div class="table-card">
            <div class="section-divider">&#128202; Resumen por Política</div>
            <table class="table table-sm table-hover">
                <thead>
                    <tr>
                        <th>Sección</th>
                        <th>Política</th>
                        <th class="text-center">OK</th>
                        <th class="text-center">WARN</th>
                        <th class="text-center">FAIL</th>
                        <th style="min-width:150px;">Cumplimiento</th>
                    </tr>
                </thead>
                <tbody>
                    $policySummaryRows
                </tbody>
            </table>
        </div>

        <!-- Detail Table -->
        <div class="table-card">
            <div class="section-divider">&#128269; Detalle de Verificaciones ($($script:totalChecks) checks)</div>
            <table class="table table-sm table-hover detail-table">
                <thead>
                    <tr>
                        <th style="width:80px;">Estado</th>
                        <th>Política</th>
                        <th>Configuración</th>
                        <th>Valor Actual</th>
                        <th>Recomendado</th>
                    </tr>
                </thead>
                <tbody>
                    $htmlDetailRows
                </tbody>
            </table>
        </div>

        <!-- Remediation Guide -->
        <div class="card shadow-sm border-danger mb-4">
            <div class="card-header text-white bg-danger">&#128295; Guía de Remediación ZAP</div>
            <div class="card-body">
                <h6 class="fw-bold">Si ZAP está deshabilitado en Anti-Spam:</h6>
                <pre class="bg-light p-3 rounded"><code>Get-HostedContentFilterPolicy | Set-HostedContentFilterPolicy -SpamZapEnabled `$true -PhishZapEnabled `$true</code></pre>

                <h6 class="fw-bold mt-3">Si ZAP está deshabilitado en Anti-Malware:</h6>
                <pre class="bg-light p-3 rounded"><code>Get-MalwareFilterPolicy | Set-MalwareFilterPolicy -ZapEnabled `$true</code></pre>

                <h6 class="fw-bold mt-3">Si hay reglas de transporte con SCL=-1:</h6>
                <p class="text-muted">Revisar y eliminar o modificar las reglas que establecen <code>SCL=-1</code>, ya que impiden que ZAP actúe sobre los mensajes que coincidan con esas reglas.</p>
                <pre class="bg-light p-3 rounded"><code>Get-TransportRule | Where-Object { `$_.SetSCL -eq -1 } | Format-Table Name, State, Priority -AutoSize</code></pre>

                <h6 class="fw-bold mt-3">Si hay Allow Lists configuradas:</h6>
                <p class="text-muted">Los remitentes y dominios en listas de permitidos no son afectados por ZAP. Migrar a Tenant Allow/Block List puede proporcionar un control más seguro.</p>
                <pre class="bg-light p-3 rounded"><code># Ver allow lists actuales
Get-HostedContentFilterPolicy | Format-List Name, AllowedSenders, AllowedSenderDomains</code></pre>
            </div>
        </div>

        <!-- Documentation Links -->
        <div class="card shadow-sm border-primary mb-4">
            <div class="card-header text-white" style="background-color: #0078d4;">&#128221; Documentación ZAP — Microsoft Learn</div>
            <div class="card-body">
                <div class="list-group">
                    <div class="list-group-item task-link">
                        <strong>&#128279; Zero-hour auto purge (ZAP) in Microsoft Defender for Office 365</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-purge" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Recommended settings for EOP and MDO security</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Configure Anti-Spam policies</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/anti-spam-policies-configure" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Configure Anti-Malware policies</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/anti-malware-policies-configure" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Quarantine policies</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/quarantine-policies" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Microsoft Defender Portal — Threat Policies</strong><br>
                        <small><a href="https://security.microsoft.com/threatpolicy" target="_blank" class="link-docs">&#128218; Abrir portal</a></small>
                    </div>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div class="text-center py-4">
            <p class="text-muted">chiringuito365.com&reg; | Internal Tools 2026</p>
        </div>

    </div><!-- /container -->
</body>
</html>
"@

# Save and open HTML report
$reportPath = Join-Path -Path $reportDir -ChildPath $htmlFile
$htmlReport | Out-File -FilePath $reportPath -Encoding utf8 -Force
Write-Host ""
Write-Host "  Reporte HTML generado: $reportPath" -ForegroundColor Green
Invoke-Item $reportPath
