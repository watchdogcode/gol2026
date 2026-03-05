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
    Valida todas las políticas de Microsoft Defender for Office 365 (MDO).

.DESCRIPTION
    Este script revisa la configuración de las políticas de:
    - Anti-Spam (HostedContentFilterPolicy)
    - Anti-Malware (MalwareFilterPolicy)
    - Anti-Phishing (AntiPhishPolicy)
    - Safe Links (SafeLinksPolicy)
    - Safe Attachments (SafeAttachmentPolicy + SafeAttachmentRule + AtpPolicyForO365)
    - Connection Filtering (HostedConnectionFilterPolicy)
    - Preset Security Policies (EOPProtectionPolicyRule + ATPProtectionPolicyRule)

    Compara los valores actuales contra las configuraciones recomendadas por Microsoft
    (Standard y Strict) y genera un reporte con el estado de cada política.

.NOTES
    Requiere conexión previa a Exchange Online y Security & Compliance:
        Connect-ExchangeOnline
        Connect-IPPSSession

    Autor : Ernesto Cobos Roqueñí
    Fecha : 3/Marzo/2026
    Versión: 2.6
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
    Install-Module ExchangeOnlineManagement 
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

    $color = switch ($Status) {
        'PASS' { 'Green'  }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red'    }
        'INFO' { 'Cyan'   }
        default { 'White' }
    }

    # Track for HTML report
    $null = $script:htmlRows.Add([pscustomobject]@{
        Section       = $script:currentSection
        PolicyName    = $script:currentPolicyName
        Setting       = $Setting
        CurrentValue  = $CurrentValue
        Recommended   = $RecommendedValue
        Status        = $Status
    })
}

function Write-SectionHeader {
    param([string]$Title)
}

function Write-PolicyHeader {
    param([string]$PolicyName)
}

# ─────────────────────────────────────────────
# Contadores globales y tracking de políticas
# ─────────────────────────────────────────────
$script:totalChecks = 0
$script:passCount   = 0
$script:warnCount   = 0
$script:failCount   = 0

# Tracking por política: clave = "Seccion|NombrePolitica", valor = @{Pass=0; Fail=0; Warn=0}
$script:policyResults = @{}
$script:currentPolicyKey = $null
$script:currentPolicyName = $null
$script:currentSection = $null

# HTML row tracking
$script:htmlRows = [System.Collections.ArrayList]::new()

function Set-CurrentPolicy {
    param([string]$Section, [string]$PolicyName)
    $script:currentPolicyKey = "$Section|$PolicyName"
    $script:currentPolicyName = $PolicyName
    $script:currentSection = $Section
    if (-not $script:policyResults.ContainsKey($script:currentPolicyKey)) {
        $script:policyResults[$script:currentPolicyKey] = @{ Pass = 0; Fail = 0; Warn = 0 }
    }
}

function Test-Setting {
    param(
        [string]$Setting,
        $CurrentValue,
        $RecommendedValue,
        [switch]$IsArray
    )

    $script:totalChecks++

    $currentStr     = if ($null -eq $CurrentValue) { "<null>" } elseif ($IsArray) { ($CurrentValue -join ', ') } else { "$CurrentValue" }
    $recommendedStr = if ($IsArray) { ($RecommendedValue -join ', ') } else { "$RecommendedValue" }

    if ($IsArray) {
        $match = ($null -ne $CurrentValue) -and (
            (Compare-Object $CurrentValue $RecommendedValue -SyncWindow 0 | Measure-Object).Count -eq 0
        )
    }
    else {
        $match = "$CurrentValue" -eq "$RecommendedValue"
    }

    if ($match) {
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
# Conexión a Exchange Online y Security & Compliance
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "Validando conexion a Exchange Online / Security & Compliance..." -ForegroundColor DarkGray

# Intentar conectar a Exchange Online si no hay sesión activa
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

# Intentar conectar a Security & Compliance (IPPSSession) si los cmdlets de MDO no están disponibles
$mdoAvailable = $true
try {
    $null = Get-Command Get-SafeLinksPolicy -ErrorAction Stop
    Write-Host "  Cmdlets de MDO (Safe Links/Attachments) disponibles." -ForegroundColor Green
}
catch {
    Write-Host "  Cmdlets de MDO no disponibles. Conectando a Security & Compliance..." -ForegroundColor Yellow
    try {
        Connect-IPPSSession -ShowBanner:$false -ErrorAction Stop
        # Verificar de nuevo después de conectar
        $null = Get-Command Get-SafeLinksPolicy -ErrorAction Stop
        Write-Host "  Conexion a Security & Compliance establecida." -ForegroundColor Green
    }
    catch {
        $mdoAvailable = $false
        Write-Host "[!!] No se pudieron habilitar los cmdlets de MDO." -ForegroundColor Yellow
        Write-Host "     Asegurate de tener licencia MDO P1/P2. Las secciones Safe Links/Attachments se omitiran." -ForegroundColor Yellow
    }
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host ""
Write-Host "Reporte de Validación de Políticas MDO" -ForegroundColor White
Write-Host "Fecha: $timestamp" -ForegroundColor DarkGray
Write-Host "Tenant: $((Get-OrganizationConfig).DisplayName)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Validando políticas de MDO..." -ForegroundColor Yellow

# ═════════════════════════════════════════════
# 1. ANTI-SPAM — Get-HostedContentFilterPolicy
# ═════════════════════════════════════════════
Write-SectionHeader "1. ANTI-SPAM (HostedContentFilterPolicy)"

$spamPolicies = Get-HostedContentFilterPolicy

foreach ($policy in $spamPolicies) {
    Set-CurrentPolicy -Section "Anti-Spam" -PolicyName $policy.Name
    Write-PolicyHeader $policy.Name

    # Acciones por veredicto (recomendaciones Strict)
    Test-Setting -Setting "SpamAction"                  -CurrentValue $policy.SpamAction                  -RecommendedValue "MoveToJmf"
    Test-Setting -Setting "HighConfidenceSpamAction"    -CurrentValue $policy.HighConfidenceSpamAction    -RecommendedValue "Quarantine"
    Test-Setting -Setting "PhishSpamAction"             -CurrentValue $policy.PhishSpamAction             -RecommendedValue "Quarantine"
    Test-Setting -Setting "HighConfidencePhishAction"   -CurrentValue $policy.HighConfidencePhishAction   -RecommendedValue "Quarantine"
    Test-Setting -Setting "BulkSpamAction"              -CurrentValue $policy.BulkSpamAction              -RecommendedValue "MoveToJmf"

    # Umbral de correo masivo (Strict = 5, Standard = 6)
    Test-Setting -Setting "BulkThreshold"               -CurrentValue $policy.BulkThreshold               -RecommendedValue "5"

    # Retención en cuarentena
    Test-Setting -Setting "QuarantineRetentionPeriod"   -CurrentValue $policy.QuarantineRetentionPeriod   -RecommendedValue "30"

    # Safety Tips
    Test-Setting -Setting "InlineSafetyTipsEnabled"     -CurrentValue $policy.InlineSafetyTipsEnabled     -RecommendedValue "True"

    # ZAP
    Test-Setting -Setting "SpamZapEnabled"              -CurrentValue $policy.SpamZapEnabled              -RecommendedValue "True"
    Test-Setting -Setting "PhishZapEnabled"             -CurrentValue $policy.PhishZapEnabled             -RecommendedValue "True"

    # Allowed / Blocked senders y dominios
    if ($policy.AllowedSenders.Count -gt 0 -or $policy.AllowedSenderDomains.Count -gt 0) {
        $script:totalChecks++
        $script:warnCount++
        Write-Status -Setting "AllowedSenders/Domains" `
                     -CurrentValue "Senders: $($policy.AllowedSenders.Count), Domains: $($policy.AllowedSenderDomains.Count)" `
                     -RecommendedValue "0 (evitar listas allow)" `
                     -Status 'WARN'
    }
    else {
        $script:totalChecks++
        $script:passCount++
        Write-Status -Setting "AllowedSenders/Domains" -CurrentValue "Ninguno" -RecommendedValue "0" -Status 'PASS'
    }
}

# ═════════════════════════════════════════════
# 2. ANTI-MALWARE — Get-MalwareFilterPolicy
# ═════════════════════════════════════════════
Write-SectionHeader "2. ANTI-MALWARE (MalwareFilterPolicy)"

$malwarePolicies = Get-MalwareFilterPolicy

foreach ($policy in $malwarePolicies) {
    Set-CurrentPolicy -Section "Anti-Malware" -PolicyName $policy.Name
    Write-PolicyHeader $policy.Name

    # ZAP para malware
    Test-Setting -Setting "ZapEnabled"                          -CurrentValue $policy.ZapEnabled                          -RecommendedValue "True"

    # Filtro de tipos de archivo comunes
    Test-Setting -Setting "EnableFileFilter"                    -CurrentValue $policy.EnableFileFilter                    -RecommendedValue "True"

    # Notificaciones internas
    Test-SettingWarn -Setting "EnableInternalSenderAdminNotifications" -CurrentValue $policy.EnableInternalSenderAdminNotifications -RecommendedValue "True"

    # Política de adjuntos no escaneables
    Test-Setting -Setting "FileTypeAction"                      -CurrentValue $policy.FileTypes.Count                     -RecommendedValue ($policy.FileTypes.Count)

    # Quarantine tag
    if ($policy.QuarantineTag) {
        $script:totalChecks++
        $script:passCount++
        Write-Status -Setting "QuarantineTag" -CurrentValue $policy.QuarantineTag -RecommendedValue "Configurado" -Status 'INFO'
    }
    else {
        $script:totalChecks++
        $script:warnCount++
        Write-Status -Setting "QuarantineTag" -CurrentValue "<no configurado>" -RecommendedValue "Configurar" -Status 'WARN'
    }

    # Extensiones bloqueadas comunes
    $recommendedExtensions = @('ace','ani','apk','app','appx','arj','bat','cab','cmd','com','deb','dex',
        'dll','docm','elf','exe','hta','img','iso','jar','jnlp','kext','lha','lib','library','lnk','lzh',
        'macho','mde','msc','msi','msix','msp','mst','pif','ppa','ppam','reg','rev','scf','scr','sct',
        'sys','uif','vb','vbe','vbs','vxd','wsc','wsf','wsh','xll','xz','z')

    $missingExtensions = @($recommendedExtensions | Where-Object { $_ -notin @($policy.FileTypes) })
    if ($missingExtensions.Count -gt 0 -and $policy.EnableFileFilter -eq $true) {
        $script:totalChecks++
        $script:warnCount++
        $allMissing = $missingExtensions -join ', '
        Write-Status -Setting "Extensiones bloqueadas faltantes" `
                     -CurrentValue "$($missingExtensions.Count) faltantes" `
                     -RecommendedValue "Agregar: $allMissing" `
                     -Status 'WARN'
    }
    elseif ($policy.EnableFileFilter -eq $true) {
        $script:totalChecks++
        $script:passCount++
        Write-Status -Setting "Extensiones bloqueadas" -CurrentValue "Todas cubiertas" -RecommendedValue "Completo" -Status 'PASS'
    }
}

# ═════════════════════════════════════════════
# 3. ANTI-PHISHING — Get-AntiPhishPolicy
# ═════════════════════════════════════════════
Write-SectionHeader "3. ANTI-PHISHING (AntiPhishPolicy)"

$phishPolicies = Get-AntiPhishPolicy

foreach ($policy in $phishPolicies) {
    Set-CurrentPolicy -Section "Anti-Phishing" -PolicyName $policy.Name
    Write-PolicyHeader $policy.Name

    # Estado general
    Test-Setting -Setting "Enabled"                             -CurrentValue $policy.Enabled                             -RecommendedValue "True"

    # Protección de suplantación (Impersonation)
    Test-Setting -Setting "EnableMailboxIntelligence"           -CurrentValue $policy.EnableMailboxIntelligence           -RecommendedValue "True"
    Test-Setting -Setting "EnableMailboxIntelligenceProtection" -CurrentValue $policy.EnableMailboxIntelligenceProtection -RecommendedValue "True"
    Test-Setting -Setting "EnableSpoofIntelligence"             -CurrentValue $policy.EnableSpoofIntelligence             -RecommendedValue "True"
    Test-Setting -Setting "EnableOrganizationDomainsProtection" -CurrentValue $policy.EnableOrganizationDomainsProtection -RecommendedValue "True"

    # Acciones
    Test-Setting -Setting "AuthenticationFailAction"            -CurrentValue $policy.AuthenticationFailAction            -RecommendedValue "MoveToJmf"

    # Suplantación de usuario
    Test-SettingWarn -Setting "EnableTargetedUserProtection"    -CurrentValue $policy.EnableTargetedUserProtection        -RecommendedValue "True"
    Test-SettingWarn -Setting "EnableTargetedDomainsProtection" -CurrentValue $policy.EnableTargetedDomainsProtection     -RecommendedValue "True"

    # Umbrales de phishing
    Test-Setting -Setting "PhishThresholdLevel"                 -CurrentValue $policy.PhishThresholdLevel                 -RecommendedValue "3"

    # Safety Tips
    Test-Setting -Setting "EnableSimilarUsersSafetyTips"        -CurrentValue $policy.EnableSimilarUsersSafetyTips        -RecommendedValue "True"
    Test-Setting -Setting "EnableSimilarDomainsSafetyTips"      -CurrentValue $policy.EnableSimilarDomainsSafetyTips      -RecommendedValue "True"
    Test-Setting -Setting "EnableUnusualCharactersSafetyTips"   -CurrentValue $policy.EnableUnusualCharactersSafetyTips   -RecommendedValue "True"

    # Honor DMARC
    Test-SettingWarn -Setting "HonorDmarcPolicy"                -CurrentValue $policy.HonorDmarcPolicy                   -RecommendedValue "True"

    # Primer contacto
    Test-Setting -Setting "EnableFirstContactSafetyTips"        -CurrentValue $policy.EnableFirstContactSafetyTips        -RecommendedValue "True"

    # Acciones impersonación
    if ($policy.EnableTargetedUserProtection -eq $true) {
        Test-Setting -Setting "TargetedUserProtectionAction"    -CurrentValue $policy.TargetedUserProtectionAction        -RecommendedValue "Quarantine"
    }
    if ($policy.EnableTargetedDomainsProtection -eq $true) {
        Test-Setting -Setting "TargetedDomainProtectionAction"  -CurrentValue $policy.TargetedDomainProtectionAction      -RecommendedValue "Quarantine"
    }
    Test-Setting -Setting "MailboxIntelligenceProtectionAction" -CurrentValue $policy.MailboxIntelligenceProtectionAction -RecommendedValue "MoveToJmf"
}

# ═════════════════════════════════════════════
# 4. SAFE LINKS — Get-SafeLinksPolicy
# ═════════════════════════════════════════════
if ($mdoAvailable) {
    Write-SectionHeader "4. SAFE LINKS (SafeLinksPolicy)"

    $safeLinksPolicies = Get-SafeLinksPolicy

    if ($safeLinksPolicies.Count -eq 0) {
        $script:totalChecks++
        $script:failCount++
    }

    foreach ($policy in $safeLinksPolicies) {
        Set-CurrentPolicy -Section "Safe Links" -PolicyName $policy.Name
        Write-PolicyHeader $policy.Name

        Test-Setting -Setting "EnableSafeLinksForEmail"         -CurrentValue $policy.EnableSafeLinksForEmail         -RecommendedValue "True"
        Test-Setting -Setting "EnableSafeLinksForTeams"         -CurrentValue $policy.EnableSafeLinksForTeams         -RecommendedValue "True"
        Test-Setting -Setting "EnableSafeLinksForOffice"        -CurrentValue $policy.EnableSafeLinksForOffice        -RecommendedValue "True"
        Test-Setting -Setting "ScanUrls"                        -CurrentValue $policy.ScanUrls                        -RecommendedValue "True"
        Test-Setting -Setting "DeliverMessageAfterScan"         -CurrentValue $policy.DeliverMessageAfterScan         -RecommendedValue "True"
        Test-Setting -Setting "DisableUrlRewrite"               -CurrentValue $policy.DisableUrlRewrite               -RecommendedValue "False"
        Test-Setting -Setting "EnableForInternalSenders"        -CurrentValue $policy.EnableForInternalSenders        -RecommendedValue "True"
        Test-Setting -Setting "TrackClicks"                     -CurrentValue $policy.TrackClicks                     -RecommendedValue "True"
        Test-SettingWarn -Setting "EnableOrganizationBranding"  -CurrentValue $policy.EnableOrganizationBranding      -RecommendedValue "True"

        # URLs en lista de exclusión
        if ($policy.DoNotRewriteUrls.Count -gt 0) {
            $script:totalChecks++
            $script:warnCount++
            Write-Status -Setting "DoNotRewriteUrls" `
                         -CurrentValue "$($policy.DoNotRewriteUrls.Count) URLs excluidas" `
                         -RecommendedValue "Revisar lista de exclusiones" `
                         -Status 'WARN'
            foreach ($url in $policy.DoNotRewriteUrls) {
                # URL listed in HTML report
            }
        }
        else {
            $script:totalChecks++
            $script:passCount++
            Write-Status -Setting "DoNotRewriteUrls" -CurrentValue "Ninguna" -RecommendedValue "0 exclusiones" -Status 'PASS'
        }
    }
}

# ═════════════════════════════════════════════
# 5. SAFE ATTACHMENTS — Get-SafeAttachmentPolicy
# ═════════════════════════════════════════════
if ($mdoAvailable) {
    Write-SectionHeader "5. SAFE ATTACHMENTS (SafeAttachmentPolicy)"

    $safeAttachPolicies = Get-SafeAttachmentPolicy

    if ($safeAttachPolicies.Count -eq 0) {
        $script:totalChecks++
        $script:failCount++
    }

    foreach ($policy in $safeAttachPolicies) {
        Set-CurrentPolicy -Section "Safe Attachments" -PolicyName $policy.Name
        Write-PolicyHeader $policy.Name

        # Acción: Block es la más segura, Dynamic Delivery es la recomendada para balance
        $actionOk = $policy.Action -in @('Block', 'DynamicDelivery')
        $script:totalChecks++
        if ($actionOk) {
            $script:passCount++
            Write-Status -Setting "Action" -CurrentValue $policy.Action -RecommendedValue "Block o DynamicDelivery" -Status 'PASS'
        }
        else {
            $script:failCount++
            Write-Status -Setting "Action" -CurrentValue $policy.Action -RecommendedValue "Block o DynamicDelivery" -Status 'FAIL'
        }

        Test-Setting -Setting "Enable"                          -CurrentValue $policy.Enable                          -RecommendedValue "True"
        Test-Setting -Setting "QuarantineTag"                   -CurrentValue ($null -ne $policy.QuarantineTag)       -RecommendedValue "True"

        # Redirección (para análisis)
        Test-SettingWarn -Setting "Redirect"                    -CurrentValue $policy.Redirect                        -RecommendedValue "True"

        if ($policy.Redirect -eq $true -and $policy.RedirectAddress) {
            Write-Status -Setting "RedirectAddress" -CurrentValue $policy.RedirectAddress -RecommendedValue "Configurado" -Status 'INFO'
            $script:totalChecks++
            $script:passCount++
        }
        elseif ($policy.Redirect -eq $true -and -not $policy.RedirectAddress) {
            $script:totalChecks++
            $script:failCount++
            Write-Status -Setting "RedirectAddress" -CurrentValue "<vacio>" -RecommendedValue "Debe configurarse si Redirect=True" -Status 'FAIL'
        }

        # ActionOnError (propiedad deprecada en versiones recientes, verificar si existe)
        if ($null -ne $policy.PSObject.Properties['ActionOnError']) {
            Test-Setting -Setting "ActionOnError"               -CurrentValue $policy.ActionOnError               -RecommendedValue "True"
        }
    }

    # ─────────────────────────────────────────
    # Configuración global de Safe Attachments
    # ─────────────────────────────────────────
    Set-CurrentPolicy -Section "Safe Attachments (ATP Global)" -PolicyName "Configuración Global"
    Write-PolicyHeader "Configuración Global (ATP)"
    try {
        $atpPolicy = Get-AtpPolicyForO365 -ErrorAction Stop
        Test-Setting -Setting "EnableATPForSPOTeamsODB"         -CurrentValue $atpPolicy.EnableATPForSPOTeamsODB       -RecommendedValue "True"
        Test-Setting -Setting "EnableSafeDocs"                  -CurrentValue $atpPolicy.EnableSafeDocs                -RecommendedValue "True"
        Test-Setting -Setting "AllowSafeDocsOpen"               -CurrentValue $atpPolicy.AllowSafeDocsOpen             -RecommendedValue "False"
    }
    catch {
        # ATP policy not available — skipped
    }

    # ─────────────────────────────────────────
    # Safe Attachment Rules (a quién aplican)
    # ─────────────────────────────────────────
    try {
        $safeAttachRules = Get-SafeAttachmentRule -ErrorAction Stop
        if ($safeAttachRules.Count -eq 0) {
            $script:totalChecks++
            $script:failCount++
            Write-Status -Setting "SafeAttachmentRules" -CurrentValue "No hay reglas configuradas" -RecommendedValue "Al menos 1 regla activa" -Status 'FAIL'
        }
        foreach ($rule in $safeAttachRules) {
            Set-CurrentPolicy -Section "Safe Attachment Rules" -PolicyName $rule.Name

            # Estado de la regla
            Test-Setting -Setting "State"         -CurrentValue $rule.State         -RecommendedValue "Enabled"

            # Prioridad
            $script:totalChecks++
            $script:passCount++
            Write-Status -Setting "Priority" -CurrentValue $rule.Priority -RecommendedValue "Configurado" -Status 'INFO'
            if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
                $script:policyResults[$script:currentPolicyKey].Pass++
            }

            # Verificar que tenga destinatarios asignados
            $hasRecipients = ($rule.SentTo.Count -gt 0) -or ($rule.SentToMemberOf.Count -gt 0) -or ($rule.RecipientDomainIs.Count -gt 0)
            $script:totalChecks++
            if ($hasRecipients) {
                $script:passCount++
                if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
                    $script:policyResults[$script:currentPolicyKey].Pass++
                }
                $recipientInfo = @()
                if ($rule.SentTo.Count -gt 0)            { $recipientInfo += "SentTo: $($rule.SentTo.Count)" }
                if ($rule.SentToMemberOf.Count -gt 0)    { $recipientInfo += "Groups: $($rule.SentToMemberOf.Count)" }
                if ($rule.RecipientDomainIs.Count -gt 0)  { $recipientInfo += "Domains: $($rule.RecipientDomainIs -join ', ')" }
                Write-Status -Setting "Destinatarios asignados" -CurrentValue ($recipientInfo -join '; ') -RecommendedValue "Configurado" -Status 'PASS'
            }
            else {
                $script:warnCount++
                if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
                    $script:policyResults[$script:currentPolicyKey].Warn++
                }
                Write-Status -Setting "Destinatarios asignados" -CurrentValue "Ninguno" -RecommendedValue "Asignar usuarios, grupos o dominios" -Status 'WARN'
            }

            # Excepciones
            $hasExceptions = ($rule.ExceptIfSentTo.Count -gt 0) -or ($rule.ExceptIfSentToMemberOf.Count -gt 0) -or ($rule.ExceptIfRecipientDomainIs.Count -gt 0)
            if ($hasExceptions) {
                $script:totalChecks++
                $script:warnCount++
                if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
                    $script:policyResults[$script:currentPolicyKey].Warn++
                }
                $exceptInfo = @()
                if ($rule.ExceptIfSentTo.Count -gt 0)            { $exceptInfo += "ExceptSentTo: $($rule.ExceptIfSentTo.Count)" }
                if ($rule.ExceptIfSentToMemberOf.Count -gt 0)    { $exceptInfo += "ExceptGroups: $($rule.ExceptIfSentToMemberOf.Count)" }
                if ($rule.ExceptIfRecipientDomainIs.Count -gt 0)  { $exceptInfo += "ExceptDomains: $($rule.ExceptIfRecipientDomainIs -join ', ')" }
                Write-Status -Setting "Excepciones" -CurrentValue ($exceptInfo -join '; ') -RecommendedValue "Revisar exclusiones" -Status 'WARN'
            }
        }
    }
    catch {
        # Safe Attachment Rules not available — skipped
    }
}

# ═══════════════════════════════════════════════
# 6. CONNECTION FILTERING — Get-HostedConnectionFilterPolicy
# ═══════════════════════════════════════════════
Write-SectionHeader "6. CONNECTION FILTERING (HostedConnectionFilterPolicy)"

try {
    $connFilterPolicies = Get-HostedConnectionFilterPolicy -ErrorAction Stop

    foreach ($policy in $connFilterPolicies) {
        Set-CurrentPolicy -Section "Connection Filter" -PolicyName $policy.Name
        Write-PolicyHeader $policy.Name

        # IP Allow List
        if ($policy.IPAllowList.Count -gt 0) {
            $script:totalChecks++
            $script:warnCount++
            if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
                $script:policyResults[$script:currentPolicyKey].Warn++
            }
            Write-Status -Setting "IPAllowList" `
                         -CurrentValue "$($policy.IPAllowList.Count) IPs: $($policy.IPAllowList -join ', ')" `
                         -RecommendedValue "Revisar - minimizar IPs permitidas" `
                         -Status 'WARN'
        }
        else {
            $script:totalChecks++
            $script:passCount++
            if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
                $script:policyResults[$script:currentPolicyKey].Pass++
            }
            Write-Status -Setting "IPAllowList" -CurrentValue "Vacia" -RecommendedValue "Sin IPs permitidas (ideal)" -Status 'PASS'
        }

        # IP Block List
        if ($policy.IPBlockList.Count -gt 0) {
            $script:totalChecks++
            $script:passCount++
            if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
                $script:policyResults[$script:currentPolicyKey].Pass++
            }
            Write-Status -Setting "IPBlockList" `
                         -CurrentValue "$($policy.IPBlockList.Count) IPs bloqueadas" `
                         -RecommendedValue "Configurado" `
                         -Status 'INFO'
        }
        else {
            $script:totalChecks++
            $script:passCount++
            if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
                $script:policyResults[$script:currentPolicyKey].Pass++
            }
            Write-Status -Setting "IPBlockList" -CurrentValue "Vacia" -RecommendedValue "Opcional" -Status 'INFO'
        }

        # EnableSafeList (usar lista segura de Microsoft)
        Test-Setting -Setting "EnableSafeList"                  -CurrentValue $policy.EnableSafeList                  -RecommendedValue "False"

        # DirectoryBasedEdgeBlockMode
        Test-Setting -Setting "DirectoryBasedEdgeBlockMode"     -CurrentValue $policy.DirectoryBasedEdgeBlockMode     -RecommendedValue "Default"
    }
}
catch {
    # Connection Filtering policy not available — skipped
}

# ═════════════════════════════════════════════
# 7. PRESET SECURITY POLICIES
# ═════════════════════════════════════════════
Write-SectionHeader "7. PRESET SECURITY POLICIES"

try {
    # ─────────────────────────────────────────
    # EOP Protection Policy Rules (Standard / Strict)
    # ─────────────────────────────────────────
    $eopRules = Get-EOPProtectionPolicyRule -ErrorAction Stop

    $standardEOP = $eopRules | Where-Object { $_.Identity -like '*Standard*' }
    $strictEOP   = $eopRules | Where-Object { $_.Identity -like '*Strict*' }

    # Standard Preset — EOP
    Set-CurrentPolicy -Section "Preset Security Policies" -PolicyName "Standard Preset (EOP)"
    Write-PolicyHeader "Standard Preset (EOP)"

    if ($standardEOP) {
        $eopStdState = if ($standardEOP.State -eq 'Enabled') { 'Enabled' } else { $standardEOP.State }
        Test-Setting -Setting "StandardPreset-EOP-State" -CurrentValue $eopStdState -RecommendedValue "Enabled"
        Test-Setting -Setting "StandardPreset-EOP-Priority" -CurrentValue $standardEOP.Priority -RecommendedValue "1"

        # Sentto / ExceptIf groups
        $stdSentTo = if ($standardEOP.SentTo.Count -gt 0 -or $standardEOP.SentToMemberOf.Count -gt 0 -or $standardEOP.RecipientDomainIs.Count -gt 0) { 'Configurado' } else { 'Todos los destinatarios' }
        $script:totalChecks++
        $script:passCount++
        if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "StandardPreset-EOP-Scope" -CurrentValue $stdSentTo -RecommendedValue "Configurado o Todos" -Status 'PASS'

        if ($standardEOP.ExceptIfSentTo.Count -gt 0 -or $standardEOP.ExceptIfSentToMemberOf.Count -gt 0 -or $standardEOP.ExceptIfRecipientDomainIs.Count -gt 0) {
            $exceptCount = ($standardEOP.ExceptIfSentTo.Count + $standardEOP.ExceptIfSentToMemberOf.Count + $standardEOP.ExceptIfRecipientDomainIs.Count)
            $script:totalChecks++
            $script:warnCount++
            if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
            Write-Status -Setting "StandardPreset-EOP-Exceptions" -CurrentValue "$exceptCount exclusiones configuradas" -RecommendedValue "Revisar exclusiones" -Status 'WARN'
        }
        else {
            $script:totalChecks++
            $script:passCount++
            if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
            Write-Status -Setting "StandardPreset-EOP-Exceptions" -CurrentValue "Ninguna" -RecommendedValue "Sin exclusiones (ideal)" -Status 'PASS'
        }
    }
    else {
        $script:totalChecks++
        $script:failCount++
        if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Fail++ }
        Write-Status -Setting "StandardPreset-EOP" -CurrentValue "No configurada" -RecommendedValue "Habilitada" -Status 'FAIL'
    }

    # Strict Preset — EOP
    Set-CurrentPolicy -Section "Preset Security Policies" -PolicyName "Strict Preset (EOP)"
    Write-PolicyHeader "Strict Preset (EOP)"

    if ($strictEOP) {
        $eopStrState = if ($strictEOP.State -eq 'Enabled') { 'Enabled' } else { $strictEOP.State }
        Test-Setting -Setting "StrictPreset-EOP-State" -CurrentValue $eopStrState -RecommendedValue "Enabled"
        Test-Setting -Setting "StrictPreset-EOP-Priority" -CurrentValue $strictEOP.Priority -RecommendedValue "0"

        $strSentTo = if ($strictEOP.SentTo.Count -gt 0 -or $strictEOP.SentToMemberOf.Count -gt 0 -or $strictEOP.RecipientDomainIs.Count -gt 0) { 'Configurado' } else { 'Todos los destinatarios' }
        $script:totalChecks++
        $script:passCount++
        if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "StrictPreset-EOP-Scope" -CurrentValue $strSentTo -RecommendedValue "Configurado o Todos" -Status 'PASS'

        if ($strictEOP.ExceptIfSentTo.Count -gt 0 -or $strictEOP.ExceptIfSentToMemberOf.Count -gt 0 -or $strictEOP.ExceptIfRecipientDomainIs.Count -gt 0) {
            $exceptCount = ($strictEOP.ExceptIfSentTo.Count + $strictEOP.ExceptIfSentToMemberOf.Count + $strictEOP.ExceptIfRecipientDomainIs.Count)
            $script:totalChecks++
            $script:warnCount++
            if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
            Write-Status -Setting "StrictPreset-EOP-Exceptions" -CurrentValue "$exceptCount exclusiones configuradas" -RecommendedValue "Revisar exclusiones" -Status 'WARN'
        }
        else {
            $script:totalChecks++
            $script:passCount++
            if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
            Write-Status -Setting "StrictPreset-EOP-Exceptions" -CurrentValue "Ninguna" -RecommendedValue "Sin exclusiones (ideal)" -Status 'PASS'
        }
    }
    else {
        $script:totalChecks++
        $script:warnCount++
        if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
        Write-Status -Setting "StrictPreset-EOP" -CurrentValue "No configurada" -RecommendedValue "Habilitada (recomendado para admins/VIP)" -Status 'WARN'
    }
}
catch {
    # EOP Preset rules not available — skipped
}

if ($script:mdoAvailable) {
    try {
        # ─────────────────────────────────────────
        # ATP Protection Policy Rules (Standard / Strict)
        # ─────────────────────────────────────────
        $atpRules = Get-ATPProtectionPolicyRule -ErrorAction Stop

        $standardATP = $atpRules | Where-Object { $_.Identity -like '*Standard*' }
        $strictATP   = $atpRules | Where-Object { $_.Identity -like '*Strict*' }

        # Standard Preset — ATP (MDO)
        Set-CurrentPolicy -Section "Preset Security Policies" -PolicyName "Standard Preset (MDO/ATP)"
        Write-PolicyHeader "Standard Preset (MDO/ATP)"

        if ($standardATP) {
            $atpStdState = if ($standardATP.State -eq 'Enabled') { 'Enabled' } else { $standardATP.State }
            Test-Setting -Setting "StandardPreset-ATP-State" -CurrentValue $atpStdState -RecommendedValue "Enabled"
            Test-Setting -Setting "StandardPreset-ATP-Priority" -CurrentValue $standardATP.Priority -RecommendedValue "1"

            $stdAtpSentTo = if ($standardATP.SentTo.Count -gt 0 -or $standardATP.SentToMemberOf.Count -gt 0 -or $standardATP.RecipientDomainIs.Count -gt 0) { 'Configurado' } else { 'Todos los destinatarios' }
            $script:totalChecks++
            $script:passCount++
            if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
            Write-Status -Setting "StandardPreset-ATP-Scope" -CurrentValue $stdAtpSentTo -RecommendedValue "Configurado o Todos" -Status 'PASS'

            if ($standardATP.ExceptIfSentTo.Count -gt 0 -or $standardATP.ExceptIfSentToMemberOf.Count -gt 0 -or $standardATP.ExceptIfRecipientDomainIs.Count -gt 0) {
                $exceptCount = ($standardATP.ExceptIfSentTo.Count + $standardATP.ExceptIfSentToMemberOf.Count + $standardATP.ExceptIfRecipientDomainIs.Count)
                $script:totalChecks++
                $script:warnCount++
                if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
                Write-Status -Setting "StandardPreset-ATP-Exceptions" -CurrentValue "$exceptCount exclusiones configuradas" -RecommendedValue "Revisar exclusiones" -Status 'WARN'
            }
            else {
                $script:totalChecks++
                $script:passCount++
                if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
                Write-Status -Setting "StandardPreset-ATP-Exceptions" -CurrentValue "Ninguna" -RecommendedValue "Sin exclusiones (ideal)" -Status 'PASS'
            }
        }
        else {
            $script:totalChecks++
            $script:failCount++
            if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Fail++ }
            Write-Status -Setting "StandardPreset-ATP" -CurrentValue "No configurada" -RecommendedValue "Habilitada" -Status 'FAIL'
        }

        # Strict Preset — ATP (MDO)
        Set-CurrentPolicy -Section "Preset Security Policies" -PolicyName "Strict Preset (MDO/ATP)"
        Write-PolicyHeader "Strict Preset (MDO/ATP)"

        if ($strictATP) {
            $atpStrState = if ($strictATP.State -eq 'Enabled') { 'Enabled' } else { $strictATP.State }
            Test-Setting -Setting "StrictPreset-ATP-State" -CurrentValue $atpStrState -RecommendedValue "Enabled"
            Test-Setting -Setting "StrictPreset-ATP-Priority" -CurrentValue $strictATP.Priority -RecommendedValue "0"

            $strAtpSentTo = if ($strictATP.SentTo.Count -gt 0 -or $strictATP.SentToMemberOf.Count -gt 0 -or $strictATP.RecipientDomainIs.Count -gt 0) { 'Configurado' } else { 'Todos los destinatarios' }
            $script:totalChecks++
            $script:passCount++
            if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
            Write-Status -Setting "StrictPreset-ATP-Scope" -CurrentValue $strAtpSentTo -RecommendedValue "Configurado o Todos" -Status 'PASS'

            if ($strictATP.ExceptIfSentTo.Count -gt 0 -or $strictATP.ExceptIfSentToMemberOf.Count -gt 0 -or $strictATP.ExceptIfRecipientDomainIs.Count -gt 0) {
                $exceptCount = ($strictATP.ExceptIfSentTo.Count + $strictATP.ExceptIfSentToMemberOf.Count + $strictATP.ExceptIfRecipientDomainIs.Count)
                $script:totalChecks++
                $script:warnCount++
                if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
                Write-Status -Setting "StrictPreset-ATP-Exceptions" -CurrentValue "$exceptCount exclusiones configuradas" -RecommendedValue "Revisar exclusiones" -Status 'WARN'
            }
            else {
                $script:totalChecks++
                $script:passCount++
                if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
                Write-Status -Setting "StrictPreset-ATP-Exceptions" -CurrentValue "Ninguna" -RecommendedValue "Sin exclusiones (ideal)" -Status 'PASS'
            }
        }
        else {
            $script:totalChecks++
            $script:warnCount++
            if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
            Write-Status -Setting "StrictPreset-ATP" -CurrentValue "No configurada" -RecommendedValue "Habilitada (recomendado para admins/VIP)" -Status 'WARN'
        }
    }
    catch {
        # ATP Preset rules not available — skipped
    }
}

# ═════════════════════════════════════════════
# RESUMEN FINAL (solo para HTML)
# ═════════════════════════════════════════════

# ═════════════════════════════════════════════
# GENERACION DE REPORTE HTML
# ═════════════════════════════════════════════

$tenantName = (Get-OrganizationConfig).DisplayName
$safeTenantName = $tenantName -replace '[\\/:*?"<>|]', '_'
$reportTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$date2 = Get-Date -Format "ddMMyyHHmmss"
$htmlFile = "MDO_PolicyValidation_${safeTenantName}_${date2}.html"

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

    # Section header row
    if ($row.Section -and $row.Section -ne $lastSection) {
        $htmlDetailRows += "<tr class='section-row'><td colspan='5'><strong>$($row.Section)</strong></td></tr>`n"
        $lastSection = $row.Section
    }

    $safeCurrentValue = [System.Web.HttpUtility]::HtmlEncode($row.CurrentValue)
    $safeRecommended  = [System.Web.HttpUtility]::HtmlEncode($row.Recommended)
    $safeSetting      = [System.Web.HttpUtility]::HtmlEncode($row.Setting)
    $safePolicyName   = [System.Web.HttpUtility]::HtmlEncode($row.PolicyName)

    # Resaltar Built-In Protection Policy en rojo para Safe Links / Safe Attachments
    $policyNameHtml = if ($row.PolicyName -eq 'Built-In Protection Policy' -and $row.Section -in @('Safe Links','Safe Attachments')) {
        "<span style='color:#dc3545;font-weight:700;'>$safePolicyName</span>"
    } else { $safePolicyName }

    $htmlDetailRows += @"
<tr>
    <td class='$statusClass'>$statusIcon $($row.Status)</td>
    <td class='policy-name'>$policyNameHtml</td>
    <td><strong>$safeSetting</strong></td>
    <td><code>$safeCurrentValue</code></td>
    <td><code>$safeRecommended</code></td>
</tr>
"@
}

# Build policy summary rows
$policySummaryRows = ""
foreach ($key in $script:policyResults.Keys | Sort-Object) {
    $parts  = $key -split '\|', 2
    $section = $parts[0]
    $name    = $parts[1]
    $r       = $script:policyResults[$key]
    $total   = $r.Pass + $r.Fail + $r.Warn
    if ($total -gt 0) { $pctP = [math]::Round(($r.Pass / $total) * 100, 0) } else { $pctP = 0 }

    # Progress bar color
    if ($pctP -ge 80) { $barColor = '#28a745' } elseif ($pctP -ge 60) { $barColor = '#ffc107' } else { $barColor = '#dc3545' }

    # Resaltar Built-In Protection Policy en rojo para Safe Links / Safe Attachments
    $nameHtml = if ($name -eq 'Built-In Protection Policy' -and $section -in @('Safe Links','Safe Attachments')) {
        "<strong style='color:#dc3545;'>$name</strong>"
    } else { "<strong>$name</strong>" }

    $policySummaryRows += @"
<tr>
    <td>$section</td>
    <td>$nameHtml</td>
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
    <title>MDO Policy Validation Report</title>
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
        <h1>Reporte de Validación de Políticas MDO</h1>
        <p>Fecha: $reportTimestamp</p>
        <p style="font-size: 1.15rem;">Tenant: <strong>$tenantName</strong></p>
        <p><em>&ldquo;La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad&rdquo;</em></p>
    </div>

    <div class="container-fluid px-4">

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
                    <div class="stat-label">Cumplimiento</div>
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

        <!-- Action Items & Recommendations -->
        <div class="card shadow-sm border-primary mb-4">
            <div class="card-header text-white" style="background-color: #0078d4;">&#128221; Documentación y Recomendaciones Microsoft</div>
            <div class="card-body">
                <div class="list-group">
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
                        <strong>&#128279; Configure Anti-Phishing policies</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-mdo-configure" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Configure Safe Links policies</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Configure Safe Attachments policies</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-policies-configure" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Configure connection filtering</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-configure" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Tenant Allow/Block List</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/tenant-allow-block-list-about" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Quarantine policies</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/quarantine-policies" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Microsoft Defender Portal</strong><br>
                        <small><a href="https://security.microsoft.com/threatpolicy" target="_blank" class="link-docs">&#128218; Threat Policies</a></small>
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
Write-Host "  Reporte HTML generado: $reportPath" -ForegroundColor Green
Invoke-Item $reportPath
