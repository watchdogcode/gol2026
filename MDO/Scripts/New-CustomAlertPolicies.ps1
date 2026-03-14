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
    Crea un conjunto de Alert Policies personalizadas en Microsoft 365 Defender / Purview
    para monitorear actividades críticas de seguridad.

.DESCRIPTION
    Este script crea políticas de alerta (Protection Alerts) utilizando el cmdlet
    New-ProtectionAlert. Al iniciar, solicita interactivamente la lista de destinatarios
    (usuarios o listas de distribución) que recibirán las notificaciones por correo.

    Categorías de alertas cubiertas:
    ─────────────────────────────────────────────
    Threat Management
      • Mailbox Audit Bypass Monitoring
      • Reglas de reenvío de correo sospechosas (Inbox Rules)
      • Modificación de Transport Rules
      • Cambios en políticas Anti-Phishing
      • Cambios en políticas Anti-Spam
      • Cambios en políticas Anti-Malware
      • Cambios en Safe Attachments / Safe Links
      • Envío de correo desde usuario restringido

    Data Loss Prevention
      • Cambios en políticas DLP
      • Búsquedas de eDiscovery iniciadas
      • Exportación de resultados de eDiscovery

    Access Control & Permissions
      • Asignación de roles administrativos en Exchange
      • Elevación de privilegios (Add member to role)
      • Cambios en permisos de buzón (Add-MailboxPermission)
      • Cambios en Conditional Access Policies

    File & SharePoint Activities
      • Compartir archivos externamente en SharePoint/OneDrive
      • Eliminación masiva de archivos

    ─────────────────────────────────────────────

    Referencia:
    https://learn.microsoft.com/en-us/defender-office-365/alert-policies-defender-portal
    https://learn.microsoft.com/en-us/purview/audit-log-activities
    https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-protectionalert

.PARAMETER NotifyUsers
    Lista de direcciones de correo (usuarios o listas de distribución) separadas por coma
    que recibirán las notificaciones de las alertas. Si no se proporciona, el script
    preguntará interactivamente.

.PARAMETER WhatIf
    Muestra las alertas que se crearían sin ejecutar la creación.

.EXAMPLE
    .\New-CustomAlertPolicies.ps1
    Ejecuta el script de forma interactiva, solicitando los destinatarios de notificación.

.EXAMPLE
    .\New-CustomAlertPolicies.ps1 -NotifyUsers "secops@contoso.com,soc-dl@contoso.com"
    Crea todas las alertas enviando notificaciones a secops@contoso.com y soc-dl@contoso.com.

.NOTES
    Requiere conexión previa a Security & Compliance PowerShell:
        Connect-IPPSSession

    Permisos requeridos:
        - Organization Management o Security Administrator en Microsoft Purview

    Autor  : Ernesto Cobos Roqueñí
    Fecha  : 13/Marzo/2026
    Versión: 1.0
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$NotifyUsers
)

# ═══════════════════════════════════════════════════════════════
#  VALIDACIÓN DE MÓDULO
# ═══════════════════════════════════════════════════════════════

if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
    Write-Host "[OK] Módulo ExchangeOnlineManagement instalado correctamente." -ForegroundColor DarkGray
}
else {
    Write-Host "[X] Módulo ExchangeOnlineManagement no encontrado. " -ForegroundColor Red -NoNewline
    Write-Host "Descargando e instalando..." -ForegroundColor Yellow
    Install-Module ExchangeOnlineManagement -Force -Scope CurrentUser
}

# ═══════════════════════════════════════════════════════════════
#  CONEXIÓN A EXCHANGE ONLINE Y SECURITY & COMPLIANCE
# ═══════════════════════════════════════════════════════════════

# Conexión a Exchange Online
try {
    $null = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "[OK] Conexión a Exchange Online verificada." -ForegroundColor Green
}
catch {
    Write-Host "[i] Conectando a Exchange Online..." -ForegroundColor Yellow
    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Host "[OK] Conexión a Exchange Online establecida." -ForegroundColor Green
    }
    catch {
        Write-Host "[X] No se pudo conectar a Exchange Online: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

# Conexión a Security & Compliance (IPPSSession)
try {
    $null = Get-ProtectionAlert -Identity "Suspicious email sending patterns" -ErrorAction Stop 2>$null
    Write-Host "[OK] Conexión a Security & Compliance verificada." -ForegroundColor Green
}
catch {
    Write-Host "[i] Conectando a Security & Compliance..." -ForegroundColor Yellow
    try {
        Connect-IPPSSession -ShowBanner:$false -ErrorAction Stop
        Write-Host "[OK] Conexión a Security & Compliance establecida." -ForegroundColor Green
    }
    catch {
        Write-Host "[X] No se pudo conectar a Security & Compliance: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

# ═══════════════════════════════════════════════════════════════
#  SOLICITAR DESTINATARIOS DE NOTIFICACIÓN
# ═══════════════════════════════════════════════════════════════

if ([string]::IsNullOrWhiteSpace($NotifyUsers)) {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  CONFIGURACIÓN DE NOTIFICACIONES PARA ALERT POLICIES           ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Ingrese los destinatarios de las notificaciones de alerta." -ForegroundColor White
    Write-Host "Puede ser una lista de distribución o usuarios individuales." -ForegroundColor Gray
    Write-Host "Para múltiples destinatarios, sepárelos con coma." -ForegroundColor Gray
    Write-Host ""
    Write-Host "Ejemplos:" -ForegroundColor DarkGray
    Write-Host "  secops@contoso.com" -ForegroundColor DarkGray
    Write-Host "  secops@contoso.com,ciso@contoso.com" -ForegroundColor DarkGray
    Write-Host "  dl-security-operations@contoso.com" -ForegroundColor DarkGray
    Write-Host ""

    do {
        $NotifyUsers = Read-Host "Destinatarios (-NotifyUser)"
        if ([string]::IsNullOrWhiteSpace($NotifyUsers)) {
            Write-Host "  [!] Debe ingresar al menos un destinatario." -ForegroundColor Yellow
        }
    } while ([string]::IsNullOrWhiteSpace($NotifyUsers))
}

# Parsear y validar formato de correos
$notifyList = $NotifyUsers -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

foreach ($email in $notifyList) {
    if ($email -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        Write-Host "[X] Formato de correo no válido: $email" -ForegroundColor Red
        return
    }
}

Write-Host ""
Write-Host "Destinatarios configurados:" -ForegroundColor Green
$notifyList | ForEach-Object { Write-Host "  → $_" -ForegroundColor White }
Write-Host ""

# ═══════════════════════════════════════════════════════════════
#  DEFINICIÓN DE ALERT POLICIES
# ═══════════════════════════════════════════════════════════════

$alertPolicies = @(

    # ── THREAT MANAGEMENT ──────────────────────────────────────

    @{
        Name         = "Custom - Mailbox Audit Bypass Monitoring"
        Category     = "ThreatManagement"
        Operation    = "Set-MailboxAuditBypassAssociation"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se configura un bypass de auditoría en un buzón. Un atacante podría usar esto para evitar que sus acciones queden registradas en los logs de auditoría."
    },

    @{
        Name         = "Custom - Suspicious Inbox Rule Created"
        Category     = "ThreatManagement"
        Operation    = "New-InboxRule"
        Severity     = "Medium"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se crea una nueva regla de bandeja de entrada. Las reglas de reenvío pueden ser usadas por atacantes para exfiltrar correo."
    },

    @{
        Name         = "Custom - Inbox Rule Modified"
        Category     = "ThreatManagement"
        Operation    = "Set-InboxRule"
        Severity     = "Medium"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se modifica una regla de bandeja de entrada existente. Cambios en reglas pueden indicar actividad de compromiso."
    },

    @{
        Name         = "Custom - Transport Rule Created"
        Category     = "ThreatManagement"
        Operation    = "New-TransportRule"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se crea una nueva regla de transporte. Las transport rules pueden redirigir o modificar correo a nivel organizacional."
    },

    @{
        Name         = "Custom - Transport Rule Modified"
        Category     = "ThreatManagement"
        Operation    = "Set-TransportRule"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se modifica una regla de transporte existente. Cambios no autorizados pueden comprometer el flujo de correo."
    },

    @{
        Name         = "Custom - Transport Rule Removed"
        Category     = "ThreatManagement"
        Operation    = "Remove-TransportRule"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se elimina una regla de transporte. Un atacante podría eliminar reglas de seguridad para facilitar ataques."
    },

    @{
        Name         = "Custom - Anti-Phish Policy Modified"
        Category     = "ThreatManagement"
        Operation    = "Set-AntiPhishPolicy"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se modifica una política Anti-Phishing. Cambios no autorizados pueden debilitar la protección contra phishing."
    },

    @{
        Name         = "Custom - Anti-Spam Policy Modified"
        Category     = "ThreatManagement"
        Operation    = "Set-HostedContentFilterPolicy"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se modifica una política Anti-Spam. Cambios pueden permitir que correo malicioso evada los filtros."
    },

    @{
        Name         = "Custom - Anti-Malware Policy Modified"
        Category     = "ThreatManagement"
        Operation    = "Set-MalwareFilterPolicy"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se modifica una política Anti-Malware. Cambios pueden reducir la capacidad de detección de malware."
    },

    @{
        Name         = "Custom - Safe Attachments Policy Modified"
        Category     = "ThreatManagement"
        Operation    = "Set-SafeAttachmentPolicy"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se modifica una política de Safe Attachments. Cambios pueden permitir que adjuntos maliciosos lleguen a los usuarios."
    },

    @{
        Name         = "Custom - Safe Links Policy Modified"
        Category     = "ThreatManagement"
        Operation    = "Set-SafeLinksPolicy"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se modifica una política de Safe Links. Cambios pueden exponer a usuarios a URLs maliciosas."
    },

    @{
        Name         = "Custom - Mail Forwarding Rule via Set-Mailbox"
        Category     = "ThreatManagement"
        Operation    = "Set-Mailbox"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se modifica un buzón (Set-Mailbox). Incluye cambios de reenvío (ForwardingAddress, ForwardingSmtpAddress) que pueden usarse para exfiltrar correo."
    },

    # ── DATA LOSS PREVENTION ──────────────────────────────────

    @{
        Name         = "Custom - eDiscovery Search Started"
        Category     = "DataLossPrevention"
        Operation    = "SearchStarted"
        Severity     = "Medium"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se inicia una búsqueda de eDiscovery. Búsquedas no autorizadas pueden indicar intentos de acceso a datos sensibles."
    },

    @{
        Name         = "Custom - eDiscovery Search Exported"
        Category     = "DataLossPrevention"
        Operation    = "SearchExported"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se exportan resultados de eDiscovery. La exportación puede ser usada para exfiltrar grandes volúmenes de datos."
    },

    @{
        Name         = "Custom - DLP Policy Changed"
        Category     = "DataLossPrevention"
        Operation    = "Set-DlpCompliancePolicy"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se modifica una política DLP. Cambios no autorizados pueden permitir la fuga de datos sensibles."
    },

    @{
        Name         = "Custom - DLP Policy Removed"
        Category     = "DataLossPrevention"
        Operation    = "Remove-DlpCompliancePolicy"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se elimina una política DLP. La eliminación de políticas puede dejar datos sensibles sin protección."
    },

    # ── ACCESS CONTROL & PERMISSIONS ──────────────────────────

    @{
        Name         = "Custom - Admin Role Member Added"
        Category     = "AccessGovernance"
        Operation    = "Add-RoleGroupMember"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se agrega un miembro a un grupo de roles administrativos. La elevación de privilegios no autorizada es una técnica común de atacantes."
    },

    @{
        Name         = "Custom - Management Role Assignment Created"
        Category     = "AccessGovernance"
        Operation    = "New-ManagementRoleAssignment"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se crea una nueva asignación de rol de administración. Asignaciones no autorizadas pueden otorgar permisos excesivos."
    },

    @{
        Name         = "Custom - Mailbox Permission Changed"
        Category     = "AccessGovernance"
        Operation    = "Add-MailboxPermission"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se agregan permisos a un buzón. Un atacante puede otorgarse acceso a buzones de otros usuarios."
    },

    @{
        Name         = "Custom - Mailbox Delegation Added (RecipientPermission)"
        Category     = "AccessGovernance"
        Operation    = "Add-RecipientPermission"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se agrega un permiso de delegación SendAs a un buzón. Permite enviar correo en nombre de otro usuario."
    },

    # ── FILE & SHAREPOINT ACTIVITIES ──────────────────────────

    @{
        Name         = "Custom - File Shared Externally"
        Category     = "DataLossPrevention"
        Operation    = "SharingSet"
        Severity     = "Medium"
        ThreatType   = "Activity"
        Aggregation  = "SimpleAggregation"
        Description  = "Alerta cuando se comparten archivos. El compartir externo no controlado puede resultar en fuga de datos. Agrega por volumen."
    },

    @{
        Name         = "Custom - Anonymous Sharing Link Created"
        Category     = "DataLossPrevention"
        Operation    = "AnonymousLinkCreated"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "None"
        Description  = "Alerta cuando se crea un enlace anónimo para compartir. Los enlaces anónimos pueden ser accedidos por cualquier persona sin autenticación."
    },

    @{
        Name         = "Custom - Mass File Deletion"
        Category     = "DataLossPrevention"
        Operation    = "FileDeleted"
        Severity     = "High"
        ThreatType   = "Activity"
        Aggregation  = "AnomalousAggregation"
        Description  = "Alerta ante eliminación anómala de archivos. La eliminación masiva puede indicar sabotaje o ransomware."
    }
)

# ═══════════════════════════════════════════════════════════════
#  CREACIÓN DE ALERT POLICIES
# ═══════════════════════════════════════════════════════════════

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Creando $($alertPolicies.Count) Alert Policies personalizadas" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$created  = 0
$skipped  = 0
$failed   = 0

foreach ($alert in $alertPolicies) {

    $alertName = $alert.Name
    Write-Host "  [$($alertPolicies.IndexOf($alert) + 1)/$($alertPolicies.Count)] " -NoNewline -ForegroundColor DarkGray

    # Verificar si ya existe
    $existing = $null
    try {
        $existing = Get-ProtectionAlert -Identity $alertName -ErrorAction SilentlyContinue 2>$null
    }
    catch {
        # No existe, continuamos
    }

    if ($existing) {
        Write-Host "[SKIP] " -NoNewline -ForegroundColor Yellow
        Write-Host "$alertName — ya existe." -ForegroundColor Gray
        $skipped++
        continue
    }

    if ($PSCmdlet.ShouldProcess($alertName, "New-ProtectionAlert")) {
        try {
            $params = @{
                Name            = $alertName
                Category        = $alert.Category
                NotifyUser      = $notifyList
                ThreatType      = $alert.ThreatType
                Operation       = $alert.Operation
                Description     = $alert.Description
                Severity        = $alert.Severity
                AggregationType = $alert.Aggregation
            }

            New-ProtectionAlert @params -ErrorAction Stop | Out-Null

            Write-Host "[OK]   " -NoNewline -ForegroundColor Green
            Write-Host "$alertName" -ForegroundColor White
            Write-Host "         Operación: $($alert.Operation) | Severidad: $($alert.Severity) | Categoría: $($alert.Category)" -ForegroundColor DarkGray
            $created++
        }
        catch {
            Write-Host "[FAIL] " -NoNewline -ForegroundColor Red
            Write-Host "$alertName" -ForegroundColor White
            Write-Host "         Error: $($_.Exception.Message)" -ForegroundColor Red
            $failed++
        }
    }
}

# ═══════════════════════════════════════════════════════════════
#  RESUMEN
# ═══════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  RESUMEN DE EJECUCIÓN" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Total definidas : $($alertPolicies.Count)" -ForegroundColor White
Write-Host "  Creadas         : $created" -ForegroundColor Green
Write-Host "  Ya existentes   : $skipped" -ForegroundColor Yellow
Write-Host "  Errores         : $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "White" })
Write-Host "  Notificaciones a: $($notifyList -join ', ')" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

if ($created -gt 0) {
    Write-Host "  Para verificar las alertas creadas ejecute:" -ForegroundColor Gray
    Write-Host '  Get-ProtectionAlert | Where-Object { $_.Name -like "Custom -*" } | Format-Table Name, Severity, Category, IsEnabled' -ForegroundColor DarkGray
    Write-Host ""
}
