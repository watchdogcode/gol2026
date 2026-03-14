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
    Crea una Alert Policy para monitorear cuando se configura un Mailbox Audit Bypass
    mediante Set-MailboxAuditBypassAssociation.

.DESCRIPTION
    Este script crea una política de alerta (Protection Alert) que notifica cuando alguien
    ejecuta Set-MailboxAuditBypassAssociation en el tenant. Esta operación permite que las
    acciones de un usuario o cuenta de servicio no sean registradas en los logs de auditoría
    del buzón, lo cual es una técnica conocida de evasión post-compromiso.

    Al iniciar, el script solicita interactivamente a qué usuarios o lista de distribución
    se enviarán las notificaciones de la alerta.

    Referencia:
    https://learn.microsoft.com/en-us/defender-office-365/alert-policies-defender-portal
    https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-protectionalert
    https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-mailboxauditbypassassociation

.PARAMETER NotifyUsers
    Lista de direcciones de correo (usuarios o listas de distribución) separadas por coma
    que recibirán las notificaciones. Si no se proporciona, el script preguntará
    interactivamente.

.EXAMPLE
    .\New-MailboxAuditBypassAlert.ps1
    Ejecuta el script de forma interactiva, solicitando los destinatarios.

.EXAMPLE
    .\New-MailboxAuditBypassAlert.ps1 -NotifyUsers "secops@contoso.com"
    Crea la alerta enviando notificaciones a secops@contoso.com.

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
    Write-Host "║  CONFIGURACIÓN DE NOTIFICACIÓN - Mailbox Audit Bypass Alert    ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Ingrese los destinatarios de la notificación de alerta." -ForegroundColor White
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
#  CREAR ALERT POLICY
# ═══════════════════════════════════════════════════════════════

$alertName = "Mailbox Audit Bypass Monitoring [Custom Alert]"

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Creando Alert Policy: $alertName" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Verificar si ya existe
$existing = $null
try {
    $existing = Get-ProtectionAlert -Identity $alertName -ErrorAction SilentlyContinue 2>$null
}
catch {
    # No existe, continuamos
}

if ($existing) {
    Write-Host "[SKIP] La alerta '$alertName' ya existe." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Detalles actuales:" -ForegroundColor Gray
    Write-Host "    Severidad : $($existing.Severity)" -ForegroundColor White
    Write-Host "    Categoría : $($existing.Category)" -ForegroundColor White
    Write-Host "    Habilitada: $($existing.IsEnabled)" -ForegroundColor White
    Write-Host "    Operación : $($existing.Operation)" -ForegroundColor White
    Write-Host ""
    return
}

if ($PSCmdlet.ShouldProcess($alertName, "New-ProtectionAlert")) {
    try {
        New-ProtectionAlert `
            -Category ThreatManagement `
            -Name $alertName `
            -NotifyUser $notifyList `
            -ThreatType Activity `
            -Operation "Set-MailboxAuditBypassAssociation" `
            -Severity High `
            -AggregationType None `
            -Description "Alerta cuando se configura un bypass de auditoría en un buzón mediante Set-MailboxAuditBypassAssociation. Un atacante podría usar esto para evitar que sus acciones queden registradas en los logs de auditoría." `
            -ErrorAction Stop | Out-Null

        Write-Host "[OK] Alert Policy creada exitosamente." -ForegroundColor Green
        Write-Host ""
        Write-Host "  Nombre    : $alertName" -ForegroundColor White
        Write-Host "  Categoría : ThreatManagement" -ForegroundColor White
        Write-Host "  Operación : Set-MailboxAuditBypassAssociation" -ForegroundColor White
        Write-Host "  Severidad : High" -ForegroundColor White
        Write-Host "  Agregación: None" -ForegroundColor White
        Write-Host "  Notifica a: $($notifyList -join ', ')" -ForegroundColor White
        Write-Host ""
    }
    catch {
        Write-Host "[FAIL] No se pudo crear la alerta." -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        return
    }
}

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Para verificar la alerta ejecute:" -ForegroundColor Gray
Write-Host "  Get-ProtectionAlert -Identity '$alertName' | Format-List" -ForegroundColor DarkGray
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
