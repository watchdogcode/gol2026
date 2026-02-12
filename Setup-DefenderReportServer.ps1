<#
.SYNOPSIS
    Setup-DefenderReportServer.ps1
    Script de configuración inicial para servidor Defender XDR Reporting

.DESCRIPTION
    Ayuda a configurar el entorno del servidor para ejecutar New-DefenderXDRWeeklyReport.ps1
    - Crea estructura de directorios
    - Configura ClientSecret encriptado con DPAPI
    - Valida permisos de la App Registration
    - Crea script wrapper para Task Scheduler

.EXAMPLE
    .\Setup-DefenderReportServer.ps1

.NOTES
    Debe ejecutarse con la cuenta de servicio que ejecutará los reportes programados.
#>

param(
    [string]$ConfigPath = "C:\Config\DefenderXDR",
    [string]$ReportsPath = "C:\Reports",
    [string]$ScriptsPath = "C:\Scripts"
)

$ErrorActionPreference = "Stop"

Write-Host "`n=== Configuración Inicial - Defender XDR Reports ===" -ForegroundColor Cyan
Write-Host "Usuario actual: $env:USERNAME" -ForegroundColor Gray
Write-Host "Fecha: $(Get-Date -Format 'yyyy-MM-dd HH:mm')`n" -ForegroundColor Gray

# --- PASO 1: Crear estructura de directorios ---
Write-Host "[1/6] Creando estructura de directorios..." -ForegroundColor Yellow

$Directories = @(
    $ConfigPath,
    "$ReportsPath\Weekly",
    "$ReportsPath\Logs",
    "$ReportsPath\CSV_Export",
    $ScriptsPath
)

foreach ($Dir in $Directories) {
    if (-not (Test-Path $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        Write-Host "  ✓ Creado: $Dir" -ForegroundColor Green
    } else {
        Write-Host "  ⊙ Ya existe: $Dir" -ForegroundColor Gray
    }
}

# --- PASO 2: Solicitar credenciales Azure AD ---
Write-Host "`n[2/6] Configuración de Azure AD App Registration" -ForegroundColor Yellow

$TenantId = Read-Host "Ingrese Tenant ID"
$ClientId = Read-Host "Ingrese Client ID (App Registration)"

Write-Host "`nMétodos de autenticación disponibles:" -ForegroundColor Cyan
Write-Host "  1. Client Secret (Recomendado para servidores)"
Write-Host "  2. Device Code (Para testing manual)"
Write-Host "  3. Saltar (configuraré después)"

$AuthChoice = Read-Host "Seleccione método [1-3]"

$UseSecret = $false
$SecretFile = "$ConfigPath\ClientSecret.enc"

if ($AuthChoice -eq "1") {
    Write-Host "`n  Configurando Client Secret..." -ForegroundColor Cyan
    $SecretPlain = Read-Host "Ingrese Client Secret" -AsSecureString
    
    # Encriptar con DPAPI (CurrentUser)
    $SecretPlain | ConvertFrom-SecureString | Out-File $SecretFile -Force
    Write-Host "  ✓ Secret encriptado guardado en: $SecretFile" -ForegroundColor Green
    Write-Host "    IMPORTANTE: Solo funcionará con el usuario actual ($env:USERNAME)" -ForegroundColor Yellow
    
    $UseSecret = $true
}
elseif ($AuthChoice -eq "2") {
    Write-Host "  ⊙ Usará Device Code para autenticación interactiva" -ForegroundColor Gray
}
else {
    Write-Host "  ⊙ Configuración de autenticación omitida" -ForegroundColor Gray
}

# --- PASO 3: Guardar configuración ---
Write-Host "`n[3/6] Guardando configuración..." -ForegroundColor Yellow

$Config = @{
    TenantId = $TenantId
    ClientId = $ClientId
    AuthMode = if ($UseSecret) { "Secret" } else { "DeviceCode" }
    SecretFile = if ($UseSecret) { $SecretFile } else { $null }
    ConfigDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    ConfiguredBy = $env:USERNAME
    ScriptPath = "$ScriptsPath\New-DefenderXDRWeeklyReport.ps1"
    OutputPath = "$ReportsPath\Weekly"
    LogPath = "$ReportsPath\Logs"
}

$ConfigFile = "$ConfigPath\Config.json"
$Config | ConvertTo-Json | Out-File $ConfigFile -Encoding UTF8 -Force
Write-Host "  ✓ Configuración guardada en: $ConfigFile" -ForegroundColor Green

# --- PASO 4: Validar permisos (opcional) ---
Write-Host "`n[4/6] Validación de permisos de App Registration" -ForegroundColor Yellow
$ValidatePerms = Read-Host "¿Desea validar permisos ahora? (Requiere conectividad) [S/n]"

if ($ValidatePerms -ne "n" -and $ValidatePerms -ne "N") {
    try {
        Write-Host "  Intentando autenticación de prueba..." -ForegroundColor Cyan
        
        $AuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        
        if ($UseSecret) {
            $SecureSecret = Get-Content $SecretFile | ConvertTo-SecureString
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureSecret)
            $PlainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            
            $Body = @{
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = $PlainSecret
                scope         = "https://api.security.microsoft.com/.default"
            }
            
            $TokenResponse = Invoke-RestMethod -Method Post -Uri $AuthUri -Body $Body
            
            Write-Host "  ✓ Autenticación exitosa" -ForegroundColor Green
            Write-Host "  ✓ Token recibido (expira en $($TokenResponse.expires_in) segundos)" -ForegroundColor Green
            
            # Test API call
            $TestUri = "https://api.security.microsoft.com/api/advancedhunting/run"
            $Headers = @{
                "Authorization" = "Bearer $($TokenResponse.access_token)"
                "Content-Type"  = "application/json"
            }
            $TestQuery = @{ Query = "print Version='Test', Status='OK'" } | ConvertTo-Json
            
            $TestResult = Invoke-RestMethod -Method Post -Uri $TestUri -Headers $Headers -Body $TestQuery
            Write-Host "  ✓ API de Advanced Hunting accesible" -ForegroundColor Green
            Write-Host "  ✓ Permisos verificados correctamente" -ForegroundColor Green
        }
        else {
            Write-Host "  ⊙ Validación omitida (requiere Client Secret)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  ✗ Error en validación: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Verifique que la App Registration tenga:" -ForegroundColor Yellow
        Write-Host "    - Permiso: AdvancedHunting.Read.All (Application)" -ForegroundColor Yellow
        Write-Host "    - Admin Consent otorgado" -ForegroundColor Yellow
    }
}
else {
    Write-Host "  ⊙ Validación omitida" -ForegroundColor Gray
}

# --- PASO 5: Copiar script principal ---
Write-Host "`n[5/6] Copiando script principal..." -ForegroundColor Yellow

$CurrentScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$SourceScript = Join-Path $CurrentScriptDir "New-DefenderXDRWeeklyReport.ps1"

if (Test-Path $SourceScript) {
    Copy-Item $SourceScript -Destination $ScriptsPath -Force
    Write-Host "  ✓ Script copiado a: $ScriptsPath" -ForegroundColor Green
} else {
    Write-Host "  ⚠ Script principal no encontrado en: $SourceScript" -ForegroundColor Yellow
    Write-Host "    Cópielo manualmente a: $ScriptsPath\New-DefenderXDRWeeklyReport.ps1" -ForegroundColor Yellow
}

# --- PASO 6: Crear script wrapper ---
Write-Host "`n[6/6] Creando script wrapper para ejecución programada..." -ForegroundColor Yellow

$WrapperScript = @"
#Requires -Version 5.1
<#
.SYNOPSIS
    Wrapper script para ejecutar Defender XDR Weekly Report
    Generado automáticamente por Setup-DefenderReportServer.ps1
    
.NOTES
    Usuario configurado: $env:USERNAME
    Fecha configuración: $(Get-Date -Format 'yyyy-MM-dd HH:mm')
#>

`$ErrorActionPreference = "Stop"

# Cargar configuración
`$ConfigFile = "$ConfigFile"
`$Config = Get-Content `$ConfigFile -Raw | ConvertFrom-Json

# Preparar parámetros
`$Params = @{
    TenantId = `$Config.TenantId
    ClientId = `$Config.ClientId
    AuthMode = `$Config.AuthMode
    TimeWindowDays = 7
    OutputPath = Join-Path `$Config.OutputPath "DefenderXDR_`$(Get-Date -Format 'yyyyMMdd').html"
    LogPath = Join-Path `$Config.LogPath "DefenderXDR_`$(Get-Date -Format 'yyyyMMdd').log"
    ExportCsv = `$true
    UseParallel = `$true
}

# Cargar Client Secret si está configurado
if (`$Config.AuthMode -eq "Secret" -and `$Config.SecretFile) {
    if (Test-Path `$Config.SecretFile) {
        `$Params['ClientSecret'] = Get-Content `$Config.SecretFile | ConvertTo-SecureString
    } else {
        Write-Error "Secret file not found: `$(`$Config.SecretFile)"
        exit 1
    }
}

# Ejecutar reporte
try {
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Iniciando Defender XDR Weekly Report..." -ForegroundColor Cyan
    
    & `$Config.ScriptPath @Params
    
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Reporte completado exitosamente" -ForegroundColor Green
    
    # Limpieza de reportes antiguos (mantener 60 días)
    `$RetentionDays = 60
    Get-ChildItem "`$(`$Config.OutputPath)\*.html" | 
        Where-Object LastWriteTime -lt (Get-Date).AddDays(-`$RetentionDays) | 
        Remove-Item -Force -ErrorAction SilentlyContinue
    
    Get-ChildItem "`$(`$Config.LogPath)\*.log" | 
        Where-Object LastWriteTime -lt (Get-Date).AddDays(-`$RetentionDays) | 
        Remove-Item -Force -ErrorAction SilentlyContinue
}
catch {
    Write-Error "Error ejecutando reporte: `$(`$_.Exception.Message)"
    exit 1
}
"@

$WrapperPath = "$ScriptsPath\Run-DefenderXDRWeeklyReport.ps1"
$WrapperScript | Out-File $WrapperPath -Encoding UTF8 -Force
Write-Host "  ✓ Wrapper creado en: $WrapperPath" -ForegroundColor Green

# --- RESUMEN FINAL ---
Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
Write-Host "✓ CONFIGURACIÓN COMPLETADA" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor Cyan

Write-Host "`nArchivos creados:" -ForegroundColor Yellow
Write-Host "  • Config: $ConfigFile"
if ($UseSecret) {
    Write-Host "  • Secret: $SecretFile (SOLO usuario: $env:USERNAME)"
}
Write-Host "  • Wrapper: $WrapperPath"
Write-Host "  • Script: $ScriptsPath\New-DefenderXDRWeeklyReport.ps1"

Write-Host "`nPróximos pasos:" -ForegroundColor Yellow
Write-Host "  1. Probar ejecución manual:" -ForegroundColor Cyan
Write-Host "     & '$WrapperPath'" -ForegroundColor White
Write-Host ""
Write-Host "  2. Crear tarea programada (Task Scheduler):" -ForegroundColor Cyan
Write-Host "     PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File '$WrapperPath'" -ForegroundColor White
Write-Host ""
Write-Host "  3. Verificar logs en:" -ForegroundColor Cyan
Write-Host "     $ReportsPath\Logs\" -ForegroundColor White
Write-Host ""
Write-Host "  4. Agregar email (opcional):" -ForegroundColor Cyan
Write-Host "     Editar wrapper y agregar: -SendMail `$true -SmtpServer 'smtp.office365.com' -To 'soc@empresa.com'" -ForegroundColor White

Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan

# Preguntar si crear tarea programada
Write-Host "`n¿Desea crear una Tarea Programada ahora? [S/n]" -ForegroundColor Yellow
$CreateTask = Read-Host

if ($CreateTask -ne "n" -and $CreateTask -ne "N") {
    Write-Host "`nConfiguración de Task Scheduler:" -ForegroundColor Cyan
    Write-Host "  Frecuencia: Semanal (Lunes 7:00 AM)"
    Write-Host "  Script: $WrapperPath"
    Write-Host "  Usuario: $env:USERDOMAIN\$env:USERNAME"
    
    $Confirm = Read-Host "`n¿Continuar? [S/n]"
    
    if ($Confirm -ne "n" -and $Confirm -ne "N") {
        try {
            $Action = New-ScheduledTaskAction -Execute 'PowerShell.exe' `
                -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$WrapperPath`""
            
            $Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 7am
            
            $Settings = New-ScheduledTaskSettingsSet `
                -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
                -RestartCount 3 `
                -RestartInterval (New-TimeSpan -Minutes 10)
            
            Register-ScheduledTask `
                -TaskName "DefenderXDR-WeeklyReport" `
                -Action $Action `
                -Trigger $Trigger `
                -Settings $Settings `
                -Description "Genera reporte semanal de seguridad de Defender XDR" `
                -User "$env:USERDOMAIN\$env:USERNAME" `
                -Force
            
            Write-Host "`n  ✓ Tarea programada creada: DefenderXDR-WeeklyReport" -ForegroundColor Green
            Write-Host "    Próxima ejecución: $(((Get-ScheduledTask -TaskName 'DefenderXDR-WeeklyReport').Triggers[0].StartBoundary))" -ForegroundColor Gray
        }
        catch {
            Write-Host "`n  ✗ Error creando tarea: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "    Créela manualmente usando Task Scheduler GUI" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n✓ Setup completado. Happy reporting! 🛡️`n" -ForegroundColor Green
