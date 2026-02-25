<#
.SYNOPSIS
    Setup-DefenderReportServer.ps1
    Script de configuracion inicial para Defender XDR Daily & Weekly Reporting.

.DESCRIPTION
    Configura el entorno completo para ejecutar:
      - New-DefenderXDRDailyReport.ps1  (reporte diario)
      - New-DefenderXDRWeeklyReport.ps1 (reporte semanal)

    Acciones que realiza:
      1. Crea estructura de directorios segura
      2. Solicita y almacena credenciales (DPAPI-encrypted)
      3. Valida permisos de App Registration contra la API
      4. Copia los scripts a la ruta de ejecucion
      5. Genera wrappers seguros para Task Scheduler
      6. Crea tareas programadas (Daily 7:00 AM / Weekly Lunes 7:30 AM)

.PARAMETER ConfigPath
    Ruta para archivos de configuracion (default: $PSScriptRoot\Config).

.PARAMETER ReportsPath
    Ruta base para reportes generados (default: $PSScriptRoot\Reports).

.PARAMETER ScriptsPath
    Ruta donde se copiaran los scripts de reporte (default: $PSScriptRoot).

.PARAMETER SkipValidation
    Omite la validacion de permisos contra la API.

.PARAMETER SkipScheduledTasks
    Omite la creacion de tareas programadas.

.EXAMPLE
    .\Setup-DefenderReportServer.ps1
    .\Setup-DefenderReportServer.ps1 -SkipScheduledTasks

.NOTES
    Debe ejecutarse con la cuenta de servicio que ejecutara los reportes programados.
    Las credenciales se protegen con DPAPI (solo funcionan con el usuario que ejecuto el setup).
    Permiso requerido en App Registration: AdvancedHunting.Read.All (Application).
#>

param(
    [string]$ConfigPath   = "$PSScriptRoot\Config",
    [string]$ReportsPath  = "$PSScriptRoot\Reports",
    [string]$ScriptsPath  = "$PSScriptRoot",
    [switch]$SkipValidation,
    [switch]$SkipScheduledTasks
)

$ErrorActionPreference = "Stop"

# ============================================================
#  UTILIDADES
# ============================================================

function Mask-String {
    param([string]$Value, [int]$VisibleChars = 4)
    if ([string]::IsNullOrEmpty($Value)) { return '****' }
    if ($Value.Length -le $VisibleChars) { return '****' }
    return ('*' * ($Value.Length - $VisibleChars)) + $Value.Substring($Value.Length - $VisibleChars)
}

function Write-Step {
    param([string]$Step, [string]$Message)
    Write-Host "`n[$Step] $Message" -ForegroundColor Yellow
}

function Write-Ok {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Skip {
    param([string]$Message)
    Write-Host "  [--] $Message" -ForegroundColor Gray
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  [!!] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "  $Message" -ForegroundColor Cyan
}

# ============================================================
#  BANNER
# ============================================================

$Banner = @"

  ===================================================================
   Defender XDR Report Server - Setup
   Daily & Weekly Security Operations Reports
  ===================================================================
   Usuario  : $env:USERDOMAIN\$env:USERNAME
   Equipo   : $env:COMPUTERNAME
   Fecha    : $(Get-Date -Format 'yyyy-MM-dd HH:mm')
   PS       : $($PSVersionTable.PSVersion)
  ===================================================================

"@

Write-Host $Banner -ForegroundColor Cyan

# ============================================================
#  PASO 1: Estructura de directorios
# ============================================================

Write-Step "1/7" "Creando estructura de directorios..."

$Directories = @(
    $ConfigPath,
    "$ReportsPath\Daily",
    "$ReportsPath\Weekly",
    "$ReportsPath\Logs"
)

foreach ($Dir in $Directories) {
    if (-not (Test-Path $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        Write-Ok "Creado: $Dir"
    } else {
        Write-Skip "Ya existe: $Dir"
    }
}

# Proteger carpeta de configuracion (solo usuario actual + SYSTEM)
try {
    $Acl = Get-Acl $ConfigPath
    $Acl.SetAccessRuleProtection($true, $false)
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "$env:USERDOMAIN\$env:USERNAME", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $Acl.AddAccessRule($Rule)
    $RuleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $Acl.AddAccessRule($RuleSystem)
    Set-Acl -Path $ConfigPath -AclObject $Acl -ErrorAction SilentlyContinue
    Write-Ok "ACL restringida aplicada a $ConfigPath"
} catch {
    Write-Skip "No se pudo restringir ACL (requiere permisos elevados)"
}

# ============================================================
#  PASO 2: Credenciales Azure AD
# ============================================================

Write-Step "2/7" "Configuracion de Azure AD App Registration"

$TenantId = Read-Host "  Ingrese Tenant ID"
$ClientId = Read-Host "  Ingrese Client ID (App Registration)"

Write-Host ""
Write-Info "Metodos de autenticacion disponibles:"
Write-Host "    1. Client Secret  (Recomendado para ejecucion automatizada)" -ForegroundColor White
Write-Host "    2. Device Code    (Para testing manual interactivo)" -ForegroundColor White
Write-Host "    3. Saltar         (Configurare las credenciales despues)" -ForegroundColor White

$AuthChoice = Read-Host "`n  Seleccione metodo [1-3]"

$AuthMode   = "DeviceCode"
$UseSecret  = $false
$SecretFile = "$ConfigPath\ClientSecret.enc"
$PlainSecretForValidation = $null

if ($AuthChoice -eq "1") {
    Write-Info "Configurando Client Secret..."
    $SecretInput = Read-Host "  Ingrese Client Secret" -AsSecureString

    # Guardar encriptado con DPAPI (solo usuario actual puede descifrar)
    $SecretInput | ConvertFrom-SecureString | Out-File $SecretFile -Force

    # Obtener plain text para validacion inmediata
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecretInput)
    $PlainSecretForValidation = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    Write-Ok "Secret encriptado (DPAPI) guardado en: $SecretFile"
    Write-Host "       Solo funciona con el usuario: $env:USERDOMAIN\$env:USERNAME" -ForegroundColor DarkYellow

    $AuthMode  = "Secret"
    $UseSecret = $true
}
elseif ($AuthChoice -eq "2") {
    $AuthMode = "DeviceCode"
    Write-Skip "Usara Device Code para autenticacion interactiva"
}
else {
    Write-Skip "Configuracion de autenticacion omitida"
}

# Mostrar resumen enmascarado
Write-Host ""
Write-Info "Resumen de credenciales (enmascarado):"
Write-Host "    Tenant ID : $(Mask-String $TenantId)" -ForegroundColor White
Write-Host "    Client ID : $(Mask-String $ClientId)" -ForegroundColor White
Write-Host "    Secret    : $(if ($UseSecret) {'********'} else {'(no configurado)'})" -ForegroundColor White
Write-Host "    Auth Mode : $AuthMode" -ForegroundColor White

# ============================================================
#  PASO 3: Guardar configuracion
# ============================================================

Write-Step "3/7" "Guardando configuracion..."

$Config = @{
    TenantId      = $TenantId
    ClientId      = $ClientId
    AuthMode      = $AuthMode
    SecretFile    = if ($UseSecret) { $SecretFile } else { $null }
    ConfigDate    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    ConfiguredBy  = "$env:USERDOMAIN\$env:USERNAME"
    ScriptsPath   = $ScriptsPath
    ReportsPath   = $ReportsPath
    LogPath       = "$ReportsPath\Logs"
    DailyScript   = "$ScriptsPath\New-DefenderXDRDailyReport.ps1"
    WeeklyScript  = "$ScriptsPath\New-DefenderXDRWeeklyReport.ps1"
}

$ConfigFile = "$ConfigPath\Config.json"
$Config | ConvertTo-Json -Depth 3 | Out-File $ConfigFile -Encoding UTF8 -Force
Write-Ok "Configuracion guardada en: $ConfigFile"

# ============================================================
#  PASO 4: Validar permisos contra la API
# ============================================================

Write-Step "4/7" "Validacion de permisos de App Registration"

if ($SkipValidation) {
    Write-Skip "Validacion omitida (parametro -SkipValidation)"
}
elseif (-not $UseSecret) {
    Write-Skip "Validacion requiere Client Secret (AuthMode=$AuthMode)"
}
else {
    $DoValidate = Read-Host "  Validar permisos ahora? (requiere conectividad) [S/n]"

    if ($DoValidate -notin @("n", "N")) {
        try {
            Write-Info "Intentando autenticacion de prueba..."

            $AuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            $Body = @{
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = $PlainSecretForValidation
                scope         = "https://api.security.microsoft.com/.default"
            }

            $TokenResponse = Invoke-RestMethod -Method Post -Uri $AuthUri -Body $Body -ErrorAction Stop
            Write-Ok "Autenticacion exitosa (token expira en $($TokenResponse.expires_in)s)"

            # Test Advanced Hunting
            Write-Info "Probando acceso a Advanced Hunting API..."
            $Headers = @{
                "Authorization" = "Bearer $($TokenResponse.access_token)"
                "Content-Type"  = "application/json"
            }
            $TestQuery = @{ Query = "print Test='OK', Timestamp=now()" } | ConvertTo-Json -Compress
            $TestResult = Invoke-RestMethod -Method Post `
                -Uri "https://api.security.microsoft.com/api/advancedhunting/run" `
                -Headers $Headers -Body $TestQuery -ErrorAction Stop

            Write-Ok "Advanced Hunting API accesible - Permisos verificados"
            Write-Ok "AdvancedHunting.Read.All: CONCEDIDO"
        }
        catch {
            Write-Fail "Error en validacion: $($_.Exception.Message)"
            Write-Host "    Verifique que la App Registration tenga:" -ForegroundColor DarkYellow
            Write-Host "      - Permiso: AdvancedHunting.Read.All (Application)" -ForegroundColor DarkYellow
            Write-Host "      - Admin Consent otorgado en el tenant" -ForegroundColor DarkYellow
            Write-Host "      - Client Secret vigente (no expirado)" -ForegroundColor DarkYellow
        }
    }
    else {
        Write-Skip "Validacion omitida por el usuario"
    }
}

# Limpiar secret de memoria
if ($PlainSecretForValidation) {
    $PlainSecretForValidation = $null
    [System.GC]::Collect()
}

# ============================================================
#  PASO 5: Copiar scripts de reporte
# ============================================================

Write-Step "5/7" "Copiando scripts de reporte..."

$SourceDir = Split-Path $MyInvocation.MyCommand.Path -Parent

$ScriptsToCopy = @(
    "New-DefenderXDRDailyReport.ps1",
    "New-DefenderXDRWeeklyReport.ps1"
)

foreach ($Script in $ScriptsToCopy) {
    $Source = Join-Path $SourceDir $Script
    $Dest   = Join-Path $ScriptsPath $Script

    if ($Source -eq $Dest) {
        Write-Skip "$Script ya esta en la ruta destino"
    }
    elseif (Test-Path $Source) {
        Copy-Item $Source -Destination $Dest -Force
        Write-Ok "Copiado: $Script -> $ScriptsPath"
    }
    else {
        Write-Fail "No encontrado: $Source"
        Write-Host "    Copie manualmente a: $Dest" -ForegroundColor DarkYellow
    }
}

# ============================================================
#  PASO 6: Crear wrappers para Task Scheduler
# ============================================================

Write-Step "6/7" "Creando wrappers de ejecucion programada..."

# ---- WRAPPER: Daily Report ----
$DailyWrapperContent = @"
#Requires -Version 5.1
<#
.SYNOPSIS
    Wrapper - Defender XDR Daily Report (ejecucion programada)
    Generado automaticamente por Setup-DefenderReportServer.ps1

.NOTES
    Usuario : $env:USERDOMAIN\$env:USERNAME
    Creado  : $(Get-Date -Format 'yyyy-MM-dd HH:mm')
#>

`$ErrorActionPreference = "Stop"

# Cargar configuracion
`$ConfigFile = "$ConfigFile"
if (-not (Test-Path `$ConfigFile)) { Write-Error "Config no encontrado: `$ConfigFile"; exit 1 }
`$Config = Get-Content `$ConfigFile -Raw | ConvertFrom-Json

`$OutputDir = Join-Path `$Config.ReportsPath "Daily"
if (-not (Test-Path `$OutputDir)) { New-Item -ItemType Directory -Path `$OutputDir -Force | Out-Null }

# Cargar Client Secret desde archivo encriptado (DPAPI)
`$ClientSecretPlain = `$null
if (`$Config.AuthMode -eq "Secret" -and `$Config.SecretFile) {
    if (Test-Path `$Config.SecretFile) {
        try {
            `$Secure = Get-Content `$Config.SecretFile | ConvertTo-SecureString -ErrorAction Stop
            `$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(`$Secure)
            `$ClientSecretPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(`$BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR(`$BSTR)
        } catch {
            Write-Error "No se pudo descifrar el secret. Ejecute Setup nuevamente con el usuario correcto."
            exit 1
        }
    } else {
        Write-Error "Archivo de secret no encontrado: `$(`$Config.SecretFile)"
        exit 1
    }
}

# Construir parametros
`$Params = @{
    TenantId        = `$Config.TenantId
    ClientId        = `$Config.ClientId
    AuthMode        = `$Config.AuthMode
    TimeWindowHours = 24
    OutputPath      = Join-Path `$OutputDir "Daily_SecOps_Report_`$(Get-Date -Format 'yyyyMMdd').html"
    TimeoutSec      = 120
}

if (`$ClientSecretPlain) { `$Params['ClientSecret'] = `$ClientSecretPlain }

# Ejecutar
try {
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Iniciando Defender XDR Daily Report..." -ForegroundColor Cyan
    & `$Config.DailyScript @Params
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Reporte diario completado." -ForegroundColor Green

    # Limpieza de reportes antiguos (retener 90 dias)
    `$RetentionDays = 90
    Get-ChildItem "`$OutputDir\*.html" -ErrorAction SilentlyContinue |
        Where-Object LastWriteTime -lt (Get-Date).AddDays(-`$RetentionDays) |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
catch {
    Write-Error "Error en reporte diario: `$(`$_.Exception.Message)"
    exit 1
}
finally {
    `$ClientSecretPlain = `$null
    [System.GC]::Collect()
}
"@

$DailyWrapperPath = "$ScriptsPath\Run-DefenderXDRDailyReport.ps1"
$DailyWrapperContent | Out-File $DailyWrapperPath -Encoding UTF8 -Force
Write-Ok "Wrapper diario:  $DailyWrapperPath"

# ---- WRAPPER: Weekly Report ----
$WeeklyWrapperContent = @"
#Requires -Version 5.1
<#
.SYNOPSIS
    Wrapper - Defender XDR Weekly Report (ejecucion programada)
    Generado automaticamente por Setup-DefenderReportServer.ps1

.NOTES
    Usuario : $env:USERDOMAIN\$env:USERNAME
    Creado  : $(Get-Date -Format 'yyyy-MM-dd HH:mm')
#>

`$ErrorActionPreference = "Stop"

# Cargar configuracion
`$ConfigFile = "$ConfigFile"
if (-not (Test-Path `$ConfigFile)) { Write-Error "Config no encontrado: `$ConfigFile"; exit 1 }
`$Config = Get-Content `$ConfigFile -Raw | ConvertFrom-Json

`$OutputDir = Join-Path `$Config.ReportsPath "Weekly"
if (-not (Test-Path `$OutputDir)) { New-Item -ItemType Directory -Path `$OutputDir -Force | Out-Null }

# Cargar Client Secret desde archivo encriptado (DPAPI)
`$ClientSecretPlain = `$null
if (`$Config.AuthMode -eq "Secret" -and `$Config.SecretFile) {
    if (Test-Path `$Config.SecretFile) {
        try {
            `$Secure = Get-Content `$Config.SecretFile | ConvertTo-SecureString -ErrorAction Stop
            `$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(`$Secure)
            `$ClientSecretPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(`$BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR(`$BSTR)
        } catch {
            Write-Error "No se pudo descifrar el secret. Ejecute Setup nuevamente con el usuario correcto."
            exit 1
        }
    } else {
        Write-Error "Archivo de secret no encontrado: `$(`$Config.SecretFile)"
        exit 1
    }
}

# Construir parametros
`$Params = @{
    TenantId       = `$Config.TenantId
    ClientId       = `$Config.ClientId
    AuthMode       = `$Config.AuthMode
    TimeWindowDays = 7
    OutputPath     = Join-Path `$OutputDir "Weekly_SecOps_Report_`$(Get-Date -Format 'yyyyMMdd').html"
    LogPath        = Join-Path `$Config.LogPath "DefenderXDR_Weekly_`$(Get-Date -Format 'yyyyMMdd').log"
    TimeoutSec     = 120
    ExportCsv      = `$true
}

if (`$ClientSecretPlain) { `$Params['ClientSecret'] = `$ClientSecretPlain }

# Ejecutar
try {
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Iniciando Defender XDR Weekly Report..." -ForegroundColor Cyan
    & `$Config.WeeklyScript @Params
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Reporte semanal completado." -ForegroundColor Green

    # Limpieza de reportes antiguos (retener 90 dias)
    `$RetentionDays = 90
    Get-ChildItem "`$OutputDir\*.html" -ErrorAction SilentlyContinue |
        Where-Object LastWriteTime -lt (Get-Date).AddDays(-`$RetentionDays) |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
catch {
    Write-Error "Error en reporte semanal: `$(`$_.Exception.Message)"
    exit 1
}
finally {
    `$ClientSecretPlain = `$null
    [System.GC]::Collect()
}
"@

$WeeklyWrapperPath = "$ScriptsPath\Run-DefenderXDRWeeklyReport.ps1"
$WeeklyWrapperContent | Out-File $WeeklyWrapperPath -Encoding UTF8 -Force
Write-Ok "Wrapper semanal: $WeeklyWrapperPath"

# ============================================================
#  PASO 7: Tareas programadas
# ============================================================

Write-Step "7/7" "Tareas programadas (Task Scheduler)"

if ($SkipScheduledTasks) {
    Write-Skip "Creacion de tareas omitida (parametro -SkipScheduledTasks)"
}
else {
    $CreateTasks = Read-Host "  Crear tareas programadas? [S/n]"

    if ($CreateTasks -notin @("n", "N")) {

        $TaskDefs = @(
            @{
                Name    = "DefenderXDR-DailyReport"
                Script  = $DailyWrapperPath
                Trigger = { New-ScheduledTaskTrigger -Daily -At 7am }
                Desc    = "Reporte diario de seguridad - Defender XDR (Daily 7:00 AM)"
            },
            @{
                Name    = "DefenderXDR-WeeklyReport"
                Script  = $WeeklyWrapperPath
                Trigger = { New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "7:30AM" }
                Desc    = "Reporte semanal de seguridad - Defender XDR (Lunes 7:30 AM)"
            }
        )

        foreach ($Task in $TaskDefs) {
            try {
                $Action = New-ScheduledTaskAction -Execute 'PowerShell.exe' `
                    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($Task.Script)`""

                $Trigger = & $Task.Trigger

                $Settings = New-ScheduledTaskSettingsSet `
                    -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
                    -RestartCount 3 `
                    -RestartInterval (New-TimeSpan -Minutes 10) `
                    -StartWhenAvailable

                Register-ScheduledTask `
                    -TaskName $Task.Name `
                    -Action $Action `
                    -Trigger $Trigger `
                    -Settings $Settings `
                    -Description $Task.Desc `
                    -User "$env:USERDOMAIN\$env:USERNAME" `
                    -Force | Out-Null

                Write-Ok "Tarea creada: $($Task.Name) - $($Task.Desc)"
            }
            catch {
                Write-Fail "Error creando '$($Task.Name)': $($_.Exception.Message)"
                Write-Host "    Puede crearla manualmente desde Task Scheduler" -ForegroundColor DarkYellow
            }
        }
    }
    else {
        Write-Skip "Tareas programadas omitidas por el usuario"
    }
}

# ============================================================
#  RESUMEN FINAL
# ============================================================

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  CONFIGURACION COMPLETADA" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor Cyan

Write-Host "`n  Archivos de configuracion:" -ForegroundColor Yellow
Write-Host "    Config       : $ConfigFile"
if ($UseSecret) {
    Write-Host "    Secret (DPAPI): $SecretFile  (usuario: $env:USERNAME)"
}

Write-Host "`n  Scripts de reporte:" -ForegroundColor Yellow
Write-Host "    Daily  : $ScriptsPath\New-DefenderXDRDailyReport.ps1"
Write-Host "    Weekly : $ScriptsPath\New-DefenderXDRWeeklyReport.ps1"

Write-Host "`n  Wrappers (Task Scheduler):" -ForegroundColor Yellow
Write-Host "    Daily  : $DailyWrapperPath"
Write-Host "    Weekly : $WeeklyWrapperPath"

Write-Host "`n  Reportes se guardan en:" -ForegroundColor Yellow
Write-Host "    Daily  : $ReportsPath\Daily\"
Write-Host "    Weekly : $ReportsPath\Weekly\"
Write-Host "    Logs   : $ReportsPath\Logs\"

Write-Host "`n  Ejecucion manual de prueba:" -ForegroundColor Yellow
Write-Host "    & '$DailyWrapperPath'" -ForegroundColor White
Write-Host "    & '$WeeklyWrapperPath'" -ForegroundColor White

Write-Host "`n  Agregar email (editar wrappers):" -ForegroundColor Yellow
Write-Host "    -SendMail `$true -SmtpServer 'smtp.office365.com' -To 'soc@empresa.com'" -ForegroundColor White

Write-Host "`n" -NoNewline
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  Setup completado.`n" -ForegroundColor Green
