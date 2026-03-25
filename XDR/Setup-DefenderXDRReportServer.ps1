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
      5. Configura notificaciones por correo (opcional)
      6. Genera wrappers seguros para Task Scheduler
      7. Crea tareas programadas (Daily 7:00 AM / Weekly Lunes 7:30 AM)
      8. Ejecuta prueba de validacion (opcional)

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

.PARAMETER SkipEmail
    Omite la configuracion de notificaciones por correo.

.EXAMPLE
    .\Setup-DefenderReportServer.ps1
    .\Setup-DefenderReportServer.ps1 -SkipScheduledTasks
    .\Setup-DefenderReportServer.ps1 -SkipEmail -SkipValidation

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
    [switch]$SkipScheduledTasks,
    [switch]$SkipEmail
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

Write-Step "1/9" "Creando estructura de directorios..."

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

Write-Step "2/9" "Configuracion de Azure AD App Registration"

$TenantId = Read-Host "  Ingrese Tenant ID"
$ClientId = Read-Host "  Ingrese Client ID (App Registration)"

Write-Host ""
Write-Info "Metodos de autenticacion disponibles:"
Write-Host "    1. Client Secret  (Recomendado para ejecucion automatizada via Task Scheduler)" -ForegroundColor White
Write-Host "    2. Certificado    (Recomendado para alta seguridad, soportado solo por Weekly)" -ForegroundColor White
Write-Host "    3. Device Code    (Para testing manual o servidores sin browser)" -ForegroundColor White
Write-Host "    4. Interactivo    (Login browser popup, solo para ejecucion manual)" -ForegroundColor White
Write-Host "    5. Saltar         (Configurare las credenciales despues)" -ForegroundColor White

$AuthChoice = Read-Host "`n  Seleccione metodo [1-5]"

$AuthMode        = "Secret"
$UseSecret       = $false
$UseCertificate  = $false
$SecretFile      = "$ConfigPath\ClientSecret.enc"
$CertThumbprint  = $null
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
    Write-Info "Configurando autenticacion por Certificado..."
    $CertThumbprint = Read-Host "  Ingrese la huella digital (Thumbprint) del certificado"

    # Validar que el certificado existe en el almacen del usuario
    $CertFound = Get-ChildItem Cert:\CurrentUser\My | Where-Object Thumbprint -eq $CertThumbprint
    if ($CertFound) {
        Write-Ok "Certificado encontrado: $($CertFound.Subject) (Expira: $($CertFound.NotAfter.ToString('yyyy-MM-dd')))"
        if ($CertFound.NotAfter -lt (Get-Date).AddDays(30)) {
            Write-Fail "ADVERTENCIA: El certificado expira en menos de 30 dias"
        }
    }
    else {
        $CertFound = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object Thumbprint -eq $CertThumbprint
        if ($CertFound) {
            Write-Ok "Certificado encontrado en LocalMachine: $($CertFound.Subject)"
        }
        else {
            Write-Fail "Certificado no encontrado en el almacen. Verifique el thumbprint."
            Write-Host "    El certificado debe estar en Cert:\CurrentUser\My o Cert:\LocalMachine\My" -ForegroundColor DarkYellow
        }
    }

    $AuthMode       = "Certificate"
    $UseCertificate = $true

    Write-Host ""
    Write-Host "  NOTA: El modo Certificate solo es soportado por el reporte semanal." -ForegroundColor DarkYellow
    Write-Host "    El reporte diario se ejecutara con DeviceCode o requiere Client Secret." -ForegroundColor DarkYellow

    $DailyAuthFallback = Read-Host "  Desea configurar tambien Client Secret para el reporte diario? [S/n]"
    if ($DailyAuthFallback -notin @("n", "N")) {
        $SecretInput = Read-Host "  Ingrese Client Secret" -AsSecureString
        $SecretInput | ConvertFrom-SecureString | Out-File $SecretFile -Force

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecretInput)
        $PlainSecretForValidation = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        Write-Ok "Secret para reporte diario guardado en: $SecretFile"
        $UseSecret = $true
    }
}
elseif ($AuthChoice -eq "3") {
    $AuthMode = "DeviceCode"
    Write-Skip "Usara Device Code para autenticacion"
    Write-Host "    El reporte diario requiere Az.Accounts o ClientId+TenantId (fallback REST)" -ForegroundColor DarkYellow
}
elseif ($AuthChoice -eq "4") {
    $AuthMode = "Interactive"
    Write-Skip "Usara autenticacion interactiva (browser popup)"
    Write-Host ""
    Write-Fail "ADVERTENCIA: El modo Interactivo NO es compatible con Task Scheduler."
    Write-Host "    Las tareas programadas no pueden abrir ventanas de browser." -ForegroundColor DarkYellow
    Write-Host "    Use este modo solo para ejecucion manual de pruebas." -ForegroundColor DarkYellow
    Write-Host "    Para automatizacion, use Client Secret (opcion 1) o Certificado (opcion 2)." -ForegroundColor DarkYellow
}
else {
    Write-Skip "Configuracion de autenticacion omitida"
    Write-Host "    Se usara AuthMode=Secret por defecto (requiere ClientSecret o variable de entorno)." -ForegroundColor DarkYellow
}

# Mostrar resumen enmascarado
Write-Host ""
Write-Info "Resumen de credenciales (enmascarado):"
Write-Host "    Tenant ID   : $(Mask-String $TenantId)" -ForegroundColor White
Write-Host "    Client ID   : $(Mask-String $ClientId)" -ForegroundColor White
Write-Host "    Secret      : $(if ($UseSecret) {'********'} else {'(no configurado)'})" -ForegroundColor White
Write-Host "    Certificado : $(if ($UseCertificate) { Mask-String $CertThumbprint } else { '(no configurado)' })" -ForegroundColor White
Write-Host "    Auth Mode   : $AuthMode" -ForegroundColor White

# ============================================================
#  PASO 3: Guardar configuracion
# ============================================================

Write-Step "3/9" "Guardando configuracion..."

# Determinar AuthMode efectivo para cada script
# Daily: soporta Secret, Interactive, DeviceCode (NO Certificate)
# Weekly: soporta Secret, Interactive, DeviceCode, Certificate
$DailyAuthMode = if ($AuthMode -eq "Certificate") {
    if ($UseSecret) { "Secret" } else { "DeviceCode" }
} else { $AuthMode }

$WeeklyAuthMode = $AuthMode

$Config = @{
    TenantId        = $TenantId
    ClientId        = $ClientId
    AuthMode        = $AuthMode
    DailyAuthMode   = $DailyAuthMode
    WeeklyAuthMode  = $WeeklyAuthMode
    SecretFile      = if ($UseSecret) { $SecretFile } else { $null }
    CertThumbprint  = if ($UseCertificate) { $CertThumbprint } else { $null }
    ConfigDate      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    ConfiguredBy    = "$env:USERDOMAIN\$env:USERNAME"
    ScriptsPath     = $ScriptsPath
    ReportsPath     = $ReportsPath
    LogPath         = "$ReportsPath\Logs"
    DailyScript     = "$ScriptsPath\New-DefenderXDRDailyReport.ps1"
    WeeklyScript    = "$ScriptsPath\New-DefenderXDRWeeklyReport.ps1"
    SendMail        = $false
    SmtpServer      = $null
    MailFrom        = $null
    MailTo          = $null
    DailyTimeWindowHours = 720
    WeeklyTimeWindowDays = 7
    WeeklyExportCsv      = $true
    RetentionDays   = 90
}

$ConfigFile = "$ConfigPath\Config.json"
$Config | ConvertTo-Json -Depth 3 | Out-File $ConfigFile -Encoding UTF8 -Force
Write-Ok "Configuracion guardada en: $ConfigFile"

# ============================================================
#  PASO 4: Validar permisos contra la API
# ============================================================

Write-Step "4/9" "Validacion de permisos de App Registration"

if ($SkipValidation) {
    Write-Skip "Validacion omitida (parametro -SkipValidation)"
}
elseif (-not $UseSecret -and -not $UseCertificate) {
    Write-Skip "Validacion requiere Client Secret o Certificado (AuthMode=$AuthMode)"
}
else {
    $DoValidate = Read-Host "  Validar permisos ahora? (requiere conectividad) [S/n]"

    if ($DoValidate -notin @("n", "N")) {
        try {
            Write-Info "Intentando autenticacion de prueba..."

            $AuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            $TokenResponse = $null

            if ($UseSecret -and $PlainSecretForValidation) {
                # Validar con Client Secret
                $Body = @{
                    grant_type    = "client_credentials"
                    client_id     = $ClientId
                    client_secret = $PlainSecretForValidation
                    scope         = "https://api.security.microsoft.com/.default"
                }
                $TokenResponse = Invoke-RestMethod -Method Post -Uri $AuthUri -Body $Body -ErrorAction Stop
                Write-Ok "Autenticacion con Client Secret exitosa (token expira en $($TokenResponse.expires_in)s)"
            }
            elseif ($UseCertificate -and $CertThumbprint) {
                # Validar con Certificado (requiere MSAL.PS o Az.Accounts)
                if (Get-Module -ListAvailable -Name "Az.Accounts") {
                    Connect-AzAccount -ServicePrincipal -TenantId $TenantId -ApplicationId $ClientId `
                        -CertificateThumbprint $CertThumbprint -ErrorAction Stop | Out-Null
                    $TokenData = Get-AzAccessToken -ResourceUrl "https://api.security.microsoft.com" -ErrorAction Stop
                    $AccessToken = if ($TokenData.Token -is [System.Security.SecureString]) {
                        $TokenData.Token | ConvertFrom-SecureString -AsPlainText
                    } else { $TokenData.Token }
                    Write-Ok "Autenticacion con Certificado exitosa"
                }
                else {
                    Write-Skip "Validacion de certificado requiere Az.Accounts. Instale con: Install-Module Az.Accounts"
                }
            }

            # Test Advanced Hunting (si se obtuvo token)
            $TestToken = if ($TokenResponse) { $TokenResponse.access_token } elseif ($AccessToken) { $AccessToken } else { $null }

            if ($TestToken) {
                Write-Info "Probando acceso a Advanced Hunting API..."
                $Headers = @{
                    "Authorization" = "Bearer $TestToken"
                    "Content-Type"  = "application/json"
                }
                $TestQuery = @{ Query = "print Test='OK', Timestamp=now()" } | ConvertTo-Json -Compress
                $null = Invoke-RestMethod -Method Post `
                    -Uri "https://api.security.microsoft.com/api/advancedhunting/run" `
                    -Headers $Headers -Body $TestQuery -ErrorAction Stop

                Write-Ok "Advanced Hunting API accesible - Permisos verificados"
                Write-Ok "AdvancedHunting.Read.All: CONCEDIDO"
            }
        }
        catch {
            Write-Fail "Error en validacion: $($_.Exception.Message)"
            Write-Host "    Verifique que la App Registration tenga:" -ForegroundColor DarkYellow
            Write-Host "      - Permiso: AdvancedHunting.Read.All (Application)" -ForegroundColor DarkYellow
            Write-Host "      - Admin Consent otorgado en el tenant" -ForegroundColor DarkYellow
            Write-Host "      - Client Secret/Certificado vigente (no expirado)" -ForegroundColor DarkYellow
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

Write-Step "5/9" "Copiando scripts de reporte..."

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
#  PASO 6: Configuracion de notificaciones por correo
# ============================================================

Write-Step "6/9" "Configuracion de notificaciones por correo (opcional)"

if ($SkipEmail) {
    Write-Skip "Configuracion de correo omitida (parametro -SkipEmail)"
}
else {
    $ConfigureEmail = Read-Host "  Configurar envio de reportes por correo? [s/N]"

    if ($ConfigureEmail -in @("s", "S")) {
        $SmtpServer = Read-Host "  Servidor SMTP (ej: smtp.office365.com)"
        $MailFrom   = Read-Host "  Direccion remitente (From)"
        $MailTo     = Read-Host "  Direccion destinatario (To)"

        # Actualizar config con datos de correo
        $Config.SendMail   = $true
        $Config.SmtpServer = $SmtpServer
        $Config.MailFrom   = $MailFrom
        $Config.MailTo     = $MailTo

        $Config | ConvertTo-Json -Depth 3 | Out-File $ConfigFile -Encoding UTF8 -Force

        Write-Ok "Correo configurado: $MailFrom -> $MailTo via $SmtpServer"
    }
    else {
        Write-Skip "Notificaciones por correo omitidas"
    }
}

# ============================================================
#  PASO 7: Crear wrappers para Task Scheduler
# ============================================================

Write-Step "7/9" "Creando wrappers de ejecucion programada..."

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

# Determinar AuthMode para el Daily (no soporta Certificate)
`$DailyAuth = `$Config.DailyAuthMode
if (-not `$DailyAuth) { `$DailyAuth = `$Config.AuthMode }

# Cargar Client Secret desde archivo encriptado (DPAPI)
`$ClientSecretPlain = `$null
if ((`$DailyAuth -eq "Secret") -and `$Config.SecretFile) {
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
`$DailyTimeWindowHours = if (`$Config.DailyTimeWindowHours) { [int]`$Config.DailyTimeWindowHours } else { 720 }
`$Params = @{
    TenantId        = `$Config.TenantId
    ClientId        = `$Config.ClientId
    AuthMode        = `$DailyAuth
    TimeWindowHours = `$DailyTimeWindowHours
    OutputPath      = Join-Path `$OutputDir "Daily_SecOps_Report_`$(Get-Date -Format 'yyyyMMdd').html"
    TimeoutSec      = 120
}

if (`$ClientSecretPlain) { `$Params['ClientSecret'] = `$ClientSecretPlain }

# Agregar parametros de correo si estan configurados
if (`$Config.SendMail -eq `$true -and `$Config.SmtpServer) {
    `$Params['SendMail']   = `$true
    `$Params['SmtpServer'] = `$Config.SmtpServer
    `$Params['From']       = `$Config.MailFrom
    `$Params['To']         = `$Config.MailTo
    `$Params['Subject']    = "Reporte Diario de Seguridad - M365 Defender XDR - `$(Get-Date -Format 'yyyy-MM-dd')"
}

# Ejecutar
try {
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Iniciando Defender XDR Daily Report (Auth: `$DailyAuth)..." -ForegroundColor Cyan
    & `$Config.DailyScript @Params
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Reporte diario completado." -ForegroundColor Green

    # Limpieza de reportes antiguos
    `$RetentionDays = if (`$Config.RetentionDays) { `$Config.RetentionDays } else { 90 }
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
`$LogDir    = `$Config.LogPath
if (-not (Test-Path `$OutputDir)) { New-Item -ItemType Directory -Path `$OutputDir -Force | Out-Null }
if (-not (Test-Path `$LogDir))    { New-Item -ItemType Directory -Path `$LogDir -Force | Out-Null }

# Determinar AuthMode para el Weekly
`$WeeklyAuth = `$Config.WeeklyAuthMode
if (-not `$WeeklyAuth) { `$WeeklyAuth = `$Config.AuthMode }

# Cargar Client Secret desde archivo encriptado (DPAPI) si aplica
`$ClientSecretPlain = `$null
if (`$WeeklyAuth -eq "Secret" -and `$Config.SecretFile) {
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
`$WeeklyTimeWindowDays = if (`$Config.WeeklyTimeWindowDays) { [int]`$Config.WeeklyTimeWindowDays } else { 7 }
`$WeeklyExportCsv = if (`$null -ne `$Config.WeeklyExportCsv) { [bool]`$Config.WeeklyExportCsv } else { `$true }
`$Params = @{
    TenantId       = `$Config.TenantId
    ClientId       = `$Config.ClientId
    AuthMode       = `$WeeklyAuth
    TimeWindowDays = `$WeeklyTimeWindowDays
    OutputPath     = Join-Path `$OutputDir "Weekly_SecOps_Report_`$(Get-Date -Format 'yyyyMMdd').html"
    LogPath        = Join-Path `$LogDir "DefenderXDR_Weekly_`$(Get-Date -Format 'yyyyMMdd').log"
    TimeoutSec     = 120
    ExportCsv      = `$WeeklyExportCsv
}

if (`$ClientSecretPlain) { `$Params['ClientSecret'] = `$ClientSecretPlain }

# Agregar certificado si aplica
if (`$WeeklyAuth -eq "Certificate" -and `$Config.CertThumbprint) {
    `$Params['CertThumbprint'] = `$Config.CertThumbprint
}

# Agregar parametros de correo si estan configurados
if (`$Config.SendMail -eq `$true -and `$Config.SmtpServer) {
    `$Params['SendMail']   = `$true
    `$Params['SmtpServer'] = `$Config.SmtpServer
    `$Params['To']         = `$Config.MailTo
    `$Params['Subject']    = "Defender XDR - Reporte Semanal de Amenazas - Semana `$(Get-Date -Format 'yyyy-MM-dd')"
}

# Ejecutar
try {
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Iniciando Defender XDR Weekly Report (Auth: `$WeeklyAuth)..." -ForegroundColor Cyan
    & `$Config.WeeklyScript @Params
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Reporte semanal completado." -ForegroundColor Green

    # Limpieza de reportes y CSVs antiguos
    `$RetentionDays = if (`$Config.RetentionDays) { `$Config.RetentionDays } else { 90 }
    Get-ChildItem "`$OutputDir\*" -Include "*.html","*.csv" -ErrorAction SilentlyContinue |
        Where-Object LastWriteTime -lt (Get-Date).AddDays(-`$RetentionDays) |
        Remove-Item -Force -ErrorAction SilentlyContinue

    # Limpieza de logs antiguos
    Get-ChildItem "`$LogDir\*.log" -ErrorAction SilentlyContinue |
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
#  PASO 8: Tareas programadas
# ============================================================

Write-Step "8/9" "Tareas programadas (Task Scheduler)"

if ($SkipScheduledTasks) {
    Write-Skip "Creacion de tareas omitida (parametro -SkipScheduledTasks)"
}
else {
    $CreateTasks = Read-Host "  Crear tareas programadas? [S/n]"

    if ($CreateTasks -notin @("n", "N")) {

        $TaskDefs = @()

        if ($DailyAuthMode -in @("Secret")) {
            $TaskDefs += @{
                Name    = "DefenderXDR-DailyReport"
                Script  = $DailyWrapperPath
                Trigger = { New-ScheduledTaskTrigger -Daily -At 7am }
                Desc    = "Reporte diario de seguridad - Defender XDR (Daily 7:00 AM) [Auth: $DailyAuthMode]"
            }
        }
        else {
            Write-Skip "Tarea diaria omitida: AuthMode '$DailyAuthMode' no recomendado para Task Scheduler."
        }

        if ($WeeklyAuthMode -in @("Secret", "Certificate")) {
            $TaskDefs += @{
                Name    = "DefenderXDR-WeeklyReport"
                Script  = $WeeklyWrapperPath
                Trigger = { New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "7:30AM" }
                Desc    = "Reporte semanal de seguridad - Defender XDR (Lunes 7:30 AM) [Auth: $WeeklyAuthMode]"
            }
        }
        else {
            Write-Skip "Tarea semanal omitida: AuthMode '$WeeklyAuthMode' no recomendado para Task Scheduler."
        }

        if ($TaskDefs.Count -eq 0) {
            Write-Skip "No se crearon tareas: configure AuthMode Secret (o Certificate para Weekly) para automatizacion."
        }

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

                Write-Ok "Tarea creada: $($Task.Name)"
                Write-Host "    $($Task.Desc)" -ForegroundColor DarkGray
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
#  PASO 9: Prueba de ejecucion (opcional)
# ============================================================

Write-Step "9/9" "Prueba de ejecucion"

if ($UseSecret -or $UseCertificate) {
    $RunTest = Read-Host "  Ejecutar prueba del reporte diario ahora? [s/N]"

    if ($RunTest -in @("s", "S")) {
        $DailyTestWindow = if ($Config.DailyTimeWindowHours) { $Config.DailyTimeWindowHours } else { 720 }
        Write-Info "Ejecutando prueba con ventana configurada de $DailyTestWindow horas..."
        try {
            & $DailyWrapperPath
            Write-Ok "Prueba completada exitosamente"

            # Mostrar path del reporte generado
            $TestReport = Get-ChildItem "$ReportsPath\Daily\*.html" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($TestReport) {
                Write-Ok "Reporte de prueba: $($TestReport.FullName)"
            }
        }
        catch {
            Write-Fail "Error en prueba: $($_.Exception.Message)"
            Write-Host "    Revise la configuracion y permisos. Ejecute manualmente:" -ForegroundColor DarkYellow
            Write-Host "    & '$DailyWrapperPath'" -ForegroundColor White
        }
    }
    else {
        Write-Skip "Prueba de ejecucion omitida"
    }
}
else {
    Write-Skip "Prueba requiere Client Secret o Certificado configurado"
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
if ($UseCertificate) {
    Write-Host "    Certificado  : $CertThumbprint (LocalMachine\My)"
}

Write-Host "`n  Autenticacion:" -ForegroundColor Yellow
Write-Host "    Daily  : $DailyAuthMode"
Write-Host "    Weekly : $WeeklyAuthMode"
if ($AuthMode -eq "Interactive") {
    Write-Host "    NOTA: Modo Interactive requiere sesion de usuario activa" -ForegroundColor DarkYellow
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
Write-Host "    Retencion: $($Config.RetentionDays) dias (limpieza automatica)"

if ($Config.SendMail) {
    Write-Host "`n  Configuracion de correo:" -ForegroundColor Yellow
    Write-Host "    SMTP Server : $($Config.SmtpServer)"
    Write-Host "    From        : $($Config.MailFrom)"
    Write-Host "    To          : $($Config.MailTo)"
}

Write-Host "`n  Ejecucion manual de prueba:" -ForegroundColor Yellow
Write-Host "    & '$DailyWrapperPath'" -ForegroundColor White
Write-Host "    & '$WeeklyWrapperPath'" -ForegroundColor White

if (-not $Config.SendMail) {
    Write-Host "`n  Agregar email (re-ejecutar setup o editar config.json):" -ForegroundColor Yellow
    Write-Host "    SendMail: true, SmtpServer, MailFrom, MailTo" -ForegroundColor White
}

Write-Host "`n" -NoNewline
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  Setup completado.`n" -ForegroundColor Green
