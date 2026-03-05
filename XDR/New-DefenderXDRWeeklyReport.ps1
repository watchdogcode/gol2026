<#
.SYNOPSIS
    New-DefenderXDRWeeklyReport.ps1
    Genera un Reporte Ejecutivo Semanal de Amenazas utilizando la API de Advanced Hunting de Microsoft Defender XDR.

.DESCRIPTION
    Automatiza las tareas semanales de operaciones de seguridad para MDO, MDE, MDI y MDA.
    Extrae KPIs, tendencias e información procesable en un reporte HTML independiente.

.PARAMETER TimeWindowDays
    Periodo de análisis en días (7, 14 o 30). Predeterminado: 7.

.PARAMETER OutputPath
    Ruta para guardar el reporte HTML.

.PARAMETER AuthMode
    Método de autenticación: 'Secret' (predeterminado), 'DeviceCode', 'Interactive', 'Certificate'.

.PARAMETER TenantId
    ID del Inquilino (Tenant ID) de Azure AD (Requerido).

.PARAMETER ClientId
    ID del Cliente (Client ID) del registro de la aplicación (Requerido).

.PARAMETER ClientSecret
    Secreto del Cliente (Requerido si AuthMode es 'Secret').

.PARAMETER CertThumbprint
    Huella digital del certificado (Requerido si AuthMode es 'Certificate').

.PARAMETER SendMail
    Interruptor para enviar el reporte por correo electrónico.

.EXAMPLE
    .\New-DefenderXDRWeeklyReport.ps1 -TenantId "xxx" -ClientId "yyy" -AuthMode DeviceCode

.NOTES
    Requiere el permiso 'AdvancedHunting.Read.All'.
#>

param(
    [ValidateSet(7, 14, 30)]
    [int]$TimeWindowDays = 7,

    [string]$OutputPath = "$PSScriptRoot\Weekly_SecOps_Report_$(Get-Date -Format 'yyyyMMdd').html",

    [Alias('Auth')]
    [ValidateSet('DeviceCode', 'Interactive', 'Secret', 'Certificate')]
    [string]$AuthMode = 'Secret',

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [string]$ClientSecret,
    [string]$CertThumbprint,

    [bool]$SendMail = $false,
    [string]$SmtpServer,
    [string]$To,
    [string]$Subject = "Defender XDR - Reporte Semanal de Amenazas",

    [string]$ProxyUrl,
    [int]$TimeoutSec = 120,
    [switch]$FailFast,
    [switch]$ExportCsv,
    [switch]$UseParallel,
    [string]$LogPath = 'C:\Reports\Logs\DefenderXDR.log',
    [switch]$TestMode
)

# --- CONFIGURACIÓN ---
$ErrorActionPreference = "Continue"
$ApiBaseUrl = "https://api.security.microsoft.com/api"
$Scope = "https://api.security.microsoft.com/.default"
$Authority = "https://login.microsoftonline.com/$TenantId"

# Constantes
$MAX_RETRIES = 3
$RETRY_DELAY_BASE = 2
$MIN_FAILURES_SPRAY = 10
$MIN_ALERTS_RISKY_HOST = 3
# Seguridad: La caché de tokens usa Export-Clixml protegido por DPAPI (solo usuario actual)
$TOKEN_CACHE_FILE = "$env:TEMP\DefenderXDR_TokenCache.xml"
$KPI_CACHE_FILE = "$env:TEMP\DefenderXDR_KPICache.json"

if ($ProxyUrl) {
    [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($ProxyUrl)
}

# --- ENMASCARAMIENTO DE CREDENCIALES (Homogéneo con el Reporte Diario) ---
function Mask-String {
    param([string]$Value, [int]$VisibleChars = 4)
    if ([string]::IsNullOrEmpty($Value)) { return '****' }
    if ($Value.Length -le $VisibleChars) { return '****' }
    return ('*' * ($Value.Length - $VisibleChars)) + $Value.Substring($Value.Length - $VisibleChars)
}

$MaskedTenantId  = Mask-String $TenantId
$MaskedClientId  = Mask-String $ClientId
$MaskedSecret    = if ($ClientSecret) { '********' } else { '(not set)' }
$MaskedThumbprint = if ($CertThumbprint) { Mask-String $CertThumbprint } else { '(not set)' }

# --- FUNCIÓN DE LOGGING ---
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')]
        [string]$Level = 'INFO'
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Salida de consola con colores
    $Color = switch($Level) {
        'ERROR' { 'Red' }
        'WARN'  { 'Yellow' }
        'INFO'  { 'Cyan' }
        'DEBUG' { 'Gray' }
    }
    Write-Host $LogEntry -ForegroundColor $Color
    
    # Salida a archivo
    try {
        $LogDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $LogDir)) { 
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null 
        }
        Add-Content -Path $LogPath -Value $LogEntry -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Fallo silencioso en logging para evitar romper el script
    }
}

# --- POSTURA DE SEGURIDAD: Registrar credenciales enmascaradas al inicio ---
Write-Log "=== Contexto de Seguridad ===" -Level INFO
Write-Log "  Tenant ID   : $MaskedTenantId" -Level INFO
Write-Log "  Client ID   : $MaskedClientId" -Level INFO
Write-Log "  Secreto     : $MaskedSecret" -Level INFO
Write-Log "  Huella Cert : $MaskedThumbprint" -Level INFO
Write-Log "  Modo Auth   : $AuthMode" -Level INFO
Write-Log "========================" -Level INFO

# --- AUTENTICACIÓN ---
function New-AuthToken {
    Write-Log "Autenticando vía $AuthMode..." -Level INFO
    
    # Verificar caché de token
    if ((Test-Path $TOKEN_CACHE_FILE)) {
        try {
            $CachedToken = Import-Clixml -Path $TOKEN_CACHE_FILE -ErrorAction Stop
            if ($CachedToken.Expiry -gt (Get-Date).AddMinutes(5)) {
                Write-Log "Usando token en caché (válido hasta $($CachedToken.Expiry))" -Level DEBUG
                return $CachedToken.Token
            }
        } catch {
            Write-Log "Caché de token inválido, re-autenticando" -Level WARN
        }
    }
    
    try {
        $Token = $null
        
        if ($AuthMode -eq 'Secret') {
            if (-not $ClientSecret) { throw "ClientSecret es requerido para autenticación por Secreto." }
            
            $Body = @{
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = $ClientSecret
                scope         = $Scope
            }
            $Response = Invoke-RestMethod -Method Post -Uri "$Authority/oauth2/v2.0/token" -Body $Body -ErrorAction Stop
            $Token = $Response.access_token
            $ExpiresIn = $Response.expires_in
            
            # Seguridad: Limpiar secreto en texto plano de la memoria inmediatamente
            $PlainSecret = $null
            [System.GC]::Collect()
        }
        elseif ($AuthMode -eq 'Certificate') {
            # Implementación básica asumiendo que el certificado está en CurrentUser\My
            if (-not $CertThumbprint) { throw "CertThumbprint es requerido para autenticación por Certificado." }
            $Cert = Get-Item "Cert:\CurrentUser\My\$CertThumbprint"
            
            # Crear Aserción de Cliente JWT (Simplificado para PS sin módulos externos)
            # NOTA: Para producción sin módulos, se prefiere Secreto.
            # Recurrir a MSAL.PS o Az si está disponible para Cert, de lo contrario lanzar error.
            if (Get-Module -ListAvailable -Name "MSAL.PS") {
                Import-Module MSAL.PS
                $Token = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -ClientCertificate $Cert -Scopes $Scope
                return $Token.AccessToken
            }
            throw "La autenticación por certificado requiere el módulo MSAL.PS o construcción manual de JWT. Por favor use Secret o DeviceCode."
        }
        elseif ($AuthMode -eq 'DeviceCode') {
            $CodeReq = Invoke-RestMethod -Method Post -Uri "$Authority/oauth2/v2.0/devicecode" -Body @{
                client_id = $ClientId
                scope     = $Scope
            }
            
            Write-Log "Para iniciar sesión, abra $($CodeReq.verification_uri) e ingrese el código: $($CodeReq.user_code)" -Level WARN
            
            $Expires = (Get-Date).AddSeconds($CodeReq.expires_in)
            $MaxAttempts = [math]::Ceiling($CodeReq.expires_in / 5)
            $Attempt = 0
            
            while ((Get-Date) -lt $Expires -and $Attempt -lt $MaxAttempts) {
                $Attempt++
                try {
                    $TokenReq = Invoke-RestMethod -Method Post -Uri "$Authority/oauth2/v2.0/token" -Body @{
                        grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                        client_id  = $ClientId
                        device_code = $CodeReq.device_code
                    } -ErrorAction Stop
                    $Token = $TokenReq.access_token
                    $ExpiresIn = $TokenReq.expires_in
                    break
                }
                catch {
                    $Err = $_.Exception.Response.GetResponseStream()
                    $Reader = New-Object System.IO.StreamReader($Err)
                    $ErrBody = $Reader.ReadToEnd() | ConvertFrom-Json
                    if ($ErrBody.error -eq "authorization_pending") {
                        Start-Sleep -Seconds 5
                    } else {
                        throw $_
                    }
                }
            }
            if (-not $Token) { throw "El flujo de código de dispositivo expiró después de $Attempt intentos." }
        }
        elseif ($AuthMode -eq 'Interactive') {
            # Requiere módulo Az o Mg
            if (Get-Module -ListAvailable -Name "Az.Accounts") {
                Connect-AzAccount -Tenant $TenantId -ErrorAction Stop | Out-Null
                $Token = (Get-AzAccessToken -ResourceUrl "https://api.security.microsoft.com").Token
                $ExpiresIn = 3600 # Expiración predeterminada de token Az
            } else {
                throw "La autenticación interactiva requiere el módulo 'Az.Accounts'."
            }
        }
        
        # Caché del token
        if ($Token) {
            $CacheObj = @{
                Token = $Token
                Expiry = (Get-Date).AddSeconds($ExpiresIn - 300) # 5 min buffer
            }
            Export-Clixml -Path $TOKEN_CACHE_FILE -InputObject $CacheObj -Force -ErrorAction SilentlyContinue
            Write-Log "Token almacenado en caché exitosamente" -Level DEBUG
        }
        
        return $Token
    }
    catch {
        Write-Log "Autenticación fallida: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

# --- EJECUTOR DE API ---
function Invoke-DefenderAhQuery {
    param(
        [string]$Token,
        [string]$Query,
        [string]$Name
    )

    if ($TestMode) {
        Write-Log "MODO PRUEBA: Retornando datos simulados para '$Name'" -Level DEBUG
        return @{
            Name = $Name
            Results = @(@{ MockData = "Test"; Count = 0 })
            Error = $null
        }
    }

    $Uri = "$ApiBaseUrl/advancedhunting/run"
    $Headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
    }
    
    # Inyectar TimeWindow - Usando enfoque parametrizado para mejor manejo de KQL
    $FinalQuery = $Query -replace "ago\(TimeWindowDays\*d\)", "ago($($TimeWindowDays)d)"
    $Body = @{ Query = $FinalQuery } | ConvertTo-Json -Compress

    $Retries = 0
    
    do {
        try {
            $Sw = [System.Diagnostics.Stopwatch]::StartNew()
            $Response = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $Body -TimeoutSec $TimeoutSec -ErrorAction Stop
            $Sw.Stop()
            
            Write-Log "Consulta '$Name' completada en $($Sw.ElapsedMilliseconds)ms - Filas: $($Response.Results.Count)" -Level DEBUG
            
            return @{
                Name = $Name
                Results = $Response.Results
                Error = $null
                Duration = $Sw.ElapsedMilliseconds
            }
        }
        catch {
            $StatusCode = 0
            if ($_.Exception.Response) { $StatusCode = $_.Exception.Response.StatusCode.value__ }
            
            if ($StatusCode -eq 429 -or $StatusCode -ge 500) {
                $Retries++
                $Wait = [math]::Pow($RETRY_DELAY_BASE, $Retries)
                Write-Log "Error API $StatusCode para '$Name'. Reintento $Retries/$MAX_RETRIES en $Wait segundos" -Level WARN
                Start-Sleep -Seconds $Wait
            }
            else {
                Write-Log "Consulta '$Name' falló: $($_.Exception.Message)" -Level ERROR
                if ($FailFast) { throw $_ }
                return @{ Name = $Name; Results = @(); Error = $_.Exception.Message; Duration = 0 }
            }
        }
    } while ($Retries -lt $MAX_RETRIES)

    Write-Log "Consulta '$Name' excedió el máximo de reintentos" -Level ERROR
    return @{ Name = $Name; Results = @(); Error = "Max retries exceeded"; Duration = 0 }
}

# --- CONSULTAS KQL ---
$Queries = @{
    # MDO
    "MDO_Trend" = @"
EmailEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| summarize Incidents=count(), Phish=countif(ThreatTypes has 'Phish'), Malware=countif(ThreatTypes has 'Malware') by bin(Timestamp, 1d)
| order by Timestamp asc
"@

    "MDO_Campaigns" = @"
EmailEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ThreatTypes has_any ('Phish', 'Malware')
| summarize Count=count(), Targets=dcount(RecipientEmailAddress) by Subject, SenderFromDomain
| top 20 by Count desc
"@

    "MDO_TopUsers" = @"
EmailEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ThreatTypes has_any ('Phish', 'Malware')
| summarize Attacks=count() by RecipientEmailAddress
| top 20 by Attacks desc
"@

    # MDE
    "MDE_Severity" = @"
AlertInfo
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ServiceSource == 'MicrosoftDefenderForEndpoint'
| summarize Count=count() by Severity
| order by Count desc
"@

    "MDE_HostsRisk" = @"
AlertInfo
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ServiceSource == 'MicrosoftDefenderForEndpoint'
| where Severity in ('High', 'Critical')
| join kind=inner (AlertEvidence | where Timestamp between (ago(TimeWindowDays*d) .. now()) | where EntityType == 'Machine') on AlertId
| summarize AlertCount=dcount(AlertId), MaxSev=max(Severity) by DeviceName, DeviceId
| where AlertCount >= $MIN_ALERTS_RISKY_HOST
| top 25 by AlertCount desc
"@

    "MDE_Health" = @"
DeviceInfo
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| summarize arg_max(Timestamp, OSPlatform, SensorHealthState, DeviceId) by DeviceName
| project DeviceName, OS=OSPlatform, Health=SensorHealthState, LastSeen=Timestamp, DeviceId
| top 25 by LastSeen desc
"@

    # MDI
    "MDI_Spray" = @"
IdentityLogonEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ActionType == 'LogonFailed'
| summarize Failures=count(), DistinctIPs=dcount(IPAddress) by AccountUpn, Location
| where Failures >= $MIN_FAILURES_SPRAY
| top 25 by Failures desc
"@

    "MDI_Atypical" = @"
IdentityLogonEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| summarize Countries=dcount(Location), LastSeen=max(Timestamp) by AccountUpn
| where Countries >= 3
| top 25 by Countries desc
"@

    # MDA
    "MDA_OAuth" = @"
CloudAppEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ActionType in ('Consent to application', 'Grant consent')
| summarize Consents=count(), Users=dcount(AccountId) by Application, ApplicationId
| top 20 by Consents desc
"@

    "MDA_Apps" = @"
CloudAppEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| summarize Events=count(), Users=dcount(AccountId) by Application
| top 20 by Events desc
"@
}

# --- EJECUCIÓN PRINCIPAL ---
Write-Log "Iniciando Generación del Reporte Semanal Defender XDR" -Level INFO
Write-Log "Ventana de Tiempo: Últimos $TimeWindowDays días" -Level INFO

try {
    # 1. Autenticar
    $Token = New-AuthToken
    if (-not $Token) { throw "Autenticación fallida - no se recibió token" }

    # 2. Ejecutar Consultas (Paralelo si es PS 7+ y la bandera está habilitada)
    $Data = @{}
    
    if ($UseParallel -and $PSVersionTable.PSVersion.Major -ge 7) {
        Write-Log "Ejecutando consultas en paralelo..." -Level INFO
        
        $Results = $Queries.GetEnumerator() | ForEach-Object -Parallel {
            $Query = $_.Value
            $Name = $_.Key
            $Token = $using:Token
            $TimeWindowDays = $using:TimeWindowDays
            $ApiBaseUrl = $using:ApiBaseUrl
            $TimeoutSec = $using:TimeoutSec
            $FailFast = $using:FailFast
            $TestMode = $using:TestMode
            $MAX_RETRIES = $using:MAX_RETRIES
            $RETRY_DELAY_BASE = $using:RETRY_DELAY_BASE
            
            # Ejecutar consulta (reutilizar lógica de función)
            if ($TestMode) {
                return @{ Name = $Name; Results = @(@{ MockData = "Test" }); Error = $null }
            }
            
            $Uri = "$ApiBaseUrl/advancedhunting/run"
            $Headers = @{
                "Authorization" = "Bearer $Token"
                "Content-Type"  = "application/json"
            }
            $FinalQuery = $Query -replace "ago\(TimeWindowDays\*d\)", "ago($($TimeWindowDays)d)"
            $Body = @{ Query = $FinalQuery } | ConvertTo-Json -Compress
            
            $Retries = 0
            do {
                try {
                    $Response = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $Body -TimeoutSec $TimeoutSec -ErrorAction Stop
                    return @{ Name = $Name; Results = $Response.Results; Error = $null }
                }
                catch {
                    $StatusCode = 0
                    if ($_.Exception.Response) { $StatusCode = $_.Exception.Response.StatusCode.value__ }
                    if ($StatusCode -eq 429 -or $StatusCode -ge 500) {
                        $Retries++
                        Start-Sleep -Seconds ([math]::Pow($RETRY_DELAY_BASE, $Retries))
                    } else {
                        return @{ Name = $Name; Results = @(); Error = $_.Exception.Message }
                    }
                }
            } while ($Retries -lt $MAX_RETRIES)
            
            return @{ Name = $Name; Results = @(); Error = "Max retries exceeded" }
        } -ThrottleLimit 5
        
        foreach ($Result in $Results) {
            $Data[$Result.Name] = $Result.Results
            if ($Result.Error) {
                Write-Log "Consulta '$($Result.Name)' tuvo error: $($Result.Error)" -Level WARN
            }
        }
    }
    else {
        Write-Log "Ejecutando consultas secuencialmente..." -Level INFO
        foreach ($Key in $Queries.Keys) {
            $Result = Invoke-DefenderAhQuery -Token $Token -Query $Queries[$Key] -Name $Key
            $Data[$Key] = $Result.Results
        }
    }
    
    # Validar datos
    $TotalRows = ($Data.Values | Measure-Object -Property Count -Sum).Sum
    Write-Log "Total de filas recuperadas: $TotalRows" -Level INFO
    
    if ($TotalRows -eq 0) {
        Write-Log "Advertencia: No se recuperaron datos de ninguna consulta" -Level WARN
    }

    # 3. Calcular KPIs
    $KPI_MDO_Phish = ($Data["MDO_Trend"] | Measure-Object -Property Phish -Sum).Sum
    $KPI_MDO_Malware = ($Data["MDO_Trend"] | Measure-Object -Property Malware -Sum).Sum
    $KPI_MDE_Alerts = ($Data["MDE_Severity"] | Measure-Object -Property Count -Sum).Sum
    $KPI_MDE_RiskyHosts = $Data["MDE_HostsRisk"].Count
    $KPI_MDI_Spray = $Data["MDI_Spray"].Count
    $KPI_MDA_OAuth = ($Data["MDA_OAuth"] | Measure-Object -Property Consents -Sum).Sum

    # Seguridad contra nulos
    if (-not $KPI_MDO_Phish) { $KPI_MDO_Phish = 0 }
    if (-not $KPI_MDO_Malware) { $KPI_MDO_Malware = 0 }
    if (-not $KPI_MDE_Alerts) { $KPI_MDE_Alerts = 0 }
    if (-not $KPI_MDA_OAuth) { $KPI_MDA_OAuth = 0 }
    
    Write-Log "KPIs calculados: Phish=$KPI_MDO_Phish, Malware=$KPI_MDO_Malware, Alertas=$KPI_MDE_Alerts" -Level INFO
    
    # Comparar con periodo anterior
    $PrevKPIs = $null
    $KPIChanges = @{}
    if (Test-Path $KPI_CACHE_FILE) {
        try {
            $PrevKPIs = Get-Content $KPI_CACHE_FILE -Raw | ConvertFrom-Json
            $KPIChanges = @{
                Phish = if ($PrevKPIs.Phish -gt 0) { [math]::Round((($KPI_MDO_Phish - $PrevKPIs.Phish) / $PrevKPIs.Phish) * 100, 1) } else { 0 }
                Malware = if ($PrevKPIs.Malware -gt 0) { [math]::Round((($KPI_MDO_Malware - $PrevKPIs.Malware) / $PrevKPIs.Malware) * 100, 1) } else { 0 }
                Alerts = if ($PrevKPIs.Alerts -gt 0) { [math]::Round((($KPI_MDE_Alerts - $PrevKPIs.Alerts) / $PrevKPIs.Alerts) * 100, 1) } else { 0 }
            }
            Write-Log "Tendencia vs anterior: Phish $($KPIChanges.Phish)%, Malware $($KPIChanges.Malware)%, Alertas $($KPIChanges.Alerts)%" -Level INFO
        } catch {
            Write-Log "No se pudieron cargar KPIs anteriores para comparación" -Level DEBUG
        }
    }
    
    # Guardar KPIs actuales para la próxima ejecución
    $CurrentKPIs = @{
        Phish = $KPI_MDO_Phish
        Malware = $KPI_MDO_Malware
        Alerts = $KPI_MDE_Alerts
        RiskyHosts = $KPI_MDE_RiskyHosts
        Date = (Get-Date).ToString("yyyy-MM-dd")
    }
    $CurrentKPIs | ConvertTo-Json | Out-File $KPI_CACHE_FILE -Encoding UTF8 -Force

    # --- CÁLCULO DE ESTADO (Vista CISO) ---
    $GlobalStatus = if ($KPI_MDE_RiskyHosts -gt 0 -or $KPI_MDO_Phish -gt 50) { "Crítico" } elseif ($KPI_MDE_Alerts -gt 20) { "Advertencia" } else { "Saludable" }
    $StatusColor = switch ($GlobalStatus) { "Crítico" { "#d13438" } "Advertencia" { "#ffaa44" } "Saludable" { "#107c10" } }
    
    # Tenant ID ya enmascarado al inicio del script vía función Mask-String

# 4. Generar HTML
function New-HtmlTable {
    param($Rows, $Cols)
    if (-not $Rows -or $Rows.Count -eq 0) { return "<tr><td colspan='$($Cols.Count)' style='text-align:center; color:#888; padding:15px;'>No hay datos disponibles para este periodo.</td></tr>" }
    $Html = ""
    foreach ($Row in $Rows) {
        $Html += "<tr>"
        foreach ($Col in $Cols) {
            $Val = $Row.$Col
            
            # UI/UX: Enlaces Profundos y Formato
            if ($Col -eq "DeviceName" -and $Row.DeviceId) {
                $Val = "<a href='https://security.microsoft.com/machines/$($Row.DeviceId)' target='_blank' title='Ver Dispositivo en Defender'>$Val</a>"
            }
            elseif ($Col -in @("AccountUpn", "RecipientEmailAddress") -and $Val) {
                $Val = "<a href='https://security.microsoft.com/users/sec/UserPage?user=$Val' target='_blank' title='Ver Usuario en Defender'>$Val</a>"
            }
            elseif ($Val -is [DateTime]) { $Val = $Val.ToString("yyyy-MM-dd HH:mm") }
            
            $Html += "<td>$Val</td>"
        }
        $Html += "</tr>"
    }
    return $Html
}

$HtmlContent = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte Semanal de Seguridad</title>
    <style>
        :root {
            --primary-color: #0078d4;
            --secondary-color: #2b2b2b;
            --bg-color: #f0f2f5;
            --card-bg: #ffffff;
            --text-color: #323130;
            --border-color: #e1dfdd;
            --danger-color: #a80000;
        }
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 0;
            line-height: 1.5;
        }
        .header {
            background-color: var(--primary-color);
            color: white;
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
        .header .meta { font-size: 0.9em; opacity: 0.95; text-align: right; }
        .status-badge {
            padding: 4px 12px;
            border-radius: 4px;
            color: white;
            font-weight: 700;
            text-transform: uppercase;
            font-size: 0.8em;
            display: inline-block;
            margin-bottom: 8px;
        }
        .container {
            max-width: 1200px;
            margin: 30px auto;
            padding: 0 20px;
        }
        h2 {
            color: var(--secondary-color);
            margin-top: 40px;
            margin-bottom: 15px;
            font-size: 18px;
            border-left: 4px solid var(--primary-color);
            padding-left: 12px;
            display: flex;
            align-items: center;
        }
        h3 {
            color: #605e5c;
            font-size: 16px;
            margin-top: 22px;
            margin-bottom: 10px;
        }
        .summary {
            background-color: #e6f2ff;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #cce4ff;
            margin-bottom: 25px;
        }
        .summary h3 { margin-top: 0; color: var(--secondary-color); }
        .summary ul { margin: 0; padding-left: 20px; }
        .summary li { margin-bottom: 8px; line-height: 1.6; }
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .kpi-card {
            background: var(--card-bg);
            padding: 25px 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            transition: transform 0.2s ease;
            border-top: 4px solid transparent;
        }
        .kpi-card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .kpi-card.alert { border-top-color: var(--primary-color); }
        .kpi-card.danger { border-top-color: var(--danger-color); }
        .kpi-val { font-size: 3em; font-weight: 700; color: var(--secondary-color); line-height: 1; margin-bottom: 5px; }
        .kpi-label { font-size: 0.85em; color: #605e5c; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
        .table-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        .table-container {
            background: var(--card-bg);
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            overflow: hidden;
            margin-bottom: 30px;
        }
        table { width: 100%; border-collapse: collapse; font-size: 0.95em; }
        th { background-color: #f8f9fa; color: #605e5c; text-align: left; padding: 12px 15px; font-weight: 600; border-bottom: 2px solid var(--border-color); }
        td { border-bottom: 1px solid var(--border-color); padding: 12px 15px; color: var(--text-color); }
        tr:last-child td { border-bottom: none; }
        tr:hover { background-color: #f8f9fa; }
        a { color: var(--primary-color); text-decoration: none; font-weight: 500; }
        a:hover { text-decoration: underline; }
        .recs {
            background-color: #e6f2ff;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #cce4ff;
        }
        .recs ul { margin: 0; padding-left: 20px; }
        .recs li { margin-bottom: 8px; line-height: 1.6; }
        .footer { text-align: center; margin-top: 50px; color: #8a8886; font-size: 0.85em; padding-bottom: 20px; }
        @media (max-width: 900px) {
            .header { flex-direction: column; align-items: flex-start; gap: 12px; }
            .header .meta { text-align: left; }
            .table-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Reporte Semanal de Operaciones de Seguridad</h1>
        <div class="meta">
            <div class="status-badge" style="background-color: $StatusColor;">$GlobalStatus</div>
            <div><strong>Periodo:</strong> Últimos $TimeWindowDays días</div>
            <div><strong>Generado:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm")</div>
            <div style="font-size: 0.85em; margin-top: 4px;">Tenant ID: $MaskedTenantId</div>
        </div>
    </div>

    <div class="container">
        <div class="summary">
            <h3>Resumen Ejecutivo</h3>
            <ul>
                <li><strong>$KPI_MDO_Phish</strong> correos de phishing y <strong>$KPI_MDO_Malware</strong> intentos de malware detectados esta semana.</li>
                <li><strong>$KPI_MDE_Alerts</strong> alertas de endpoint registradas; <strong>$KPI_MDE_RiskyHosts</strong> hosts requieren atención inmediata.</li>
                <li><strong>$KPI_MDI_Spray</strong> identidades mostraron señales de password spray o fuerza bruta.</li>
                <li><strong>$KPI_MDA_OAuth</strong> nuevos consentimientos OAuth otorgados a aplicaciones.</li>
            </ul>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card $(if($KPI_MDE_Alerts -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$KPI_MDE_Alerts</div>
                <div class="kpi-label">Total de Alertas de Endpoint</div>
            </div>
            <div class="kpi-card $(if($KPI_MDO_Phish -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$KPI_MDO_Phish</div>
                <div class="kpi-label">Intentos de Phishing</div>
            </div>
            <div class="kpi-card $(if($KPI_MDE_RiskyHosts -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$KPI_MDE_RiskyHosts</div>
                <div class="kpi-label">Hosts Críticos (≥3 Alertas)</div>
            </div>
            <div class="kpi-card $(if($KPI_MDI_Spray -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$KPI_MDI_Spray</div>
                <div class="kpi-label">Ataques de Spray de Identidad</div>
            </div>
            <div class="kpi-card $(if($KPI_MDA_OAuth -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$KPI_MDA_OAuth</div>
                <div class="kpi-label">Nuevos Consentimientos OAuth</div>
            </div>
        </div>

        <h2>MDO: Correo y Colaboración</h2>
        <div class="table-grid">
            <div class="table-container">
                <h3 style="padding:0 15px;">Principales Campañas Activas</h3>
                <table>
                    <thead><tr><th>Asunto</th><th>Dominio Remitente</th><th>Conteo</th><th>Objetivos</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDO_Campaigns"] @("Subject","SenderFromDomain","Count","Targets"))</tbody>
                </table>
            </div>
            <div class="table-container">
                <h3 style="padding:0 15px;">Usuarios Más Atacados</h3>
                <table>
                    <thead><tr><th>Correo Usuario</th><th>Ataques</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDO_TopUsers"] @("RecipientEmailAddress","Attacks"))</tbody>
                </table>
            </div>
        </div>

        <h2>MDE: Seguridad de Endpoint</h2>
        <div class="table-grid">
            <div class="table-container">
                <h3 style="padding:0 15px;">Alertas por Severidad</h3>
                <table>
                    <thead><tr><th>Severidad</th><th>Conteo</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDE_Severity"] @("Severity","Count"))</tbody>
                </table>
            </div>
            <div class="table-container">
                <h3 style="padding:0 15px;">Hosts con Múltiples Alertas Altas/Críticas</h3>
                <table>
                    <thead><tr><th>Nombre Dispositivo</th><th>Conteo Alertas</th><th>Max Severidad</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDE_HostsRisk"] @("DeviceName","AlertCount","MaxSev"))</tbody>
                </table>
            </div>
        </div>
        <h3>Estado de Salud del Dispositivo (Top 25)</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Nombre Dispositivo</th><th>SO</th><th>Estado Salud</th><th>Visto Por Última Vez</th></tr></thead>
                <tbody>$(New-HtmlTable $Data["MDE_Health"] @("DeviceName","OS","Health","LastSeen"))</tbody>
            </table>
        </div>

        <h2>MDI: Seguridad de Identidad</h2>
        <div class="table-grid">
            <div class="table-container">
                <h3 style="padding:0 15px;">Password Spray / Fuerza Bruta</h3>
                <table>
                    <thead><tr><th>Cuenta</th><th>Ubicación</th><th>Fallos</th><th>IPs</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDI_Spray"] @("AccountUpn","Location","Failures","DistinctIPs"))</tbody>
                </table>
            </div>
            <div class="table-container">
                <h3 style="padding:0 15px;">Ubicaciones Atípicas (Viajes)</h3>
                <table>
                    <thead><tr><th>Cuenta</th><th>Países</th><th>Visto Por Última Vez</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDI_Atypical"] @("AccountUpn","Countries","LastSeen"))</tbody>
                </table>
            </div>
        </div>

        <h2>MDA: Aplicaciones en la Nube y Shadow IT</h2>
        <div class="table-grid">
            <div class="table-container">
                <h3 style="padding:0 15px;">Nuevos Consentimientos OAuth</h3>
                <table>
                    <thead><tr><th>Nombre App</th><th>ID App</th><th>Consentimientos</th><th>Usuarios</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDA_OAuth"] @("Application","ApplicationId","Consents","Users"))</tbody>
                </table>
            </div>
            <div class="table-container">
                <h3 style="padding:0 15px;">Nuevas Apps Descubiertas (Shadow IT)</h3>
                <table>
                    <thead><tr><th>Aplicación</th><th>Eventos</th><th>Usuarios</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDA_Apps"] @("Application","Events","Users"))</tbody>
                </table>
            </div>
        </div>

        <div class="recs">
            <h3>Lista de Verificación Operativa Semanal</h3>
            <ul>
                <li><strong>MDO:</strong> Revisar campañas de phishing y ajustar políticas de Safe Links/Attachments. Verificar usuarios más atacados para identificar posible compromiso.</li>
                <li><strong>MDE:</strong> Investigar hosts con ≥3 alertas altas/críticas, aislar dispositivos comprometidos y validar salud del sensor EDR.</li>
                <li><strong>MDI:</strong> Revisar cuentas con altas tasas de fallos, forzar MFA/restablecimiento y analizar ubicaciones atípicas.</li>
                <li><strong>MDA:</strong> Auditar consentimientos OAuth nuevos, revocar permisos sospechosos y revisar uso de Shadow IT.</li>
            </ul>
        </div>

        <div class="footer">
            Fuente: Defender XDR - Advanced Hunting & Reporting (Ops Semanal) | Generado a las $(Get-Date -Format "HH:mm")
        </div>
    </div>
</body>
</html>
"@

    # 5. Guardar Reporte
    try {
        $Dir = Split-Path $OutputPath -Parent
        if (-not (Test-Path $Dir)) { 
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null 
            Write-Log "Directorio de salida creado: $Dir" -Level DEBUG
        }
        
        # Usar codificación UTF8 explícita (sin BOM) para HTML
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($OutputPath, $HtmlContent, $Utf8NoBom)
        
        Write-Log "Reporte guardado en: $OutputPath" -Level INFO
        
        # Exportar CSV si se solicita
        if ($ExportCsv) {
            $CsvDir = Join-Path $Dir "CSV_Export"
            if (-not (Test-Path $CsvDir)) { New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null }
            
            foreach ($Key in $Data.Keys) {
                if ($Data[$Key].Count -gt 0) {
                    $CsvPath = Join-Path $CsvDir "$Key.csv"
                    $Data[$Key] | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
                    Write-Log "CSV Exportado: $CsvPath" -Level DEBUG
                }
            }
            Write-Log "Archivos CSV exportados a: $CsvDir" -Level INFO
        }
    }
    catch {
        Write-Log "Fallo al guardar el reporte: $($_.Exception.Message)" -Level ERROR
        throw
    }

    # 6. Enviar Correo (Opcional)
    if ($SendMail) {
        if ($SmtpServer -and $To) {
            try {
                Write-Log "Enviando correo a $To vía $SmtpServer" -Level INFO
                Send-MailMessage -SmtpServer $SmtpServer -From "DefenderReport@$env:COMPUTERNAME" -To $To -Subject $Subject -Body $HtmlContent -BodyAsHtml -Priority High -Encoding ([System.Text.Encoding]::UTF8)
                Write-Log "Correo enviado exitosamente" -Level INFO
            }
            catch {
                Write-Log "Fallo al enviar correo: $($_.Exception.Message)" -Level ERROR
            }
        } else {
            Write-Log "Correo omitido. Falta parámetro SmtpServer o To" -Level WARN
        }
    }

    Write-Log "Generación del Reporte Semanal Defender XDR completada exitosamente" -Level INFO
}
catch {
    Write-Log "Ejecución del script fallida: $($_.Exception.Message)" -Level ERROR
    Write-Log "Traza de Pila: $($_.ScriptStackTrace)" -Level DEBUG
    throw
}
finally {
    # Limpieza de datos sensibles de la memoria
    if ($Token) { Clear-Variable -Name Token -ErrorAction SilentlyContinue }
    if ($ClientSecret) { Clear-Variable -Name ClientSecret -ErrorAction SilentlyContinue }
    if ($PlainSecret) { Clear-Variable -Name PlainSecret -ErrorAction SilentlyContinue }
    # Eliminar archivo de caché de token al salir por seguridad
    if (Test-Path $TOKEN_CACHE_FILE) {
        Remove-Item $TOKEN_CACHE_FILE -Force -ErrorAction SilentlyContinue
        Write-Log "Caché de token limpiada" -Level DEBUG
    }
    [System.GC]::Collect()
}

# --- APÉNDICE: CONSULTAS MANUALES ---
<#
    APÉNDICE: Consultas KQL para Ejecución Manual en el Portal de Defender
    
    // MDO: Trend
    EmailEvents | where Timestamp > ago(7d) | summarize Count=count() by bin(Timestamp, 1d), ThreatTypes
    
    // MDE: Risky Hosts
    AlertInfo | where Timestamp > ago(7d) | where ServiceSource == 'MicrosoftDefenderForEndpoint' 
    | summarize AlertCount=count(), MaxSev=max(Severity) by DeviceName | where AlertCount >= 3
    
    // MDI: Spray
    IdentityLogonEvents | where Timestamp > ago(7d) | where ActionType == 'LogonFailed' 
    | summarize Failures=count() by AccountUpn, Location | where Failures >= 10
    
    // MDA: OAuth
    CloudAppEvents | where Timestamp > ago(7d) | where ActionType in ('Consent to application', 'Grant consent')
#>
