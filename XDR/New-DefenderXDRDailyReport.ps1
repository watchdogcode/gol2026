<#
.SYNOPSIS
    Generador de Reporte Diario de Operaciones de Seguridad usando la API de Microsoft 365 Defender.
    Automatiza consultas KQL de Advanced Hunting para MDO, MDE, MDI y MDA.

.DESCRIPTION
    Este script se autentica contra la API de M365 Defender, ejecuta un conjunto definido de
    consultas de hunting diarias y genera un reporte ejecutivo profesional en HTML.

.PARAMETER TimeWindowHours
    Ventana de tiempo en horas para el análisis (Por defecto: 24).

.PARAMETER OutputPath
    Ruta completa para el archivo HTML de salida.

.PARAMETER AuthMode
    Método de autenticación: 'Secret', 'Interactive', 'DeviceCode'.
    Para 'Secret', asegúrese de configurar $ClientId, $TenantId y $ClientSecret (o variables de entorno).

.NOTES
    Endpoint de API: https://api.security.microsoft.com
    Permiso requerido: AdvancedHunting.Read.All
#>

param(
    [int]$TimeWindowHours = 24,
    [string]$OutputPath = "$PSScriptRoot\Daily_SecOps_Report_$(Get-Date -Format 'yyyyMMdd').html",
    [string]$TenantId = $env:AZURE_TENANT_ID,
    [string]$ClientId = $env:AZURE_CLIENT_ID,
    [string]$ClientSecret = $env:AZURE_CLIENT_SECRET,
    [ValidateSet("Secret", "Interactive", "DeviceCode")]
    [string]$AuthMode = "Secret",
    [bool]$SendMail = $false,
    [string]$SmtpServer,
    [string]$From,
    [string]$To,
    [string]$Subject = "Reporte Diario de Seguridad - M365 Defender XDR",
    [int]$TimeoutSec = 120,
    [bool]$FailFast = $false
)

# --- CONFIGURACIÓN Y VARIABLES GLOBALES ---
$ErrorActionPreference = "Stop"
$ApiBaseUrl = "https://api.security.microsoft.com/api"
$ResourceUrl = "https://api.security.microsoft.com"
$ReportDate = Get-Date
$StartDate = $ReportDate.AddHours(-$TimeWindowHours)

# --- ENMASCARAMIENTO DE CREDENCIALES ---
function Mask-String {
    param([string]$Value, [int]$VisibleChars = 4)
    if ([string]::IsNullOrEmpty($Value)) { return '****' }
    if ($Value.Length -le $VisibleChars) { return '****' }
    return ('*' * ($Value.Length - $VisibleChars)) + $Value.Substring($Value.Length - $VisibleChars)
}

$MaskedTenantId  = Mask-String $TenantId
$MaskedClientId  = Mask-String $ClientId
$MaskedSecret    = if ($ClientSecret) { '********' } else { '(no configurado)' }

# --- FUNCIÓN DE REGISTRO (LOG) ---
function Write-Log {
    param([string]$Message, [string]$Level="INFO")
    $Color = switch($Level) { "INFO" {"Cyan"} "WARN" {"Yellow"} "ERROR" {"Red"} default {"White"} }
    Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] [$Level] $Message" -ForegroundColor $Color
}

# --- POSTURA DE SEGURIDAD: Registrar credenciales enmascaradas al inicio ---
Write-Log "=== Contexto de Seguridad ==="
Write-Log "  Tenant ID   : $MaskedTenantId"
Write-Log "  Client ID   : $MaskedClientId"
Write-Log "  Secret      : $MaskedSecret"
Write-Log "  Auth Mode   : $AuthMode"
Write-Log "=============================="

# --- AUTENTICACIÓN ---
function Get-M365Token {
    Write-Log "Obteniendo Token de Acceso vía $AuthMode..."
    
    try {
        if ($AuthMode -eq "Secret") {
            if (-not ($TenantId -and $ClientId -and $ClientSecret)) {
                throw "Para autenticación 'Secret', se requieren TenantId, ClientId y ClientSecret."
            }
            $Body = @{
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = $ClientSecret
                scope         = "$ResourceUrl/.default"
            }
            $TokenReq = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $Body -ErrorAction Stop
            return $TokenReq.access_token
        }
        elseif ($AuthMode -in @("Interactive", "DeviceCode")) {
            # --- Opción 1: Az.Accounts (recomendado) ---
            if (Get-Module -ListAvailable -Name "Az.Accounts") {
                Write-Log "Usando Az.Accounts para autenticación $AuthMode..."

                # Verificar si existe un contexto activo; conectar si no
                $AzContext = Get-AzContext -ErrorAction SilentlyContinue
                if (-not $AzContext) {
                    Write-Log "No hay sesión activa de Azure. Iniciando conexión ($AuthMode)..."
                    if ($AuthMode -eq "DeviceCode") {
                        Connect-AzAccount -UseDeviceAuthentication -ErrorAction Stop | Out-Null
                    } else {
                        Connect-AzAccount -ErrorAction Stop | Out-Null
                    }
                }

                $TokenData = Get-AzAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop

                # Compatibilidad: Az.Accounts >= 3.0 devuelve Token como SecureString
                if ($TokenData.Token -is [System.Security.SecureString]) {
                    return $TokenData.Token | ConvertFrom-SecureString -AsPlainText
                }
                return $TokenData.Token
            }
            # --- Opción 2: Device Code manual vía REST (sin dependencias de módulos) ---
            else {
                Write-Log "Módulo 'Az.Accounts' no encontrado. Usando flujo Device Code vía REST..." -Level WARN

                if (-not $ClientId -or -not $TenantId) {
                    throw "Se requieren ClientId y TenantId para autenticación sin Az.Accounts. Instale el módulo: Install-Module Az.Accounts -Scope CurrentUser"
                }

                # Solicitar código de dispositivo
                $DeviceCodeBody = @{
                    client_id = $ClientId
                    scope     = "$ResourceUrl/.default offline_access"
                }
                $DeviceCodeReq = Invoke-RestMethod -Method Post `
                    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
                    -Body $DeviceCodeBody -ErrorAction Stop

                Write-Log "=== AUTENTICACIÓN REQUERIDA ===" -Level WARN
                Write-Log $DeviceCodeReq.message -Level WARN

                # Sondear hasta obtener token o expirar
                $Interval = [int]$DeviceCodeReq.interval
                $ExpiresIn = [int]$DeviceCodeReq.expires_in
                $Elapsed = 0

                while ($Elapsed -lt $ExpiresIn) {
                    Start-Sleep -Seconds $Interval
                    $Elapsed += $Interval

                    try {
                        $PollBody = @{
                            grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
                            client_id   = $ClientId
                            device_code = $DeviceCodeReq.device_code
                        }
                        $TokenReq = Invoke-RestMethod -Method Post `
                            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                            -Body $PollBody -ErrorAction Stop

                        Write-Log "Token obtenido exitosamente vía Device Code."
                        return $TokenReq.access_token
                    }
                    catch {
                        $ErrBody = $null
                        try { $ErrBody = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
                        if ($ErrBody.error -eq "authorization_pending") { continue }
                        elseif ($ErrBody.error -eq "expired_token") {
                            throw "El código de dispositivo ha expirado. Ejecute el script nuevamente."
                        }
                        else { throw $_ }
                    }
                }

                throw "Tiempo de espera agotado para la autenticación Device Code."
            }
        }
    }
    catch {
        Write-Log "Error de Autenticación: $_" -Level ERROR
        throw $_
    }
}

# --- EJECUCIÓN DE API ---
function Invoke-HuntingQuery {
    param(
        [string]$Token,
        [string]$Query,
        [string]$Name
    )

    $Uri = "$ApiBaseUrl/advancedhunting/run"
    $Headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
    }
    
    # Inyectar ventana de tiempo
    $FinalQuery = $Query -replace "ago\(24h\)", "ago($($TimeWindowHours)h)"
    $Body = @{ Query = $FinalQuery } | ConvertTo-Json -Compress

    $Retries = 0
    $MaxRetries = 3
    
    do {
        try {
            $Sw = [System.Diagnostics.Stopwatch]::StartNew()
            $Response = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $Body -TimeoutSec $TimeoutSec -ErrorAction Stop
            $Sw.Stop()
            
            Write-Log "Consulta ['$Name'] ejecutada en $($Sw.ElapsedMilliseconds)ms. Filas: $($Response.Results.Count)"
            
            return @{
                Name = $Name
                Results = $Response.Results
                Stats = $Response.Stats
                Error = $null
            }
        }
        catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            if ($StatusCode -eq 429 -or $StatusCode -ge 500) {
                $Retries++
                $Wait = [math]::Pow(2, $Retries)
                Write-Log "Error de API $StatusCode. Reintentando en $Wait segundos..." -Level WARN
                Start-Sleep -Seconds $Wait
            }
            else {
                Write-Log "Consulta ['$Name'] Falló: $_" -Level ERROR
                if ($FailFast) { throw $_ }
                return @{ Name = $Name; Results = @(); Error = $_.Exception.Message }
            }
        }
    } while ($Retries -lt $MaxRetries)

    return @{ Name = $Name; Results = @(); Error = "Máximo de reintentos excedido" }
}

# --- DEFINICIONES KQL ---
$Queries = @{
    "MDO_Campaigns" = @"
EmailEvents
| where Timestamp >= ago(24h)
| where ThreatTypes has_any ("Phish","Malware")
| where DeliveryAction == "Delivered"
| summarize Events=count(), Targets=dcount(RecipientEmailAddress) by Subject, SenderFromDomain
| top 10 by Events desc
"@

    "MDO_TopUrls" = @"
EmailUrlInfo
| where Timestamp >= ago(24h)
| summarize Hits=count() by UrlDomain
| top 20 by Hits desc
"@

    "MDO_TopUsers" = @"
EmailEvents
| where Timestamp >= ago(24h) and ThreatTypes has "Phish"
| summarize Attempts=count() by RecipientEmailAddress
| top 20 by Attempts desc
"@

    "MDE_AlertsBySev" = @"
AlertInfo
| where Timestamp >= ago(24h) and ServiceSource == "MicrosoftDefenderForEndpoint"
| summarize Count=count() by Severity
| order by Count desc
"@

    "MDI_HighRiskUsers" = @"
EntraIdSignInEvents
| where Timestamp >= ago(24h)
| where RiskLevelAggregated in (50, 100)
| summarize Events=count() by 
AccountUpn, RiskLevelAggregated
| top 25 by Events desc
"@

    "MDE_Health" = @"
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
| project Timestamp, DeviceName, OSPlatform, ExposureLevel, OnboardingStatus
| where OnboardingStatus !in ("Onboarded","Unknown") or ExposureLevel in ("High","Medium")
| top 50 by Timestamp desc
"@

    "MDI_BruteForce" = @"
IdentityLogonEvents
| where Timestamp >= ago(24h)
| summarize Fails=countif(ActionType == "LogonFailed"), Success=countif(ActionType == "LogonSuccess"), LastSeen=max(Timestamp) by AccountUpn, IPAddress, Location
| where Fails >= 20 and Success > 0
| order by Fails desc
"@

    "MDI_AtypicalLocations" = @"
IdentityLogonEvents
| where Timestamp >= ago(24h)
| summarize Locations=dcount(Location), LastSeen=max(Timestamp) by AccountUpn
| where Locations >= 3
| order by Locations desc
"@

    "MDA_OAuth" = @"
CloudAppEvents
| where Timestamp >= ago(24h)
| where ActionType in ("Consent to application","Grant consent")
| summarize Consents=count(), Users=dcount(AccountId) by Application, ApplicationId
| top 20 by Consents desc
"@

    "MDA_ShadowIT" = @"
CloudAppEvents
| where Timestamp >= ago(24h)
| summarize Events=count(), Users=dcount(AccountId) by Application
| top 20 by Events desc
"@
}

# --- EJECUCIÓN PRINCIPAL ---

# 1. Autenticar
$Token = Get-M365Token

# 2. Ejecutar Consultas
$Data = @{}
foreach ($Key in $Queries.Keys) {
    $Result = Invoke-HuntingQuery -Token $Token -Query $Queries[$Key] -Name $Key
    $Data[$Key] = $Result.Results
}

# 3. Calcular KPIs
$Kpi_TotalAlerts = ($Data["MDE_AlertsBySev"] | Measure-Object -Property Count -Sum).Sum
if (-not $Kpi_TotalAlerts) { $Kpi_TotalAlerts = 0 }

$Kpi_PhishDelivered = ($Data["MDO_Campaigns"] | Measure-Object -Property Events -Sum).Sum
if (-not $Kpi_PhishDelivered) { $Kpi_PhishDelivered = 0 }

$Kpi_CompromisedIdentities = $Data["MDI_BruteForce"].Count
$Kpi_HighRiskUsers = $Data["MDI_HighRiskUsers"].Count
$Kpi_NewOAuth = ($Data["MDA_OAuth"] | Measure-Object -Property Consents -Sum).Sum
if (-not $Kpi_NewOAuth) { $Kpi_NewOAuth = 0 }

# --- SELECCIÓN ALEATORIA DE KQL DIARIO ---
$MdoDailyQueries = @(
    @{ Title="Alertas MDO de Alta Severidad (Cola de Incidentes)"; Query="AlertInfo | where Timestamp > ago(24h) | where ServiceSource == 'MicrosoftDefenderForOffice365' and Severity == 'High' | summarize Count=count() by Title" },
    @{ Title="Phishing/Malware Entregado (Falsos Negativos)"; Query="EmailEvents | where Timestamp > ago(24h) | where DeliveryAction == 'Delivered' and ThreatTypes has_any ('Phish','Malware') | project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, ThreatTypes" },
    @{ Title="Principales Campañas Activas (Vista de Campañas)"; Query="EmailEvents | where Timestamp > ago(24h) | where isnotempty(CampaignId) | summarize Events=count(), Targets=dcount(RecipientEmailAddress) by CampaignId, Subject | top 5 by Events desc" },
    @{ Title="Actividad ZAP (Investigación Automatizada)"; Query="EmailPostDeliveryEvents | where Timestamp > ago(24h) | where ActionType has 'ZAP' | summarize Count=count() by ActionTrigger, ActionResult" },
    @{ Title="Adjuntos Sospechosos Entregados (Análisis)"; Query="EmailAttachmentInfo | where Timestamp > ago(24h) | join kind=inner (EmailEvents | where DeliveryAction == 'Delivered') on NetworkMessageId | where FileType in ('exe', 'ps1', 'vbs', 'iso', 'js') | project Timestamp, FileName, RecipientEmailAddress" }
)
$SelectedMdoQuery = $MdoDailyQueries | Get-Random

# 4. Generar HTML
function ConvertTo-HtmlTable {
    param($Rows, $Columns)
    if (-not $Rows -or $Rows.Count -eq 0) { return "<tr><td colspan='$($Columns.Count)' style='text-align:center; color:#666;'>No se encontraron datos en el período</td></tr>" }
    
    $Html = ""
    foreach ($Row in $Rows) {
        $Html += "<tr>"
        foreach ($Col in $Columns) {
            $Val = $Row.$Col
            if ($Val -is [DateTime]) { $Val = $Val.ToString("yyyy-MM-dd HH:mm") }
            $Html += "<td>$Val</td>"
        }
        $Html += "</tr>"
    }
    return $Html
}

$HtmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte Diario de Seguridad</title>
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
        .header .meta { font-size: 0.9em; opacity: 0.9; text-align: right; }
        
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

        /* Cuadrícula de KPIs */
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
        
        /* Tablas */
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
        
        /* Recomendaciones */
        .recs { 
            background-color: #e6f2ff; 
            padding: 20px; 
            border-radius: 8px; 
            border: 1px solid #cce4ff;
        }
        .recs ul { margin: 0; padding-left: 20px; }
        .recs li { margin-bottom: 8px; line-height: 1.6; }
        
        /* Actividades Diarias */
        .activities { 
            background-color: var(--card-bg); 
            border-radius: 8px; 
            padding: 20px; 
            margin-bottom: 30px; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            border-left: 5px solid var(--primary-color);
        }
        .activities h4 { margin-top: 0; margin-bottom: 15px; color: var(--secondary-color); font-size: 1.1em; }
        .activities ul { margin: 0; padding-left: 20px; }
        .activities li { margin-bottom: 8px; font-size: 1em; color: var(--text-color); }
        .activities li a { color: var(--primary-color); text-decoration: none; font-weight: 500; }
        .activities li a:hover { text-decoration: underline; }
        
        .footer { text-align: center; margin-top: 50px; color: #8a8886; font-size: 0.85em; padding-bottom: 20px; }

        /* Tareas Operativas */
        .ops-section { margin-bottom: 30px; }
        .ops-group {
            background: var(--card-bg);
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            overflow: hidden;
            margin-bottom: 20px;
        }
        .ops-group-header {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 14px 20px;
            font-weight: 600;
            font-size: 1em;
            color: #fff;
            letter-spacing: 0.3px;
        }
        .ops-group-header.mdo  { background: linear-gradient(135deg, #0078d4, #005a9e); }
        .ops-group-header.mdi  { background: linear-gradient(135deg, #e97a00, #c25e00); }
        .ops-group-header.entra { background: linear-gradient(135deg, #107c10, #0b5e0b); }
        .ops-group-header .icon { font-size: 1.2em; }
        .ops-badge {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.7em;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            line-height: 1.6;
        }
        .ops-badge.daily   { background: rgba(255,255,255,0.25); color: #fff; }
        .ops-badge.weekly  { background: rgba(255,255,255,0.15); color: rgba(255,255,255,0.9); border: 1px solid rgba(255,255,255,0.3); }
        .ops-table { width: 100%; border-collapse: collapse; font-size: 0.92em; }
        .ops-table th {
            background-color: #f8f9fa;
            color: #605e5c;
            text-align: left;
            padding: 10px 16px;
            font-weight: 600;
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 2px solid var(--border-color);
        }
        .ops-table td {
            padding: 11px 16px;
            border-bottom: 1px solid #f0f0f0;
            vertical-align: middle;
        }
        .ops-table tr:last-child td { border-bottom: none; }
        .ops-table tr:hover { background-color: #fafbfc; }
        .ops-task-name {
            font-family: 'Segoe UI Semibold', 'Segoe UI', sans-serif;
            font-weight: 600;
            color: var(--text-color);
            font-size: 0.93em;
        }
        .ops-freq {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75em;
            font-weight: 600;
        }
        .ops-freq.daily  { background: #e6f2ff; color: #0078d4; }
        .ops-freq.weekly { background: #fff4e6; color: #e97a00; }
        .ops-btn {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 5px 14px;
            border-radius: 5px;
            font-size: 0.82em;
            font-weight: 600;
            text-decoration: none;
            transition: all 0.15s ease;
        }
        .ops-btn.portal {
            background: #0078d4;
            color: #fff;
        }
        .ops-btn.portal:hover { background: #005a9e; }
        .ops-btn.doc {
            background: #f3f2f1;
            color: #323130;
            border: 1px solid #d2d0ce;
        }
        .ops-btn.doc:hover { background: #e1dfdd; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Reporte Diario de Operaciones de Seguridad</h1>
        <div class="meta">
            <div><strong>Período:</strong> $($StartDate.ToString("yyyy-MM-dd HH:mm")) - $($ReportDate.ToString("yyyy-MM-dd HH:mm"))</div>
            <div style="font-size: 0.85em; margin-top: 4px;">Tenant ID: $MaskedTenantId</div>
        </div>
    </div>

    <div class="container">
        <!-- KPIs -->
        <div class="kpi-grid">
            <div class="kpi-card alert">
                <div class="kpi-val">$Kpi_TotalAlerts</div>
                <div class="kpi-label">Total Alertas (MDE)</div>
            </div>
            <div class="kpi-card $(if($Kpi_PhishDelivered -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$Kpi_PhishDelivered</div>
                <div class="kpi-label">Phishing Entregado</div>
            </div>
            <div class="kpi-card $(if($Kpi_HighRiskUsers -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$Kpi_HighRiskUsers</div>
                <div class="kpi-label">Usuarios de Alto Riesgo</div>
            </div>
            <div class="kpi-card $(if($Kpi_CompromisedIdentities -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$Kpi_CompromisedIdentities</div>
                <div class="kpi-label">Fuerza Bruta en Identidades</div>
            </div>
            <div class="kpi-card alert">
                <div class="kpi-val">$Kpi_NewOAuth</div>
                <div class="kpi-label">Nuevos Consentimientos OAuth</div>
            </div>
        </div>

        <!-- Sección MDO -->
        <h2>MDO: Correo Electrónico y Colaboración</h2>
        <div class="activities">
            <h4>Actividades Diarias</h4>
            <ul>
                <li><a href="https://security.microsoft.com/incidents">Monitorear incidentes y alertas de correo electrónico y colaboración.</a>
                    <div style="margin-top:8px; padding:10px; background:#f8f9fa; border-left:3px solid #0078d4; font-family:Consolas, monospace; font-size:0.85em; color:#333;">
                        <div style="font-weight:bold; color:#0078d4; margin-bottom:5px;">💡 KQL Recomendado: $($SelectedMdoQuery.Title)</div>
                        <div style="white-space:pre-wrap;">$($SelectedMdoQuery.Query)</div>
                    </div>
                </li>
                <li><a href="https://security.microsoft.com/campaigns">Evaluar campañas de phishing y malware que fueron entregadas.</a></li>
                <li><a href="https://security.microsoft.com/action-center/pending">Revisar acciones automatizadas pendientes o incompletas (AIR).</a></li>
                <li><a href="https://security.microsoft.com/submissions">Clasificar mensajes sospechosos reportados por usuarios.</a></li>
                <li><a href="https://security.microsoft.com/alerts">Gestionar alertas con clasificación y remediaciones necesarias.</a></li>
            </ul>
        </div>
        
        <h3>Principales Campañas de Phishing Entregadas</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Asunto</th><th>Dominio del Remitente</th><th>Eventos</th><th>Objetivos</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["MDO_Campaigns"] @("Subject","SenderFromDomain","Events","Targets"))</tbody>
            </table>
        </div>
        
        <h3>Usuarios Más Atacados (Phishing)</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Destinatario</th><th>Intentos</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["MDO_TopUsers"] @("RecipientEmailAddress","Attempts"))</tbody>
            </table>
        </div>

        <!-- Sección MDE -->
        <h2>MDE: Seguridad de Endpoints</h2>
        <h3>Alertas por Severidad</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Severidad</th><th>Cantidad</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["MDE_AlertsBySev"] @("Severity","Count"))</tbody>
            </table>
        </div>

        <!-- Sección MDI -->
        <h2>MDI: Seguridad de Identidades</h2>
        <h3>Potencial de éxito de Ataque de Fuerza Bruta</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Cuenta</th><th>Dirección IP</th><th>Ubicación</th><th>Fallos</th><th>Éxitos</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["MDI_BruteForce"] @("AccountUpn","IPAddress","Location","Fails","Success"))</tbody>
            </table>
        </div>

        <h3>Usuarios con Inicios de Sesión de Alto Riesgo</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Cuenta</th><th>Nivel de Riesgo</th><th>Eventos</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["MDI_HighRiskUsers"] @("UserPrincipalName","RiskLevelAggregated","Events"))</tbody>
            </table>
        </div>

        <!-- Sección MDA -->
        <h2>MDA: Aplicaciones en la Nube y Shadow IT</h2>
        <h3>Nuevos Consentimientos OAuth</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Aplicación</th><th>AppId</th><th>Consentimientos</th><th>Usuarios</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["MDA_OAuth"] @("Application","ApplicationId","Consents","Users"))</tbody>
            </table>
        </div>

        <!-- Recomendaciones -->
        <h2>Recomendaciones y Acciones Diarias</h2>
        <div class="recs">
            <ul>
                <li><strong>MDO:</strong> Revisar $(if($Kpi_PhishDelivered -gt 0){"las <b>$Kpi_PhishDelivered</b> campañas de phishing entregadas"}else{"las campañas de phishing"}) y validar la efectividad de ZAP. Verificar los usuarios más atacados para capacitación de concientización.</li>
                <li><strong>MDI:</strong> Investigar los <b>$Kpi_HighRiskUsers</b> usuarios con inicios de sesión de alto riesgo. Restablecer contraseñas o aplicar MFA en sesiones riesgosas.</li>
                <li><strong>MDI:</strong> Analizar las <b>$Kpi_CompromisedIdentities</b> cuentas con éxito de fuerza bruta. Restablecer contraseñas y aplicar MFA si no está configurado.</li>
                <li><strong>MDA:</strong> Auditar los <b>$Kpi_NewOAuth</b> nuevos consentimientos OAuth. Revocar permisos de publicadores sospechosos o no verificados.</li>
            </ul>
        </div>
        
        <!-- Tareas Operativas -->
        <h2>Tareas Operativas</h2>
        <div class="ops-section">

            <!-- ═══ MDO ═══ -->
            <div class="ops-group">
                <div class="ops-group-header mdo">
                    <span class="icon">&#x1f4e7;</span> Microsoft Defender for Office 365
                    <span class="ops-badge daily">7 Diarias</span>
                    <span class="ops-badge weekly">3 Semanales</span>
                </div>
                <table class="ops-table">
                    <thead><tr><th style="width:42%">Tarea</th><th style="width:14%">Frecuencia</th><th style="width:22%">Portal</th><th style="width:22%">Documentación</th></tr></thead>
                    <tbody>
                        <tr><td class="ops-task-name">Revisar_alertas_activas</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/alerts" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#monitoreo-de-alertas" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Monitoreo_de_Incidentes</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/incidents" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#monitoreo-de-incidentes" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Triage_de_Mensajes_de_Teams_Reportados_por_Usuarios</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://admin.teams.microsoft.com/policies/messaging?view=reportedsafety" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#triage-de-mensajes-de-teams-reportados-por-usuarios" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisar_y_Actuar_sobre_los_AIRs</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/action-center/pending" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#revisar-y-actuar-sobre-los-airs" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisar_las_Tendencias_de_Detección_de_Correo_en_MDO</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/reports/TPSAggregateReportATP" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#revisar-las-tendencias-de-detecci%C3%B3n-de-correo-en-microsoft-defender-for-office-365" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisar_Campañas_de_Phishing_y_Malware_Entregados</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/threatexplorerv3" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#revisar-campa%C3%B1as-de-phishing-y-malware-que-resultaron-en-correos-entregados" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisión_de_Top_Targeted_Users</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/threatexplorerv3" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#revisi%C3%B3n-de-top-targeted-users" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisar_Tendencias_de_Detección_de_Correo_en_MDO</td><td><span class="ops-freq weekly">Semanal</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/emailandcollabreport" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/02%20Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md#revisar-tendencias-de-detecci%C3%B3n-de-correo-en-microsoft-defender-for-office-365" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Identificar_Usuarios_Más_Atacados_por_Malware_y_Phishing</td><td><span class="ops-freq weekly">Semanal</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/emailandcollabreport" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/02%20Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md#identificar-usuarios-m%C3%A1s-atacados-por-malware-y-phishing" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisar_Campañas_de_Malware_y_Phishing</td><td><span class="ops-freq weekly">Semanal</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/threatexplorerv3" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/02%20Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md#revisar-campa%C3%B1as-de-malware-y-phishing-campaigns--mdo-p2" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                    </tbody>
                </table>
            </div>

            <!-- ═══ MDI ═══ -->
            <div class="ops-group">
                <div class="ops-group-header mdi">
                    <span class="icon">&#x1f6e1;</span> Microsoft Defender for Identity
                    <span class="ops-badge daily">5 Diarias</span>
                    <span class="ops-badge weekly">2 Semanales</span>
                </div>
                <table class="ops-table">
                    <thead><tr><th style="width:42%">Tarea</th><th style="width:14%">Frecuencia</th><th style="width:22%">Portal</th><th style="width:22%">Documentación</th></tr></thead>
                    <tbody>
                        <tr><td class="ops-task-name">Revisar_ITDR_Dashboard</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/identities/dashboard" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-itdr-dashboard-identities--dashboard" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Triage_de_Incidentes_por_Prioridad</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/incidents" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#triage-de-incidentes-por-prioridad-incidents--alerts" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Configurar_Tuning_para_Benign_False_Positives</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/advanced-hunting" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#configurar-tuning-para-benign--false-positives-advanced-hunting" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Proactive_hunting_diario_o_semanal</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/v2/advanced-hunting" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#proactive-hunting-diario-o-semanal-seg%C3%BAn-madurez" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisar_Health_Issues_Global_y_Sensor</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/identities/health-issues" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-health-issues-global-y-sensor" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisar_recomendaciones_de_Secure_Score</td><td><span class="ops-freq weekly">Semanal</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/securescore" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Gu%C3%ADa%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-recomendaciones-de-secure-score-por-producto" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisar_y_responder_a_amenazas_emergentes</td><td><span class="ops-freq weekly">Semanal</span></td><td><a class="ops-btn portal" href="https://security.microsoft.com/advanced-hunting" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Gu%C3%ADa%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-y-responder-a-amenazas-emergentes-custom-detections" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                    </tbody>
                </table>
            </div>

            <!-- ═══ EntraID ═══ -->
            <div class="ops-group">
                <div class="ops-group-header entra">
                    <span class="icon">&#x1f510;</span> Microsoft Entra ID
                    <span class="ops-badge daily">4 Diarias</span>
                    <span class="ops-badge weekly">3 Semanales</span>
                </div>
                <table class="ops-table">
                    <thead><tr><th style="width:42%">Tarea</th><th style="width:14%">Frecuencia</th><th style="width:22%">Portal</th><th style="width:22%">Documentación</th></tr></thead>
                    <tbody>
                        <tr><td class="ops-task-name">Monitorear_eventos_de_inicio_de_sesión_y_autenticación</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://entra.microsoft.com/#view/Microsoft_AAD_IAM/SignInLogsList.ReactView/timeRangeType/last24hours/showApplicationSignIns~/true" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/EntraID/Gu%C3%ADa%20Operacional%20Microsoft%20EntraID%20Diaria.md#monitorear-eventos-de-inicio-de-sesi%C3%B3n-y-autenticaci%C3%B3n" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisión_de_Usuarios_con_Riesgo_Alto_Medio</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskyUsers" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/EntraID/Gu%C3%ADa%20Operacional%20Microsoft%20EntraID%20Diaria.md#revisi%C3%B3n-de-usuarios-con-riesgo-alto--medio" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisión_de_Inicios_de_Sesión_con_Riesgo</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskySignIns" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/EntraID/Gu%C3%ADa%20Operacional%20Microsoft%20EntraID%20Diaria.md#revisi%C3%B3n-de-inicios-de-sesi%C3%B3n-con-riesgo" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisar_alertas_de_Microsoft_Entra_Connect_Health</td><td><span class="ops-freq daily">Diaria</span></td><td><a class="ops-btn portal" href="https://entra.microsoft.com/#view/Microsoft_AAD_Connect_Health/ConnectHealthMenuBlade/~/overview" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/EntraID/Gu%C3%ADa%20Operacional%20Microsoft%20EntraID%20Diaria.md#revisar-alertas-de-microsoft-entra-connect-health-entornos-h%C3%ADbridos" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisión_de_cambios_administrativos</td><td><span class="ops-freq weekly">Semanal</span></td><td><a class="ops-btn portal" href="https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuditLogList.ReactView" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Semanales.md#revisi%C3%B3n-de-cambios-administrativos" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Seguimiento_del_Identity_Secure_Score</td><td><span class="ops-freq weekly">Semanal</span></td><td><a class="ops-btn portal" href="https://entra.microsoft.com/#view/Microsoft_AAD_IAM/EntraRecommendationsIdentitySecureScore.ReactView" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Semanales.md#seguimiento-del-identity-secure-score" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisión_de_errores_de_sincronización_antiguos</td><td><span class="ops-freq weekly">Semanal</span></td><td><a class="ops-btn portal" href="https://entra.microsoft.com/#view/Microsoft_AAD_Connect_Provisioning/CrossTenantSynchronizationConfiguration.ReactView" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Semanales.md#revisi%C3%B3n-de-errores-de-sincronizaci%C3%B3n-antiguos" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                    </tbody>
                </table>
            </div>

        </div>

        <div class="footer">
            Generado por Operaciones de Seguridad Automatizadas | Microsoft 365 Defender XDR
        </div>
    </div>
</body>
</html>
"@

# 5. Guardar Resultado
try {
    $Dir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
    $HtmlContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Log "Reporte guardado en: $OutputPath"
}
catch {
    Write-Log "Error al guardar el reporte: $_" -Level ERROR
}

# 6. Enviar Correo (Opcional)
if ($SendMail) {
    if ($SmtpServer -and $From -and $To) {
        try {
            Write-Log "Enviando correo a $To..."
            Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To -Subject $Subject -Body $HtmlContent -BodyAsHtml -Priority High
            Write-Log "Correo enviado exitosamente."
        }
        catch {
            Write-Log "Error al enviar correo: $_" -Level ERROR
        }
    } else {
        Write-Log "Envío de correo omitido. Faltan parámetros SMTP." -Level WARN
    }
}
