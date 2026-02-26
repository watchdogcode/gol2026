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
            # Intentar usar módulos Az o Mg si están disponibles para flujos interactivos
            if (Get-Module -ListAvailable -Name "Az.Accounts") {
                Write-Log "Usando Az.Accounts para token interactivo..."
                $TokenData = Get-AzAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop
                return $TokenData.Token
            }
            elseif (Get-Module -ListAvailable -Name "Microsoft.Graph.Authentication") {
                Write-Log "Usando Microsoft.Graph para token interactivo..."
                # Conectar si no hay conexión activa
                if (-not (Get-MgContext)) { Connect-MgGraph -Scopes "AdvancedHunting.Read.All" -NoWelcome }
                $TokenData = Get-MgAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop
                return $TokenData
            }
            else {
                throw "No se encontraron los módulos 'Az.Accounts' o 'Microsoft.Graph.Authentication'. Requeridos para autenticación Interactive/DeviceCode."
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
        <h3>Potencial de éxito de Fuerza Bruta</h3>
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
