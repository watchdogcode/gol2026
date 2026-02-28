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
| where Timestamp >= ago(24h)
| where ServiceSource has "Endpoint"
| summarize Count=count() by Severity
| order by Count desc
"@

    "XDR_AllAlerts" = @"
AlertInfo
| where Timestamp >= ago(24h)
| summarize Count=count() by ServiceSource, Severity
| order by Count desc
"@

    "XDR_Incidents" = @"
AlertInfo
| where Timestamp >= ago(24h)
| join kind=leftouter (AlertEvidence | where Timestamp >= ago(24h) | summarize Entities=dcount(EntityType), DevicesAffected=dcount(DeviceId) by AlertId) on AlertId
| project Timestamp, AlertId, Title, Severity, ServiceSource, Category, Entities=coalesce(Entities, 0), DevicesAffected=coalesce(DevicesAffected, 0)
| order by Timestamp desc
| take 25
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
$Kpi_TotalAlerts = ($Data["XDR_AllAlerts"] | Measure-Object -Property Count -Sum).Sum
if (-not $Kpi_TotalAlerts) { $Kpi_TotalAlerts = 0 }

$Kpi_IncidentCount = $Data["XDR_Incidents"].Count
if (-not $Kpi_IncidentCount) { $Kpi_IncidentCount = 0 }

$Kpi_PhishDelivered = ($Data["MDO_Campaigns"] | Measure-Object -Property Events -Sum).Sum
if (-not $Kpi_PhishDelivered) { $Kpi_PhishDelivered = 0 }

$Kpi_CompromisedIdentities = $Data["MDI_BruteForce"].Count
$Kpi_HighRiskUsers = $Data["MDI_HighRiskUsers"].Count
$Kpi_NewOAuth = ($Data["MDA_OAuth"] | Measure-Object -Property Consents -Sum).Sum
if (-not $Kpi_NewOAuth) { $Kpi_NewOAuth = 0 }

# --- CATÁLOGO COMPLETO DE KQL (MDO Advanced Hunting) ---
# Fuente: https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/04%20Paquete%20MDO%20KQL%20Advance%20Hunting.md
$MdoKqlCatalog = @(
    # ── Spoofing y Autenticación ──
    @{ Id=1;  Category="Spoofing y Autenticación"; Title="Spoofing: From (Header) ≠ MailFrom (Envelope)"; Query=@"
let lookback = 7d;
EmailEvents
| where Timestamp >= ago(lookback)
| where isempty(SenderFromDomain) == false and isempty(SenderMailFromDomain) == false
| where SenderFromDomain != SenderMailFromDomain
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
"@ },
    @{ Id=2;  Category="Spoofing y Autenticación"; Title="Spoofing: Header From interno vs MailFrom externo"; Query=@"
let lookback = 7d;
let orgDomains = dynamic(["contoso.com","contoso.mx"]); // <-- Cambia por tus dominios
EmailEvents
| where Timestamp >= ago(lookback)
| where SenderFromDomain in (orgDomains)
| where SenderMailFromDomain !in (orgDomains)
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
"@ },
    @{ Id=3;  Category="Spoofing y Autenticación"; Title="Spoofing: Fallos de Autenticación (SPF/DKIM/DMARC)"; Query=@"
let lookback = 7d;
EmailEvents
| where Timestamp >= ago(lookback)
| extend Auth = parse_json(AuthenticationDetails)
| extend SPF = tostring(Auth.SPF), DKIM = tostring(Auth.DKIM), DMARC = tostring(Auth.DMARC)
| where SPF has_any ("fail","softfail","temperror","permerror") or DKIM has_any ("fail","none","temperror","permerror") or DMARC has_any ("fail","none","temperror","permerror")
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, SPF, DKIM, DMARC, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
"@ },
    @{ Id=4;  Category="Spoofing y Autenticación"; Title="Spoofing: Análisis de Campañas"; Query=@"
let lookback = 7d;
EmailEvents
| where Timestamp >= ago(lookback)
| where SenderFromDomain != SenderMailFromDomain
| summarize Msgs = count(), Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by SenderFromDomain, SenderMailFromDomain, SenderFromAddress
| order by Msgs desc, Recipients desc
"@ },
    # ── Impersonation & Brand Protection ──
    @{ Id=5;  Category="Impersonation y Brand Protection"; Title="Impersonation: Dominios Typosquat (Levenshtein)"; Query=@"
let lookback = 14d;
let protectedDomains = dynamic(["contoso.com","fabrikam.com"]); // <-- dominios a proteger
EmailEvents
| where Timestamp >= ago(lookback)
| where SenderFromDomain !in (protectedDomains)
| mv-expand pd = protectedDomains
| extend Distance = levenshtein_distance(SenderFromDomain, tostring(pd))
| where Distance between (1 .. 2)
| summarize Msgs = count(), Recipients = dcount(RecipientEmailAddress), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), ExampleFrom = any(SenderFromAddress) by SenderFromDomain, ProtectedDomain=tostring(pd), Distance
| order by Distance asc, Msgs desc
"@ },
    @{ Id=6;  Category="Impersonation y Brand Protection"; Title="Impersonation: Homoglyph / Punycode"; Query=@"
let lookback = 30d;
EmailEvents
| where Timestamp >= ago(lookback)
| where SenderFromDomain has "xn--" or SenderFromDomain matches regex @"[^\u0000-\u007F]"
| summarize Msgs=count(), Recipients=dcount(RecipientEmailAddress), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), ExampleFrom=any(SenderFromAddress), Subjects=make_set(Subject, 5) by SenderFromDomain
| order by Msgs desc
"@ },
    @{ Id=7;  Category="Impersonation y Brand Protection"; Title="Impersonation: Usuario VIP"; Query=@"
let lookback = 14d;
let vipUsers = dynamic(["ceo@contoso.com","cfo@contoso.com","payments@contoso.com"]);
EmailEvents
| where Timestamp >= ago(lookback)
| extend FromAddr = tolower(SenderFromAddress), FromAlias = tostring(split(tolower(SenderFromAddress),"@")[0])
| mv-expand vip = vipUsers
| extend VipAlias = tostring(split(tolower(tostring(vip)),"@")[0])
| extend Dist = levenshtein_distance(FromAlias, VipAlias)
| where Dist between (1 .. 2) and FromAddr != tolower(tostring(vip))
| summarize Msgs=count(), Recipients=dcount(RecipientEmailAddress), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), ExampleFrom=any(SenderFromAddress), Subjects=make_set(Subject, 5) by ImpersonatingAlias=FromAlias, VipImpersonated=tostring(vip), Dist, SenderFromDomain
| order by Dist asc, Msgs desc
"@ },
    @{ Id=8;  Category="Impersonation y Brand Protection"; Title="Impersonation: Dominios Look-alike (Heurística Simple)"; Query=@"
let Lookback = 30d;
let brand = "contoso.com";
EmailEvents
| where Timestamp > ago(Lookback)
| extend FromDomain = tostring(split(SenderFromAddress,"@")[1])
| where FromDomain != brand
| extend Dist = abs(strlen(FromDomain) - strlen(brand))
| where Dist <= 3
| where FromDomain contains "cont0so" or FromDomain contains "c0ntoso" or FromDomain contains "contoso-sec" or FromDomain contains "contoso-support"
| summarize count(), Victims=dcount(RecipientEmailAddress) by FromDomain
| order by count_ desc
"@ },
    # ── Phishing, BEC & Ingeniería Social ──
    @{ Id=9;  Category="Phishing, BEC e Ingeniería Social"; Title="BEC: Señales de Urgencia y Pagos"; Query=@"
let lookback = 7d;
let becKeywords = dynamic(["urgent","wire","payment","invoice","transfer","bank","remittance","pago","transferencia","factura","urgente"]);
EmailEvents
| where Timestamp >= ago(lookback)
| where SenderFromDomain != SenderMailFromDomain or SenderFromDomain has "xn--"
| where Subject has_any (becKeywords)
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
"@ },
    @{ Id=10; Category="Phishing, BEC e Ingeniería Social"; Title="Spear-phishing a VIPs"; Query=@"
let Lookback = 14d;
let vip_list = dynamic(["ceo@contoso.com","cfo@contoso.com","board.alias@contoso.com"]);
EmailEvents
| where Timestamp > ago(Lookback)
| where RecipientEmailAddress in (vip_list)
| where DeliveryLocation in ("Inbox","Folder","JunkFolder")
| extend AuthFail = not( AuthenticationDetails has "dmarc=pass" and AuthenticationDetails has "spf=pass" )
| summarize Total=count(), DistinctSenders=dcount(SenderFromAddress), WithAuthIssues=countif(AuthFail), HighConfidencePhish=countif(ThreatTypes has "Phish" and DetectionMethods has "ZAP" or DetectionMethods has "PhishFilter") by RecipientEmailAddress
| order by HighConfidencePhish desc, WithAuthIssues desc
"@ },
    @{ Id=11; Category="Phishing, BEC e Ingeniería Social"; Title="BEC Ligero: Reply-To Mismatch"; Query=@"
let Lookback = 14d;
EmailEvents
| where Timestamp > ago(Lookback)
| where DeliveryLocation in ("Inbox","Folder")
| extend ReplyToDomain = tostring(parse_json(AdditionalFields).ReplyToDomain)
| extend FromDomain = tostring(split(SenderFromAddress,"@")[1])
| where isnotempty(ReplyToDomain) and ReplyToDomain != FromDomain
| summarize count(), DistinctSenders=dcount(SenderFromAddress) by ReplyToDomain, FromDomain
| order by count_ desc
"@ },
    @{ Id=12; Category="Phishing, BEC e Ingeniería Social"; Title="Técnica Quasi-QRCode / Image Only"; Query=@"
let Lookback = 14d;
let delivered_images = EmailEvents
    | where Timestamp > ago(Lookback)
    | where DeliveryLocation in ("Inbox","Folder")
    | join kind=leftanti (EmailUrlInfo | where Timestamp > ago(Lookback) | project NetworkMessageId) on NetworkMessageId
    | join kind=inner (EmailAttachmentInfo | where Timestamp > ago(Lookback)
        | where tolower(FileType) has "image" or FileName matches regex @"\.(png|jpg|jpeg|gif)$") on NetworkMessageId
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject, Timestamp;
delivered_images
| join kind=leftsemi (UrlClickEvents | where Timestamp > ago(Lookback) | project RecipientEmailAddress, Timestamp) on RecipientEmailAddress
| summarize MensajesImagenes=count(), DistinctRecipients=dcount(RecipientEmailAddress)
"@ },
    @{ Id=13; Category="Phishing, BEC e Ingeniería Social"; Title="Kits de Phishing (Formularios)"; Query=@"
let Lookback = 14d;
let form_kits = dynamic(["forms.co","formcrafts.com","typeform.com","smartsheet.com","airtable.com","notion.site","google.com/forms","formulario.link"]);
EmailUrlInfo
| where Timestamp > ago(Lookback)
| where UrlDomain has_any (form_kits)
| summarize count(), Victims=dcount(RecipientEmailAddress) by UrlDomain
| order by count_ desc
"@ },
    # ── Análisis de URLs & Adjuntos ──
    @{ Id=14; Category="Análisis de URLs y Adjuntos"; Title="Pivot por URLs Sospechosas"; Query=@"
let lookback = 7d;
let suspicious = EmailEvents
| where Timestamp >= ago(lookback)
| where SenderFromDomain != SenderMailFromDomain
| project NetworkMessageId, Timestamp, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject;
suspicious
| join kind=inner (
    EmailUrlInfo
    | where Timestamp >= ago(lookback)
    | project NetworkMessageId, Url, UrlDomain
) on NetworkMessageId
| summarize UrlCount=count(), Recipients=dcount(RecipientEmailAddress), Examples=make_set(Url, 10) by SenderFromDomain, SenderFromAddress, Subject
| order by UrlCount desc
"@ },
    @{ Id=15; Category="Análisis de URLs y Adjuntos"; Title="URLs de Bajo Rédito / TLDs de Riesgo"; Query=@"
let Lookback = 14d;
let risky_tlds = dynamic([".top",".xyz",".click",".monster",".fit",".rest",".lol",".casa"]);
let delivered_urls = EmailEvents
    | where Timestamp > ago(Lookback)
    | where DeliveryLocation in ("Inbox","Folder","JunkFolder")
    | join kind=inner (EmailUrlInfo | where Timestamp > ago(Lookback)) on NetworkMessageId
    | extend Tld = tostring(extract(@"(\.[A-Za-z0-9\-]{2,})$", 1, UrlDomain))
    | where Tld in (risky_tlds)
    | project Timestamp, RecipientEmailAddress, SenderFromAddress, Url, UrlDomain, NetworkMessageId;
delivered_urls
| join kind=leftsemi (UrlClickEvents | where Timestamp > ago(Lookback) | project NetworkMessageId) on NetworkMessageId
| summarize Clics=count() by UrlDomain
| order by Clics desc
"@ },
    @{ Id=16; Category="Análisis de URLs y Adjuntos"; Title="Campaña Activa: Múltiples Clics en misma URL"; Query=@"
let Lookback = 7d;
UrlClickEvents
| where Timestamp > ago(Lookback)
| summarize DistinctVictims=dcount(RecipientEmailAddress), FirstClick=min(Timestamp), LastClick=max(Timestamp) by Url
| where DistinctVictims >= 3
| order by DistinctVictims desc, LastClick desc
"@ },
    @{ Id=17; Category="Análisis de URLs y Adjuntos"; Title="Bloqueos de Safe Links"; Query=@"
let Lookback = 14d;
UrlClickEvents
| where Timestamp > ago(Lookback)
| where ClickVerdict in ("Blocked","BlockedBySafeLinks")
| summarize BlockedClicks=count(), Victims=dcount(RecipientEmailAddress) by UrlDomain
| order by BlockedClicks desc
"@ },
    @{ Id=18; Category="Análisis de URLs y Adjuntos"; Title="Adjuntos de Riesgo (Ejecutables/Scripts)"; Query=@"
let Lookback = 14d;
let risky_ext = dynamic([".html",".htm",".hta",".js",".vbs",".wsf",".lnk",".iso",".img",".dll",".exe",".ps1",".bat",".cmd",".jar"]);
EmailAttachmentInfo
| where Timestamp > ago(Lookback)
| extend Ext = tolower(tostring(extract(@"\.[^.]+$", 0, FileName)))
| where Ext in (risky_ext)
| join kind=inner (EmailEvents | where DeliveryLocation in ("Inbox","Folder","JunkFolder")) on NetworkMessageId
| summarize count(), DistinctRecipients=dcount(RecipientEmailAddress) by Ext, SenderFromAddress
| order by count_ desc
"@ },
    @{ Id=19; Category="Análisis de URLs y Adjuntos"; Title="Adjuntos HTML/HTA con Data URI"; Query=@"
let Lookback = 14d;
EmailAttachmentInfo
| where Timestamp > ago(Lookback)
| where tolower(FileName) matches regex @"\.(html|htm|hta)$"
| join kind=inner (EmailEvents) on NetworkMessageId
| join kind=leftouter (EmailUrlInfo) on NetworkMessageId
| extend IsDataUri = iif(isnotempty(Url) and Url startswith "data:text/html", true, false)
| summarize Total=count(), DataUri=countif(IsDataUri) by SenderFromAddress
| order by DataUri desc, Total desc
"@ },
    # ── Detección de Anomalías & Comportamiento ──
    @{ Id=20; Category="Detección de Anomalías y Comportamiento"; Title="Dominio del Remitente Recién Visto"; Query=@"
let Lookback = 14d;
let Baseline = 45d;
let recent = EmailEvents
  | where Timestamp > ago(Lookback)
  | extend SenderDomain = tostring(split(SenderFromAddress, "@")[1])
  | summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Cnt=count() by SenderDomain;
let historical = EmailEvents
  | where Timestamp between (ago(Baseline) .. ago(Lookback))
  | extend SenderDomain = tostring(split(SenderFromAddress, "@")[1])
  | summarize PrevCnt=count() by SenderDomain;
recent
| join kind=leftouter (historical) on SenderDomain
| where isnull(PrevCnt) or PrevCnt == 0
| order by Cnt desc, LastSeen desc
"@ },
    @{ Id=21; Category="Detección de Anomalías y Comportamiento"; Title="Usuarios con Alto Volumen de Reportes"; Query=@"
let Lookback = 30d;
CloudAppEvents
| where Timestamp > ago(Lookback)
| where ActionType == "UserSubmission"
| summarize Reports=count() by UserId
| order by Reports desc
"@ },
    @{ Id=22; Category="Detección de Anomalías y Comportamiento"; Title="Top Targets (Pareto de Riesgo)"; Query=@"
let Lookback = 30d;
let delivered_threats = EmailEvents
  | where Timestamp > ago(Lookback)
  | where ThreatTypes has_any ("Phish","Malware","CredentialPhish");
let clicked = UrlClickEvents
  | where Timestamp > ago(Lookback)
  | summarize Clicks=count() by RecipientEmailAddress;
delivered_threats
| summarize Delivered=count(), DistinctSenders=dcount(SenderFromAddress) by RecipientEmailAddress
| join kind=leftouter clicked on RecipientEmailAddress
| extend Clicks = coalesce(Clicks, 0)
| order by Delivered desc, Clicks desc
"@ },
    @{ Id=23; Category="Detección de Anomalías y Comportamiento"; Title="Reglas de Bandeja de Entrada Post-Compromiso"; Query=@"
let Lookback = 7d;
EmailEvents
| where Timestamp > ago(Lookback)
| where ActionType == "InboxRuleCreated" or ActionType == "InboxRuleUpdated"
| extend Rule = parse_json(AdditionalDetails)
| extend FwdTo = tostring(Rule.ForwardTo)
| where isnotempty(FwdTo) and not(FwdTo endswith "@contoso.com")
| project Timestamp, AccountUpn, FwdTo, SenderFromAddress, IPAddress, Subject
| order by Timestamp desc
"@ },
    @{ Id=24; Category="Detección de Anomalías y Comportamiento"; Title="Clics desde Ubicaciones Atípicas"; Query=@"
let Lookback = 14d;
let baseline = UrlClickEvents
  | where Timestamp between (ago(60d) .. ago(Lookback))
  | summarize BaselineCountries=make_set(RecipientCountry) by RecipientEmailAddress;
UrlClickEvents
| where Timestamp > ago(Lookback)
| join kind=leftouter baseline on RecipientEmailAddress
| extend Known=set_has_element(BaselineCountries, RecipientCountry)
| where Known == false
| summarize Clicks=count() by RecipientEmailAddress, RecipientCountry
| order by Clicks desc
"@ },
    @{ Id=25; Category="Detección de Anomalías y Comportamiento"; Title="Top Campañas Activas"; Query=@"
let Lookback = 7d;
EmailEvents
| where Timestamp > ago(Lookback)
| where DeliveryLocation in ("Inbox","Folder","JunkFolder")
| summarize Msgs=count(), Victims=dcount(RecipientEmailAddress), Senders=dcount(SenderFromAddress) by SenderFromDomain, Subject
| order by Msgs desc
"@ },
    # ── Efectividad de Defensa & Post-Delivery ──
    @{ Id=26; Category="Efectividad de Defensa y Post-Delivery"; Title="Mensajes Remediados Post-Entrega (ZAP)"; Query=@"
let lookback = 7d;
EmailPostDeliveryEvents
| where Timestamp >= ago(lookback)
| where ActionType in ("ZAP","Quarantine","SoftDelete","HardDelete")
| project Timestamp, NetworkMessageId, ActionType, ActionResult, RecipientEmailAddress
| order by Timestamp desc
"@ },
    @{ Id=27; Category="Efectividad de Defensa y Post-Delivery"; Title="Evasión Inicial + ZAP Posterior"; Query=@"
let Lookback = 14d;
EmailPostDeliveryEvents
| where Timestamp > ago(Lookback)
| where ActionType in ("SoftDelete","MoveToQuarantine","ZAP")
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(Lookback)
    | where DetectionMethods !has "PhishFilter" and ThreatTypes == ""
) on NetworkMessageId
| project Timestamp, ActionType, RecipientEmailAddress, SenderFromAddress, Subject, NetworkMessageId
| order by Timestamp desc
"@ },
    @{ Id=28; Category="Efectividad de Defensa y Post-Delivery"; Title="Bypass por Allow/Override"; Query=@"
let Lookback = 30d;
EmailEvents
| where Timestamp > ago(Lookback)
| where OrgLevelAction in ("Allow","DeliverToInbox") or (DetectionMethods has "UserOverride" or DetectionMethods has "AdminOverride")
| summarize Total=count(), DistinctSenders=dcount(SenderFromAddress) by OrgLevelAction, DetectionMethods
| order by Total desc
"@ }
)

# Seleccionar un KQL aleatorio del catálogo MDO
$SelectedMdoKql = $MdoKqlCatalog | Get-Random

# --- CATÁLOGO KQL: MDE (Advanced Hunting – Endpoint Security) ---
$MdeKqlCatalog = @(
    @{ Id=1; Category="Alertas y Severidad"; Title="Alertas MDE por Severidad y Categoría"; Query=@"
let TimeRange = 7d;
AlertInfo
| where Timestamp >= ago(TimeRange)
| where ServiceSource has "Endpoint"
| summarize Count=count() by Severity, Category
| order by Count desc
"@ },
    @{ Id=2; Category="Alertas y Severidad"; Title="Top 10 Alertas Repetitivas MDE"; Query=@"
let TimeRange = 7d;
AlertInfo
| where Timestamp >= ago(TimeRange)
| where ServiceSource has "Endpoint"
| summarize Count=count(), Devices=dcount(AlertId) by Title, Severity, Category
| top 10 by Count desc
"@ },
    @{ Id=3; Category="Procesos Sospechosos"; Title="Ejecución de LOLBins (Living Off The Land)"; Query=@"
let TimeRange = 7d;
let lolbins = dynamic(["certutil.exe","mshta.exe","regsvr32.exe","rundll32.exe","wscript.exe","cscript.exe","msiexec.exe","bitsadmin.exe","forfiles.exe","pcalua.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(TimeRange)
| where FileName in~ (lolbins)
| summarize Count=count(), Devices=dcount(DeviceName), Users=dcount(AccountName) by FileName, FolderPath
| order by Count desc
"@ },
    @{ Id=4; Category="Procesos Sospechosos"; Title="Ejecuciones de PowerShell con Encoding/Bypass"; Query=@"
let TimeRange = 7d;
DeviceProcessEvents
| where Timestamp >= ago(TimeRange)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("-enc","-encoded","-bypass","hidden","-nop","-w hidden","IEX","Invoke-Expression","downloadstring")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
"@ },
    @{ Id=5; Category="Procesos Sospechosos"; Title="Creación de Tareas Programadas Sospechosas"; Query=@"
let TimeRange = 7d;
DeviceProcessEvents
| where Timestamp >= ago(TimeRange)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
"@ },
    @{ Id=6; Category="Conexiones de Red"; Title="Conexiones Salientes a IPs Públicas Poco Comunes"; Query=@"
let TimeRange = 7d;
DeviceNetworkEvents
| where Timestamp >= ago(TimeRange)
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| summarize Connections=count(), Devices=dcount(DeviceName) by RemoteIP, RemotePort, RemoteUrl
| where Connections >= 5
| order by Connections desc
"@ },
    @{ Id=7; Category="Conexiones de Red"; Title="DNS Tunneling / Exfiltración DNS"; Query=@"
let TimeRange = 1d;
DeviceNetworkEvents
| where Timestamp >= ago(TimeRange)
| where RemotePort == 53
| summarize DNSQueries=count(), DistinctDomains=dcount(RemoteUrl) by DeviceName, InitiatingProcessAccountName
| where DNSQueries > 1000 or DistinctDomains > 500
| order by DNSQueries desc
"@ },
    @{ Id=8; Category="Movimiento Lateral"; Title="Logons Exitosos en Múltiples Dispositivos (1h)"; Query=@"
let TimeRange = 1d;
let Window = 1h;
let MinDevices = 5;
DeviceLogonEvents
| where Timestamp >= ago(TimeRange)
| where ActionType == "LogonSuccess"
| where LogonType in ("Interactive","RemoteInteractive","Network")
| summarize Devices=dcount(DeviceName), DeviceList=make_set(DeviceName, 20), Logons=count() by AccountName, AccountDomain, bin(Timestamp, Window)
| where Devices >= MinDevices
| order by Devices desc
"@ },
    @{ Id=9; Category="Ransomware y Archivos"; Title="Indicadores de Ransomware (Renombrado Masivo)"; Query=@"
let TimeRange = 1d;
DeviceFileEvents
| where Timestamp >= ago(TimeRange)
| where ActionType == "FileRenamed"
| summarize FilesRenamed=count(), Extensions=make_set(extract(@"\.[^.]+$", 0, FileName), 20) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName
| where FilesRenamed > 100
| order by FilesRenamed desc
"@ },
    @{ Id=10; Category="Vulnerabilidades"; Title="Vulnerabilidades Críticas por Dispositivo (TVM)"; Query=@"
DeviceTvmSoftwareVulnerabilities
| where VulnerabilitySeverityLevel == "Critical"
| summarize CriticalVulns=count(), Software=make_set(SoftwareName, 20) by DeviceName
| order by CriticalVulns desc
| take 25
"@ },
    @{ Id=11; Category="Vulnerabilidades"; Title="Top CVEs Críticos Explotables"; Query=@"
DeviceTvmSoftwareVulnerabilities
| where VulnerabilitySeverityLevel == "Critical"
| where IsExploitAvailable == true
| summarize AffectedDevices=dcount(DeviceName), Software=make_set(SoftwareName, 10) by CveId
| order by AffectedDevices desc
| take 20
"@ },
    @{ Id=12; Category="Exposición de Dispositivos"; Title="Dispositivos con Exposición Alta o Media"; Query=@"
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
| where ExposureLevel in ("High","Medium")
| project DeviceName, OSPlatform, ExposureLevel, OnboardingStatus, Timestamp
| order by ExposureLevel asc, Timestamp desc
| take 50
"@ }
)
$SelectedMdeKql = $MdeKqlCatalog | Get-Random

# --- CATÁLOGO KQL: MDI (Advanced Hunting – Identity Threat Detection) ---
# Fuente: https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Paquete%20MDI%20KQL%20Advance%20Hunting.md
$MdiKqlCatalog = @(
    @{ Id=1; Category="Alertas e Incidentes MDI"; Title="Alertas de Defender for Identity (últimos 7d)"; Query=@"
let TimeRange = 7d;
AlertInfo
| where Timestamp >= ago(TimeRange)
| where ServiceSource has_any ("Microsoft Defender for Identity", "MicrosoftDefenderForIdentity", "Defender for Identity", "MDI")
| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, DetectionSource, ProviderName
| order by Timestamp desc
"@ },
    @{ Id=2; Category="Alertas e Incidentes MDI"; Title="Incidentes con Evidencias de Identidad"; Query=@"
let TimeRange = 7d;
IncidentInfo
| where Timestamp >= ago(TimeRange)
| project Timestamp, IncidentId, Title, Severity, Status, Classification, Determination
| order by Timestamp desc
"@ },
    @{ Id=3; Category="Fuerza Bruta y Spray"; Title="Password Spraying – Múltiples Fallos por Cuenta"; Query=@"
let TimeRange = 1d;
let FailureThreshold = 15;
IdentityLogonEvents
| where Timestamp >= ago(TimeRange)
| where ActionType in ("LogonFailed", "InvalidPassword", "UserLoginFailed", "Failure")
| summarize FailedLogons=count(), SrcIPs=dcount(IPAddress) by AccountUpn, AccountName, AccountDomain
| where FailedLogons >= FailureThreshold and SrcIPs >= 3
| order by FailedLogons desc
"@ },
    @{ Id=4; Category="Fuerza Bruta y Spray"; Title="Cuentas Privilegiadas con Múltiples Fallos"; Query=@"
let TimeRange = 1d;
let FailureThreshold = 8;
IdentityLogonEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has "Fail"
| summarize Failures=count() by AccountUpn, AccountName
| where Failures >= FailureThreshold
| join kind=leftouter IdentityAccountInfo on AccountUpn
| where IsPrivileged == true
| project AccountUpn, AccountName, Failures, IsPrivileged
| order by Failures desc
"@ },
    @{ Id=5; Category="Reconocimiento LDAP/SAM-R"; Title="Enumeración LDAP / SAM-R Anómala"; Query=@"
let TimeRange = 1d;
IdentityQueryEvents
| where Timestamp >= ago(TimeRange)
| where ActionType in ("SamR query", "Ldap query")
| summarize QueryCount=count() by DeviceName, AccountUpn, bin(Timestamp, 1h)
| where QueryCount > 500
| order by QueryCount desc
"@ },
    @{ Id=6; Category="Reconocimiento LDAP/SAM-R"; Title="Enumeración de Objetos AD (Usuarios/Grupos)"; Query=@"
let TimeRange = 7d;
IdentityQueryEvents
| where Timestamp >= ago(TimeRange)
| summarize Events=count(), SrcIPs=dcount(IPAddress) by AccountUpn, AccountName, AccountDomain
| order by Events desc
"@ },
    @{ Id=7; Category="Movimiento Lateral"; Title="Logons Exitosos en Múltiples Equipos (1h)"; Query=@"
let Lookback = 1d;
let Window = 1h;
let MinDevices = 6;
IdentityLogonEvents
| where Timestamp >= ago(Lookback)
| where ActionType in ("LogonSuccess", "LogonAttempted")
| summarize Devices=dcount(DeviceName), DeviceList=make_set(DeviceName, 25), TotalLogons=count() by AccountUpn, AccountName, AccountDomain, bin(Timestamp, Window)
| where Devices >= MinDevices
| order by Devices desc
"@ },
    @{ Id=8; Category="Persistencia y Escalación"; Title="sAMAccountName Spoofing / noPac"; Query=@"
let TimeRange = 7d;
IdentityDirectoryEvents
| where Timestamp >= ago(TimeRange)
| where ActionType contains "Account"
| extend OldSamAccount = tostring(parse_json(AdditionalFields).OldValue)
| extend NewSamAccount = tostring(parse_json(AdditionalFields).NewValue)
| where OldSamAccount != NewSamAccount and NewSamAccount endswith "$"
| project Timestamp, AccountUpn, TargetAccountUpn, OldSamAccount, NewSamAccount, DeviceName
| order by Timestamp desc
"@ },
    @{ Id=9; Category="Persistencia y Escalación"; Title="Cambios de UPN Sospechosos"; Query=@"
let TimeRange = 7d;
IdentityDirectoryEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("UPN", "User principal name", "UserPrincipalName")
| project Timestamp, AccountUpn, TargetAccountUpn, ActionType, AdditionalFields, DeviceName
| order by Timestamp desc
"@ },
    @{ Id=10; Category="Persistencia y Escalación"; Title="Actividad PowerShell en Domain Controllers"; Query=@"
let TimeRange = 7d;
IdentityDirectoryEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has "PowerShell"
| project Timestamp, AccountUpn, ActionType, AdditionalFields, DeviceName, DestinationDeviceName
| order by Timestamp desc
"@ },
    @{ Id=11; Category="Exfiltración DNS"; Title="DNS Tunneling / Exfiltración"; Query=@"
let TimeRange = 1d;
DeviceNetworkEvents
| where Timestamp >= ago(TimeRange)
| where RemotePort == 53
| summarize DNSQueries=count(), DistinctDomains=dcount(RemoteUrl) by DeviceName, InitiatingProcessAccountName
| where DNSQueries > 1000 or DistinctDomains > 500
| order by DNSQueries desc
"@ }
)
$SelectedMdiKql = $MdiKqlCatalog | Get-Random

# --- CATÁLOGO KQL: Entra ID (Advanced Hunting – Identity Governance) ---
# Fuente: https://github.com/watchdogcode/gol2026/blob/V2.1/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md
$EntraKqlCatalog = @(
    # ── A) Detección – Usuarios ──
    @{ Id=1; Category="Detección de Usuarios"; Title="Top Fallos de Inicio de Sesión por Usuario"; Query=@"
let Lookback = 1d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), Apps=dcount(Application), IPs=dcount(IPAddress) by AccountUpn
| order by Failures desc
"@ },
    @{ Id=2; Category="Detección de Usuarios"; Title="Top Fallos por IP (Brute Force / Spray)"; Query=@"
let Lookback = 1d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), Users=dcount(AccountUpn), Apps=dcount(Application) by IPAddress, Country
| order by Users desc, Failures desc
"@ },
    @{ Id=3; Category="Detección de Usuarios"; Title="Password Spraying (una IP a Muchos Usuarios)"; Query=@"
let Lookback = 1d;
let MinUsers = 15;
let MinFailures = 50;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), Users=dcount(AccountUpn), SampleUsers=make_set(AccountUpn, 20) by IPAddress, Country
| where Users >= MinUsers and Failures >= MinFailures
| order by Users desc, Failures desc
"@ },
    @{ Id=4; Category="Detección de Usuarios"; Title="Spray Distribuido (Muchas IPs a un Usuario)"; Query=@"
let Lookback = 1d;
let MinIPs = 10;
let MinFailures = 30;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), IPs=dcount(IPAddress), SampleIPs=make_set(IPAddress, 20) by AccountUpn
| where IPs >= MinIPs and Failures >= MinFailures
| order by IPs desc, Failures desc
"@ },
    @{ Id=5; Category="Detección de Usuarios"; Title="Picos de Fallos por Ventana (Detección de Ráfagas)"; Query=@"
let Lookback = 1d;
let Window = 10m;
let Spike = 30;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count() by IPAddress, AccountUpn, bin(Timestamp, Window)
| where Failures >= Spike
| order by Failures desc
"@ },
    @{ Id=6; Category="Detección de Riesgo"; Title="Sign-ins de Alto Riesgo (Medium/High)"; Query=@"
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where RiskLevelAggregated in (50, 100)
| project Timestamp, AccountUpn, RiskLevelAggregated, RiskState, RiskDetails, Application, ResourceDisplayName, IPAddress, Country
| order by Timestamp desc
"@ },
    @{ Id=7; Category="Detección de Riesgo"; Title="Usuarios At Risk o Confirmed Compromised"; Query=@"
let Lookback = 14d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where RiskState in (4, 5)
| project Timestamp, AccountUpn, RiskState, RiskDetails, Application, ResourceDisplayName, IPAddress, Country
| order by Timestamp desc
"@ },
    @{ Id=8; Category="MFA y Conditional Access"; Title="Sign-in sin MFA Cuando se Esperaba MFA"; Query=@"
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where AuthenticationRequirement == "singleFactorAuthentication"
| summarize SignIns=count(), Apps=dcount(Application), Countries=dcount(Country) by AccountUpn
| order by SignIns desc
"@ },
    @{ Id=9; Category="MFA y Conditional Access"; Title="MFA Requerido pero CA No Aplicado / Falló"; Query=@"
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ConditionalAccessStatus in (1,2)
| project Timestamp, AccountUpn, Application, ConditionalAccessStatus, ConditionalAccessPolicies, IPAddress, Country
| order by Timestamp desc
"@ },
    @{ Id=10; Category="Anomalías Geográficas"; Title="Token Issuer ADFS (Entornos Híbridos)"; Query=@"
let Lookback = 14d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where TokenIssuerType == 1
| summarize SignIns=count(), Users=dcount(AccountUpn), Apps=dcount(Application) by Application, ResourceDisplayName
| order by SignIns desc
"@ },
    @{ Id=11; Category="Anomalías Geográficas"; Title="Sign-ins desde Países Nuevos por Usuario"; Query=@"
let Lookback = 30d;
let Recent = 2d;
let historical = EntraIdSignInEvents
| where Timestamp between (ago(Lookback) .. ago(Recent))
| summarize KnownCountries=make_set(Country, 200) by AccountUpn;
EntraIdSignInEvents
| where Timestamp >= ago(Recent)
| summarize RecentCountries=make_set(Country, 50), RecentIPs=make_set(IPAddress, 50) by AccountUpn
| join kind=leftouter historical on AccountUpn
| extend NewCountries = set_difference(RecentCountries, KnownCountries)
| where array_length(NewCountries) > 0
| project AccountUpn, NewCountries, RecentIPs
| order by array_length(NewCountries) desc
"@ },
    @{ Id=12; Category="Anomalías Geográficas"; Title="Nuevos Dispositivos por Usuario"; Query=@"
let Lookback = 30d;
let Recent = 2d;
let historical = EntraIdSignInEvents
| where Timestamp between (ago(Lookback) .. ago(Recent))
| summarize KnownDevices=make_set(EntraIdDeviceId, 500) by AccountUpn;
EntraIdSignInEvents
| where Timestamp >= ago(Recent)
| summarize RecentDevices=make_set(EntraIdDeviceId, 100), SampleApps=make_set(Application, 20) by AccountUpn
| join kind=leftouter historical on AccountUpn
| extend NewDevices = set_difference(RecentDevices, KnownDevices)
| where array_length(NewDevices) > 0
| project AccountUpn, NewDevices, SampleApps
"@ },
    @{ Id=13; Category="Dispositivos y Compliance"; Title="Acceso desde Dispositivos No Gestionados"; Query=@"
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where IsManaged == 0 or IsCompliant == 0
| summarize SignIns=count(), Apps=dcount(Application), Countries=dcount(Country) by AccountUpn, IsManaged, IsCompliant
| order by SignIns desc
"@ },
    @{ Id=14; Category="Dispositivos y Compliance"; Title="Invitados / Externos con Actividad"; Query=@"
let Lookback = 14d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where IsGuestUser == true or IsExternalUser == 1
| summarize SignIns=count(), Apps=make_set(Application, 20), Countries=make_set(Country, 20) by AccountUpn
| order by SignIns desc
"@ },
    # ── B) Workload Identities ──
    @{ Id=15; Category="Workload Identities (SPN)"; Title="Fallos de Service Principals / Managed Identity"; Query=@"
let Lookback = 7d;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), IPs=dcount(IPAddress), Countries=dcount(Country) by ServicePrincipalName, ServicePrincipalId, IsManagedIdentity
| order by Failures desc
"@ },
    @{ Id=16; Category="Workload Identities (SPN)"; Title="SPN con Muchas IPs (Posible Abuso / Token Theft)"; Query=@"
let Lookback = 7d;
let MinIPs = 10;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Lookback)
| summarize SignIns=count(), IPs=dcount(IPAddress), SampleIPs=make_set(IPAddress, 25) by ServicePrincipalName, ServicePrincipalId
| where IPs >= MinIPs
| order by IPs desc, SignIns desc
"@ },
    @{ Id=17; Category="Workload Identities (SPN)"; Title="Nuevos Países para un SPN (Baseline)"; Query=@"
let Lookback = 30d;
let Recent = 2d;
let historical = EntraIdSpnSignInEvents
| where Timestamp between (ago(Lookback) .. ago(Recent))
| summarize KnownCountries=make_set(Country, 200) by ServicePrincipalId;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Recent)
| summarize RecentCountries=make_set(Country, 50), RecentIPs=make_set(IPAddress, 50) by ServicePrincipalId, ServicePrincipalName
| join kind=leftouter historical on ServicePrincipalId
| extend NewCountries = set_difference(RecentCountries, KnownCountries)
| where array_length(NewCountries) > 0
| project ServicePrincipalName, ServicePrincipalId, NewCountries, RecentIPs
"@ },
    # ── C) Abuso de Microsoft Graph ──
    @{ Id=18; Category="Abuso de Microsoft Graph"; Title="Fallos 401/403 en Graph (Enumeración/Abuso)"; Query=@"
let Lookback = 1d;
GraphApiAuditEvents
| where Timestamp >= ago(Lookback)
| where ResponseStatusCode in ("401","403")
| summarize Attempts=count(), URIs=make_set(RequestUri, 25) by AccountObjectId, ApplicationId, IPAddress, Scopes
| order by Attempts desc
"@ },
    @{ Id=19; Category="Abuso de Microsoft Graph"; Title="Volumen Anómalo de Llamadas Graph"; Query=@"
let Lookback = 1d;
let Spike = 500;
GraphApiAuditEvents
| where Timestamp >= ago(Lookback)
| summarize Requests=count(), DistinctUris=dcount(RequestUri) by AccountObjectId, ApplicationId
| where Requests >= Spike
| order by Requests desc
"@ },
    @{ Id=20; Category="Abuso de Microsoft Graph"; Title="Read-Heavy (Alto Ratio GET)"; Query=@"
let Lookback = 1d;
GraphApiAuditEvents
| where Timestamp >= ago(Lookback)
| summarize Total=count(), Gets=countif(RequestMethod == "GET"), Ratio=round(todouble(Gets)/todouble(Total), 3) by AccountObjectId, ApplicationId
| where Total > 200 and Ratio > 0.9
| order by Total desc
"@ },
    @{ Id=21; Category="Abuso de Microsoft Graph"; Title="Scopes Sensibles (Mail, Files, Directory)"; Query=@"
let Lookback = 7d;
let HighRiskScopes = dynamic(["Mail.Read","Mail.ReadWrite","Mail.ReadWrite.All","Files.Read","Files.ReadWrite","Files.ReadWrite.All","Sites.Read.All","Sites.ReadWrite.All","Directory.Read.All","Directory.ReadWrite.All","User.Read.All","Group.Read.All"]);
GraphApiAuditEvents
| where Timestamp >= ago(Lookback)
| where Scopes has_any (HighRiskScopes)
| summarize Requests=count(), IPs=dcount(IPAddress), URIs=make_set(RequestUri, 25) by AccountObjectId, ApplicationId, Scopes
| order by Requests desc
"@ },
    # ── E) Investigación – Correlaciones ──
    @{ Id=22; Category="Investigación y Correlación"; Title="Sign-ins de Alto Riesgo → Actividad Graph (±30 min)"; Query=@"
let Lookback = 7d;
let PivotWindow = 30m;
let risky = EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where RiskLevelAggregated in (50,100) or RiskState in (4,5)
| project SignInTime=Timestamp, AccountUpn, AccountObjectId, IPAddress, Country, Application, CorrelationId;
GraphApiAuditEvents
| join kind=inner (risky) on AccountObjectId
| where Timestamp between (SignInTime - PivotWindow .. SignInTime + PivotWindow)
| project SignInTime, Timestamp, AccountUpn, ApplicationId, IPAddress, RequestMethod, RequestUri, Scopes, ResponseStatusCode
| order by SignInTime desc, Timestamp desc
"@ },
    @{ Id=23; Category="Investigación y Correlación"; Title="Password Spraying → Éxitos Posteriores"; Query=@"
let Lookback = 1d;
let Window = 1h;
let MinUsers = 15;
let suspects = EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), Users=dcount(AccountUpn) by IPAddress
| where Users >= MinUsers
| project IPAddress;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| join kind=inner (suspects) on IPAddress
| summarize Failures=countif(ErrorCode!=0), Success=countif(ErrorCode==0), Users=dcount(AccountUpn) by IPAddress, bin(Timestamp, Window)
| order by Success desc
"@ },
    @{ Id=24; Category="Investigación y Correlación"; Title="CA No Aplicado → Qué Apps y Usuarios"; Query=@"
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ConditionalAccessStatus == 2
| summarize Events=count(), Users=dcount(AccountUpn) by Application, ResourceDisplayName
| order by Events desc
"@ },
    # ── G) Eventos de Gestión de Entra ──
    @{ Id=25; Category="Gestión Administrativa Entra"; Title="Top Acciones Administrativas de Entra ID"; Query=@"
let Lookback = 14d;
let AppName = "Azure Active Directory";
CloudAppEvents
| where Timestamp >= ago(Lookback)
| where Application == AppName
| where IsAdminOperation == true
| summarize Events=count(), Actors=make_set(AccountDisplayName, 20), IPs=make_set(IPAddress, 20) by ActionType
| order by Events desc
"@ },
    @{ Id=26; Category="Gestión Administrativa Entra"; Title="Acciones de Consent / Permission / Role"; Query=@"
let Lookback = 30d;
let AppName = "Azure Active Directory";
CloudAppEvents
| where Timestamp >= ago(Lookback)
| where Application == AppName
| where ActionType has_any ("consent", "permission", "role", "grant", "app")
| project Timestamp, ActionType, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, RawEventData, AdditionalFields
| order by Timestamp desc
"@ }
)
$SelectedEntraKql = $EntraKqlCatalog | Get-Random

# --- CATÁLOGO KQL: MDA (Advanced Hunting – Cloud App Security) ---
$MdaKqlCatalog = @(
    @{ Id=1; Category="OAuth y Consentimientos"; Title="Nuevos Consentimientos OAuth (Últimos 7d)"; Query=@"
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType in ("Consent to application","Grant consent")
| summarize Consents=count(), Users=dcount(AccountId) by Application, ApplicationId
| top 20 by Consents desc
"@ },
    @{ Id=2; Category="OAuth y Consentimientos"; Title="Apps OAuth con Permisos de Alto Riesgo"; Query=@"
let TimeRange = 30d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("consent","permission","grant")
| where RawEventData has_any ("Mail.ReadWrite","Files.ReadWrite.All","Directory.ReadWrite.All","Sites.ReadWrite.All")
| project Timestamp, ActionType, Application, AccountDisplayName, RawEventData
| order by Timestamp desc
"@ },
    @{ Id=3; Category="Shadow IT"; Title="Top Aplicaciones Cloud por Actividad"; Query=@"
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| summarize Events=count(), Users=dcount(AccountId) by Application
| top 25 by Events desc
"@ },
    @{ Id=4; Category="Shadow IT"; Title="Aplicaciones Nuevas (Primera Vez Vistas en 7d)"; Query=@"
let Lookback = 7d;
let Baseline = 60d;
let recent = CloudAppEvents
| where Timestamp >= ago(Lookback)
| summarize FirstSeen=min(Timestamp), Events=count() by Application;
let historical = CloudAppEvents
| where Timestamp between (ago(Baseline) .. ago(Lookback))
| summarize PrevEvents=count() by Application;
recent
| join kind=leftanti historical on Application
| order by Events desc
"@ },
    @{ Id=5; Category="Operaciones Administrativas"; Title="Operaciones Admin en Aplicaciones Cloud"; Query=@"
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where IsAdminOperation == true
| summarize Events=count(), IPs=make_set(IPAddress, 20) by Application, ActionType, AccountDisplayName
| order by Events desc
"@ },
    @{ Id=6; Category="Operaciones Administrativas"; Title="Acciones de Eliminación Masiva"; Query=@"
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("Delete","Remove","Purge")
| summarize Deletions=count(), Users=dcount(AccountId) by Application, ActionType
| where Deletions > 10
| order by Deletions desc
"@ },
    @{ Id=7; Category="Descarga y Exfiltración"; Title="Descargas Masivas desde Cloud Apps"; Query=@"
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("Download","FileDownloaded","Export")
| summarize Downloads=count(), Apps=dcount(Application) by AccountDisplayName, AccountObjectId
| where Downloads > 50
| order by Downloads desc
"@ },
    @{ Id=8; Category="Descarga y Exfiltración"; Title="Compartir Archivos con Externos"; Query=@"
let TimeRange = 14d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("SharingSet","SharingInvitationCreated","Anonymous")
| summarize Shares=count(), Apps=dcount(Application) by AccountDisplayName, AccountObjectId
| where Shares > 20
| order by Shares desc
"@ },
    @{ Id=9; Category="Anomalías de Acceso"; Title="Actividad desde Países Poco Comunes"; Query=@"
let TimeRange = 7d;
let Baseline = 60d;
let known = CloudAppEvents
| where Timestamp between (ago(Baseline) .. ago(TimeRange))
| summarize KnownCountries=make_set(CountryCode, 200) by AccountId;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| summarize RecentCountries=make_set(CountryCode, 50), Events=count() by AccountId, AccountDisplayName
| join kind=leftouter known on AccountId
| extend NewCountries = set_difference(RecentCountries, KnownCountries)
| where array_length(NewCountries) > 0
| project AccountDisplayName, NewCountries, Events
| order by array_length(NewCountries) desc
"@ },
    @{ Id=10; Category="Anomalías de Acceso"; Title="Viaje Imposible (Actividad en 2+ Países en <2h)"; Query=@"
let TimeRange = 1d;
let Window = 2h;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| summarize Countries=make_set(CountryCode, 10), MinTime=min(Timestamp), MaxTime=max(Timestamp) by AccountId, AccountDisplayName, bin(Timestamp, Window)
| where array_length(Countries) >= 2
| project AccountDisplayName, Countries, MinTime, MaxTime
| order by MaxTime desc
"@ }
)
$SelectedMdaKql = $MdaKqlCatalog | Get-Random

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
        .ops-group-header.mde  { background: linear-gradient(135deg, #d83b01, #a52a00); }
        .ops-group-header.mdi  { background: linear-gradient(135deg, #e97a00, #c25e00); }
        .ops-group-header.entra { background: linear-gradient(135deg, #107c10, #0b5e0b); }
        .ops-group-header.mda  { background: linear-gradient(135deg, #8764b8, #6b4fa0); }
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
            <div class="kpi-card $(if($Kpi_TotalAlerts -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$Kpi_TotalAlerts</div>
                <div class="kpi-label">Total Alertas XDR</div>
            </div>
            <div class="kpi-card $(if($Kpi_IncidentCount -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$Kpi_IncidentCount</div>
                <div class="kpi-label">Incidentes Activos</div>
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

        <!-- ═══ Tareas Operativas MDO (Daily) ═══ -->
        <div class="ops-section">
            <div class="ops-group">
                <div class="ops-group-header mdo">
                    <span class="icon">&#x1f4e7;</span> Tareas Operativas - Microsoft Defender for Office 365
                    <span class="ops-badge daily">7 Diarias</span>
                </div>
                <table class="ops-table">
                    <thead><tr><th style="width:50%">Tarea</th><th style="width:25%">Portal</th><th style="width:25%">Documentación</th></tr></thead>
                    <tbody>
                        <tr><td class="ops-task-name">Revisar alertas activas</td><td><a class="ops-btn portal" href="https://security.microsoft.com/alerts" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#monitoreo-de-alertas" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Monitoreo de Incidentes</td><td><a class="ops-btn portal" href="https://security.microsoft.com/incidents" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#monitoreo-de-incidentes" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Triage de Mensajes de Teams Reportados por Usuarios</td><td><a class="ops-btn portal" href="https://admin.teams.microsoft.com/policies/messaging?view=reportedsafety" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#triage-de-mensajes-de-teams-reportados-por-usuarios" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisar y Actuar sobre los AIRs</td><td><a class="ops-btn portal" href="https://security.microsoft.com/action-center/pending" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#revisar-y-actuar-sobre-los-airs" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisar las Tendencias de Detección de Correo en MDO</td><td><a class="ops-btn portal" href="https://security.microsoft.com/reports/TPSAggregateReportATP" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#revisar-las-tendencias-de-detecci%C3%B3n-de-correo-en-microsoft-defender-for-office-365" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisar Campañas de Phishing y Malware Entregados</td><td><a class="ops-btn portal" href="https://security.microsoft.com/threatexplorerv3" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#revisar-campa%C3%B1as-de-phishing-y-malware-que-resultaron-en-correos-entregados" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisión de Top Targeted Users</td><td><a class="ops-btn portal" href="https://security.microsoft.com/threatexplorerv3" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#revisi%C3%B3n-de-top-targeted-users" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Recomendación de KQL diario – MDO -->
        <div class="ops-group" style="margin-top: 20px;">
            <div class="ops-group-header mdo">
                <span class="icon">&#x1f50d;</span> Recomendación de KQL diario – MDO
                <span class="ops-badge daily">#$($SelectedMdoKql.Id) de 28</span>
            </div>
            <div style="padding: 20px;">
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
                    <span style="background:#e6f2ff; color:#0078d4; padding:3px 10px; border-radius:4px; font-size:0.78em; font-weight:600;">$($SelectedMdoKql.Category)</span>
                </div>
                <h3 style="margin:0 0 12px 0; color:var(--secondary-color); font-size:1.05em;">$($SelectedMdoKql.Title)</h3>
                <div style="background:#1e1e1e; color:#d4d4d4; padding:16px; border-radius:6px; font-family:'Cascadia Code','Consolas',monospace; font-size:0.82em; line-height:1.6; overflow-x:auto; white-space:pre-wrap;">$($SelectedMdoKql.Query)</div>
                <div style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">
                    <a class="ops-btn portal" href="https://security.microsoft.com/v2/advanced-hunting" target="_blank">&#x1f517; Ejecutar en Advanced Hunting</a>
                    <a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/04%20Paquete%20MDO%20KQL%20Advance%20Hunting.md" target="_blank">&#x1f4d6; Ver Catálogo Completo (28 KQL)</a>
                </div>
            </div>
        </div>

        <!-- ═══════════════════════════════════════════════════════ -->
        <!-- ═══ SECCIÓN XDR: Alertas e Incidentes Consolidados ═══ -->
        <!-- ═══════════════════════════════════════════════════════ -->

        <h2>XDR: Alertas e Incidentes Consolidados</h2>

        <h3>Alertas por Servicio y Severidad</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Servicio</th><th>Severidad</th><th>Cantidad</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["XDR_AllAlerts"] @("ServiceSource","Severity","Count"))</tbody>
            </table>
        </div>

        <h3>Top 25 Alertas Recientes</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Hora</th><th>Alerta</th><th>Severidad</th><th>Servicio</th><th>Categoría</th><th>Entidades</th><th>Dispositivos</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["XDR_Incidents"] @("Timestamp","Title","Severity","ServiceSource","Category","Entities","DevicesAffected"))</tbody>
            </table>
        </div>

        <!-- ═══════════════════════════════════════════════════════ -->
        <!-- ═══ SECCIÓN MDE: Seguridad de Endpoints ═══ -->
        <!-- ═══════════════════════════════════════════════════════ -->

        <h2>MDE: Seguridad de Endpoints</h2>
        <h3>Alertas MDE por Severidad</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Severidad</th><th>Cantidad</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["MDE_AlertsBySev"] @("Severity","Count"))</tbody>
            </table>
        </div>

        <!-- Recomendación de KQL diario – MDE -->
        <div class="ops-group" style="margin-top: 20px;">
            <div class="ops-group-header mde">
                <span class="icon">&#x1f50d;</span> Recomendación de KQL diario – MDE
                <span class="ops-badge daily">#$($SelectedMdeKql.Id) de 12</span>
            </div>
            <div style="padding: 20px;">
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
                    <span style="background:#fce4ec; color:#d83b01; padding:3px 10px; border-radius:4px; font-size:0.78em; font-weight:600;">$($SelectedMdeKql.Category)</span>
                </div>
                <h3 style="margin:0 0 12px 0; color:var(--secondary-color); font-size:1.05em;">$($SelectedMdeKql.Title)</h3>
                <div style="background:#1e1e1e; color:#d4d4d4; padding:16px; border-radius:6px; font-family:'Cascadia Code','Consolas',monospace; font-size:0.82em; line-height:1.6; overflow-x:auto; white-space:pre-wrap;">$($SelectedMdeKql.Query)</div>
                <div style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">
                    <a class="ops-btn portal" href="https://security.microsoft.com/v2/advanced-hunting" target="_blank">&#x1f517; Ejecutar en Advanced Hunting</a>
                </div>
            </div>
        </div>

        <!-- ═══════════════════════════════════════════════════════ -->
        <!-- ═══ SECCIÓN MDI: Seguridad de Identidades ═══ -->
        <!-- ═══════════════════════════════════════════════════════ -->

        <h2>MDI: Seguridad de Identidades</h2>

        <!-- Tareas Operativas MDI -->
        <div class="ops-section">
            <div class="ops-group">
                <div class="ops-group-header mdi">
                    <span class="icon">&#x1f6e1;</span> Tareas Operativas - Microsoft Defender for Identity
                    <span class="ops-badge daily">5 Diarias</span>
                </div>
                <table class="ops-table">
                    <thead><tr><th style="width:50%">Tarea</th><th style="width:25%">Portal</th><th style="width:25%">Documentación</th></tr></thead>
                    <tbody>
                        <tr><td class="ops-task-name">Revisar ITDR Dashboard</td><td><a class="ops-btn portal" href="https://security.microsoft.com/identities/dashboard" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-itdr-dashboard-identities--dashboard" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Triage de Incidentes por Prioridad</td><td><a class="ops-btn portal" href="https://security.microsoft.com/incidents" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#triage-de-incidentes-por-prioridad-incidents--alerts" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Configurar Tuning para Benign False Positives</td><td><a class="ops-btn portal" href="https://security.microsoft.com/advanced-hunting" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#configurar-tuning-para-benign--false-positives-advanced-hunting" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Proactive hunting diario o semanal</td><td><a class="ops-btn portal" href="https://security.microsoft.com/v2/advanced-hunting" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#proactive-hunting-diario-o-semanal-seg%C3%BAn-madurez" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisar Health Issues Global y Sensor</td><td><a class="ops-btn portal" href="https://security.microsoft.com/identities/health-issues" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-health-issues-global-y-sensor" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                    </tbody>
                </table>
            </div>
        </div>

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

        <!-- Recomendación de KQL diario – MDI -->
        <div class="ops-group" style="margin-top: 20px;">
            <div class="ops-group-header mdi">
                <span class="icon">&#x1f50d;</span> Recomendación de KQL diario – MDI
                <span class="ops-badge daily">#$($SelectedMdiKql.Id) de 11</span>
            </div>
            <div style="padding: 20px;">
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
                    <span style="background:#fff3e0; color:#e97a00; padding:3px 10px; border-radius:4px; font-size:0.78em; font-weight:600;">$($SelectedMdiKql.Category)</span>
                </div>
                <h3 style="margin:0 0 12px 0; color:var(--secondary-color); font-size:1.05em;">$($SelectedMdiKql.Title)</h3>
                <div style="background:#1e1e1e; color:#d4d4d4; padding:16px; border-radius:6px; font-family:'Cascadia Code','Consolas',monospace; font-size:0.82em; line-height:1.6; overflow-x:auto; white-space:pre-wrap;">$($SelectedMdiKql.Query)</div>
                <div style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">
                    <a class="ops-btn portal" href="https://security.microsoft.com/v2/advanced-hunting" target="_blank">&#x1f517; Ejecutar en Advanced Hunting</a>
                    <a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Paquete%20MDI%20KQL%20Advance%20Hunting.md" target="_blank">&#x1f4d6; Ver Catálogo Completo (11 KQL)</a>
                </div>
            </div>
        </div>

        <!-- ═══════════════════════════════════════════════════════ -->
        <!-- ═══ SECCIÓN Entra ID: Gobernanza de Identidades ═══ -->
        <!-- ═══════════════════════════════════════════════════════ -->

        <h2>Entra ID: Gobernanza de Identidades</h2>

        <!-- Tareas Operativas EntraID -->
        <div class="ops-section">
            <div class="ops-group">
                <div class="ops-group-header entra">
                    <span class="icon">&#x1f510;</span> Tareas Operativas - Microsoft Entra ID
                    <span class="ops-badge daily">4 Diarias</span>
                </div>
                <table class="ops-table">
                    <thead><tr><th style="width:50%">Tarea</th><th style="width:25%">Portal</th><th style="width:25%">Documentación</th></tr></thead>
                    <tbody>
                        <tr><td class="ops-task-name">Monitorear eventos de inicio de sesión y autenticación</td><td><a class="ops-btn portal" href="https://entra.microsoft.com/#view/Microsoft_AAD_IAM/SignInLogsList.ReactView/timeRangeType/last24hours/showApplicationSignIns~/true" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/EntraID/Gu%C3%ADa%20Operacional%20Microsoft%20EntraID%20Diaria.md#monitorear-eventos-de-inicio-de-sesi%C3%B3n-y-autenticaci%C3%B3n" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisión de Usuarios con Riesgo Alto Medio</td><td><a class="ops-btn portal" href="https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskyUsers" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/EntraID/Gu%C3%ADa%20Operacional%20Microsoft%20EntraID%20Diaria.md#revisi%C3%B3n-de-usuarios-con-riesgo-alto--medio" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisión de Inicios de Sesión con Riesgo</td><td><a class="ops-btn portal" href="https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskySignIns" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/EntraID/Gu%C3%ADa%20Operacional%20Microsoft%20EntraID%20Diaria.md#revisi%C3%B3n-de-inicios-de-sesi%C3%B3n-con-riesgo" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                        <tr><td class="ops-task-name">Revisar alertas de Microsoft Entra Connect Health</td><td><a class="ops-btn portal" href="https://entra.microsoft.com/#view/Microsoft_AAD_Connect_Health/ConnectHealthMenuBlade/~/overview" target="_blank">&#x1f517; Abrir Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/EntraID/Gu%C3%ADa%20Operacional%20Microsoft%20EntraID%20Diaria.md#revisar-alertas-de-microsoft-entra-connect-health-entornos-h%C3%ADbridos" target="_blank">&#x1f4d6; Ver Guía</a></td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Recomendación de KQL diario – Entra ID -->
        <div class="ops-group" style="margin-top: 20px;">
            <div class="ops-group-header entra">
                <span class="icon">&#x1f50d;</span> Recomendación de KQL diario – Entra ID
                <span class="ops-badge daily">#$($SelectedEntraKql.Id) de 26</span>
            </div>
            <div style="padding: 20px;">
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
                    <span style="background:#e8f5e9; color:#107c10; padding:3px 10px; border-radius:4px; font-size:0.78em; font-weight:600;">$($SelectedEntraKql.Category)</span>
                </div>
                <h3 style="margin:0 0 12px 0; color:var(--secondary-color); font-size:1.05em;">$($SelectedEntraKql.Title)</h3>
                <div style="background:#1e1e1e; color:#d4d4d4; padding:16px; border-radius:6px; font-family:'Cascadia Code','Consolas',monospace; font-size:0.82em; line-height:1.6; overflow-x:auto; white-space:pre-wrap;">$($SelectedEntraKql.Query)</div>
                <div style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">
                    <a class="ops-btn portal" href="https://security.microsoft.com/v2/advanced-hunting" target="_blank">&#x1f517; Ejecutar en Advanced Hunting</a>
                    <a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/V2.1/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md" target="_blank">&#x1f4d6; Ver Catálogo Completo (26 KQL)</a>
                </div>
            </div>
        </div>

        <!-- ═══════════════════════════════════════════════════════ -->
        <!-- ═══ SECCIÓN MDA: Aplicaciones en la Nube ═══ -->
        <!-- ═══════════════════════════════════════════════════════ -->

        <h2>MDA: Aplicaciones en la Nube y Shadow IT</h2>

        <h3>Nuevos Consentimientos OAuth</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Aplicación</th><th>AppId</th><th>Consentimientos</th><th>Usuarios</th></tr></thead>
                <tbody>$(ConvertTo-HtmlTable $Data["MDA_OAuth"] @("Application","ApplicationId","Consents","Users"))</tbody>
            </table>
        </div>

        <!-- Recomendación de KQL diario – MDA -->
        <div class="ops-group" style="margin-top: 20px;">
            <div class="ops-group-header mda">
                <span class="icon">&#x1f50d;</span> Recomendación de KQL diario – MDA
                <span class="ops-badge daily">#$($SelectedMdaKql.Id) de 10</span>
            </div>
            <div style="padding: 20px;">
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
                    <span style="background:#ede7f6; color:#8764b8; padding:3px 10px; border-radius:4px; font-size:0.78em; font-weight:600;">$($SelectedMdaKql.Category)</span>
                </div>
                <h3 style="margin:0 0 12px 0; color:var(--secondary-color); font-size:1.05em;">$($SelectedMdaKql.Title)</h3>
                <div style="background:#1e1e1e; color:#d4d4d4; padding:16px; border-radius:6px; font-family:'Cascadia Code','Consolas',monospace; font-size:0.82em; line-height:1.6; overflow-x:auto; white-space:pre-wrap;">$($SelectedMdaKql.Query)</div>
                <div style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">
                    <a class="ops-btn portal" href="https://security.microsoft.com/v2/advanced-hunting" target="_blank">&#x1f517; Ejecutar en Advanced Hunting</a>
                </div>
            </div>
        </div>

        <!-- ═══════════════════════════════════════════════════════ -->
        <!-- ═══ Recomendaciones y Acciones ═══ -->
        <!-- ═══════════════════════════════════════════════════════ -->

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
