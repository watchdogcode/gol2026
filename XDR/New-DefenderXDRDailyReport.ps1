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
    [int]$TimeWindowHours = 180,
    [string]$OutputPath = "$PSScriptRoot\Daily_SecOps_Report_$(Get-Date -Format 'yyyyMMdd').html",
    [string]$TemplatePath = "$PSScriptRoot\Nuevo_Dashboard_SecOps_GOL (3).html",
    [string]$TenantId = $env:AZURE_TENANT_ID,
    [string]$ClientId = $env:AZURE_CLIENT_ID,
    [string]$ClientSecret = $env:AZURE_CLIENT_SECRET,
    [Alias('CertThumbprint')]
    [string]$CertificateThumbprint = $env:AZURE_CLIENT_CERT_THUMBPRINT,
    [string]$CertificatePath = $env:AZURE_CLIENT_CERT_PATH,
    [System.Security.SecureString]$CertificatePassword,
    [ValidateSet("Secret", "Certificate", "Interactive", "DeviceCode")]
    [string]$AuthMode = "Secret",
    [bool]$SendMail = $false,
    [string]$SmtpServer,
    [string]$From,
    [string]$To,
    [string]$Subject = "Reporte Diario de Seguridad - M365 Defender XDR",
    [int]$TimeoutSec = 120,
    [bool]$FailFast = $false,
    [int]$CustomDetectionsWindowHours = 180,
    [switch]$IncludeMDO,
    [switch]$IncludeMDE,
    [switch]$IncludeMDI,
    [switch]$IncludeMDA
)

$TenantId = if ($null -ne $TenantId) { $TenantId.Trim() } else { $TenantId }
$ClientId = if ($null -ne $ClientId) { $ClientId.Trim() } else { $ClientId }
$ClientSecret = if ($null -ne $ClientSecret) { $ClientSecret.Trim() } else { $ClientSecret }
$CertificateThumbprint = if ($null -ne $CertificateThumbprint) { ($CertificateThumbprint -replace '\s','').ToUpperInvariant() } else { $CertificateThumbprint }
$CertificatePath = if ($null -ne $CertificatePath) { $CertificatePath.Trim() } else { $CertificatePath }
$AuthMode = if ($null -ne $AuthMode) { $AuthMode.Trim() } else { $AuthMode }

# --- SELECCIÓN DE PRODUCTOS (si no se especifica ninguno, se incluyen todos) ---
$RunMDO = $IncludeMDO.IsPresent
$RunMDE = $IncludeMDE.IsPresent
$RunMDI = $IncludeMDI.IsPresent
$RunMDA = $IncludeMDA.IsPresent
if (-not ($RunMDO -or $RunMDE -or $RunMDI -or $RunMDA)) {
    $RunMDO = $RunMDE = $RunMDI = $RunMDA = $true
}

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
$MaskedCertThumb = if ($CertificateThumbprint) { Mask-String $CertificateThumbprint 6 } else { '(no configurado)' }
$MaskedCertPath  = if ($CertificatePath) { $CertificatePath } else { '(no configurado)' }

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
Write-Log "  Cert Thumb  : $MaskedCertThumb"
Write-Log "  Cert Path   : $MaskedCertPath"
Write-Log "  Auth Mode   : $AuthMode"
Write-Log "=============================="

# --- AUTENTICACIÓN ---
function ConvertTo-Base64Url {
    param([byte[]]$Bytes)

    $B64 = [Convert]::ToBase64String($Bytes)
    $B64 = $B64.TrimEnd('=')
    $B64 = $B64.Replace('+', '-').Replace('/', '_')
    return $B64
}

function Get-ExceptionResponseBody {
    param([Parameter(Mandatory)]$ErrorRecord)

    $ErrorDetailsMessage = $ErrorRecord.ErrorDetails.Message
    if ($ErrorDetailsMessage) {
        return [string]$ErrorDetailsMessage
    }

    $Response = $ErrorRecord.Exception.Response
    if (-not $Response) {
        return $null
    }

    try {
        if ($Response.Content) {
            return $Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        }
    }
    catch {}

    try {
        $Stream = $Response.GetResponseStream()
        if ($Stream) {
            $Reader = New-Object System.IO.StreamReader($Stream)
            try {
                return $Reader.ReadToEnd()
            }
            finally {
                $Reader.Dispose()
                $Stream.Dispose()
            }
        }
    }
    catch {}

    return $null
}

function Get-CertificateForAuth {
    if ($CertificatePath) {
        if (-not (Test-Path $CertificatePath)) {
            throw "No se encontró el certificado en ruta: $CertificatePath"
        }

        if ($CertificatePassword) {
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $CertificatePath,
                $CertificatePassword,
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
            )
        }

        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $CertificatePath,
            $null,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        )
    }

    if (-not $CertificateThumbprint) {
        throw "Para AuthMode 'Certificate', especifique -CertificateThumbprint o -CertificatePath."
    }

    $NormalizedThumb = ($CertificateThumbprint -replace '\s','').ToUpperInvariant()
    foreach ($StoreLocation in @('CurrentUser', 'LocalMachine')) {
        $Store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $StoreLocation)
        try {
            $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $Found = $Store.Certificates | Where-Object { $_.Thumbprint -eq $NormalizedThumb } | Select-Object -First 1
            if ($Found) {
                return $Found
            }
        }
        finally {
            $Store.Close()
        }
    }

    throw "No se encontró un certificado con thumbprint '$CertificateThumbprint' en CurrentUser/My o LocalMachine/My."
}

function New-ClientAssertionJwt {
    param(
        [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$TenantId
    )

    if (-not $Certificate.HasPrivateKey) {
        throw "El certificado no contiene clave privada."
    }

    $Rsa = $null
    try {
        $Rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    }
    catch {
        $Rsa = $null
    }

    if (-not $Rsa -and $Certificate.PrivateKey -is [System.Security.Cryptography.RSA]) {
        $Rsa = [System.Security.Cryptography.RSA]$Certificate.PrivateKey
    }

    if (-not $Rsa) {
        throw "No se pudo obtener la clave privada RSA del certificado. Verifique que tenga clave privada exportable y algoritmo RSA."
    }

    $Now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $Audience = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $Header = @{
        alg = 'RS256'
        typ = 'JWT'
        x5t = (ConvertTo-Base64Url -Bytes $Certificate.GetCertHash())
    }

    $Payload = @{
        aud = $Audience
        iss = $ClientId
        sub = $ClientId
        jti = ([Guid]::NewGuid().ToString())
        nbf = $Now - 300
        exp = $Now + 600
    }

    $HeaderJson = ($Header | ConvertTo-Json -Compress)
    $PayloadJson = ($Payload | ConvertTo-Json -Compress)

    $EncodedHeader = ConvertTo-Base64Url -Bytes ([Text.Encoding]::UTF8.GetBytes($HeaderJson))
    $EncodedPayload = ConvertTo-Base64Url -Bytes ([Text.Encoding]::UTF8.GetBytes($PayloadJson))
    $UnsignedToken = "$EncodedHeader.$EncodedPayload"

    $SignatureBytes = $Rsa.SignData(
        [Text.Encoding]::UTF8.GetBytes($UnsignedToken),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $EncodedSignature = ConvertTo-Base64Url -Bytes $SignatureBytes

    return "$UnsignedToken.$EncodedSignature"
}

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
        elseif ($AuthMode -eq "Certificate") {
            if (-not ($TenantId -and $ClientId)) {
                throw "Para autenticación 'Certificate', se requieren TenantId y ClientId."
            }

            $Cert = Get-CertificateForAuth
            Write-Log "Usando certificado '$($Cert.Subject)' (thumbprint: $($Cert.Thumbprint)) para autenticación por certificado."

            $ClientAssertion = New-ClientAssertionJwt -Certificate $Cert -ClientId $ClientId -TenantId $TenantId
            $Body = @{
                grant_type            = 'client_credentials'
                client_id             = $ClientId
                scope                 = "$ResourceUrl/.default"
                client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                client_assertion      = $ClientAssertion
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
                        $ErrDetailsMessage = $_.ErrorDetails.Message
                        if ($ErrDetailsMessage) {
                            try { $ErrBody = $ErrDetailsMessage | ConvertFrom-Json } catch {}
                        }
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
        $RawMessage = $_.Exception.Message
        $ErrorJson = $null
        $ResponseBody = Get-ExceptionResponseBody -ErrorRecord $_
        if ($ResponseBody) {
            try { $ErrorJson = $ResponseBody | ConvertFrom-Json } catch {}
        }

        if ($ErrorJson -and $ErrorJson.error_codes -contains 700027) {
            Write-Log "Error de Autenticación (AADSTS700027): certificado no registrado en la aplicación." -Level ERROR
            Write-Log "AppId objetivo: $ClientId" -Level ERROR
            Write-Log "Acción requerida: cargue el certificado público (.cer) del mismo certificado usado para firmar en Entra ID > App registrations > Certificates & secrets." -Level ERROR
            Write-Log "Verifique que TenantId/AppId coincidan con el registro donde cargó el certificado y espere la propagación de claves (1-5 min)." -Level ERROR

            if ($ErrorJson.error_description -match "Thumbprint of key used by client:\s*'([^']+)'") {
                Write-Log "Thumbprint enviado por el cliente: $($Matches[1])" -Level ERROR
            }

            Write-Log $ErrorJson.error_description -Level ERROR
        }
        elseif ($ResponseBody) {
            Write-Log "Error de Autenticación: $RawMessage" -Level ERROR
            Write-Log "Detalle devuelto por Entra ID: $ResponseBody" -Level ERROR
        }
        else {
            Write-Log "Error de Autenticación: $RawMessage" -Level ERROR
        }
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

    "XDR_Trend7d" = @"
AlertInfo
| where Timestamp >= ago(7d)
| summarize Count=dcount(AlertId) by Day=bin(Timestamp, 1d)
| order by Day asc
"@

    "XDR_AlertsTop" = @"
AlertInfo
| where Timestamp >= ago(24h)
| project Timestamp,
          AlertId,
          Title = tostring(column_ifexists("Title", "")),
          Severity = tostring(column_ifexists("Severity", "")),
          ServiceSource = tostring(column_ifexists("ServiceSource", "")),
          Status = tostring(column_ifexists("Status", "")),
          Category = tostring(column_ifexists("Category", ""))
| order by Timestamp desc
| take 500
"@

    "MDO_ThreatMetrics7d" = @"
let p = toscalar(EmailEvents | where Timestamp >= ago(7d) and ThreatTypes has "Phish" | summarize c=count());
let m = toscalar(EmailEvents | where Timestamp >= ago(7d) and ThreatTypes has "Malware" | summarize c=count());
let s = toscalar(EmailEvents | where Timestamp >= ago(7d) and SenderFromDomain != SenderMailFromDomain | summarize c=count());
let u = toscalar(EmailUrlInfo | where Timestamp >= ago(7d) | summarize c=count());
print Phishing=p, UrlMaliciosa=u, Suplantacion=s, Malware=m
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

# 2. Ejecutar Consultas (filtradas por producto activo)
$Data = @{}
foreach ($Key in $Queries.Keys) {
    if ($Key.StartsWith("MDO_") -and -not $RunMDO) { continue }
    if ($Key.StartsWith("MDE_") -and -not $RunMDE) { continue }
    if ($Key.StartsWith("MDI_") -and -not $RunMDI) { continue }
    if ($Key.StartsWith("MDA_") -and -not $RunMDA) { continue }
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

# 4. Generar HTML usando plantilla base
function ConvertTo-HtmlSafe {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-SeverityClass {
    param([string]$Severity)
    $s = ([string]$Severity).ToLowerInvariant()
    if ($s -match "critical|crit") { return "critical" }
    if ($s -match "high|alto") { return "high" }
    if ($s -match "medium|medio") { return "medium" }
    if ($s -match "low|bajo") { return "low" }
    return "info"
}

function Get-SeverityRank {
    param([string]$Severity)
    switch (Get-SeverityClass $Severity) {
        "critical" { 4 }
        "high" { 3 }
        "medium" { 2 }
        "low" { 1 }
        default { 0 }
    }
}

function Get-SeverityTextEs {
    param([string]$Severity)
    switch (Get-SeverityClass $Severity) {
        "critical" { "Crítico" }
        "high" { "Alto" }
        "medium" { "Medio" }
        "low" { "Bajo" }
        default { "Info" }
    }
}

function Get-StateClass {
    param([string]$Status)
    $s = ([string]$Status).ToLowerInvariant()
    if ($s -match "new|nuevo") { return "new" }
    if ($s -match "active|investig|inprogress|ongoing") { return "investigating" }
    if ($s -match "resolved|closed|mitigated|contained|resuelto") { return "contained" }
    return "investigating"
}

function Get-StateTextEs {
    param([string]$Status)
    $s = ([string]$Status).ToLowerInvariant()
    if ($s -match "new|nuevo") { return "Nuevo" }
    if ($s -match "resolved|closed|mitigated|contained|resuelto") { return "Contenido" }
    if ($s -match "active|inprogress|ongoing|investig") { return "En investigación" }
    return "En investigación"
}

function Get-WorkloadFromServiceSource {
    param([string]$ServiceSource)
    $s = [string]$ServiceSource
    if ($s -match "Office|Email|Exchange|Teams") { return "MDO" }
    if ($s -match "Endpoint|Device") { return "MDE" }
    if ($s -match "Identity|Defender for Identity|MDI") { return "MDI" }
    if ($s -match "Entra|Azure Active Directory|AAD") { return "Entra" }
    if ($s -match "Cloud App|MCAS|Defender for Cloud Apps") { return "MDA" }
    return "Otros"
}

function Get-RelativeAgeText {
    param([datetime]$When)
    if (-not $When) { return "N/D" }
    $ts = New-TimeSpan -Start $When -End (Get-Date)
    if ($ts.TotalMinutes -lt 60) { return "hace $([math]::Max(1, [int]$ts.TotalMinutes)) min" }
    if ($ts.TotalHours -lt 24) { return "hace $([math]::Max(1, [int]$ts.TotalHours)) h" }
    return "hace $([math]::Max(1, [int]$ts.TotalDays)) d"
}

function Get-KpiTrend {
    param([int]$Current, [int]$Previous)
    $Delta = $Current - $Previous
    if ($Delta -gt 0) {
        return @{ Class = "up"; Text = "&#x25B2; +$Delta vs. ayer" }
    }
    if ($Delta -lt 0) {
        return @{ Class = "down"; Text = "&#x25BC; $Delta vs. ayer" }
    }
    return @{ Class = "flat"; Text = "&#x2013; sin cambio" }
}

function Set-ContentBetweenMarkers {
    param(
        [string]$Html,
        [string]$StartMarker,
        [string]$EndMarker,
        [string]$InjectedHtml
    )
    $startIx = $Html.IndexOf($StartMarker)
    if ($startIx -lt 0) { return $Html }
    $fromIx = $startIx + $StartMarker.Length
    $endIx = $Html.IndexOf($EndMarker, $fromIx)
    if ($endIx -lt 0) { return $Html }
    return $Html.Substring(0, $fromIx) + "`r`n" + $InjectedHtml + "`r`n                        " + $Html.Substring($endIx)
}

function Update-KpiCardByLabel {
    param(
        [string]$Html,
        [string]$Label,
        [int]$Value,
        [string]$TrendClass,
        [string]$TrendText,
        [string]$CardClass
    )
    $escapedLabel = [regex]::Escape($Label)
    $pattern = '(?s)(<a class="kpi-card\s+)([^"]+)("[^>]*>.*?<div class="kpi-val">)([^<]*)(</div>\s*<div class="kpi-label">\s*{0}\s*</div>\s*<span class="kpi-trend\s+)([^"]+)("[^>]*>)(.*?)(</span>)' -f $escapedLabel
    return [regex]::Replace($Html, $pattern, {
        param($m)
        return $m.Groups[1].Value + $CardClass + $m.Groups[3].Value + $Value + $m.Groups[5].Value + $TrendClass + $m.Groups[7].Value + $TrendText + $m.Groups[9].Value
    }, 1)
}

function Build-IncidentRows {
    param([object[]]$Rows)
    if (-not $Rows -or $Rows.Count -eq 0) {
        return '<tr><td colspan="7" style="text-align:center; color:#666;">No se encontraron incidentes activos en el período.</td></tr>'
    }

    $html = ""
    foreach ($r in $Rows) {
        $sevClass = Get-SeverityClass $r.Severity
        $sevText = Get-SeverityTextEs $r.Severity
        $stateClass = Get-StateClass $r.Status
        $stateText = Get-StateTextEs $r.Status
        $entity = if ($r.ServiceSource) { "$($r.ServiceSource): $($r.Category)" } else { "N/D" }
        $id = if ($r.AlertId) { $r.AlertId } else { "N/D" }
        $age = Get-RelativeAgeText ([datetime]$r.Timestamp)
        $title = ConvertTo-HtmlSafe $r.Title

        $html += @"
                        <tr>
                            <td class="id-cell">$(ConvertTo-HtmlSafe $id)</td>
                            <td>$title</td>
                            <td><span class="sev $sevClass">$sevText</span></td>
                            <td><span class="state $stateClass">$stateText</span></td>
                            <td>$age</td>
                            <td class="entity">$(ConvertTo-HtmlSafe $entity)</td>
                            <td><a class="btn portal" href="https://security.microsoft.com/incidents" target="_blank" rel="noopener noreferrer">Ver</a></td>
                        </tr>
"@
    }
    return $html.TrimEnd()
}

function Build-DetectionRows {
    param([object[]]$Rows)
    if (-not $Rows -or $Rows.Count -eq 0) {
        return '<tr><td colspan="6" style="text-align:center; color:#666;">No se encontraron detecciones personalizadas con actividad.</td></tr>'
    }

    $html = ""
    foreach ($r in $Rows) {
        $sevClass = Get-SeverityClass $r.Severity
        $sevText = Get-SeverityTextEs $r.Severity
        $last = if ($r.LastSeen -is [datetime]) { Get-RelativeAgeText $r.LastSeen } else { "N/D" }
        $html += @"
                        <tr>
                            <td>$(ConvertTo-HtmlSafe $r.Rule)</td>
                            <td class="entity">$(ConvertTo-HtmlSafe $r.Workload)</td>
                            <td><span class="sev $sevClass">$sevText</span></td>
                            <td>$(ConvertTo-HtmlSafe $r.Matches)</td>
                            <td class="entity">$last</td>
                            <td><a class="btn portal" href="https://security.microsoft.com/v2/advanced-hunting" target="_blank" rel="noopener noreferrer">Investigar</a></td>
                        </tr>
"@
    }
    return $html.TrimEnd()
}

function Build-TopAlertsBlock {
    param([object[]]$Rows)
    if (-not $Rows -or $Rows.Count -eq 0) {
        return @"
            <div class="empty-state">
                <span class="ok-dot" aria-hidden="true"></span>
                <div><strong>Sin alertas activas.</strong> No se detectaron alertas en el período analizado.</div>
            </div>
"@
    }

    $body = ""
    foreach ($r in ($Rows | Sort-Object @{Expression={ Get-SeverityRank $_.Severity }; Descending=$true}, @{Expression='Timestamp'; Descending=$true} | Select-Object -First 5)) {
        $sevClass = Get-SeverityClass $r.Severity
        $sevText = Get-SeverityTextEs $r.Severity
        $stateClass = Get-StateClass $r.Status
        $stateText = Get-StateTextEs $r.Status
        $body += @"
                            <tr>
                                <td>$(Get-RelativeAgeText ([datetime]$r.Timestamp))</td>
                                <td>$(ConvertTo-HtmlSafe $r.Title)</td>
                                <td><span class="sev $sevClass">$sevText</span></td>
                                <td><span class="state $stateClass">$stateText</span></td>
                                <td><a class="btn portal" href="https://security.microsoft.com/alerts" target="_blank" rel="noopener noreferrer">Ver</a></td>
                            </tr>
"@
    }

    return @"
            <div class="table-container">
                <div class="table-scroll">
                <table>
                    <thead>
                        <tr>
                            <th scope="col">Antigüedad</th>
                            <th scope="col">Alerta</th>
                            <th scope="col">Severidad</th>
                            <th scope="col">Estado</th>
                            <th scope="col">Acción</th>
                        </tr>
                    </thead>
                    <tbody>
$body
                    </tbody>
                </table>
                </div>
            </div>
"@
}

function Set-WorkloadAlertBlock {
    param([string]$Html, [string]$SectionId, [string]$BlockHtml)
    $pattern = '(?s)(<section id="{0}">.*?<h3 class="block-title">Alertas del workload &mdash; Top 5 por criticidad</h3>\s*)(<div class="empty-state">.*?</div>|<div class="table-container">.*?</div>\s*</div>)' -f $SectionId
    return [regex]::Replace($Html, $pattern, { param($m) $m.Groups[1].Value + $BlockHtml }, 1)
}

function Build-DonutWrap {
    param([hashtable]$SeverityCounts)
    $critical = [int]$SeverityCounts["critical"]
    $high = [int]$SeverityCounts["high"]
    $medium = [int]$SeverityCounts["medium"]
    $low = [int]$SeverityCounts["low"]
    $total = $critical + $high + $medium + $low
    if ($total -le 0) { $total = 1 }

    $circ = 2 * [math]::PI * 60
    $c1 = ($critical / $total) * $circ
    $c2 = ($high / $total) * $circ
    $c3 = ($medium / $total) * $circ
    $c4 = ($low / $total) * $circ

    return @"
                    <div class="donut-wrap">
                        <svg width="150" height="150" viewBox="0 0 160 160" role="img" aria-label="Gráfica de dona de severidad de incidentes">
                            <circle cx="80" cy="80" r="60" fill="none" stroke="rgba(0,0,0,0.06)" stroke-width="22"></circle>
                            <g transform="rotate(-90 80 80)" fill="none" stroke-width="22">
                                <circle cx="80" cy="80" r="60" stroke="#7a0018" stroke-dasharray="$([math]::Round($c1,2)) $([math]::Round($circ-$c1,2))" stroke-dashoffset="0"></circle>
                                <circle cx="80" cy="80" r="60" stroke="#d13438" stroke-dasharray="$([math]::Round($c2,2)) $([math]::Round($circ-$c2,2))" stroke-dashoffset="-$([math]::Round($c1,2))"></circle>
                                <circle cx="80" cy="80" r="60" stroke="#ff8c00" stroke-dasharray="$([math]::Round($c3,2)) $([math]::Round($circ-$c3,2))" stroke-dashoffset="-$([math]::Round($c1+$c2,2))"></circle>
                                <circle cx="80" cy="80" r="60" stroke="#8764b8" stroke-dasharray="$([math]::Round($c4,2)) $([math]::Round($circ-$c4,2))" stroke-dashoffset="-$([math]::Round($c1+$c2+$c3,2))"></circle>
                            </g>
                            <text x="80" y="74" text-anchor="middle" font-size="30" font-weight="700" fill="currentColor">$($critical + $high + $medium + $low)</text>
                            <text x="80" y="96" text-anchor="middle" font-size="11" fill="currentColor" opacity="0.7">activos</text>
                        </svg>
                        <ul class="donut-legend">
                            <li><span class="sw" style="background:#7a0018;"></span><span class="lv">Crítico</span><span class="ct">$critical</span></li>
                            <li><span class="sw" style="background:#d13438;"></span><span class="lv">Alto</span><span class="ct">$high</span></li>
                            <li><span class="sw" style="background:#ff8c00;"></span><span class="lv">Medio</span><span class="ct">$medium</span></li>
                            <li><span class="sw" style="background:#8764b8;"></span><span class="lv">Bajo</span><span class="ct">$low</span></li>
                        </ul>
                    </div>
"@
}

function Build-TrendSvg {
    param([int[]]$Values)
    if (-not $Values -or $Values.Count -eq 0) { $Values = @(0,0,0,0,0,0,0) }
    $max = [math]::Max(1, ($Values | Measure-Object -Maximum).Maximum)
    $points = @()
    for ($i = 0; $i -lt $Values.Count; $i++) {
        $x = 30 + ($i * (290 / [math]::Max(1, $Values.Count - 1)))
        $y = 95 - (($Values[$i] / $max) * 70)
        $points += "{0:N1},{1:N1}" -f $x, $y
    }
    $pointsText = ($points -join " ")
    $today = $Values[-1]
    return @"
                    <div class="chart-note">Incidentes activos por día &middot; hoy: $today</div>
                    <svg width="100%" height="130" viewBox="0 0 340 130" preserveAspectRatio="none" role="img" aria-label="Tendencia de incidentes de los últimos 7 días">
                        <line x1="30" y1="95" x2="320" y2="95" stroke="rgba(0,0,0,0.12)" stroke-width="1"></line>
                        <polygon points="$pointsText 320,95 30,95" fill="rgba(0,120,212,0.12)"></polygon>
                        <polyline points="$pointsText" fill="none" stroke="#0078d4" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"></polyline>
                    </svg>
"@
}

function Build-WorkloadBars {
    param([hashtable]$WorkloadCounts)
    $ordered = @("MDE","MDO","MDI","MDA","Entra")
    $max = 1
    foreach ($k in $ordered) { if ([int]$WorkloadCounts[$k] -gt $max) { $max = [int]$WorkloadCounts[$k] } }

    $colors = @{
        "MDE" = "#d83b01"
        "MDO" = "#0078d4"
        "MDI" = "#e97a00"
        "MDA" = "#8764b8"
        "Entra" = "#107c10"
    }

    $rows = ""
    foreach ($k in $ordered) {
        $v = [int]$WorkloadCounts[$k]
        $w = [math]::Round((100 * $v) / $max, 1)
        $label = if ($k -eq "Entra") { "Entra ID" } else { $k }
        $rows += '<div class="bar-row"><span class="bar-label">{0}</span><span class="bar-track"><span class="bar-fill" style="width:{1}%; background:{2};"></span></span><span class="bar-val">{3}</span></div>' -f $label, $w, $colors[$k], $v
    }
    return '<div class="bars">{0}</div>' -f $rows
}

function Build-MdoMetricChart {
    param([Alias('M')][hashtable]$Metrics)
    $phishing = [int]$Metrics["Phishing"]
    $urlMaliciosa = [int]$Metrics["UrlMaliciosa"]
    $suplantacion = [int]$Metrics["Suplantacion"]
    $malware = [int]$Metrics["Malware"]
    $total = $phishing + $urlMaliciosa + $suplantacion + $malware
    if ($total -le 0) { $total = 1 }
    $max = [math]::Max(1, [math]::Max([math]::Max($phishing, $urlMaliciosa), [math]::Max($suplantacion, $malware)))

    $h1 = [math]::Round(($phishing / $max) * 130, 1)
    $h2 = [math]::Round(($urlMaliciosa / $max) * 130, 1)
    $h3 = [math]::Round(($suplantacion / $max) * 130, 1)
    $h4 = [math]::Round(($malware / $max) * 130, 1)

    $y1 = 155 - $h1
    $y2 = 155 - $h2
    $y3 = 155 - $h3
    $y4 = 155 - $h4

    return @"
                    <div class="chart-note">Correos con amenaza detectada en los últimos 7 días &middot; total: $($phishing + $urlMaliciosa + $suplantacion + $malware)</div>
                    <svg width="100%" height="200" viewBox="0 0 360 200" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Métrica MDO por categoría">
                        <line x1="20" y1="155" x2="340" y2="155" stroke="rgba(128,128,128,0.4)" stroke-width="1"></line>
                        <rect x="34" y="$y1" width="52" height="$h1" rx="4" fill="#d13438"></rect>
                        <text x="60" y="$([math]::Max(18,$y1-7))" text-anchor="middle" font-size="12" font-weight="700" fill="currentColor">$phishing</text>
                        <text x="60" y="172" text-anchor="middle" font-size="10" fill="currentColor" opacity="0.75">Phishing</text>
                        <rect x="114" y="$y2" width="52" height="$h2" rx="4" fill="#ff8c00"></rect>
                        <text x="140" y="$([math]::Max(18,$y2-7))" text-anchor="middle" font-size="12" font-weight="700" fill="currentColor">$urlMaliciosa</text>
                        <text x="140" y="172" text-anchor="middle" font-size="10" fill="currentColor" opacity="0.75">URL malic.</text>
                        <rect x="194" y="$y3" width="52" height="$h3" rx="4" fill="#8764b8"></rect>
                        <text x="220" y="$([math]::Max(18,$y3-7))" text-anchor="middle" font-size="12" font-weight="700" fill="currentColor">$suplantacion</text>
                        <text x="220" y="172" text-anchor="middle" font-size="10" fill="currentColor" opacity="0.75">Suplantación</text>
                        <rect x="274" y="$y4" width="52" height="$h4" rx="4" fill="#7a0018"></rect>
                        <text x="300" y="$([math]::Max(18,$y4-7))" text-anchor="middle" font-size="12" font-weight="700" fill="currentColor">$malware</text>
                        <text x="300" y="172" text-anchor="middle" font-size="10" fill="currentColor" opacity="0.75">Malware</text>
                    </svg>
"@
}

if (-not (Test-Path $TemplatePath)) {
    throw "No se encontró la plantilla HTML: $TemplatePath"
}

# KPIs basados en datos ya consultados
$Kpi_IncidentesActivos = [int]$Kpi_IncidentCount
$Kpi_DeteccionesPersonalizadas = [int](
    (($Data["MDO_Campaigns"] | Measure-Object -Property Events -Sum).Sum) +
    (@($Data["MDE_Health"]).Count) +
    (@($Data["MDI_BruteForce"]).Count) +
    ((@($Data["MDI_HighRiskUsers"]) | Measure-Object -Property Events -Sum).Sum) +
    (($Data["MDA_OAuth"] | Measure-Object -Property Consents -Sum).Sum)
)

if (-not $Kpi_DeteccionesPersonalizadas) { $Kpi_DeteccionesPersonalizadas = 0 }

$AllAlertsTop = @($Data["XDR_AlertsTop"])
$AllAlertsAgg = @($Data["XDR_AllAlerts"])

$WorkloadCounts = @{ MDO = 0; MDE = 0; MDI = 0; Entra = 0; MDA = 0 }
foreach ($r in $AllAlertsAgg) {
    $wl = Get-WorkloadFromServiceSource $r.ServiceSource
    if ($WorkloadCounts.ContainsKey($wl)) {
        $WorkloadCounts[$wl] += [int]$r.Count
    }
}

$Kpi_MdoAlerts = [int]$WorkloadCounts["MDO"]
$Kpi_MdeAlerts = [int]$WorkloadCounts["MDE"]
$Kpi_EntraRisk = [int]$Kpi_HighRiskUsers
$Kpi_MdiAlerts = [int]$WorkloadCounts["MDI"]
$Kpi_MdaOauth = [int]$Kpi_NewOAuth

$KpiDeltaQueries = @{
    "Incidentes Activos" = @"
let t0 = startofday(now());
let y0 = t0 - 1d;
let c = toscalar(AlertInfo | where Timestamp between (t0 .. now()) | summarize d=dcount(AlertId));
let p = toscalar(AlertInfo | where Timestamp between (y0 .. t0) | summarize d=dcount(AlertId));
print Current=c, Previous=p
"@;
    "Detecciones Personalizadas" = @"
let t0 = startofday(now());
let y0 = t0 - 1d;
let c1 = toscalar(EmailEvents | where Timestamp between (t0 .. now()) and ThreatTypes has "Phish" | summarize c=count());
let c2 = toscalar(DeviceInfo | where Timestamp between (t0 .. now()) and ExposureLevel in ("High","Medium") | summarize c=dcount(DeviceId));
let c3 = toscalar(IdentityLogonEvents | where Timestamp between (t0 .. now()) | summarize c=dcount(AccountUpn));
let c4 = toscalar(EntraIdSignInEvents | where Timestamp between (t0 .. now()) and RiskLevelAggregated in (50, 100) | summarize c=dcount(AccountUpn));
let c5 = toscalar(CloudAppEvents | where Timestamp between (t0 .. now()) and ActionType in ("Consent to application","Grant consent") | summarize c=count());
let p1 = toscalar(EmailEvents | where Timestamp between (y0 .. t0) and ThreatTypes has "Phish" | summarize c=count());
let p2 = toscalar(DeviceInfo | where Timestamp between (y0 .. t0) and ExposureLevel in ("High","Medium") | summarize c=dcount(DeviceId));
let p3 = toscalar(IdentityLogonEvents | where Timestamp between (y0 .. t0) | summarize c=dcount(AccountUpn));
let p4 = toscalar(EntraIdSignInEvents | where Timestamp between (y0 .. t0) and RiskLevelAggregated in (50, 100) | summarize c=dcount(AccountUpn));
let p5 = toscalar(CloudAppEvents | where Timestamp between (y0 .. t0) and ActionType in ("Consent to application","Grant consent") | summarize c=count());
print Current=(c1+c2+c3+c4+c5), Previous=(p1+p2+p3+p4+p5)
"@;
    "Alertas Defender for Office" = @"
let t0 = startofday(now());
let y0 = t0 - 1d;
let c = toscalar(AlertInfo | where Timestamp between (t0 .. now()) and ServiceSource has_any ("Office", "Email", "Exchange", "Teams") | summarize c=count());
let p = toscalar(AlertInfo | where Timestamp between (y0 .. t0) and ServiceSource has_any ("Office", "Email", "Exchange", "Teams") | summarize c=count());
print Current=c, Previous=p
"@;
    "Alertas Defender for Endpoint" = @"
let t0 = startofday(now());
let y0 = t0 - 1d;
let c = toscalar(AlertInfo | where Timestamp between (t0 .. now()) and ServiceSource has_any ("Endpoint", "Device") | summarize c=count());
let p = toscalar(AlertInfo | where Timestamp between (y0 .. t0) and ServiceSource has_any ("Endpoint", "Device") | summarize c=count());
print Current=c, Previous=p
"@;
    "Usuarios en Riesgo Entra ID" = @"
let t0 = startofday(now());
let y0 = t0 - 1d;
let c = toscalar(EntraIdSignInEvents | where Timestamp between (t0 .. now()) and RiskLevelAggregated in (50,100) | summarize c=dcount(AccountUpn));
let p = toscalar(EntraIdSignInEvents | where Timestamp between (y0 .. t0) and RiskLevelAggregated in (50,100) | summarize c=dcount(AccountUpn));
print Current=c, Previous=p
"@;
    "Alertas Defender for Identity" = @"
let t0 = startofday(now());
let y0 = t0 - 1d;
let c = toscalar(AlertInfo | where Timestamp between (t0 .. now()) and ServiceSource has_any ("Identity", "Defender for Identity", "MDI") | summarize c=count());
let p = toscalar(AlertInfo | where Timestamp between (y0 .. t0) and ServiceSource has_any ("Identity", "Defender for Identity", "MDI") | summarize c=count());
print Current=c, Previous=p
"@;
    "Consentimientos OAuth (Cloud Apps)" = @"
let t0 = startofday(now());
let y0 = t0 - 1d;
let c = toscalar(CloudAppEvents | where Timestamp between (t0 .. now()) and ActionType in ("Consent to application","Grant consent") | summarize c=count());
let p = toscalar(CloudAppEvents | where Timestamp between (y0 .. t0) and ActionType in ("Consent to application","Grant consent") | summarize c=count());
print Current=c, Previous=p
"@
}

$KpiDelta = @{}
foreach ($k in $KpiDeltaQueries.Keys) {
    $res = Invoke-HuntingQuery -Token $Token -Query $KpiDeltaQueries[$k] -Name "KPI_$k"
    $row = @($res.Results | Select-Object -First 1)
    $cur = if ($row -and $row[0].Current -ne $null) { [int]$row[0].Current } else { 0 }
    $prev = if ($row -and $row[0].Previous -ne $null) { [int]$row[0].Previous } else { 0 }
    $KpiDelta[$k] = Get-KpiTrend -Current $cur -Previous $prev
}

$Detections = @(
    [pscustomobject]@{ Rule = "Campañas de phishing entregadas"; Workload = "MDO"; Severity = "High"; Matches = [int]$Kpi_PhishDelivered; LastSeen = $ReportDate },
    [pscustomobject]@{ Rule = "Dispositivos con exposición alta o media"; Workload = "MDE"; Severity = "Medium"; Matches = @($Data["MDE_Health"]).Count; LastSeen = (@($Data["MDE_Health"]) | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp },
    [pscustomobject]@{ Rule = "Fuerza bruta con éxito"; Workload = "MDI"; Severity = "High"; Matches = @($Data["MDI_BruteForce"]).Count; LastSeen = (@($Data["MDI_BruteForce"]) | Sort-Object LastSeen -Descending | Select-Object -First 1).LastSeen },
    [pscustomobject]@{ Rule = "Inicios de sesión de alto riesgo"; Workload = "Entra ID"; Severity = "High"; Matches = @($Data["MDI_HighRiskUsers"]).Count; LastSeen = $ReportDate },
    [pscustomobject]@{ Rule = "Nuevos consentimientos OAuth"; Workload = "MDA"; Severity = "Medium"; Matches = [int]$Kpi_NewOAuth; LastSeen = $ReportDate }
) | Where-Object { $_.Matches -gt 0 }

$SeverityCounts = @{ critical = 0; high = 0; medium = 0; low = 0 }
foreach ($a in $AllAlertsAgg) {
    $cls = Get-SeverityClass $a.Severity
    if ($SeverityCounts.ContainsKey($cls)) {
        $SeverityCounts[$cls] += [int]$a.Count
    }
}

$trendLookup = @{}
foreach ($t in @($Data["XDR_Trend7d"])) {
    $dayKey = ([datetime]$t.Day).ToString("yyyy-MM-dd")
    $trendLookup[$dayKey] = [int]$t.Count
}

$trendValues = @()
for ($i = 6; $i -ge 0; $i--) {
    $d = (Get-Date).Date.AddDays(-$i).ToString("yyyy-MM-dd")
    if ($trendLookup.ContainsKey($d)) {
        $trendValues += [int]$trendLookup[$d]
    }
    else {
        $trendValues += 0
    }
}

$mdoMetricRow = @($Data["MDO_ThreatMetrics7d"] | Select-Object -First 1)
$MdoMetric = @{
    Phishing = if ($mdoMetricRow) { [int]$mdoMetricRow.Phishing } else { 0 }
    UrlMaliciosa = if ($mdoMetricRow) { [int]$mdoMetricRow.UrlMaliciosa } else { 0 }
    Suplantacion = if ($mdoMetricRow) { [int]$mdoMetricRow.Suplantacion } else { 0 }
    Malware = if ($mdoMetricRow) { [int]$mdoMetricRow.Malware } else { 0 }
}

$MdoTop = @($AllAlertsTop | Where-Object { (Get-WorkloadFromServiceSource $_.ServiceSource) -eq "MDO" })
$MdeTop = @($AllAlertsTop | Where-Object { (Get-WorkloadFromServiceSource $_.ServiceSource) -eq "MDE" })
$MdiTop = @($AllAlertsTop | Where-Object { (Get-WorkloadFromServiceSource $_.ServiceSource) -eq "MDI" })
$EntraTop = @($AllAlertsTop | Where-Object { (Get-WorkloadFromServiceSource $_.ServiceSource) -eq "Entra" })
$MdaTop = @($AllAlertsTop | Where-Object { (Get-WorkloadFromServiceSource $_.ServiceSource) -eq "MDA" })

$IncidentRows = Build-IncidentRows (@($Data["XDR_Incidents"] | Sort-Object @{Expression={ Get-SeverityRank $_.Severity }; Descending=$true}, @{Expression='Timestamp'; Descending=$true} | Select-Object -First 5))
$DetectionRows = Build-DetectionRows (@($Detections | Sort-Object @{Expression={ Get-SeverityRank $_.Severity }; Descending=$true}, @{Expression='Matches'; Descending=$true} | Select-Object -First 6))

$HtmlContent = Get-Content -Raw -Path $TemplatePath -Encoding UTF8

# Encabezado
$HtmlContent = [regex]::Replace($HtmlContent, '(?s)(<div><strong>Período:</strong>).*?(</div>)', "$1 $($StartDate.ToString('yyyy-MM-dd HH:mm')) &rarr; $($ReportDate.ToString('yyyy-MM-dd HH:mm'))$2", 1)
$HtmlContent = [regex]::Replace($HtmlContent, '(?s)(<div><strong>Generado:</strong>).*?(</div>)', "$1 $((Get-Date).ToString('yyyy-MM-dd HH:mm')) (CST)$2", 1)
$HtmlContent = [regex]::Replace($HtmlContent, '(?s)<div style="opacity:0.85;">Tenant ID:.*?</div>', ('<div style="opacity:0.85;">Tenant ID: {0}</div>' -f (ConvertTo-HtmlSafe $MaskedTenantId)), 1)

# Banner de estado
$risk = if ($Kpi_IncidentesActivos -gt 0 -or $SeverityCounts["critical"] -gt 0) { "Alto" } elseif ($Kpi_DeteccionesPersonalizadas -gt 0) { "Medio" } else { "Bajo" }
$title = if ($risk -eq "Alto") { "Atención requerida" } elseif ($risk -eq "Medio") { "Seguimiento activo" } else { "Operación estable" }
$statusSub = "$Kpi_IncidentesActivos incidentes activos y $Kpi_DeteccionesPersonalizadas detecciones personalizadas en el período."
$HtmlContent = [regex]::Replace($HtmlContent, '(?s)<div class="status-title">.*?</div>', ('<div class="status-title">{0}</div>' -f $title), 1)
$HtmlContent = [regex]::Replace($HtmlContent, '(?s)<div class="status-sub">.*?</div>', ('<div class="status-sub">{0}</div>' -f $statusSub), 1)
$HtmlContent = [regex]::Replace($HtmlContent, '(?s)<span class="status-chip">.*?</span>', ('<span class="status-chip">Riesgo: {0}</span>' -f $risk), 1)

# KPIs
$CardClassIncidentes = if ($Kpi_IncidentesActivos -gt 0) { "high" } else { "none" }
$CardClassDetecciones = if ($Kpi_DeteccionesPersonalizadas -gt 0) { "high" } else { "none" }
$CardClassMdo = if ($Kpi_MdoAlerts -gt 0) { "high" } else { "none" }
$CardClassMde = if ($Kpi_MdeAlerts -gt 0) { "high" } else { "none" }
$CardClassEntra = if ($Kpi_EntraRisk -gt 0) { "high" } else { "none" }
$CardClassMdi = if ($Kpi_MdiAlerts -gt 0) { "high" } else { "none" }
$CardClassMda = if ($Kpi_MdaOauth -gt 0) { "medium" } else { "none" }

$HtmlContent = Update-KpiCardByLabel -Html $HtmlContent -Label "Incidentes Activos" -Value $Kpi_IncidentesActivos -TrendClass $KpiDelta["Incidentes Activos"].Class -TrendText $KpiDelta["Incidentes Activos"].Text -CardClass $CardClassIncidentes
$HtmlContent = Update-KpiCardByLabel -Html $HtmlContent -Label "Detecciones Personalizadas" -Value $Kpi_DeteccionesPersonalizadas -TrendClass $KpiDelta["Detecciones Personalizadas"].Class -TrendText $KpiDelta["Detecciones Personalizadas"].Text -CardClass $CardClassDetecciones
$HtmlContent = Update-KpiCardByLabel -Html $HtmlContent -Label "Alertas Defender for Office" -Value $Kpi_MdoAlerts -TrendClass $KpiDelta["Alertas Defender for Office"].Class -TrendText $KpiDelta["Alertas Defender for Office"].Text -CardClass $CardClassMdo
$HtmlContent = Update-KpiCardByLabel -Html $HtmlContent -Label "Alertas Defender for Endpoint" -Value $Kpi_MdeAlerts -TrendClass $KpiDelta["Alertas Defender for Endpoint"].Class -TrendText $KpiDelta["Alertas Defender for Endpoint"].Text -CardClass $CardClassMde
$HtmlContent = Update-KpiCardByLabel -Html $HtmlContent -Label "Usuarios en Riesgo Entra ID" -Value $Kpi_EntraRisk -TrendClass $KpiDelta["Usuarios en Riesgo Entra ID"].Class -TrendText $KpiDelta["Usuarios en Riesgo Entra ID"].Text -CardClass $CardClassEntra
$HtmlContent = Update-KpiCardByLabel -Html $HtmlContent -Label "Alertas Defender for Identity" -Value $Kpi_MdiAlerts -TrendClass $KpiDelta["Alertas Defender for Identity"].Class -TrendText $KpiDelta["Alertas Defender for Identity"].Text -CardClass $CardClassMdi
$HtmlContent = Update-KpiCardByLabel -Html $HtmlContent -Label "Consentimientos OAuth (Cloud Apps)" -Value $Kpi_MdaOauth -TrendClass $KpiDelta["Consentimientos OAuth (Cloud Apps)"].Class -TrendText $KpiDelta["Consentimientos OAuth (Cloud Apps)"].Text -CardClass $CardClassMda

# Tablas: incidentes y detecciones
$HtmlContent = Set-ContentBetweenMarkers -Html $HtmlContent -StartMarker "<!-- ⇩⇩⇩ INYECCIÓN AUTOMÁTICA: filas de incidentes reales (una por incidente) ⇩⇩⇩ -->" -EndMarker "<!-- ⇧⇧⇧ FIN INYECCIÓN AUTOMÁTICA ⇧⇧⇧ -->" -InjectedHtml $IncidentRows
$HtmlContent = Set-ContentBetweenMarkers -Html $HtmlContent -StartMarker "<!-- ⇩⇩⇩ INYECCIÓN AUTOMÁTICA: filas de detecciones reales ⇩⇩⇩ -->" -EndMarker "<!-- ⇧⇧⇧ FIN INYECCIÓN AUTOMÁTICA ⇧⇧⇧ -->" -InjectedHtml $DetectionRows

$HtmlContent = [regex]::Replace($HtmlContent, '(?s)<caption>Mostrando .*? incidentes activos, ordenados por severidad y antigüedad\.</caption>', "<caption>Mostrando $([math]::Min(5, @($Data['XDR_Incidents']).Count)) de $(@($Data['XDR_Incidents']).Count) incidentes activos, ordenados por severidad y antigüedad.</caption>", 1)
$HtmlContent = [regex]::Replace($HtmlContent, '(?s)<caption>Mostrando .*? reglas de detección personalizada con coincidencias en el período\.</caption>', "<caption>Mostrando $([math]::Min(6, @($Detections).Count)) de $(@($Detections).Count) reglas de detección personalizada con coincidencias en el período.</caption>", 1)

$remainingInc = [math]::Max(0, @($Data["XDR_Incidents"]).Count - [math]::Min(5, @($Data["XDR_Incidents"]).Count))
$remainingDet = [math]::Max(0, @($Detections).Count - [math]::Min(6, @($Detections).Count))
$HtmlContent = [regex]::Replace($HtmlContent, '(?s)<tr class="row-more"><td colspan="7">\+ .*?</td></tr>', ('<tr class="row-more"><td colspan="7">+ {0} incidentes adicionales &middot; <a href="https://security.microsoft.com/incidents" target="_blank" rel="noopener noreferrer">Ver los {1} en el portal &rarr;</a></td></tr>' -f $remainingInc, @($Data['XDR_Incidents']).Count), 1)
$HtmlContent = [regex]::Replace($HtmlContent, '(?s)<tr class="row-more"><td colspan="6">\+ .*?</td></tr>', ('<tr class="row-more"><td colspan="6">+ {0} detecciones adicionales &middot; <a href="https://security.microsoft.com/v2/custom-detection" target="_blank" rel="noopener noreferrer">Ver las {1} en el portal &rarr;</a></td></tr>' -f $remainingDet, @($Detections).Count), 1)

# Gráficas
$HtmlContent = [regex]::Replace($HtmlContent, '(?s)<div class="donut-wrap">.*?</div>\s*</div>', (Build-DonutWrap -SeverityCounts $SeverityCounts) + "`r`n                </div>", 1)
$HtmlContent = [regex]::Replace($HtmlContent, '(?s)<div class="chart-note">Incidentes activos por día.*?</svg>', (Build-TrendSvg -Values $trendValues), 1)
$HtmlContent = [regex]::Replace($HtmlContent, '(?s)<div class="bars">.*?</div>', (Build-WorkloadBars -WorkloadCounts $WorkloadCounts), 1)
$HtmlContent = [regex]::Replace($HtmlContent, '(?s)<div class="chart-note">Correos con amenaza detectada.*?</svg>', (Build-MdoMetricChart -M $MdoMetric), 1)

# Top 5 por workload
$HtmlContent = Set-WorkloadAlertBlock -Html $HtmlContent -SectionId "mdo" -BlockHtml (Build-TopAlertsBlock -Rows $MdoTop)
$HtmlContent = Set-WorkloadAlertBlock -Html $HtmlContent -SectionId "mde" -BlockHtml (Build-TopAlertsBlock -Rows $MdeTop)
$HtmlContent = Set-WorkloadAlertBlock -Html $HtmlContent -SectionId "mdi" -BlockHtml (Build-TopAlertsBlock -Rows $MdiTop)
$HtmlContent = Set-WorkloadAlertBlock -Html $HtmlContent -SectionId "entra" -BlockHtml (Build-TopAlertsBlock -Rows $EntraTop)
$HtmlContent = Set-WorkloadAlertBlock -Html $HtmlContent -SectionId "mda" -BlockHtml (Build-TopAlertsBlock -Rows $MdaTop)

# El reporte final es operacional: ocultar etiquetas de ejemplo/actualización.
$HtmlContent = $HtmlContent -replace '\s*<span class="demo-tag">Tendencias de ejemplo</span>', ''
$HtmlContent = $HtmlContent -replace '\s*<span class="demo-tag">Actualizado</span>', ''
$HtmlContent = $HtmlContent -replace '\s*<span class="demo-tag">Datos de ejemplo</span>', ''
$HtmlContent = $HtmlContent -replace '\s*<span class="demo-tag">Ejemplo</span>', ''

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
