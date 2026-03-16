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

.PARAMETER TenantId
    Tenant ID de Entra ID. Toma por defecto $env:AZURE_TENANT_ID.

.PARAMETER ClientId
    App/Client ID de la aplicación registrada. Toma por defecto $env:AZURE_CLIENT_ID.

.PARAMETER ClientSecret
    Secreto de la aplicación para AuthMode Secret. Toma por defecto $env:AZURE_CLIENT_SECRET.

.PARAMETER AuthMode
    Método de autenticación: 'Secret', 'Certificate', 'Interactive', 'DeviceCode'.
    Para 'Secret', configure $ClientId, $TenantId y $ClientSecret.
    Para 'Certificate', configure $ClientId, $TenantId y el certificado por thumbprint o ruta PFX.

.PARAMETER CertificateThumbprint
    Thumbprint del certificado en CurrentUser/My o LocalMachine/My.

.PARAMETER CertificatePath
    Ruta a archivo PFX/P12 para autenticación por certificado.

.PARAMETER CertificatePassword
    Password SecureString para abrir CertificatePath (opcional si el PFX no tiene password).

.PARAMETER TimeoutSec
    Timeout por consulta a la API (segundos). Por defecto: 120.

.PARAMETER FailFast
    Si es $true, detiene ejecución ante el primer error de consulta.

.PARAMETER IncludeMDO
    Incluir secciones de Microsoft Defender for Office 365. Si no se especifica ningún producto, se incluyen todos.

.PARAMETER IncludeMDE
    Incluir secciones de Microsoft Defender for Endpoint. Si no se especifica ningún producto, se incluyen todos.

.PARAMETER IncludeMDI
    Incluir secciones de Microsoft Defender for Identity y Entra ID. Si no se especifica ningún producto, se incluyen todos.

.PARAMETER IncludeMDA
    Incluir secciones de Microsoft Defender for Cloud Apps. Si no se especifica ningún producto, se incluyen todos.

.EXAMPLE
    .\New-DefenderXDRWeeklyReport.ps1
    Ejecuta el reporte con AuthMode Secret (default) y todos los productos habilitados.

.EXAMPLE
    .\New-DefenderXDRWeeklyReport.ps1 -AuthMode Certificate -TenantId "<tenant>" -ClientId "<appId>" -CertificateThumbprint "<thumbprint>"
    Ejecuta el reporte usando autenticación por certificado desde el store de certificados.

.EXAMPLE
    $pwd = Read-Host "Password del PFX" -AsSecureString
    .\New-DefenderXDRWeeklyReport.ps1 -AuthMode Certificate -TenantId "<tenant>" -ClientId "<appId>" -CertificatePath "C:\certs\app.pfx" -CertificatePassword $pwd
    Ejecuta el reporte usando un certificado PFX.

.EXAMPLE
    .\New-DefenderXDRWeeklyReport.ps1 -IncludeMDO -IncludeMDE
    Ejecuta el reporte solo con las secciones de MDO y MDE.

.EXAMPLE
    .\New-DefenderXDRWeeklyReport.ps1 -IncludeMDA
    Ejecuta el reporte solo con la sección de MDA (Cloud Apps).

.NOTES
    Requiere el permiso 'AdvancedHunting.Read.All'.
#>

param(
    [ValidateSet(7, 14, 30)]
    [int]$TimeWindowDays = 30,

    [string]$OutputPath = "$PSScriptRoot\Weekly_SecOps_Report_$(Get-Date -Format 'yyyyMMdd').html",

    [string]$TenantId = $env:AZURE_TENANT_ID,
    [string]$ClientId = $env:AZURE_CLIENT_ID,
    [string]$ClientSecret = $env:AZURE_CLIENT_SECRET,
    [string]$CertificateThumbprint = $env:AZURE_CLIENT_CERT_THUMBPRINT,
    [string]$CertificatePath = $env:AZURE_CLIENT_CERT_PATH,
    [System.Security.SecureString]$CertificatePassword,

    [ValidateSet('DeviceCode', 'Interactive', 'Secret', 'Certificate')]
    [string]$AuthMode = 'Secret',

    [bool]$SendMail = $false,
    [string]$SmtpServer,
    [string]$To,
    [string]$Subject = "Defender XDR - Reporte Semanal de Amenazas",

    [string]$ProxyUrl,
    [int]$TimeoutSec = 120,
    [bool]$FailFast = $false,
    [switch]$ExportCsv,
    [switch]$UseParallel,
    [string]$LogPath = 'C:\Reports\Logs\DefenderXDR.log',
    [switch]$TestMode,
    [switch]$IncludeMDO,
    [switch]$IncludeMDE,
    [switch]$IncludeMDI,
    [switch]$IncludeMDA
)

# --- SELECCIÓN DE PRODUCTOS (si no se especifica ninguno, se incluyen todos) ---
$RunMDO = $IncludeMDO.IsPresent
$RunMDE = $IncludeMDE.IsPresent
$RunMDI = $IncludeMDI.IsPresent
$RunMDA = $IncludeMDA.IsPresent
if (-not ($RunMDO -or $RunMDE -or $RunMDI -or $RunMDA)) {
    $RunMDO = $RunMDE = $RunMDI = $RunMDA = $true
}

# --- CONFIGURACIÓN ---
$ErrorActionPreference = "Continue"
$ApiBaseUrl = "https://api.security.microsoft.com/api"
$ResourceUrl = "https://api.security.microsoft.com"
$Scope = "$ResourceUrl/.default"
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
$MaskedThumbprint = if ($CertificateThumbprint) { Mask-String $CertificateThumbprint 6 } else { '(no configurado)' }
$MaskedCertPath  = if ($CertificatePath) { $CertificatePath } else { '(no configurado)' }

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
Write-Log "  Ruta Cert   : $MaskedCertPath" -Level INFO
Write-Log "  Modo Auth   : $AuthMode" -Level INFO
Write-Log "========================" -Level INFO

# --- AUTENTICACIÓN (Homogéneo con Reporte Diario) ---
function ConvertTo-Base64Url {
    param([byte[]]$Bytes)

    $B64 = [Convert]::ToBase64String($Bytes)
    $B64 = $B64.TrimEnd('=')
    $B64 = $B64.Replace('+', '-').Replace('/', '_')
    return $B64
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
            if (Get-Module -ListAvailable -Name "Az.Accounts") {
                Write-Log "Usando Az.Accounts para autenticación $AuthMode..."

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

                if ($TokenData.Token -is [System.Security.SecureString]) {
                    return $TokenData.Token | ConvertFrom-SecureString -AsPlainText
                }
                return $TokenData.Token
            }
            else {
                Write-Log "Módulo 'Az.Accounts' no encontrado. Usando flujo Device Code vía REST..." -Level WARN

                if (-not $ClientId -or -not $TenantId) {
                    throw "Se requieren ClientId y TenantId para autenticación sin Az.Accounts. Instale el módulo: Install-Module Az.Accounts -Scope CurrentUser"
                }

                $DeviceCodeBody = @{
                    client_id = $ClientId
                    scope     = "$ResourceUrl/.default offline_access"
                }
                $DeviceCodeReq = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" -Body $DeviceCodeBody -ErrorAction Stop

                Write-Log "=== AUTENTICACION REQUERIDA ===" -Level WARN
                Write-Log $DeviceCodeReq.message -Level WARN

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
                        $TokenReq = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $PollBody -ErrorAction Stop

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
        $RawMessage = $_.Exception.Message
        $ErrorJson = $null
        try { $ErrorJson = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}

        if ($ErrorJson -and $ErrorJson.error_codes -contains 700027) {
            Write-Log "Error de Autenticación (AADSTS700027): certificado no registrado en la aplicación." -Level ERROR
            Write-Log "AppId objetivo: $ClientId" -Level ERROR
            Write-Log "Acción requerida: cargue el certificado público (.cer) del mismo certificado usado para firmar en Entra ID > App registrations > Certificates and secrets." -Level ERROR
            Write-Log "Verifique que TenantId/AppId coincidan con el registro donde cargó el certificado y espere la propagación de claves (1-5 min)." -Level ERROR

            if ($ErrorJson.error_description -match "Thumbprint of key used by client:\s*'([^']+)'") {
                Write-Log "Thumbprint enviado por el cliente: $($Matches[1])" -Level ERROR
            }

            Write-Log $ErrorJson.error_description -Level ERROR
        }
        else {
            Write-Log "Autenticación fallida: $RawMessage" -Level ERROR
        }
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
    $Token = Get-M365Token
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
        <div class="kpi-grid">
            <div class="kpi-card $(if($KPI_MDE_Alerts -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$KPI_MDE_Alerts</div>
                <div class="kpi-label">Alertas de Defender for Endpoint</div>
            </div>
            <div class="kpi-card $(if($KPI_MDO_Phish -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$KPI_MDO_Phish</div>
                <div class="kpi-label">Alertas de Defender for Office</div>
            </div>
            <div class="kpi-card $(if($KPI_MDE_RiskyHosts -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$KPI_MDE_RiskyHosts</div>
                <div class="kpi-label">Alertas Defender for Identity</div>
            </div>
            <div class="kpi-card $(if($KPI_MDI_Spray -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$KPI_MDI_Spray</div>
                <div class="kpi-label">Usuarios con riesgo</div>
            </div>
            <div class="kpi-card $(if($KPI_MDA_OAuth -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$KPI_MDA_OAuth</div>
                <div class="kpi-label">Consentimientos Apps</div>
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


