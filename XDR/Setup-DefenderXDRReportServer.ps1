<#
.SYNOPSIS
    Setup-DefenderXDRReportServer.ps1
    Script de configuracion inicial para Defender XDR Daily & Weekly Reporting.

.DESCRIPTION
        Configura el entorno completo para ejecutar:
            - New-DefenderXDRDailyReport.ps1  (reporte diario)
            - New-DefenderXDRWeeklyReport.ps1 (reporte semanal)

    Acciones que realiza:
      1. Crea estructura de directorios segura
        2. Solicita y almacena credenciales (secret en DPAPI, certificado existente o certificado autofirmado)
      3. Valida permisos de App Registration contra la API
      4. Copia los scripts a la ruta de ejecucion
      5. Configura notificaciones por correo (opcional)
            6. Genera wrappers seguros para Task Scheduler
      7. Crea tareas programadas (Daily 7:00 AM / Weekly Lunes 7:30 AM)
      8. Ejecuta prueba de validacion (opcional)

        Si se elige autenticacion por certificado, el setup puede crear un certificado
        autofirmado, exportar el .cer publico para App Registration y dejar el thumbprint
        listo para las tareas programadas.

.PARAMETER ConfigPath
    Ruta para archivos de configuracion (default: $PSScriptRoot\Config).

.PARAMETER ReportsPath
    Ruta base para reportes generados (default: $PSScriptRoot\Reports).

.PARAMETER ScriptsPath
    Ruta donde se copiaran los scripts de reporte (default: $PSScriptRoot).

.PARAMETER RepositoryRawBaseUrl
    URL base RAW del repositorio para descargar scripts faltantes.
    Ejemplo: https://raw.githubusercontent.com/<owner>/<repo>/main/XDR

.PARAMETER SkipValidation
    Omite la validacion de permisos contra la API.

.PARAMETER SkipScheduledTasks
    Omite la creacion de tareas programadas.

.PARAMETER SkipEmail
    Omite la configuracion de notificaciones por correo.

.EXAMPLE
    .\Setup-DefenderXDRReportServer.ps1
    .\Setup-DefenderXDRReportServer.ps1 -SkipScheduledTasks
    .\Setup-DefenderXDRReportServer.ps1 -SkipEmail -SkipValidation

.NOTES
    Debe ejecutarse con la cuenta de servicio que ejecutara los reportes programados.
    Las credenciales se protegen con DPAPI (solo funcionan con el usuario que ejecuto el setup).
    Permiso requerido en App Registration: AdvancedHunting.Read.All (Application).
    Si se genera un certificado autofirmado, cargue el archivo .cer exportado en
    Entra ID > App registrations > Certificates & secrets antes de validar o programar.
#>

param(
    [string]$ConfigPath   = "$PSScriptRoot\Config",
    [string]$ReportsPath  = "$PSScriptRoot\Reports",
    [string]$ScriptsPath  = "$PSScriptRoot",
    [string]$RepositoryRawBaseUrl,
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

function Normalize-InputValue {
    param([AllowNull()][string]$Value)

    if ($null -eq $Value) {
        return $null
    }

    return $Value.Trim()
}

function Test-GuidLikeValue {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    return ($Value.Trim() -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
}

function Get-GitHubRawBaseUrl {
    param(
        [Parameter(Mandatory)][string]$SourceDir,
        [string]$OverrideUrl
    )

    if (-not [string]::IsNullOrWhiteSpace($OverrideUrl)) {
        return $OverrideUrl.TrimEnd('/')
    }

    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        return $null
    }

    try {
        $GitRemote = (& git -C $SourceDir config --get remote.origin.url 2>$null)
        if (-not $GitRemote) {
            return $null
        }

        $GitRemote = $GitRemote.Trim()

        if ($GitRemote -match '^https://github\.com/(?<owner>[^/]+)/(?<repo>[^/]+?)(\.git)?$') {
            return "https://raw.githubusercontent.com/$($Matches.owner)/$($Matches.repo)/main/XDR"
        }

        if ($GitRemote -match '^git@github\.com:(?<owner>[^/]+)/(?<repo>[^/]+?)(\.git)?$') {
            return "https://raw.githubusercontent.com/$($Matches.owner)/$($Matches.repo)/main/XDR"
        }
    }
    catch {
        return $null
    }

    return $null
}

function Get-RepositoryScriptUrl {
    param(
        [Parameter(Mandatory)][string]$ScriptName,
        [string]$RawBaseUrl
    )

    $DefaultScriptUrls = @{
        'New-DefenderXDRDailyReport.ps1'  = 'https://raw.githubusercontent.com/watchdogcode/gol2026/refs/heads/main/XDR/New-DefenderXDRDailyReport.ps1'
        'New-DefenderXDRWeeklyReport.ps1' = 'https://raw.githubusercontent.com/watchdogcode/gol2026/refs/heads/main/XDR/New-DefenderXDRWeeklyReport.ps1'
    }

    if (-not [string]::IsNullOrWhiteSpace($RawBaseUrl)) {
        return ('{0}/{1}' -f $RawBaseUrl.TrimEnd('/'), $ScriptName)
    }

    if ($DefaultScriptUrls.ContainsKey($ScriptName)) {
        return $DefaultScriptUrls[$ScriptName]
    }

    return $null
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    $B64 = [Convert]::ToBase64String($Bytes)
    $B64 = $B64.TrimEnd('=')
    $B64 = $B64.Replace('+', '-').Replace('/', '_')
    return $B64
}

function Get-CertificateByThumbprint {
    param([Parameter(Mandatory)][string]$Thumbprint)

    $NormalizedThumb = ($Thumbprint -replace '\s','').ToUpperInvariant()
    foreach ($StoreLocation in @('CurrentUser', 'LocalMachine')) {
        $Store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $StoreLocation)
        try {
            $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $Found = $Store.Certificates | Where-Object { $_.Thumbprint -eq $NormalizedThumb } | Select-Object -First 1
            if ($Found) { return $Found }
        }
        finally {
            $Store.Close()
        }
    }

    return $null
}

function New-SelfSignedCertificateForAppAuth {
    param(
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$FriendlyName,
        [Parameter(Mandatory)][string]$CertStoreLocation,
        [int]$ValidYears = 2,
        [int]$KeyLength = 2048
    )

    $NotAfter = (Get-Date).AddYears($ValidYears)

    return New-SelfSignedCertificate `
        -Subject $Subject `
        -FriendlyName $FriendlyName `
        -CertStoreLocation $CertStoreLocation `
        -KeyAlgorithm RSA `
        -KeyLength $KeyLength `
        -KeySpec Signature `
        -KeyExportPolicy Exportable `
        -HashAlgorithm SHA256 `
        -NotAfter $NotAfter `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2')
}

function Export-PublicCertificateFile {
    param(
        [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)][string]$OutputPath
    )

    $OutputDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    Export-Certificate -Cert $Certificate -FilePath $OutputPath -Force | Out-Null
    return $OutputPath
}

function ConvertFrom-SecureStringToPlainText {
    param([Parameter(Mandatory)][System.Security.SecureString]$SecureString)

    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
}

function Ensure-AzAccountsModule {
    $AzAccountsModule = Get-Module -ListAvailable -Name 'Az.Accounts' | Sort-Object Version -Descending | Select-Object -First 1
    if ($AzAccountsModule) {
        try {
            Import-Module Az.Accounts -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Skip "Az.Accounts esta instalado pero no se pudo importar: $($_.Exception.Message)"
        }

        return $true
    }

    Write-Skip 'Az.Accounts no esta instalado en este usuario.'
    $InstallAzAccounts = Read-Host '  Instalar Az.Accounts automaticamente ahora? [S/n]'
    if ($InstallAzAccounts -in @('n','N')) {
        return $false
    }

    try {
        Write-Info 'Instalando Az.Accounts desde PSGallery en CurrentUser...'
        Install-Module -Name Az.Accounts -Repository PSGallery -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Import-Module Az.Accounts -ErrorAction Stop | Out-Null
        Write-Ok 'Az.Accounts instalado e importado correctamente.'
        return $true
    }
    catch {
        Write-Fail "No se pudo instalar Az.Accounts automaticamente: $($_.Exception.Message)"
        Write-Host '    El setup usara Device Code para Microsoft Graph si decide continuar.' -ForegroundColor DarkYellow
        return $false
    }
}

function Get-GraphDelegatedAccessToken {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [string[]]$Scopes = @('Application.ReadWrite.All')
    )

    $GraphResource = 'https://graph.microsoft.com'
    $ScopeString = (($Scopes + 'offline_access') | Select-Object -Unique) -join ' '

    if (Get-Module -ListAvailable -Name 'Az.Accounts') {
        try {
            $AzContext = Get-AzContext -ErrorAction SilentlyContinue
            if (-not $AzContext) {
                Write-Info 'No existe sesion Azure activa. Iniciando autenticacion delegada para Microsoft Graph...'
                Connect-AzAccount -Tenant $TenantId -ErrorAction Stop | Out-Null
            }

            $TokenData = Get-AzAccessToken -TenantId $TenantId -ResourceUrl $GraphResource -ErrorAction Stop
            $AccessToken = if ($TokenData.Token -is [System.Security.SecureString]) {
                ConvertFrom-SecureStringToPlainText -SecureString $TokenData.Token
            }
            else {
                [string]$TokenData.Token
            }

            return @{
                AccessToken = $AccessToken
                Source      = 'Az.Accounts'
            }
        }
        catch {
            Write-Skip "No se pudo obtener token Graph via Az.Accounts: $($_.Exception.Message)"
        }
    }

    $PublicClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
    $DeviceCodeUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
    $TokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $DeviceCodeResponse = Invoke-RestMethod -Method Post -Uri $DeviceCodeUri -Body @{
        client_id = $PublicClientId
        scope     = $ScopeString
    } -ErrorAction Stop

    Write-Host ''
    Write-Host $DeviceCodeResponse.message -ForegroundColor Yellow

    $Elapsed = 0
    $Interval = [int]$DeviceCodeResponse.interval
    $ExpiresIn = [int]$DeviceCodeResponse.expires_in

    while ($Elapsed -lt $ExpiresIn) {
        Start-Sleep -Seconds $Interval
        $Elapsed += $Interval

        try {
            $TokenResponse = Invoke-RestMethod -Method Post -Uri $TokenUri -Body @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $PublicClientId
                device_code = $DeviceCodeResponse.device_code
            } -ErrorAction Stop

            return @{
                AccessToken = [string]$TokenResponse.access_token
                Source      = 'DeviceCode'
            }
        }
        catch {
            $GraphError = $null
            if ($_.ErrorDetails.Message) {
                try { $GraphError = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
            }

            if ($GraphError.error -eq 'authorization_pending') { continue }
            if ($GraphError.error -eq 'slow_down') {
                $Interval += 5
                continue
            }
            if ($GraphError.error -eq 'expired_token') {
                throw 'El codigo de dispositivo para Microsoft Graph expiro antes de completar el registro del certificado.'
            }

            throw
        }
    }

    throw 'Tiempo de espera agotado al solicitar token delegado para Microsoft Graph.'
}

function Invoke-GraphApiRequest {
    param(
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('GET','PATCH')][string]$Method = 'GET',
        [object]$Body
    )

    $Headers = @{ Authorization = "Bearer $AccessToken" }
    if ($Method -eq 'PATCH') {
        $Headers['Content-Type'] = 'application/json'
        return Invoke-RestMethod -Method Patch -Uri $Uri -Headers $Headers -Body ($Body | ConvertTo-Json -Depth 8 -Compress) -ErrorAction Stop
    }

    return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -ErrorAction Stop
}

function ConvertTo-GraphKeyCredential {
    param([Parameter(Mandatory)]$KeyCredential)

    $GraphKeyCredential = [ordered]@{}
    foreach ($Name in @('customKeyIdentifier','displayName','endDateTime','key','keyId','startDateTime','type','usage')) {
        $Value = $KeyCredential.$Name
        if ($null -ne $Value -and $Value -ne '') {
            $GraphKeyCredential[$Name] = $Value
        }
    }

    return $GraphKeyCredential
}

function Register-CertificateWithAppRegistration {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$PublicCertificatePath
    )

    $GraphToken = Get-GraphDelegatedAccessToken -TenantId $TenantId
    Write-Ok "Token delegado Microsoft Graph obtenido via $($GraphToken.Source)"

    $Filter = [System.Uri]::EscapeDataString("appId eq '$ClientId'")
    $SearchUri = "https://graph.microsoft.com/v1.0/applications?`$filter=$Filter&`$select=id,appId,displayName"
    $SearchResponse = Invoke-GraphApiRequest -AccessToken $GraphToken.AccessToken -Uri $SearchUri -Method GET

    if (-not $SearchResponse.value -or $SearchResponse.value.Count -eq 0) {
        throw "No se encontro Application Object para appId/clientId '$ClientId'."
    }

    $Application = @($SearchResponse.value)[0]
    $ApplicationUri = "https://graph.microsoft.com/v1.0/applications/$($Application.id)?`$select=id,appId,displayName,keyCredentials"
    $ApplicationDetail = Invoke-GraphApiRequest -AccessToken $GraphToken.AccessToken -Uri $ApplicationUri -Method GET

    $CertificateKey = [Convert]::ToBase64String($Certificate.RawData)
    $CertificateThumbprintBase64 = [Convert]::ToBase64String($Certificate.GetCertHash())
    $ExistingKeyCredentials = @($ApplicationDetail.keyCredentials)

    $AlreadyExists = $ExistingKeyCredentials | Where-Object {
        ($_.customKeyIdentifier -and $_.customKeyIdentifier -eq $CertificateThumbprintBase64) -or
        ($_.key -and $_.key -eq $CertificateKey)
    } | Select-Object -First 1

    if ($AlreadyExists) {
        return @{
            ApplicationObjectId = $Application.id
            ApplicationName     = $Application.displayName
            RegistrationMode    = 'AlreadyPresent'
        }
    }

    $MergedKeyCredentials = @()
    foreach ($ExistingKey in $ExistingKeyCredentials) {
        $MergedKeyCredentials += ,(ConvertTo-GraphKeyCredential -KeyCredential $ExistingKey)
    }

    $MergedKeyCredentials += ,([ordered]@{
        customKeyIdentifier = $CertificateThumbprintBase64
        displayName         = $Certificate.Subject
        endDateTime         = $Certificate.NotAfter.ToUniversalTime().ToString('o')
        key                 = $CertificateKey
        keyId               = ([guid]::NewGuid()).Guid
        startDateTime       = $Certificate.NotBefore.ToUniversalTime().ToString('o')
        type                = 'AsymmetricX509Cert'
        usage               = 'Verify'
    })

    Invoke-GraphApiRequest -AccessToken $GraphToken.AccessToken -Uri "https://graph.microsoft.com/v1.0/applications/$($Application.id)" -Method PATCH -Body @{
        keyCredentials = $MergedKeyCredentials
    } | Out-Null

    return @{
        ApplicationObjectId = $Application.id
        ApplicationName     = $Application.displayName
        RegistrationMode    = 'Added'
        PublicCertificate   = $PublicCertificatePath
    }
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
        throw "No se pudo obtener la clave privada RSA del certificado."
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

$TenantId = Normalize-InputValue (Read-Host "  Ingrese Tenant ID")
$ClientId = Normalize-InputValue (Read-Host "  Ingrese Client ID (App Registration)")

if (-not (Test-GuidLikeValue $TenantId)) {
    throw "Tenant ID inválido. Debe tener formato GUID, por ejemplo: 00000000-0000-0000-0000-000000000000"
}

if (-not (Test-GuidLikeValue $ClientId)) {
    throw "Client ID inválido. Debe tener formato GUID, por ejemplo: 00000000-0000-0000-0000-000000000000"
}

Write-Host ""
Write-Info "Metodos de autenticacion disponibles:"
Write-Host "    1. Client Secret  (Recomendado para ejecucion automatizada via Task Scheduler)" -ForegroundColor White
Write-Host "    2. Certificado existente (thumbprint ya cargado en App Registration)" -ForegroundColor White
Write-Host "    3. Certificado autofirmado (crear en este servidor y exportar .cer)" -ForegroundColor White
Write-Host "    4. Device Code    (Para testing manual o servidores sin browser)" -ForegroundColor White
Write-Host "    5. Interactivo    (Login browser popup, solo para ejecucion manual)" -ForegroundColor White
Write-Host "    6. Saltar         (Configurare las credenciales despues)" -ForegroundColor White

$AuthChoice = Read-Host "`n  Seleccione metodo [1-6]"

$AuthMode        = "DeviceCode"
$UseSecret       = $false
$UseCertificate  = $false
$SecretFile      = "$ConfigPath\ClientSecret.enc"
$CertThumbprint  = $null
$CertSubject     = $null
$CertPublicPath  = $null
$CertStoreLocation = $null
$CertProvisioningMode = $null
$CertAutoRegistration = $false
$CertAutoRegistrationStatus = $null
$AppObjectId = $null
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
    $CertThumbprint = ((Read-Host "  Ingrese la huella digital (Thumbprint) del certificado") -replace '\s','').ToUpperInvariant()

    # Validar que el certificado existe en CurrentUser/My o LocalMachine/My
    $CertFound = Get-CertificateByThumbprint -Thumbprint $CertThumbprint
    if (-not $CertFound) {
        throw "Certificado no encontrado. Verifique thumbprint y almacén (CurrentUser/My o LocalMachine/My)."
    }

    Write-Ok "Certificado encontrado: $($CertFound.Subject) (Expira: $($CertFound.NotAfter.ToString('yyyy-MM-dd')))"
    if ($CertFound.NotAfter -lt (Get-Date).AddDays(30)) {
        Write-Fail "ADVERTENCIA: El certificado expira en menos de 30 dias"
    }

    $CertSubject = $CertFound.Subject
    $CertStoreLocation = 'Cert:\CurrentUser\My'
    $CertProvisioningMode = 'Existing'

    $ExportExistingCer = Read-Host "  Exportar .cer publico para App Registration? [S/n]"
    if ($ExportExistingCer -notin @('n','N')) {
        $DefaultExistingCerPath = Join-Path $ConfigPath "DefenderXDR-ExistingCertificate.cer"
        $RequestedExistingCerPath = Read-Host "  Ruta para exportar el .cer publico [default: $DefaultExistingCerPath]"
        if ([string]::IsNullOrWhiteSpace($RequestedExistingCerPath)) {
            $RequestedExistingCerPath = $DefaultExistingCerPath
        }
        $CertPublicPath = Export-PublicCertificateFile -Certificate $CertFound -OutputPath $RequestedExistingCerPath
        Write-Ok ".cer publico exportado: $CertPublicPath"
    }

    $AuthMode       = "Certificate"
    $UseCertificate = $true
}
elseif ($AuthChoice -eq "3") {
    Write-Info "Creando certificado autofirmado para App Registration..."

    $DefaultSubject = "CN=DefenderXDRReports-$env:COMPUTERNAME"
    $RequestedSubject = Read-Host "  Subject del certificado [default: $DefaultSubject]"
    if ([string]::IsNullOrWhiteSpace($RequestedSubject)) {
        $RequestedSubject = $DefaultSubject
    }

    $RequestedYears = Read-Host "  Validez en años [default: 2]"
    $ValidYears = 2
    if ($RequestedYears -and ($RequestedYears -as [int]) -ge 1) {
        $ValidYears = [int]$RequestedYears
    }

    $CertStoreLocation = 'Cert:\CurrentUser\My'
    $FriendlyName = "Defender XDR Report Server - $env:COMPUTERNAME"
    $DefaultCerPath = Join-Path $ConfigPath "DefenderXDR-AppRegistration.cer"
    $RequestedCerPath = Read-Host "  Ruta para exportar el .cer publico [default: $DefaultCerPath]"
    if ([string]::IsNullOrWhiteSpace($RequestedCerPath)) {
        $RequestedCerPath = $DefaultCerPath
    }

    $CreatedCert = New-SelfSignedCertificateForAppAuth `
        -Subject $RequestedSubject `
        -FriendlyName $FriendlyName `
        -CertStoreLocation $CertStoreLocation `
        -ValidYears $ValidYears

    $CertPublicPath = Export-PublicCertificateFile -Certificate $CreatedCert -OutputPath $RequestedCerPath
    $CertThumbprint = $CreatedCert.Thumbprint
    $CertSubject = $CreatedCert.Subject
    $CertProvisioningMode = 'SelfSigned'

    Write-Ok "Certificado autofirmado creado: $CertSubject"
    Write-Ok "Thumbprint: $CertThumbprint"
    Write-Ok "Expira: $($CreatedCert.NotAfter.ToString('yyyy-MM-dd'))"
    Write-Ok ".cer publico exportado: $CertPublicPath"
    Write-Host "    Cargue este .cer en Entra ID > App registrations > Certificates & secrets > Upload certificate." -ForegroundColor DarkYellow
    Write-Host "    La tarea programada usara este thumbprint automaticamente desde el store CurrentUser\\My." -ForegroundColor DarkYellow

    $AuthMode       = "Certificate"
    $UseCertificate = $true
}
elseif ($AuthChoice -eq "4") {
    $AuthMode = "DeviceCode"
    Write-Skip "Usara Device Code para autenticacion"
    Write-Host "    El reporte diario requiere Az.Accounts o ClientId+TenantId (fallback REST)" -ForegroundColor DarkYellow
}
elseif ($AuthChoice -eq "5") {
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
}

if ($UseCertificate) {
    $RegisterAutomatically = Read-Host "`n  Registrar automaticamente el certificado en App Registration via Microsoft Graph? [s/N]"
    if ($RegisterAutomatically -in @('s','S')) {
        try {
            $HasAzAccounts = Ensure-AzAccountsModule
            if ($HasAzAccounts) {
                Write-Ok 'Se utilizara Az.Accounts como metodo preferido para obtener el token de Microsoft Graph.'
            }
            else {
                Write-Skip 'Se continuara con fallback Device Code para Microsoft Graph.'
            }

            $CertificateForRegistration = Get-CertificateByThumbprint -Thumbprint $CertThumbprint
            if (-not $CertificateForRegistration) {
                throw "No se encontro el certificado '$CertThumbprint' para registrar en App Registration."
            }

            Write-Info 'Registrando certificado en App Registration usando Microsoft Graph...'
            $GraphRegistration = Register-CertificateWithAppRegistration -TenantId $TenantId -ClientId $ClientId -Certificate $CertificateForRegistration -PublicCertificatePath $CertPublicPath

            $AppObjectId = $GraphRegistration.ApplicationObjectId
            $CertAutoRegistration = $true
            $CertAutoRegistrationStatus = $GraphRegistration.RegistrationMode

            if ($GraphRegistration.RegistrationMode -eq 'AlreadyPresent') {
                Write-Skip "El certificado ya estaba registrado en la App Registration '$($GraphRegistration.ApplicationName)'."
            }
            else {
                Write-Ok "Certificado registrado en la App Registration '$($GraphRegistration.ApplicationName)' (ObjectId: $($GraphRegistration.ApplicationObjectId))"
            }
        }
        catch {
            Write-Fail "No se pudo registrar automaticamente el certificado: $($_.Exception.Message)"
            Write-Host '    Permisos requeridos en contexto delegado: Application.ReadWrite.All y rol Application Administrator o Application Developer.' -ForegroundColor DarkYellow
            Write-Host '    Puede continuar y cargar manualmente el .cer si lo prefiere.' -ForegroundColor DarkYellow
        }
    }
}

# Mostrar resumen enmascarado
Write-Host ""
Write-Info "Resumen de credenciales (enmascarado):"
Write-Host "    Tenant ID   : $(Mask-String $TenantId)" -ForegroundColor White
Write-Host "    Client ID   : $(Mask-String $ClientId)" -ForegroundColor White
Write-Host "    Secret      : $(if ($UseSecret) {'********'} else {'(no configurado)'})" -ForegroundColor White
Write-Host "    Certificado : $(if ($UseCertificate) { Mask-String $CertThumbprint } else { '(no configurado)' })" -ForegroundColor White
Write-Host "    Cert Subject: $(if ($UseCertificate -and $CertSubject) { $CertSubject } else { '(no configurado)' })" -ForegroundColor White
Write-Host "    Cert .cer   : $(if ($UseCertificate -and $CertPublicPath) { $CertPublicPath } else { '(no configurado)' })" -ForegroundColor White
Write-Host "    Cert Graph  : $(if ($UseCertificate -and $CertAutoRegistrationStatus) { $CertAutoRegistrationStatus } else { '(sin registro automatico)' })" -ForegroundColor White
Write-Host "    Auth Mode   : $AuthMode" -ForegroundColor White

# ============================================================
#  PASO 3: Guardar configuracion
# ============================================================

Write-Step "3/9" "Guardando configuracion..."

# Determinar AuthMode efectivo para cada script
# Daily y Weekly soportan Secret, Interactive, DeviceCode y Certificate.
$DailyAuthMode = $AuthMode

$WeeklyAuthMode = $AuthMode

$Config = @{
    TenantId        = $TenantId
    ClientId        = $ClientId
    AuthMode        = $AuthMode
    DailyAuthMode   = $DailyAuthMode
    WeeklyAuthMode  = $WeeklyAuthMode
    SecretFile      = if ($UseSecret) { $SecretFile } else { $null }
    CertThumbprint  = if ($UseCertificate) { $CertThumbprint } else { $null }
    CertSubject     = if ($UseCertificate) { $CertSubject } else { $null }
    CertPublicPath  = if ($UseCertificate) { $CertPublicPath } else { $null }
    CertStoreLocation = if ($UseCertificate) { $CertStoreLocation } else { $null }
    CertProvisioningMode = if ($UseCertificate) { $CertProvisioningMode } else { $null }
    CertAutoRegistration = if ($UseCertificate) { $CertAutoRegistration } else { $false }
    CertAutoRegistrationStatus = if ($UseCertificate) { $CertAutoRegistrationStatus } else { $null }
    AppObjectId     = $AppObjectId
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
            $AccessToken = $null

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
                # Validar con Certificado usando client_assertion (misma estrategia que scripts de reporte)
                $Cert = Get-CertificateByThumbprint -Thumbprint $CertThumbprint
                if (-not $Cert) {
                    throw "Certificado no encontrado para validacion. Thumbprint: $CertThumbprint"
                }

                $ClientAssertion = New-ClientAssertionJwt -Certificate $Cert -ClientId $ClientId -TenantId $TenantId
                $Body = @{
                    grant_type            = 'client_credentials'
                    client_id             = $ClientId
                    scope                 = 'https://api.security.microsoft.com/.default'
                    client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                    client_assertion      = $ClientAssertion
                }
                $TokenResponse = Invoke-RestMethod -Method Post -Uri $AuthUri -Body $Body -ErrorAction Stop
                Write-Ok "Autenticacion con Certificado exitosa"
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
            if ($_.ErrorDetails.Message -match 'AADSTS700027') {
                Write-Host "    AADSTS700027: El certificado no esta registrado en la App Registration." -ForegroundColor DarkYellow
                if ($Config.CertPublicPath) {
                    Write-Host "    Cargue el .cer generado en: $($Config.CertPublicPath)" -ForegroundColor DarkYellow
                }
                Write-Host "    Entra ID > App registrations > Certificates & secrets > Upload certificate." -ForegroundColor DarkYellow
            }
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
$RawRepoBaseUrl = Get-GitHubRawBaseUrl -SourceDir $SourceDir -OverrideUrl $RepositoryRawBaseUrl

$ScriptsToCopy = @(
    "New-DefenderXDRDailyReport.ps1",
    "New-DefenderXDRWeeklyReport.ps1"
)

foreach ($Script in $ScriptsToCopy) {
    $Source = Join-Path $SourceDir $Script
    $Dest   = Join-Path $ScriptsPath $Script
    $DestExists = Test-Path $Dest

    if (($Source -eq $Dest) -and $DestExists) {
        Write-Skip "$Script ya esta en la ruta destino"
    }
    elseif (Test-Path $Source) {
        Copy-Item $Source -Destination $Dest -Force
        Write-Ok "Copiado: $Script -> $ScriptsPath"
    }
    else {
        $DownloadUrl = Get-RepositoryScriptUrl -ScriptName $Script -RawBaseUrl $RawRepoBaseUrl
        if ($DownloadUrl) {
            try {
                Write-Info "No encontrado localmente. Descargando desde repositorio: $DownloadUrl"
                Invoke-WebRequest -Uri $DownloadUrl -OutFile $Dest -UseBasicParsing -ErrorAction Stop
                Write-Ok "Descargado: $Script -> $Dest"
            }
            catch {
                Write-Fail "No se pudo descargar $Script desde el repositorio: $($_.Exception.Message)"
                Write-Host "    URL intentada: $DownloadUrl" -ForegroundColor DarkYellow
                Write-Host "    Puede definir -RepositoryRawBaseUrl manualmente." -ForegroundColor DarkYellow
            }
        }
        else {
            Write-Fail "No encontrado: $Source"
            Write-Host "    No se detecto URL de repositorio (remote.origin.url)." -ForegroundColor DarkYellow
            Write-Host "    Puede definir -RepositoryRawBaseUrl y reintentar." -ForegroundColor DarkYellow
        }
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
`$Config.TenantId = if (`$Config.TenantId) { [string]`$Config.TenantId.Trim() } else { `$Config.TenantId }
`$Config.ClientId = if (`$Config.ClientId) { [string]`$Config.ClientId.Trim() } else { `$Config.ClientId }
`$Config.CertThumbprint = if (`$Config.CertThumbprint) { ([string]`$Config.CertThumbprint -replace '\s','').ToUpperInvariant() } else { `$Config.CertThumbprint }

if (`$Config.TenantId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    Write-Error "TenantId inválido en config.json: `$(`$Config.TenantId)"
    exit 1
}

if (`$Config.ClientId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    Write-Error "ClientId inválido en config.json: `$(`$Config.ClientId)"
    exit 1
}

`$OutputDir = Join-Path `$Config.ReportsPath "Daily"
if (-not (Test-Path `$OutputDir)) { New-Item -ItemType Directory -Path `$OutputDir -Force | Out-Null }

# Determinar AuthMode para el Daily
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
`$Params = @{
    TenantId        = `$Config.TenantId
    ClientId        = `$Config.ClientId
    AuthMode        = `$DailyAuth
    TimeWindowHours = 24
    OutputPath      = Join-Path `$OutputDir "Daily_SecOps_Report_`$(Get-Date -Format 'yyyyMMdd').html"
    TimeoutSec      = 120
}

if (`$ClientSecretPlain) { `$Params['ClientSecret'] = `$ClientSecretPlain }

if (`$DailyAuth -eq "Certificate" -and `$Config.CertThumbprint) {
    `$Params['CertificateThumbprint'] = `$Config.CertThumbprint
}

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
`$Config.TenantId = if (`$Config.TenantId) { [string]`$Config.TenantId.Trim() } else { `$Config.TenantId }
`$Config.ClientId = if (`$Config.ClientId) { [string]`$Config.ClientId.Trim() } else { `$Config.ClientId }
`$Config.CertThumbprint = if (`$Config.CertThumbprint) { ([string]`$Config.CertThumbprint -replace '\s','').ToUpperInvariant() } else { `$Config.CertThumbprint }

if (`$Config.TenantId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    Write-Error "TenantId inválido en config.json: `$(`$Config.TenantId)"
    exit 1
}

if (`$Config.ClientId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    Write-Error "ClientId inválido en config.json: `$(`$Config.ClientId)"
    exit 1
}

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
`$Params = @{
    TenantId       = `$Config.TenantId
    ClientId       = `$Config.ClientId
    AuthMode       = `$WeeklyAuth
    TimeWindowDays = 7
    OutputPath     = Join-Path `$OutputDir "Weekly_SecOps_Report_`$(Get-Date -Format 'yyyyMMdd').html"
    LogPath        = Join-Path `$LogDir "DefenderXDR_Weekly_`$(Get-Date -Format 'yyyyMMdd').log"
    TimeoutSec     = 120
    ExportCsv      = `$true
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
elseif ($AuthMode -eq "Interactive") {
    Write-Fail "Tareas programadas NO compatibles con modo Interactive (requiere browser)."
    Write-Host "    Cambie a Client Secret o Certificado para automatizacion." -ForegroundColor DarkYellow
    Write-Skip "Creacion de tareas omitida automaticamente"
}
else {
    $CreateTasks = Read-Host "  Crear tareas programadas? [S/n]"

    if ($CreateTasks -notin @("n", "N")) {

        $TaskDefs = @(
            @{
                Name    = "DefenderXDR-DailyReport"
                Script  = $DailyWrapperPath
                Trigger = { New-ScheduledTaskTrigger -Daily -At 7am }
                Desc    = "Reporte diario de seguridad - Defender XDR (Daily 7:00 AM) [Auth: $DailyAuthMode]"
            },
            @{
                Name    = "DefenderXDR-WeeklyReport"
                Script  = $WeeklyWrapperPath
                Trigger = { New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "7:30AM" }
                Desc    = "Reporte semanal de seguridad - Defender XDR (Lunes 7:30 AM) [Auth: $WeeklyAuthMode]"
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
        Write-Info "Ejecutando prueba con ventana de 1 hora (resultados minimos)..."
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
    Write-Host "    Certificado  : $CertThumbprint (CurrentUser/My o LocalMachine/My)"
    if ($Config.CertSubject) {
        Write-Host "    Subject      : $($Config.CertSubject)"
    }
    if ($Config.CertPublicPath) {
        Write-Host "    .cer publico : $($Config.CertPublicPath)"
    }
    if ($Config.CertAutoRegistrationStatus) {
        Write-Host "    Graph        : $($Config.CertAutoRegistrationStatus)"
    }
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

if ($UseCertificate -and $Config.CertPublicPath) {
    Write-Host "`n  Registro de certificado en App Registration:" -ForegroundColor Yellow
    if ($Config.CertAutoRegistrationStatus -eq 'Added' -or $Config.CertAutoRegistrationStatus -eq 'AlreadyPresent') {
        Write-Host "    El certificado ya esta registrado en Microsoft Graph para la App Registration." -ForegroundColor White
        if ($Config.AppObjectId) {
            Write-Host "    Application Object Id: $($Config.AppObjectId)" -ForegroundColor White
        }
        Write-Host "    Las tareas programadas usaran el thumbprint $($Config.CertThumbprint)" -ForegroundColor White
    }
    else {
        Write-Host "    1. Abra Entra ID > App registrations > $ClientId" -ForegroundColor White
        Write-Host "    2. Entre a Certificates & secrets > Certificates" -ForegroundColor White
        Write-Host "    3. Upload certificate: $($Config.CertPublicPath)" -ForegroundColor White
        Write-Host "    4. Espere propagacion y luego re-ejecute la validacion si fue omitida" -ForegroundColor White
        Write-Host "    5. Las tareas programadas usaran el thumbprint $($Config.CertThumbprint)" -ForegroundColor White
    }
}

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
