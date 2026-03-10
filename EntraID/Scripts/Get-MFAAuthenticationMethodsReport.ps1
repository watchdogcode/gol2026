[CmdletBinding()]
param(
    [ValidateSet('Commercial', 'USGovGCC', 'USGovGCCHigh', 'USGovDoD', 'China')]
    [string]$CloudEnvironment = 'Commercial',

    [string]$OutputFolder = 'C:\Scripts\EntraID',

    [string]$CsvFileName
)

function Get-GraphEnvironmentName {
    param([string]$Environment)

    switch ($Environment) {
        'Commercial' { 'Global' }
        'USGovGCC' { 'Global' }
        'USGovGCCHigh' { 'USGov' }
        'USGovDoD' { 'USGovDoD' }
        'China' { 'China' }
        default { 'Global' }
    }
}

function Get-FriendlyAuthMethod {
    param([object]$MethodObject)

    $typeName = $MethodObject.'@odata.type'

    switch ($typeName) {
        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' { 'Microsoft Authenticator' }
        '#microsoft.graph.softwareOathAuthenticationMethod' { 'Software OATH Token' }
        '#microsoft.graph.phoneAuthenticationMethod' {
            if ($MethodObject.phoneType) {
                "Phone ($($MethodObject.phoneType))"
            }
            else {
                'Phone'
            }
        }
        '#microsoft.graph.fido2AuthenticationMethod' { 'FIDO2 Security Key' }
        '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' { 'Windows Hello for Business' }
        '#microsoft.graph.emailAuthenticationMethod' { 'Email OTP' }
        '#microsoft.graph.temporaryAccessPassAuthenticationMethod' { 'Temporary Access Pass' }
        '#microsoft.graph.passwordAuthenticationMethod' { 'Password' }
        '#microsoft.graph.platformCredentialAuthenticationMethod' { 'Passkey (Platform Credential)' }
        '#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod' { 'Authenticator Phone Sign-In' }
        default {
            if ($typeName) {
                ($typeName -replace '^#microsoft.graph\.', '')
            }
            else {
                'Unknown'
            }
        }
    }
}

function Get-UsersFromGraph {
    $allUsers = @()
    $nextUri = '/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled&$top=999'

    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri -OutputType PSObject
        if ($response.value) {
            $allUsers += $response.value
        }
        $nextUri = $response.'@odata.nextLink'
    }
    while ($nextUri)

    return $allUsers
}

$requiredScopes = @(
    'User.Read.All',
    'UserAuthenticationMethod.Read.All'
)

$graphEnvironment = Get-GraphEnvironmentName -Environment $CloudEnvironment

if (-not (Get-MgContext)) {
    Connect-MgGraph -ContextScope CurrentUser -Environment $graphEnvironment -Scopes $requiredScopes -NoWelcome
}
else {
    $missingScopes = @($requiredScopes | Where-Object { (Get-MgContext).Scopes -notcontains $_ })
    if ($missingScopes.Count -gt 0) {
        Connect-MgGraph -ContextScope CurrentUser -Environment $graphEnvironment -Scopes $requiredScopes -NoWelcome
    }
}

if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

if (-not $CsvFileName) {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $CsvFileName = "EntraID-MFAAuthenticationMethods_$timestamp.csv"
}

$csvPath = Join-Path -Path $OutputFolder -ChildPath $CsvFileName

Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Obteniendo usuarios del tenant..." -ForegroundColor Cyan
$users = Get-UsersFromGraph

$methodUserCounter = @{}
$results = @()
$totalUsers = $users.Count
$processed = 0

foreach ($user in $users) {
    $processed++
    Write-Progress -Activity 'Analizando métodos MFA' -Status "Procesando $processed de ${totalUsers}: $($user.userPrincipalName)" -PercentComplete (($processed / [Math]::Max($totalUsers, 1)) * 100)

    $defaultMethod = 'No definido'
    $registeredMethods = @()

    try {
        $methodsResponse = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/users/$($user.id)/authentication/methods" -OutputType PSObject
        if ($methodsResponse.value) {
            $registeredMethods = @($methodsResponse.value | ForEach-Object { Get-FriendlyAuthMethod -MethodObject $_ })
        }
    }
    catch {
        $registeredMethods = @('Error al leer métodos')
    }

    try {
        $signInPreferences = Invoke-MgGraphRequest -Method GET -Uri "/beta/users/$($user.id)/authentication/signInPreferences" -OutputType PSObject
        if ($signInPreferences.isSystemPreferredAuthenticationMethodEnabled -and $signInPreferences.systemPreferredAuthenticationMethod) {
            $defaultMethod = "SystemPreferred:$($signInPreferences.systemPreferredAuthenticationMethod)"
        }
        elseif ($signInPreferences.userPreferredMethodForSecondaryAuthentication) {
            $defaultMethod = $signInPreferences.userPreferredMethodForSecondaryAuthentication
        }
    }
    catch {
        $defaultMethod = 'No disponible'
    }

    $uniqueMethodsForUser = @($registeredMethods | Where-Object { $_ -and $_ -ne 'Error al leer métodos' } | Sort-Object -Unique)

    if ($uniqueMethodsForUser.Count -eq 0) {
        $uniqueMethodsForUser = @('Sin métodos registrados')
    }

    foreach ($method in $uniqueMethodsForUser) {
        if ($methodUserCounter.ContainsKey($method)) {
            $methodUserCounter[$method]++
        }
        else {
            $methodUserCounter[$method] = 1
        }
    }

    $results += [PSCustomObject]@{
        DisplayName                     = $user.displayName
        UserPrincipalName               = $user.userPrincipalName
        AccountEnabled                  = $user.accountEnabled
        DefaultAuthenticationMethod     = $defaultMethod
        RegisteredAuthenticationMethods = ($uniqueMethodsForUser -join '; ')
    }
}

Write-Progress -Activity 'Analizando métodos MFA' -Completed

$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$sortedSummary = $methodUserCounter.GetEnumerator() | Sort-Object Value -Descending

Write-Host ''
Write-Host '==================== Resumen MFA ====================' -ForegroundColor Yellow
Write-Host ("Usuarios revisados: {0}" -f $totalUsers)
foreach ($item in $sortedSummary) {
    Write-Host ("{0}: {1}" -f $item.Key, $item.Value)
}
Write-Host ("CSV generado: {0}" -f $csvPath) -ForegroundColor Green

$summaryObject = [PSCustomObject]@{
    TotalUsersReviewed = $totalUsers
    MethodBreakdown    = @($sortedSummary | ForEach-Object { "{0}={1}" -f $_.Key, $_.Value }) -join '; '
    CsvPath            = $csvPath
}

$summaryObject
