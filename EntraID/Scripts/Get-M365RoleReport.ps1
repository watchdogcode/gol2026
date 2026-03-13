############################################################################
#This sample script is not supported under any Microsoft standard support program or service.
#This sample script is provided AS IS without warranty of any kind.
#Microsoft further disclaims all implied warranties including, without limitation, any implied
#warranties of merchantability or of fitness for a particular purpose. The entire risk arising
#out of the use or performance of the sample script and documentation remains with you. In no
#event shall Microsoft, its authors, or anyone else involved in the creation, production, or
#delivery of the scripts be liable for any damages whatsoever (including, without limitation,
#damages for loss of business profits, business interruption, loss of business information,
#or other pecuniary loss) arising out of the use of or inability to use the sample script or
#documentation, even if Microsoft has been advised of the possibility of such damages.
############################################################################

#Requires -Version 4

<#
	.SYNOPSIS
		Microsoft 365 Administrative Role Report

	.DESCRIPTION
		Enumerates members of administrative roles in Entra ID, Security & Compliance, and Exchange Online.
	.PARAMETER PasswordAgeThreshold
		Passwords older than this age (in days) are highlighted in red.  Default is 365 days.
	.PARAMETER SkipWorkload
		Provide one or more workloads (comma-separated or array) to skip.  Valid values are EntraID, SCC, EXO.
    .PARAMETER CloudEnvironment
        Cloud instance of the tenant. Possible values are Commercial, USGovGCC, USGovGCCHigh, USGovDoD, and China.
        Default value is Commercial.		
	.PARAMETER AdminUPN
		UPN of account to use when connecting to Exchange and SCC.  Helps to avoid unnecessary auth
		prompts if you have connected with the account before.
	.PARAMETER IgnoredRoles
		Array of roles to exclude from the report.  Default is Entra role of "Directory Synchronization Accounts".
		For Entra, use the display name of the role. For EXO and SCC, you can ignore role groups by display name.
	.PARAMETER Output
		Path and filename of the report.  Default is M365RoleReport.html in the current directory.
	.NOTES
        Modified from original script by Ernesto Cobos Roqueñí (erenstocrmsft)
        Version 1.1
        March 13, 2026

    .ORIGINAL_SOURCE
    https://github.com/o365soa/Scripts
		
		This script uses Bootstrap to format the report. For more information https://www.getbootstrap.com/

#>

[CmdletBinding()]
Param(
    [Int16]$PasswordAgeThreshold=365,
    $IgnoredRoles=@("Directory Synchronization Accounts"),
	[ValidateSet('EntraID','SCC','EXO')]$SkipWorkload,
	[ValidateSet("Commercial", "USGovGCC", "USGovGCCHigh", "USGovDoD", "China")][string]$CloudEnvironment="Commercial",
	[string]$AdminUPN
)

# ─────────────────────────────────────────────
# Validación de módulos requeridos
# ─────────────────────────────────────────────
$requiredModules = @(
    @{ Name = 'Microsoft.Graph.Authentication'; MinVersion = '2.0.0' },
    @{ Name = 'ExchangeOnlineManagement';       MinVersion = $null }
)

foreach ($mod in $requiredModules) {
    $installed = if ($mod.MinVersion) {
        Get-Module -ListAvailable -Name $mod.Name | Where-Object { $_.Version -ge [version]$mod.MinVersion }
    } else {
        Get-Module -ListAvailable -Name $mod.Name
    }

    if ($installed) {
        $ver = ($installed | Sort-Object Version -Descending | Select-Object -First 1).Version
        Write-Host "Módulo $($mod.Name) v$ver instalado correctamente." -ForegroundColor DarkGray
    }
    else {
        Write-Host "[X] Módulo $($mod.Name) no encontrado$(if ($mod.MinVersion) { " (mínimo v$($mod.MinVersion))" })." -ForegroundColor Red
        $respuesta = Read-Host "    ¿Deseas instalar el módulo $($mod.Name)? (S/N)"
        if ($respuesta -match '^[Ss]$') {
            Write-Host "    Descargando e instalando $($mod.Name)..." -ForegroundColor Yellow
            try {
                Install-Module -Name $mod.Name -Force -Scope CurrentUser -ErrorAction Stop
                Write-Host "    Módulo $($mod.Name) instalado exitosamente." -ForegroundColor Green
            }
            catch {
                Write-Host "    [X] Error al instalar $($mod.Name): $($_.Exception.Message)" -ForegroundColor Red
                return
            }
        }
        else {
            Write-Host "    Instalación cancelada. El script requiere $($mod.Name) para continuar." -ForegroundColor Yellow
            return
        }
    }
}

# ─────────────────────────────────────────────
# Carpeta de reportes
# ─────────────────────────────────────────────
$reportDir = "C:\Scripts\EntraID"
if (-not (Test-Path $reportDir)) {
    New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
    Write-Host "Carpeta creada: $reportDir" -ForegroundColor DarkGray
}
else {
    Write-Host "Carpeta de reportes existe: $reportDir" -ForegroundColor DarkGray
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$htmlPath  = Join-Path $reportDir "M365RoleReport_$timestamp.html"

function Get-UserDetails ($id) {
	# Use cached object if user has already been retrieved
	if ($objectDetails.ContainsKey($id)) {
		Write-Verbose -Message "User $id has previoulsy been retrieved. Using cached details."
		return $objectDetails[$id]
	}
	$dirObject = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/directoryObjects/$($id)?`$select=id,displayName" -OutputType PSObject
	if ($dirObject."@odata.type" -eq "#microsoft.graph.user") {
		$user = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/users/$($id)?`$select=userPrincipalName,accountEnabled,lastPasswordChangeDateTime,onPremisesImmutableId" -OutputType PSObject
		$signInName = $user.userPrincipalName
		if ($user.accountEnabled -eq $true) {
			$accountState = "Enabled"
		} else {
			$accountState = "Disabled"
		}

		# Determine password age
		$passwordAge = ((Get-Date) - [datetime]$user.lastPasswordChangeDateTime).Days

		# Determine default MFA method
		$signInPreferences = Invoke-MgGraphRequest -Method GET -Uri "/beta/users/$id/authentication/signInPreferences"
		if ($signInPreferences.isSystemPreferredAuthenticationMethodEnabled -eq $true) {
			$defaultMethod = $signInPreferences.systemPreferredAuthenticationMethod
		} else {
			$defaultMethod = $signInPreferences.userPreferredMethodForSecondaryAuthentication
		}

		# Get per-user MFA state
		$authRequirements = Invoke-MgGraphRequest -Method GET -Uri "/beta/users/$id/authentication/requirements"
		$mfaState = $authRequirements.perUserMfaState

		# MFA Phone Number
		$authMethods = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/users/$id/authentication/methods" -OutputType PSObject
		$mfaPhone = ($authMethods.value | Where-Object {$_.id -eq '3179e48a-750b-4051-897c-87b9720928f7'}).phoneNumber

		# Determine if cloud/synced user
		if ($null -eq $user.onPremisesImmutableId) {
			$type = "Cloud"
		} else {
			$type = "Synced"
		}
	} elseif ($dirObject."@odata.type" -eq "#microsoft.graph.servicePrincipal") {
		$signInName = "$($dirObject.displayName) (Service principal)" 
		$type = 'Cloud'
		$accountState = $null
	} else {
		$signInName = "$id (Unknown type)"
		$accountState = $null
	}
	
	$details = New-Object -TypeName PSObject -Property @{
        SignInName = $signInName
		AccountState = $accountState
        PasswordAge = $passwordAge
        MFADefault = $defaultMethod
        MFAPhone = $mfaPhone
        MFAState = $mfaState
        UserType = $type
    }
	$script:objectDetails.Add($id,$details)
	return $details
}

function Get-ExoRoleGroupMembers {
	param (
		$roleGroup,
		$roleName,
		$parentGroupName
	)
	$rgm = Get-RoleGroupMember -Identity $roleGroup.Identity
	$members = @()
	foreach ($gMember in $rgm) {
		if ($gMember.RecipientType -eq 'Group') {
			# Member is Exchange role group
			if ($parentGroupName) {
				Write-Verbose -Message "Nested role group of $parentGroupName in $roleName role group: $($gMember.Name)"
			}
			else {
				Write-Verbose -Message "Role group in $roleName role group: $($gMember.Name)"
			}
			$members += Get-ExoRoleGroupMembers -roleGroup $gMember -roleName $roleName -parentGroup $gMember.Name
		}
		elseif ($rgm.RecipientType -eq 'MailUniversalSecurityGroup') {
			# Member is Security DL
			if ($parentGroupName) {
				Write-Verbose -Message "Nested mail-enabled security group of $parentGroupName in $roleName role group: $($gMember.Name)"
			}
			else {
				Write-Verbose -Message "Mail-enabled security group in $roleName role group: $($gMember.Name)"				
			}
			$members += Get-ExoSecurityGroupMembers -group $gMember -roleName $roleName -parentGroupName $gMember.Name
		}
		else {
			# Member is individual
			if ($parentGroupName) {
				Write-Verbose -Message "User in role group $parentGroupName assigned roles of $roleName role group: $($gMember.Name) ($($gMember.WindowsLiveId))"
				$pgName = $parentGroupName + "\"
			}
			else {
				Write-Verbose -Message "User assigned roles of $roleName role group: $($gMember.Name) ($($gMember.WindowsLiveId))"
				$pgName = ""
			}
			$members += New-Object -TypeName PSObject -Property @{
				Id = $gMember.ExternalDirectoryObjectId
				ParentGroup = $pgName
			}
		}
	}
	return $members
}

function Get-ExoSecurityGroupMembers {
	param (
		$group,
		$roleName,
		$parentGroupName
	)
	$sgm = Get-DistributionGroupMember -Identity $group.Identity
	$members = @()
	foreach ($gMember in $sgm) {
		if ($gMember.RecipientType -like "*Group") {
			# Member is security group
			if ($parentGroupName) {
				Write-Verbose -Message "Nested security group of $parentGroupName in $roleName role group: $($gMember.Name)"
			}
			else {
				Write-Verbose -Message "Security group in $roleName role group: $($gMember.Name)"
			}
			$members += Get-ExoSecurityGroupMembers -group $gMember -roleName $roleName -parentGroupName $gMember.Name
		}
		else {
			# Member is individual
			if ($parentGroupName) {
				Write-Verbose -Message "User in security group $parentGroupName assigned roles of $roleName role group: $($gMember.Name) ($($gMember.WindowsLiveId))"
				$pgName = $parentGroupName + "\"
			}
			else {
				Write-Verbose -Message "User assigned roles of $roleName role group: $($gMember.Name) ($($gMember.WindowsLiveId))"
				$pgName = ""
			}
			$members += New-Object -TypeName PSObject -Property @{
				Id = $gMember.ExternalDirectoryObjectId
				ParentGroup = $pgName
			}
		}
	}
	return $members
}

$workLoads = @()
if ($SkipWorkload -notcontains 'EntraID') {$workLoads += 'EntraID'}
if ($SkipWorkload -notcontains 'SCC') {$workLoads += 'SCC'}
if ($SkipWorkload -notcontains 'EXO') {$workLoads += 'EXO'}

if ($SkipWorkload -contains 'EntraID' -and $SkipWorkload -contains 'SCC' -and $SkipWorkload -contains 'EXO') {
	Write-Error -Message 'At least one workload must not be excluded.'
	exit
}

# Directory.Read.All = Least common scope for Users and DirectoryObjects APIs
# UserAuthenticationMethod.Read.All = Scope for Authentication Methods, Sign-In Preferences, and System-Preferred MFA Method APIs. Must also have Entra role of either Global Reader or Authentication Administrator or Privileged Authentication Administrator
# Policy.Read.All = Scope for Authentication Requirements API. Must also have Entra role of either Global Reader or Authentication Policy Administrator
# RoleManagement.Read.Directory = Scope for Role Definitions and Role Assignments APIs. Must also have Entra role of User Administrator or higher
# GroupMember.Read.All = Scope for Group Membership API. Must also have Entra role of User Administrator or higher
$requiredScopes = @('Directory.Read.All','UserAuthenticationMethod.Read.All','Policy.Read.All')
if ($SkipWorkload -notcontains 'EntraID') {
	$requiredScopes += @('RoleManagement.Read.Directory')
}
if ($SkipWorkload -notcontains 'SCC') {
	$requiredScopes += @('GroupMember.Read.All')
}
$currentScopes = (Get-MgContext).Scopes
if ($currentScopes) {
	foreach ($scope in $requiredScopes) {
		if ($currentScopes -notcontains $scope) {
			$scopeNeeded = $true
			break
		}
	}
}
if ($scopeNeeded -or -not $currentScopes) {
	# Always connect to Graph (if not already with needed scopes) to get user details
	switch ($CloudEnvironment) {
		"Commercial"   {$cloud = "Global"}
		"USGovGCC"     {$cloud = "Global"}
		"USGovGCCHigh" {$cloud = "USGov"}
		"USGovDoD"     {$cloud = "USGovDoD"}
		"China"        {$cloud = "China"}            
	}
	Write-Host -ForegroundColor Green "$(Get-Date) Connecting to Microsoft Graph..."
	Connect-MgGraph -ContextScope Process -Scopes $requiredScopes -Environment $cloud -NoWelcome
}

# Connect to SCC if not skipped, if necessary
# Prefix is used to support connecting to SCC and EXO at the same time
if ($SkipWorkload -notcontains 'SCC') {
	if (-not(Get-Command -Name Get-SCCRoleGroup -ErrorAction SilentlyContinue)) {
		Write-Host 'Connecting to Security & Compliance Center...'
		if (-not $AdminUPN) {
			do {
				$AdminUPN = Read-Host -Prompt "Enter the UPN of the admin account that will be used to sign in"
			}
			until ($AdminUPN -match "^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")
			Write-Host ""
		}
		switch ($CloudEnvironment) {
			"Commercial"   {Connect-IPPSSession -UserPrincipalName $AdminUPN -Prefix SCC -WarningAction SilentlyContinue -ShowBanner:$False | Out-Null}
			"USGovGCC"     {Connect-IPPSSession -UserPrincipalName $AdminUPN -Prefix SCC -WarningAction SilentlyContinue -ShowBanner:$False | Out-Null}
			"USGovGCCHigh" {Connect-IPPSSession -ConnectionUri https://ps.compliance.protection.office365.us/PowerShell-LiveID -AzureADAuthorizationEndPointUri https://login.microsoftonline.us/common -UserPrincipalName $AdminUPN -Prefix SCC -WarningAction SilentlyContinue -ShowBanner:$False | Out-Null}
			"USGovDoD"     {Connect-IPPSSession -ConnectionUri https://l5.ps.compliance.protection.office365.us/PowerShell-LiveID -AzureADAuthorizationEndPointUri https://login.microsoftonline.us/common -UserPrincipalName $AdminUPN -Prefix SCC -WarningAction SilentlyContinue -ShowBanner:$False | Out-Null}
			"China"        {Connect-IPPSSession -ConnectionUri https://ps.compliance.protection.partner.outlook.cn/PowerShell-LiveID -AzureADAuthorizationEndPointUri https://login.partner.microsoftonline.cn/common -UserPrincipalName $AdminUPN -Prefix SCC -WarningAction SilentlyContinue -ShowBanner:$False | Out-Null}
		}
	}
}

# Connect to EXO if not skipped, if necessary
if ($SkipWorkload -notcontains 'EXO') {
	if (-not(Get-Command -Name Get-OrganizationConfig -ErrorAction SilentlyContinue)) {
		Write-Host 'Connecting to Exchange Online...'
		if (-not $AdminUPN) {
			do {
				$AdminUPN = Read-Host -Prompt "Enter the UPN of the admin account that will be used to sign in"
			}
			until ($AdminUPN -match "^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")
			Write-Host ""
		}
		switch ($CloudEnvironment) {
			"Commercial"   {Connect-ExchangeOnline -UserPrincipalName $AdminUPN -ShowBanner:$false -WarningAction SilentlyContinue | Out-Null}
			"USGovGCC"     {Connect-ExchangeOnline -UserPrincipalName $AdminUPN -ShowBanner:$false -WarningAction SilentlyContinue | Out-Null}
			"USGovGCCHigh" {Connect-ExchangeOnline -ExchangeEnvironmentName O365USGovGCCHigh -UserPrincipalName $AdminUPN -ShowBanner:$false -WarningAction SilentlyContinue | Out-Null}
			"USGovDoD"     {Connect-ExchangeOnline -ExchangeEnvironmentName O365USGovDoD -UserPrincipalName $AdminUPN -ShowBanner:$false -WarningAction SilentlyContinue | Out-Null}
			"China"        {Connect-ExchangeOnline -ExchangeEnvironmentName O365China -UserPrincipalName $AdminUPN -ShowBanner:$false -WarningAction SilentlyContinue | Out-Null}
		}
	}
}

$pUsers = New-Object -TypeName System.Collections.ArrayList
# Hash tables for storing objects so they only need to be looked up once
$objectDetails = @{}
# Hash table for storing Entra role member directory objects so they only need to be looked up once
$entraRoleMemberDirObjects = @{}

#Process Entra roles
if ($SkipWorkload -notcontains 'EntraID') {
	Write-Host 'Getting users with an active Entra role assignment...'
	
	$mRoles = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName" -OutputType PSObject
	$i = 0
	$rolesToProcess = $mRoles.value | Where-Object {$_.displayName -notin $IgnoredRoles}
	foreach ($mRole in ($rolesToProcess | Sort-Object -Property displayName)) {
		$i++
		Write-Progress -Activity "Entra Role Assignments" -CurrentOperation "Role: $($mRole.displayName)" -PercentComplete (($i/$rolesToProcess.Count) * 100)
		Write-Verbose -Message "Processing role $($mRole.displayName)"
		$mRoleMembers = @()

		# Get the members
		# Not using expand=principal because it returns all member properties, which is unnecessary
		try {
			$mRoleMembers = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$($mRole.id)'" -OutputType PSObject
		}
		catch {
			Write-Verbose -Message "No assignments found for role $($mRole.displayName) (or role not present). Skipping."
			continue
		}

	    # Iterate each member
	    foreach ($mRoleMember in $mRoleMembers.value) {
			# Use cached object if member object has already been looked up
			if ($entraRoleMemberDirObjects.ContainsKey($mRoleMember.principalId)) {
				Write-Verbose -Message "Entra role member $($mRoleMember.principalId) has previoulsy been retrieved. Using cached object."
				$memberDirObject = $entraRoleMemberDirObjects[$mRoleMember.principalId]
			} else {
				$memberDirObject = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/directoryObjects/$($mRoleMember.principalId)?`$select=id,displayName" -OutputType PSObject
				$entraRoleMemberDirObjects.Add($mRoleMember.principalId,$memberDirObject)
			}
			# If member is a role-assignable group, get the members of the group
			if ($memberDirObject."@odata.type" -eq "#microsoft.graph.group") {
				# Beta endpoint is used because service principals are not returned in v1.0
				$mGroupMembers = Invoke-MgGraphRequest -Method GET -Uri "/beta/groups/$($memberDirObject.id)/members?`$top=999&`$select=id" -OutputType PSObject
				foreach ($mGroupMember in $mGroupMembers.value) {
					Write-Verbose -Message "Member assigned $($mRole.displayName) role: $($memberDirObject.displayName)\$($mGroupMember.id)"
					
					# Get member details
					$mUser = Get-UserDetails -id $mGroupMember.id
					
					# Add to final object
					$memberDetails = New-Object -TypeName PSObject -Property @{
						SignInName = $memberDirObject.displayName + "\" + $mUser.SignInName
						PasswordAge = $mUser.PasswordAge
						Role = $mRole.displayName
						MFAState = $mUser.MFAState
						MFADefault = $mUser.MFADefault
						MFAPhone = $mUser.MFAPhone
						UserType = $mUser.UserType
						AccountState = $mUser.AccountState
						Workload = 'Entra ID'
					}
					$pUsers.Add($memberDetails) | Out-Null
				}
			} else {
				Write-Verbose -Message "Member assigned $($mRole.displayName) role: $($mRoleMember.principalId)"
				
				# Get member details
				$mUser = Get-UserDetails -id $mRoleMember.principalId

				# Add to final object
				$memberDetails = New-Object -TypeName PSObject -Property @{
					SignInName = $mUser.SignInName
					PasswordAge = $mUser.PasswordAge
					Role = $mRole.displayName
					MFAState = $mUser.MFAState
					MFADefault = $mUser.MFADefault
					MFAPhone = $mUser.MFAPhone
					UserType = $mUser.UserType
					AccountState = $mUser.AccountState
					Workload = 'Entra ID'
				}
				$pUsers.Add($memberDetails) | Out-Null
			}
	    }
	}
	Write-Progress -Activity "Entra Role Assignments" -Completed
}

# Process SCC roles
if ($SkipWorkload -notcontains 'SCC') {
	Write-Host 'Getting users with a Security & Compliance Center role assignment...'
	
	$sccRoles = Get-SCCRoleGroup
	$rolesToProcess = $sccRoles | Where-Object {$_.DisplayName -notin $IgnoredRoles}
	$i = 0
	foreach ($sccRole in ($rolesToProcess | Sort-Object -Property DisplayName)) {
		$i++
		Write-Progress -Activity "SCC Role Assignments" -CurrentOperation "Role: $($sccRole.DisplayName)" -PercentComplete (($i/$rolesToProcess.Count) * 100)
		Write-Verbose "Processing role $($sccRole.DisplayName)"
		$roleUsers = @()
		
		# Get the members
	    $sgm = Get-SCCRoleGroupMember -Identity $sccRole.Guid.Guid
	    
		# Iterate each member
	   	foreach ($sMember in $sgm) {
	        if ($sMember.RecipientType -like  '*group') {
				Write-Verbose -Message "Group assigned $($sccRole.DisplayName) role: $($sMember.DisplayName)"
				# Beta endpoint is used because service principals are not returned in v1.0
				$mgm = Invoke-MgGraphRequest -Method GET -Uri "/beta/groups/$($sMember.Guid.Guid)/transitiveMembers?`$top=999&`$select=id,displayName,mail" -OutputType PSObject
				# Nested group objects are returned in addition to their members, so exclude them
				foreach ($mMember in ($mgm.value | Where-Object {$_."@odata.type" -ne "#microsoft.graph.group"})) {
					Write-Verbose -Message "User in $($sMember.DisplayName) group assigned $($sccRole.Name) role: $($mMember.displayName) ($($mMember.mail))"
					$roleUsers += New-Object -TypeName PSObject -Property @{
						Id = $mMember.id
						ParentGroup = $sMember.Displayname + "\"
					}
				}
			}
			else {
				if ($sMember.PrimarySMTPAddress) {
					$memberID = $sMember.PrimarySMTPAddress
				}
				else {
					$memberID = "No email address"
				}
				Write-Verbose -Message "User assigned $($sccRole.Name) role: $($sMember.Name) ($memberID)"
				$roleUsers += New-Object -TypeName PSObject -Property @{
					Id = $sMember.Guid.Guid
					ParentGroup = ""
				}
			}
		}

	    # Iterate each user
	    foreach ($user in $roleUsers) {
			
	        # Get underlying user details
	        $mUser = Get-UserDetails -id $user.Id
					
			# Add to final object
	        $memberDetails = New-Object -TypeName PSObject -Property @{
	            SignInName = $user.ParentGroup + $mUser.SignInName
	            PasswordAge = $mUser.PasswordAge
	            Role = $sccRole.DisplayName
				MFAState = $mUser.MFAState
	            MFADefault = $mUser.MFADefault
	            MFAPhone = $mUser.MFAPhone
	            UserType = $mUser.UserType
				AccountState = $mUser.AccountState
				Workload = 'Security and Compliance'
	        }
			$pUsers.Add($memberDetails) | Out-Null
		}			
	}
	Write-Progress -Activity "SCC Role Assignments" -Completed
}

if ($SkipWorkload -notcontains 'EXO') {
	Write-Host 'Getting users with an Exchange Online role assignment...'
	# DisplayName is not populated for EXO roles, but Name property is the effective display name (includes spaces)
	$exoRoleGroups = Get-RoleGroup | Where-Object {$_.Name -notin $IgnoredRoles} | Select-Object  -Property Name,Identity,@{n="AssigneeType";e={"RoleGroup"}},@{n="User";e={""}}
	$directAssignments = Get-ManagementRoleAssignment | Where-Object {$_.RoleAssigneeType -eq 'User' -or $_.RoleAssigneeType -eq 'SecurityGroup'} | Select-Object -Property Name,Identity,@{n="AssigneeType";e={$_.RoleAssigneeType}},User
	$exoRoleAssignments = $exoRoleGroups + $directAssignments

	$i = 0
	foreach ($rm in ($exoRoleAssignments | Sort-Object -Property Name)) {
		$i++
		Write-Progress -Activity "EXO Role Assignments" -CurrentOperation "Role: $($rm.Name)" -PercentComplete (($i/$exoRoleAssignments.Count) * 100)
		$roleUsers = @()
		
		# Get the members
	    if ($rm.AssigneeType -eq 'RoleGroup') {
			# Type is Exchange role group
			Write-Verbose -Message "Processing role group $($rm.Name)"
			$roleUsers += Get-ExoRoleGroupMembers -roleGroup $rm -roleName $rm.Name
			}
		elseif ($rm.AssigneeType -eq 'SecurityGroup') {
			# Type is Exchange mail-enabled security group
			Write-Verbose -Message "Processing role group $($rm.Name)"
			$roleUsers += Get-ExoSecurityGroupMembers -group (Get-DistributionGroup -Identity $rm.User) -roleName $rm.Name
		}
		else {
			# Type is user
			Write-Verbose -Message "Processing role $($rm.Name)"
			Write-Verbose -Message "User directly assigned $($rm.Name) role: $($rm.User)"
			$roleUsers += New-Object -TypeName PSObject -Property @{
				Id = @((Get-User -Identity $rm.User).ExternalDirectoryObjectId)[0]
				ParentGroup = ""
			}
		}
		
	    # Iterate each user
	    foreach ($user in $roleUsers) {
			
	        # Get underlying MSOL user details
	        $mUser = Get-UserDetails -id $user.Id
					
			# Add to final object
	        $memberDetails = New-Object -TypeName PSObject -Property @{
	            SignInName = $user.ParentGroup + $mUser.SignInName
	            PasswordAge = $mUser.PasswordAge
	            Role = $rm.Name
				MFAState = $mUser.MFAState
	            MFADefault = $mUser.MFADefault
	            MFAPhone = $mUser.MFAPhone
	            UserType = $mUser.UserType
				AccountState = $mUser.AccountState
				Workload = 'Exchange Online'
	        }
			$pUsers.Add($memberDetails) | Out-Null
		}
	}
	Write-Progress -Activity "EXO Role Assignments" -Completed
}

if ($pUsers.Count -gt 0) {
	# Write the report

	$culture = [System.Globalization.CultureInfo]::CurrentCulture
	$textInfo = $culture.TextInfo

	# ─────────────────────────────────────────────
	# Contadores de resumen
	# ─────────────────────────────────────────────
	$countEntra = ($pUsers | Where-Object { $_.Workload -eq 'Entra ID' }).Count
	$countSCC   = ($pUsers | Where-Object { $_.Workload -eq 'Security and Compliance' }).Count
	$countEXO   = ($pUsers | Where-Object { $_.Workload -eq 'Exchange Online' }).Count
	$countTotal = $pUsers.Count

	try {
		$tenantDetail = Get-MgOrganization | Select-Object -First 1
		$tenantName   = $tenantDetail.DisplayName
	} catch {
		$tenantName   = "N/A"
	}
	$tenantId = (Get-MgContext).TenantId

	# ─────────────────────────────────────────────
	# Generar HTML
	# ─────────────────────────────────────────────
	$htmlHead = @"
<style>
    body   { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 20px; background: #f5f5f5; color: #333; }
    h1     { color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 8px; }
    h2     { color: #005a9e; margin-top: 30px; }
    h3     { color: #005a9e; margin-top: 20px; margin-bottom: 5px; }
    table  { border-collapse: collapse; width: 100%; margin-top: 10px; font-size: 13px; }
    th     { background: #0078d4; color: #fff; padding: 10px; text-align: left; }
    td     { border: 1px solid #ddd; padding: 8px; color: #333; }
    tr:nth-child(even) { background: #e9e9e9; }
    tr:nth-child(odd)  { background: #fff; }
    .enabled   { color: #107c10; font-weight: bold; }
    .disabled  { color: #d13438; font-weight: bold; }
    .pw-old    { background: #fde7e9; color: #d13438; font-weight: bold; }
    .pw-ok     { background: #dff6dd; color: #107c10; }
    .summary   { background: #0078d4; color: #fff; padding: 12px 20px; border-radius: 6px; display: inline-block; margin: 5px; }
</style>
"@

	$htmlBody = @"
<h1>Reporte de Asignación de Roles Administrativos - Microsoft 365 <em style="font-size: 0.75em; font-weight: normal; margin-left: 80px;">&ldquo;La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad&rdquo;</em></h1>
<p>Tenant: $tenantName | Tenant ID: $tenantId | Generado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<p>Workloads evaluados: <strong>$($workLoads -join ', ')</strong> | Umbral de antigüedad de contraseña: <strong>$PasswordAgeThreshold días</strong></p>
<p><em>Si la asignación es mediante grupo, el nombre de inicio de sesión se muestra con prefijo del grupo.</em></p>

<div>
    <span class="summary">Entra ID: $countEntra</span>
    <span class="summary">SCC: $countSCC</span>
    <span class="summary">EXO: $countEXO</span>
    <span class="summary">Total asignaciones: $countTotal</span>
</div>
"@

	$htmlTables = ""
	$workloadGrouping = $pUsers | Group-Object -Property Workload
	foreach ($w in $workloadGrouping) {

		$htmlTables += "<h2>Workload: $($w.Name)</h2>"

		$roleGrouping = $w.Group | Group-Object -Property Role
		foreach ($r in $RoleGrouping) {
			$htmlTables += "<h3>Role: $($r.Name)</h3>"
			$htmlTables += "<table>"
			$htmlTables += "<thead><tr><th>Sign-in Name</th><th>Type</th><th>Account State</th><th>Password Age</th><th>Per-user MFA</th><th>MFA Default</th><th>MFA Phone</th></tr></thead>"
			$htmlTables += "<tbody>"

			foreach($u in ($r.Group | Sort-Object -Property SignInName)) {
				$htmlTables += "<tr>"
				$htmlTables += "<td>$($u.SignInName)</td>"
				$htmlTables += "<td>$($u.UserType)</td>"

				# Account state with color
				if ($u.AccountState -eq 'Enabled') {
					$htmlTables += '<td class="enabled">Enabled</td>'
				} elseif ($u.AccountState -eq 'Disabled') {
					$htmlTables += '<td class="disabled">Disabled</td>'
				} else {
					$htmlTables += "<td>$($u.AccountState)</td>"
				}

				# Password age with color
				if (-not $u.PasswordAge) {
					$htmlTables += "<td></td>"
				} else {
					if ($u.PasswordAge -ge $PasswordAgeThreshold) {
						$htmlTables += "<td class='pw-old'>$($u.PasswordAge) Days</td>"
					} else {
						$htmlTables += "<td class='pw-ok'>$($u.PasswordAge) Days</td>"
					}
				}

				$htmlTables += "<td>$($textInfo.ToTitleCase($u.MFAState))</td>"
				if ($u.MFADefault -and $u.MFADefault.Substring(0,1) -notmatch "[A-Z]") {
					$htmlTables += "<td>$($textInfo.ToTitleCase($u.MFADefault))</td>"
				} else {
					$htmlTables += "<td>$($u.MFADefault)</td>"
				}
				$htmlTables += "<td>$($u.MFAPhone)</td>"
				$htmlTables += "</tr>"
			}

			$htmlTables += "</tbody></table>"
		}
	}

	$htmlFooter = '<footer style="text-align: center; margin-top: 40px; padding: 15px 0; border-top: 2px solid #0078d4; color: #555; font-size: 13px;">chiringuito365.com&reg; | Internal Tools 2026</footer>'

	$fullHtml = ConvertTo-Html -Head $htmlHead -Body ($htmlBody + $htmlTables + $htmlFooter) -Title "M365 Role Report" | Out-String

	try {
		$fullHtml | Out-File -FilePath $htmlPath -Encoding UTF8
		Write-Host "[OK] Reporte HTML exportado: $htmlPath" -ForegroundColor Green
		Invoke-Item $htmlPath
	}
	catch {
		Write-Host "[ERROR] Error al exportar HTML: $($_.Exception.Message)" -ForegroundColor Red
	}
}
