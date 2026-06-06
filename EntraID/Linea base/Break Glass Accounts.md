# Cuenta de emergencia (Break Glass / Emergency Access Account) 🛡️
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

**Autores:** [Ernesto Cobos Roqueñí](https://www.linkedin.com/in/ernesto-cobos/) & [Arturo Mandujano](https://www.linkedin.com/in/jose-arturo-mandujano-avila-621b00b9/)

---
## 1. Explicación
Una **cuenta de emergencia** es una cuenta administrativa utilizada únicamente cuando los administradores habituales no pueden autenticarse debido a fallos en **MFA**, **federación**, **red**, **sincronización**, **incidentes de seguridad** u otras dependencias críticas. Su propósito fundamental es garantizar que siempre exista al menos un **Global Administrator** con acceso al entorno Microsoft 365.

---

## 2. Mejores prácticas recomendadas

- Mantener **al menos dos cuentas** de emergencia.
- Que sean **cloud-only** (sin federación, sin dependencias on‑premises).
- Usar dominio `*.onmicrosoft.com`.
- Credenciales guardadas en **dos ubicaciones físicas seguras**.
- **Contraseñas que no expiren**.
- Métodos **MFA resistentes al phishing**, como **FIDO2** o passkeys físicas.
- Configuraciones **diferenciadas** para evitar puntos de falla comunes.
- Excluirlas de procesos automáticos de limpieza de cuentas.
- Monitorear **cada inicio de sesión**.

---

## 3. Implementación paso a paso
### A. Creación de cuentas
1. Crear dos cuentas cloud‑only en Entra ID:
   - `emergency1@tenant.onmicrosoft.com`
   - `emergency2@tenant.onmicrosoft.com`
2. Asignar rol **Global Administrator**.
3. Configurar MFA:
   - Cuenta 1 → **Llave FIDO2**.
   - Cuenta 2 → **Passkey física distinta**.

### B. Configuración recomendada
- Evitar dependencias con administradores comunes:
  - No federación.
  - No MFA compartido.
- Almacenar credenciales en ubicaciones seguras.
- Deshabilitar expiración de contraseña.
- Excluir de políticas de acceso condicional que puedan bloquearlas.
- Documentar proceso y activar auditoría.

### C. Validación y mantenimiento
- Probar el acceso cada **90 días**.
- Auditar cada inicio de sesión.
- Mantener registro seguro de la ubicación de credenciales.

---

## 4. Procedimiento para Crear una Regla de Detección en Microsoft Defender

## Pasos
1. Ir a: <https://security.microsoft.com/v2/advanced-hunting>
2. En en panel agregar el siguiente query:

```kusto
EntraIdSignInEvents
| where Timestamp >= ago(1h)
| where AccountUpn in ("breakglass@tenant.onmicrosoft.com", "breakglass02@tenant.onmicrosoft.com")
| project Timestamp, AccountUpn, LogonType, Application, RiskLevelAggregated, ClientAppUsed, Country, State, City
| order by Timestamp asc
```

3. Clic en **Run query**.
4. Clic en **Create detection rule**.
5. En la página **General**:
   - **Detection name:** Sign-in Break Glass Accounts
   - **Rule Description:** Detect Break Glass Accounts logins
   - **Frequency:** Continuous (NRT)
   - **Severity:** High
   - **Category:** Credential access
6. Clic en **Next**.
7. En la página **Alert settings**:
   - **Alert title:** Sign-in Break Glass Accounts
   - **Description:** Detect Break Glass Accounts logins
8. Clic en **Next**.
9. En la página **Automated actions**, clic en **Next**.
10. Clic en **Submit**.

---
## 5. Scripts, queries y automatización
### A. Crear cuenta cloud-only (PowerShell)
```powershell
# Crear cuenta cloud-only
Import-Module Microsoft.Graph.Users -ErrorAction Stop
Connect-MgGraph -Scopes "User.ReadWrite.All" -NoWelcome

# Usa contraseña ASCII fuerte para evitar problemas (sin ñ/acentos)
$PasswordProfile = @{
  Password = "***************************"
  ForceChangePasswordNextSignIn = $false
}

$params = @{
  AccountEnabled    = $true
  DisplayName       = "Emergency Access 1"
  UserPrincipalName = "breakglass@tenant.onmicrosoft.com"
  MailNickname      = "breakglass"
  PasswordProfile   = $PasswordProfile
  PasswordPolicies  = "DisablePasswordExpiration"
  UsageLocation     = "US"
}

New-MgUser @params
```
### Asignar rol Global Administrator

```powershell
# Asignar rol Global Administrator
# Requiere estar conectado:
# Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory","Directory.ReadWrite.All","User.Read.All"

$upn = "breakglass04@chiringuito365.com"

# 1) Obtener el rol Global Administrator (ya existe en tu tenant)
$role = Get-MgDirectoryRole -All | Where-Object DisplayName -eq "Global Administrator"
if (-not $role) { throw "No se encontró el rol 'Global Administrator' en DirectoryRole." }

# 2) Obtener usuario breakglass
$user = Get-MgUser -UserId $upn -ErrorAction Stop
if (-not $user) { throw "No se encontró el usuario $upn" }

# 3) Validar si ya es miembro
$alreadyMember = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All |
  Where-Object { $_.Id -eq $user.Id }

if ($alreadyMember) {
  Write-Host "El usuario ya es miembro de 'Global Administrator': $upn" -ForegroundColor Yellow
  return
}

# 4) Agregar miembro por referencia (método más estable)
New-MgDirectoryRoleMemberByRef `
  -DirectoryRoleId $role.Id `
  -BodyParameter @{
      "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.Id)"
  } -ErrorAction Stop

Write-Host "Rol 'Global Administrator' asignado a $upn" -ForegroundColor Green
```

### C. Monitorear inicios de sesión (KQL)
```kql
EntraIdSignInEvents
| where Timestamp >= ago(1h)
| where AccountUpn in ("breakglass@tenant.onmicrosoft.com","breakglass02@tenant.onmicrosoft.com")
| project Timestamp, AccountUpn, LogonType, Application, RiskLevelAggregated, ClientAppUsed, Country, State, City
| order by Timestamp asc 
```

### D. Crear alerta en Sentinel (KQL)
```kql
SigninLogs
| where UserPrincipalName has "emergency"
| where ResultType == 0
```

---

## 6. Referencias
- **Microsoft Learn:** https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access

---

## 7. Notas y advertencias
- No usar estas cuentas para tareas administrativas diarias.
- Cada inicio de sesión debe generar una alerta inmediata.
- No asociarlas a personas específicas.
- Usar métodos de autenticación distintos a los administradores regulares.
- Revisar con auditoría interna quién tiene acceso a las credenciales.


## Referencias Oficiales
- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access

---

Gol 2026 | Internal Tools