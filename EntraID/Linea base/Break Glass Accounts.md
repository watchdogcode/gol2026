# Cuenta de emergencia (Break Glass / Emergency Access Account) 🛡️
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

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

## 4. Scripts, queries y automatización
### A. Crear cuenta cloud-only (PowerShell)
```powershell
# Crear cuenta cloud-only
New-MgUser -AccountEnabled $true `
  -DisplayName "Emergency Access 1" `
  -UserPrincipalName "emergency1@tenant.onmicrosoft.com" `
  -MailNickname "emergency1" `
  -PasswordProfile @{ Password="ContraseñaMuySegura!123" }

# Asignar rol Global Administrator
$role = Get-MgDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"}
Add-MgDirectoryRoleMember -DirectoryRoleId $role.Id -DirectoryObjectId (Get-MgUser -UserId "emergency1@tenant.onmicrosoft.com").Id
```

### B. Verificar exclusión de políticas CA (PowerShell)
```powershell
Get-MgIdentityConditionalAccessPolicy |
  Where-Object { $_.Conditions.Users.IncludeUsers -contains "emergency1@tenant.onmicrosoft.com" } |
  Select DisplayName, State
```

### C. Monitorear inicios de sesión (KQL)
```kql
SigninLogs
| where UserPrincipalName in ("emergency1@tenant.onmicrosoft.com", "emergency2@tenant.onmicrosoft.com")
| sort by TimeGenerated desc
```

### D. Crear alerta en Sentinel (KQL)
```kql
SigninLogs
| where UserPrincipalName has "emergency"
| where ResultType == 0
```

---

## 5. Referencias
- **Microsoft Learn:** https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access

---

## 6. Notas y advertencias
- No usar estas cuentas para tareas administrativas diarias.
- Cada inicio de sesión debe generar una alerta inmediata.
- No asociarlas a personas específicas.
- Usar métodos de autenticación distintos a los administradores regulares.
- Revisar con auditoría interna quién tiene acceso a las credenciales.


## Referencias Oficiales
- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access

---
chiringuito365.com | Internal Tools 2026