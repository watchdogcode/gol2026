# Playbook IR - Compromiso de Identidad (MDI + Entra ID)

**Proyecto GOL 2026 — Marco SecOps Microsoft Defender XDR**
**Pilares:** Microsoft Defender for Identity (MDI) + Microsoft Entra ID (Identity Protection)
**Repositorio:** `gol2026/IR/Playbooks/`

---

## 1. Escenario y alcance

Compromiso de cuentas de usuario o de servicio: **robo de credenciales/tokens**, *password spray*, ataques a Active Directory (Kerberoasting, DCSync, Pass-the-Hash/Ticket), escalada de privilegios y movimiento lateral híbrido (on-prem AD + Entra ID). El alcance cubre identidades supervisadas por MDI (sensores en DC/AD FS) y sesiones de Entra ID.

Handoffs: entrada por phishing → *Playbook IR - Phishing y BEC*; uso de host comprometido → *Playbook IR - Ransomware y Endpoint*; consentimientos OAuth ilícitos → *Playbook IR - OAuth y Shadow IT*.

## 2. Indicadores / disparadores

- Alertas MDI: *"Suspected DCSync attack"*, *"Suspected Kerberoasting"*, *"Suspected Golden Ticket usage"*, *"Suspected Pass-the-Ticket"*, *"Account enumeration reconnaissance"*.
- Entra ID Protection: usuario/inicio de sesión marcado como *risky* (viaje imposible, IP anónima/Tor, credenciales filtradas, *unfamiliar sign-in properties*).
- *Password spray* / bloqueo masivo; MFA fatigue (múltiples *push* rechazados).
- Cambios anómalos de privilegios (adición a *Global Admin*, roles de directorio, membresías sensibles).

## 3. Severidad sugerida

| Situación | Severidad | MTTA | MTTC | MTTR |
|---|---|---|---|---|
| Compromiso de cuenta privilegiada / DCSync / Golden Ticket | **Crítico** | ≤15 min | ≤1 h | ≤8 h |
| Cuenta estándar comprometida con acceso confirmado | **Alto** | ≤30 min | ≤4 h | ≤24 h |
| Sign-in de riesgo medio sin acción posterior probada | **Medio** | ≤2 h | ≤8 h | ≤72 h |
| Reconocimiento/spray bloqueado por políticas | **Bajo** | ≤8 h | ≤24 h | ≤5 días |

## 4. Detección y Análisis

> **Referencia:** utilizar el **Paquete KQL Advanced Hunting — MDI/Entra ID** del Proyecto GOL para correlación de identidad (recon, lateral movement, abuso de privilegios). Las consultas siguientes acotan el incidente.

**a) Autenticaciones y anomalías del usuario (IdentityLogonEvents):**

```kql
IdentityLogonEvents
| where Timestamp > ago(7d)
| where AccountUpn =~ "[usuario@dominio]"
| where LogonType has_any ("Ntlm","Kerberos","Interactive","Remote")
| project Timestamp, AccountUpn, DeviceName, IPAddress, LogonType,
          Protocol, TargetDeviceName, ActionType, FailureReason
| sort by Timestamp desc
```

**b) Sign-ins de riesgo en Entra ID (AADSignInEventsBeta):**

```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AccountUpn =~ "[usuario@dominio]"
| where RiskLevelDuringSignIn in ("50","100") or ErrorCode != 0
| project Timestamp, AccountUpn, IPAddress, Country, City, Application,
          ClientAppUsed, RiskLevelDuringSignIn, ConditionalAccessStatus, ErrorCode
| sort by Timestamp desc
```

**c) Reconocimiento LDAP y cambios en directorio (IdentityQueryEvents + IdentityDirectoryEvents):**

```kql
IdentityQueryEvents
| where Timestamp > ago(3d)
| where AccountUpn =~ "[usuario@dominio]"
| where QueryType in ("SAMR","LDAP")
| project Timestamp, AccountUpn, DeviceName, QueryType, Query, QueryTarget
| union (
    IdentityDirectoryEvents
    | where Timestamp > ago(3d)
    | where ActionType has_any ("Group Membership changed","Account privilege",
            "Password change","Account Password expiry time changed")
    | project Timestamp, AccountUpn=TargetAccountUpn, ActionType, AdditionalFields
)
| sort by Timestamp desc
```

**Análisis:** confirmar cuentas y hosts implicados, determinar si hay privilegios elevados o cuentas de servicio afectadas, establecer *blast radius* (recursos accedidos, tickets emitidos) y validar el riesgo agregado del usuario en Identity Protection.

## 5. Contención

1. **Deshabilitar el usuario** — Entra ID (*Users > Account status > Block sign-in*) y/o AD on-prem (`Disable-ADAccount`). Automatizable: Graph `PATCH /users/{id}` con `accountEnabled=false`; para AD, acción *Disable user* de MDI.
2. **Revocar sesiones y tokens (revokeSignInSessions)** — invalida refresh tokens y cookies: Graph `POST /users/{id}/revokeSignInSessions` o `Revoke-MgUserSignInSession`. Fuerza re-autenticación en todos los clientes.
3. **Forzar restablecimiento de contraseña** — reset con cambio en el próximo inicio de sesión (Graph `passwordProfile.forceChangePasswordNextSignIn=true`); en cuentas de servicio, rotar y coordinar con el Owner.
4. **Marcar usuario como comprometido en Entra ID Protection** — *Confirm user compromised* (o Graph `POST /identityProtection/riskyUsers/confirmCompromised`) para elevar el riesgo y disparar políticas de acceso condicional.
5. **Revisar y revertir cambios de privilegios** — retirar de roles/grupos sensibles no autorizados; revisar *PIM* y asignaciones recientes.
6. Aislar hosts de origen vía *Playbook MDE* si son endpoints comprometidos.

## 6. Erradicación

- Rotar credenciales de cuentas afectadas y **secretos de cuentas de servicio**; si hay indicios de Golden Ticket/DCSync, **rotar dos veces `krbtgt`**.
- Eliminar persistencia en identidad: reglas de reenvío, dispositivos/MFA registrados por el atacante, apps con consentimiento (ver *Playbook OAuth*).
- Cerrar la vía de escalada (backdoors de directorio, permisos delegados anómalos).

## 7. Recuperación

- Rehabilitar la cuenta tras reset + re-registro MFA y validación de identidad del titular.
- Confirmar bajada del nivel de riesgo (*dismiss/close* en Identity Protection una vez remediado) y ausencia de sign-ins anómalos 72 h.
- Restaurar membresías legítimas verificadas con el Owner.

## 8. Post-incidente

- **Lecciones aprendidas:** vector de credencial, cobertura de MFA/acceso condicional, tiempo de contención.
- **Tuning de detecciones:** endurecer políticas de acceso condicional (bloqueo por riesgo, MFA resistente a phishing/FIDO2), afinar umbrales de Identity Protection y crear reglas custom en Advanced Hunting. Actualizar el **Paquete KQL MDI/Entra ID**.
- Revisar cuentas privilegiadas (modelo *tiered*, PIM, revisión de accesos).

## 9. Roles involucrados (RACI) y enlaces

| Actividad | IC | SOC T1/T2 | Threat Hunter | Enlace CISO/Com | Owner | Legal/RH |
|---|---|---|---|---|---|---|
| Triage y bloqueo de cuenta | A | R | C | I | I | - |
| Investigación KQL | I | C | R | I | - | - |
| Revocación sesiones/reset | A | R | C | I | C | - |
| Rotación krbtgt / servicio | A | C | C | I | R | - |
| Notificación al titular | A | I | I | R | C | C |
| Post-Incident Review | R | C | C | C | C | C |

**Enlaces Defender XDR / Entra:**
- Incidentes: `https://security.microsoft.com/incidents`
- Advanced Hunting: `https://security.microsoft.com/v2/advanced-hunting`
- Identity Protection (Risky users): `https://entra.microsoft.com` → Protection > Identity Protection
- Usuarios Entra ID: `https://entra.microsoft.com` → Identity > Users
