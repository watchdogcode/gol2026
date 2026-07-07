# Playbook IR - OAuth y Shadow IT (MDA)

**Proyecto GOL 2026 — Marco SecOps Microsoft Defender XDR**
**Pilar:** Microsoft Defender for Cloud Apps (MDA / Defender for Cloud Apps)
**Repositorio:** `gol2026/IR/Playbooks/`

---

## 1. Escenario y alcance

Abuso de aplicaciones **OAuth** (consentimiento ilícito / *illicit consent grant*, apps con permisos abusivos que leen correo/archivos, exfiltración vía Graph) y **Shadow IT** (aplicaciones en la nube no sancionadas descubiertas por Cloud Discovery). El alcance cubre *service principals* y *enterprise applications* en Entra ID monitorizados por App Governance y la actividad de apps en la nube.

Handoffs: si el consentimiento se obtuvo por phishing → *Playbook IR - Phishing y BEC*; si la cuenta que consintió está comprometida → *Playbook IR - Compromiso de Identidad*.

## 2. Indicadores / disparadores

- Alertas MDA/App Governance: *"Misleading OAuth app name"*, *"Unusual app consent"*, *"App with high privilege permissions accessing mail/files"*, *"OAuth app with suspicious Graph activity"*.
- Consentimiento a una app recién registrada solicitando `Mail.Read`, `Files.ReadWrite.All`, `offline_access`, `full_access_as_app`.
- Picos de *data upload* a apps no sancionadas en Cloud Discovery; nuevas apps de alto riesgo.
- Creación de *service principals* o adición de credenciales/certificados a apps existentes.

## 3. Severidad sugerida

| Situación | Severidad | MTTA | MTTC | MTTR |
|---|---|---|---|---|
| App OAuth exfiltrando datos con permisos de app / consentimiento admin | **Crítico** | ≤15 min | ≤1 h | ≤8 h |
| App maliciosa con consentimiento de varios usuarios, acceso confirmado | **Alto** | ≤30 min | ≤4 h | ≤24 h |
| App sospechosa con consentimiento aislado, sin exfiltración probada | **Medio** | ≤2 h | ≤8 h | ≤72 h |
| Shadow IT de bajo riesgo descubierta, sin datos sensibles | **Bajo** | ≤8 h | ≤24 h | ≤5 días |

## 4. Detección y Análisis

> **Referencia:** utilizar el **Paquete KQL Advanced Hunting — MDA** del Proyecto GOL para caza de actividad de apps en la nube y consentimientos. Las consultas siguientes acotan el incidente.

**a) Actividad de consentimiento y de la app (CloudAppEvents):**

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add app role assignment grant to user.",
        "Add delegated permission grant.","Add service principal credentials.")
| extend AppName = tostring(RawEventData.Target[?(@.Type==1)].ID)
| project Timestamp, AccountDisplayName, AccountObjectId, ActionType,
          Application, IPAddress, RawEventData
| sort by Timestamp desc
```

**b) Metadatos y permisos de la app OAuth (OAuthAppInfo):**

```kql
OAuthAppInfo
| where AppName has "[nombre_app]" or OAuthAppId == "[app_id]"
| project AppName, OAuthAppId, PublisherName, VerifiedPublisher,
          Permissions, PrivilegeLevel, ConsentType, RiskLevel, IsAdminConsented
| sort by PrivilegeLevel desc
```

**c) Uso de la app tras el consentimiento — accesos a datos (CloudAppEvents):**

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "[nombre_app]" or AppId == "[app_id]"
| where ActionType has_any ("FileDownloaded","MailItemsAccessed","FileSyncDownloaded")
| summarize Accesos = count(), Usuarios = dcount(AccountObjectId),
        Acciones = make_set(ActionType, 10) by bin(Timestamp, 1h), IPAddress
| sort by Timestamp desc
```

**Análisis:** determinar permisos concedidos (delegados vs. de aplicación), número de usuarios que consintieron, si hubo *admin consent*, editor verificado, y volumen/tipo de datos accedidos (correo/archivos). Clasificar la app en Cloud Discovery (sancionada/no sancionada) y estimar exfiltración.

## 5. Contención

1. **Revocar el consentimiento de la app OAuth** — Entra ID (*Enterprise applications > [app] > Permissions > Revoke*) o desde la alerta MDA (*Governance actions > Revoke app / Disable app*). Automatizable: Graph — eliminar `oauth2PermissionGrants` y `appRoleAssignments` del *service principal*.
2. **Deshabilitar / eliminar el service principal** — Graph `PATCH /servicePrincipals/{id}` con `accountEnabled=false` (o eliminar) para cortar el acceso inmediatamente; retirar credenciales/certificados añadidos por el atacante.
3. **Aplicar políticas de App Governance** — crear/activar política que bloquee apps con permisos de alto riesgo o editor no verificado; poner la app en cuarentena automática ante actividad anómala.
4. **Bloquear la app en Cloud Discovery** — marcar como *Unsanctioned* en MDA (*Cloud Discovery > Discovered apps*); generar script de bloqueo para proxy/firewall o etiqueta que empuje a Defender for Endpoint (*network protection*) para forzar el bloqueo en endpoints.
5. Revocar sesiones de los usuarios que consintieron si se sospecha robo de token (coordinar con *Playbook de Identidad*: `revokeSignInSessions`).

## 6. Erradicación

- Eliminar definitivamente el *service principal* y su *app registration* asociada si es maliciosa; confirmar que no quedan grants residuales en ningún usuario.
- Revisar y retirar consentimientos duplicados de la misma familia de apps; buscar apps con el mismo `PublisherName`/*reply URL*.
- Endurecer la política de consentimiento de usuario (*user consent settings*): restringir a permisos de bajo riesgo de editores verificados y habilitar el flujo de *admin consent request*.

## 7. Recuperación

- Restaurar acceso legítimo de usuarios afectados (reset/re-MFA si hubo tokens comprometidos).
- Validar con el Owner de negocio la reincorporación controlada de apps legítimas mal clasificadas.
- Monitorización reforzada de la actividad de apps 72 h; confirmar cese de accesos a datos por la app removida.

## 8. Post-incidente

- **Lecciones aprendidas:** cómo se obtuvo el consentimiento, cobertura de App Governance, datos expuestos.
- **Tuning de detecciones:** afinar políticas de App Governance y de descubrimiento, ajustar el modelo de consentimiento a *admin consent workflow*, y crear reglas custom en Advanced Hunting sobre `OAuthAppInfo`/`CloudAppEvents`. Actualizar el **Paquete KQL MDA**.
- Programa de gobierno de Shadow IT: catálogo de apps sancionadas y revisión periódica de consentimientos.

## 9. Roles involucrados (RACI) y enlaces

| Actividad | IC | SOC T1/T2 | Threat Hunter | Enlace CISO/Com | Owner | Legal/RH |
|---|---|---|---|---|---|---|
| Triage y clasificación de app | A | R | C | I | I | - |
| Investigación KQL | I | C | R | I | - | - |
| Revocar consentimiento / SP | A | R | C | I | C | - |
| Política App Governance / bloqueo | A | R | C | I | C | - |
| Evaluación de datos expuestos | A | I | C | R | C | R |
| Post-Incident Review | R | C | C | C | C | C |

**Enlaces Defender XDR / MDA:**
- Incidentes: `https://security.microsoft.com/incidents`
- App Governance: `https://security.microsoft.com/app-governance`
- Cloud Discovery: `https://security.microsoft.com/cloud-discovery`
- OAuth apps: `https://security.microsoft.com/cloudapps/oauth-apps`
- Enterprise applications (Entra): `https://entra.microsoft.com` → Identity > Applications > Enterprise applications
