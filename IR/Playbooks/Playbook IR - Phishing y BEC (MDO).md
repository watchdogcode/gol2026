# Playbook IR - Phishing y BEC (MDO)

**Proyecto GOL 2026 — Marco SecOps Microsoft Defender XDR**
**Pilar:** Microsoft Defender for Office 365 (MDO)
**Repositorio:** `gol2026/IR/Playbooks/`

---

## 1. Escenario y alcance

Campañas de **phishing** (robo de credenciales, entrega de malware por URL/adjunto) y **Business Email Compromise (BEC)** (suplantación de ejecutivos o proveedores, fraude de transferencias, secuestro de hilos de correo). El alcance cubre buzones de Exchange Online protegidos por MDO, incluyendo correos entrantes, clics de usuario y reglas de bandeja de entrada creadas tras un compromiso.

Queda **fuera de alcance**: compromiso de identidad post-clic con movimiento lateral (ver *Playbook IR - Compromiso de Identidad*) y ejecución de payload en endpoint (ver *Playbook IR - Ransomware y Endpoint*). Este playbook coordina el traspaso (*handoff*) a esos playbooks cuando corresponda.

## 2. Indicadores / disparadores

- Alertas MDO: *"A potentially malicious URL click was detected"*, *"Email messages containing malicious URL/file removed after delivery"* (ZAP), *"Email reported by user as malware or phish"*.
- Detecciones de **suplantación** (spoof/impersonation) de dominio o usuario protegido.
- Reportes de usuarios vía botón *Report Message / Report Phishing*.
- Reglas de reenvío externo o de bandeja recién creadas; picos de correos con el mismo asunto/adjunto.
- Solicitudes anómalas de cambio de datos bancarios o transferencias urgentes (patrón BEC).

## 3. Severidad sugerida

| Situación | Severidad | MTTA | MTTC | MTTR |
|---|---|---|---|---|
| BEC con fraude financiero en curso o credenciales verificadas comprometidas | **Crítico** | ≤15 min | ≤1 h | ≤8 h |
| Campaña con clic confirmado, sin exfiltración probada | **Alto** | ≤30 min | ≤4 h | ≤24 h |
| Phishing entregado sin clic / ZAP efectivo | **Medio** | ≤2 h | ≤8 h | ≤72 h |
| Correo aislado bloqueado en el borde | **Bajo** | ≤8 h | ≤24 h | ≤5 días |

## 4. Detección y Análisis

> **Referencia:** utilizar el **Paquete KQL Advanced Hunting — MDO** del Proyecto GOL para la caza extendida (triaje de campañas, correlación remitente/URL/adjunto). Las consultas siguientes son el punto de arranque específico del incidente.

**a) Alcance de la campaña por remitente/asunto (EmailEvents + EmailUrlInfo):**

```kql
let lookback = 7d;
EmailEvents
| where Timestamp > ago(lookback)
| where SenderFromAddress in~ ("[remitente_malicioso]") or Subject has "[asunto_señuelo]"
| where DeliveryAction in ("Delivered", "DeliveredToJunk")
| join kind=leftouter EmailUrlInfo on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress,
          Subject, Url, DeliveryAction, ThreatTypes
| sort by Timestamp desc
```

**b) Usuarios que hicieron clic en la URL maliciosa (UrlClickEvents):**

```kql
UrlClickEvents
| where Timestamp > ago(7d)
| where Url has "[dominio_malicioso]"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, UrlChain, Workload
| where IsClickedThrough == 1 or ActionType == "ClickAllowed"
| sort by Timestamp desc
```

**c) Adjuntos maliciosos y hash para pivotar a MDE (EmailAttachmentInfo):**

```kql
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileName has "[nombre_adjunto]" or SHA256 == "[hash]"
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress,
          FileName, FileType, SHA256, ThreatTypes
```

**Análisis:** confirmar veredicto (malicioso/phish), delimitar destinatarios, identificar quién hizo clic o ejecutó el adjunto, y determinar si hubo autenticación posterior sospechosa (pivotar a Entra ID sign-ins). Pivotar `SHA256` al *Playbook MDE* si hubo descarga.

## 5. Contención

1. **Purgar el correo de los buzones** — *Threat Explorer* (Explorer > *Actions* > *Move to* / *Soft delete* / **Hard delete**) o desde el incidente. Automatizable vía **M365 Defender / Explorer remediation API** y *Sentinel playbook* (Logic App) para remediación masiva.
2. **Bloquear remitente, dominio y URL** — Tenant Allow/Block List (TABL) en *Email & collaboration > Policies > Tenant Allow/Block Lists*; para URL usar bloqueo de URL. Vía Graph/PowerShell: `New-TenantAllowBlockListItems`.
3. **Revocar la sesión del usuario que hizo clic** — si hubo posible robo de token, ejecutar `Revoke-MgUserSignInSession` (Graph) y disparar el *Playbook de Compromiso de Identidad*.
4. **Revisar y eliminar reglas de bandeja maliciosas** — buscar reglas de reenvío externo/borrado automático (`Get-InboxRule` / Graph `messageRules`); deshabilitar reenvío externo si aplica.
5. **BEC:** notificar de inmediato a **Legal/RH** y **Finanzas** para congelar transferencias; involucrar al banco.

## 6. Erradicación

- Confirmar *hard delete* de todas las copias (incluyendo ZAP retroactivo).
- Eliminar reglas de bandeja y delegaciones no autorizadas; restablecer contraseña si hubo credenciales expuestas.
- Verificar que TABL/anti-phishing bloqueen recurrencias; ajustar políticas de *impersonation protection* para el ejecutivo suplantado.

## 7. Recuperación

- Restaurar acceso normal del usuario tras cambio de contraseña y re-MFA.
- Confirmar ausencia de reglas/permisos residuales y de nuevas alertas de la campaña.
- Comunicar a los destinatarios afectados; validar con el Owner del proceso financiero que no se ejecutaron pagos.

## 8. Post-incidente

- **Lecciones aprendidas:** vector de entrega, efectividad de ZAP, tiempo hasta la purga.
- **Tuning de detecciones:** afinar políticas anti-phishing/anti-spoof, umbrales de *impersonation*, y crear/actualizar reglas de detección personalizadas en Advanced Hunting a partir de los IOC. Enriquecer el **Paquete KQL MDO**.
- Campaña de concienciación (*Attack Simulation Training*) dirigida a usuarios que hicieron clic.

## 9. Roles involucrados (RACI) y enlaces

| Actividad | IC | SOC T1/T2 | Threat Hunter | Enlace CISO/Com | Owner | Legal/RH |
|---|---|---|---|---|---|---|
| Triage y confirmación | A | R | C | I | I | - |
| Investigación KQL | I | C | R | I | - | - |
| Purga/bloqueo (contención) | A | R | C | I | C | - |
| Fraude BEC / notificación | A | I | I | R | C | R |
| Post-Incident Review | R | C | C | C | C | C |

**Enlaces Defender XDR:**
- Incidentes: `https://security.microsoft.com/incidents`
- Threat Explorer: `https://security.microsoft.com/threatexplorer`
- Advanced Hunting: `https://security.microsoft.com/v2/advanced-hunting`
- Tenant Allow/Block Lists: `https://security.microsoft.com/tenantAllowBlockList`
