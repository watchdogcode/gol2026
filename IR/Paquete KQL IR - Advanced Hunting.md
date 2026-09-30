# Paquete IR — KQL Advanced Hunting

**Proyecto GOL · Pilar IR (Respuesta a Incidentes)**

Colección de consultas de **Advanced Hunting** para acelerar la respuesta a incidentes: determinar el **alcance (blast radius)**, apoyar la **contención** e **verificar** que las acciones surtieron efecto. Es un paquete **cross-domain** que complementa (no reemplaza) los paquetes KQL de cada pilar (MDO, MDE, MDI, Entra ID, MDA).

> Ejecuta las consultas en **[Advanced Hunting](https://security.microsoft.com/v2/advanced-hunting)** del portal de Microsoft Defender XDR.

## Cómo usar este paquete

- Las consultas están **parametrizadas con `let`** al inicio. Sustituye los marcadores `[ ]` por el valor real de la investigación (usuario, dispositivo, IP, hash, dominio, `NetworkMessageId`, etc.).
- Ajusta la **ventana de tiempo** (`Ventana`) según el caso. La retención interactiva de Advanced Hunting es de **~30 días**.
- Valida los nombres de columnas contra el **esquema de tu tenant** (*Schema reference* en Advanced Hunting); algunos campos varían por licenciamiento o versión de tabla.
- Alinea la severidad y los SLAs con la **matriz del Plan de Respuesta a Incidentes CSIRT** del proyecto.

## Índice

1. [Fase 1 — Triage y contexto del incidente](#fase-1--triage-y-contexto-del-incidente)
2. [Fase 2 — Alcance / Blast radius por entidad](#fase-2--alcance--blast-radius-por-entidad)
3. [Fase 3 — Apoyo a la contención](#fase-3--apoyo-a-la-contención)
4. [Fase 4 — Verificación post-contención](#fase-4--verificación-post-contención)
5. [Mapa de queries por playbook](#mapa-de-queries-por-playbook)
6. [Referencias](#referencias)

---

## Fase 1 — Triage y contexto del incidente

### 1.1 Alertas activas (Critical/High) con sus entidades
*Cuándo:* al abrir el turno o al declararse un incidente, para ver qué disparó y qué entidades tocó.

```kusto
let Ventana = 24h;
AlertInfo
| where Timestamp > ago(Ventana)
| where Severity in ("High", "Medium")
| join kind=inner (AlertEvidence | where Timestamp > ago(Ventana)) on AlertId
| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, DetectionSource,
          EntityType, EvidenceRole, AccountUpn, DeviceName, RemoteIP, RemoteUrl, FileName, SHA256
| order by Timestamp desc
```

### 1.2 Resumen de entidades afectadas por alerta
*Cuándo:* para consolidar rápidamente las cuentas, dispositivos e IPs involucrados en cada alerta.

```kusto
let Ventana = 24h;
AlertEvidence
| where Timestamp > ago(Ventana)
| summarize
    Cuentas      = make_set(AccountUpn, 25),
    Dispositivos = make_set(DeviceName, 25),
    IPs          = make_set(RemoteIP, 25),
    URLs         = make_set(RemoteUrl, 25),
    Archivos     = make_set(SHA256, 25)
  by AlertId
```

---

## Fase 2 — Alcance / Blast radius por entidad

El objetivo de esta fase es responder: *¿hasta dónde llegó?* Ejecuta la consulta correspondiente a la entidad pivote del incidente.

### 2.1 Por usuario — inicios de sesión (Entra ID)
```kusto
let Usuario = "[usuario@dominio]";
let Ventana = 7d;
AADSignInEventsBeta
| where Timestamp > ago(Ventana)
| where AccountUpn =~ Usuario
| project Timestamp, Application, ResourceDisplayName, IPAddress, Country, City,
          ErrorCode, RiskLevelDuringSignIn, ConditionalAccessStatus, ClientAppUsed, DeviceName
| order by Timestamp desc
```

### 2.2 Por usuario — dispositivos donde inició sesión
*Cuándo:* para saber **qué endpoints considerar para aislamiento** si la cuenta fue comprometida.

```kusto
let Cuenta = "[sAMAccountName]";
let Ventana = 7d;
DeviceLogonEvents
| where Timestamp > ago(Ventana)
| where AccountName =~ Cuenta
| summarize Inicios = count(), Ultimo = max(Timestamp) by DeviceName, LogonType
| order by Ultimo desc
```

### 2.3 Por usuario — actividad en aplicaciones en la nube (MDA)
```kusto
let ObjectId = "[user-object-id]";
let Ventana = 7d;
CloudAppEvents
| where Timestamp > ago(Ventana)
| where AccountObjectId == ObjectId
| summarize Eventos = count(), Ultimo = max(Timestamp) by Application, ActionType
| order by Eventos desc
```

### 2.4 Por dispositivo — procesos y conexiones de red (MDE)
```kusto
let Dispositivo = "[nombre-dispositivo]";
let Ventana = 3d;
union
  ( DeviceProcessEvents
    | where Timestamp > ago(Ventana) and DeviceName =~ Dispositivo
    | project Timestamp, DeviceName, Tipo = "Proceso",
              Detalle = strcat(FileName, "  ", ProcessCommandLine),
              Iniciado_por = InitiatingProcessFileName ),
  ( DeviceNetworkEvents
    | where Timestamp > ago(Ventana) and DeviceName =~ Dispositivo
    | project Timestamp, DeviceName, Tipo = "Red",
              Detalle = strcat(RemoteIP, ":", tostring(RemotePort), "  ", RemoteUrl),
              Iniciado_por = InitiatingProcessFileName )
| order by Timestamp desc
| take 200
```

### 2.5 Por IP — quién se conectó desde/hacia esa IP
```kusto
let IP = "[ip-sospechosa]";
let Ventana = 7d;
union
  ( AADSignInEventsBeta
    | where Timestamp > ago(Ventana) and IPAddress == IP
    | project Timestamp, Fuente = "SignIn", Actor = AccountUpn, Detalle = Application, ErrorCode ),
  ( DeviceNetworkEvents
    | where Timestamp > ago(Ventana) and RemoteIP == IP
    | project Timestamp, Fuente = "Endpoint", Actor = DeviceName, Detalle = InitiatingProcessFileName, ErrorCode = int(null) )
| order by Timestamp desc
```

### 2.6 Por hash de archivo — dónde apareció (MDE)
```kusto
let SHA = "[sha256]";
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == SHA
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### 2.7 Por URL/dominio — receptores y clics (MDO)
```kusto
let Dominio = "[dominio-malicioso]";
let Ventana = 7d;
EmailUrlInfo
| where Timestamp > ago(Ventana)
| where UrlDomain =~ Dominio
| join kind=inner (EmailEvents | where Timestamp > ago(Ventana)) on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Url, DeliveryAction, LatestDeliveryLocation
| order by Timestamp desc
```

```kusto
// Clics reales sobre el dominio malicioso (Safe Links)
let Dominio = "[dominio-malicioso]";
UrlClickEvents
| where Timestamp > ago(7d)
| where Url has Dominio
| project Timestamp, AccountUpn, Url, ActionType, IPAddress, Workload, IsClickedThrough
| order by Timestamp desc
```

### 2.8 Por remitente / campaña — destinatarios afectados (MDO)
```kusto
let Remitente = "[atacante@dominio]";
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress =~ Remitente
| summarize Correos = count(), Destinatarios = make_set(RecipientEmailAddress, 200)
    by Subject, DeliveryAction, ThreatTypes
| order by Correos desc
```

---

## Fase 3 — Apoyo a la contención

Estas consultas **identifican los objetivos de contención** (a qué usuarios/correos/apps aplicar la acción). La acción en sí se ejecuta desde el portal, la API de M365 Defender / Graph, o un playbook de Sentinel (ver Plan IR y playbooks).

### 3.1 Correos maliciosos aún entregados (para purga/soft-delete)
```kusto
let Remitente = "[atacante@dominio]";
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress =~ Remitente
| where DeliveryAction == "Delivered"
| project Timestamp, RecipientEmailAddress, Subject, NetworkMessageId, LatestDeliveryLocation
| order by Timestamp desc
```

### 3.2 Persistencia en correo — reglas de bandeja / delegaciones sospechosas (BEC)
```kusto
let Usuario = "[usuario@dominio]";
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules",
                       "Add-MailboxPermission", "Set-Mailbox")
| where RawEventData has "[usuario@dominio]"
| project Timestamp, ActionType, AccountDisplayName, IPAddress, RawEventData
| order by Timestamp desc
```

### 3.3 Consentimientos OAuth otorgados por el usuario (para revocar)
```kusto
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("Consent to application.",
                       "Add delegated permission grant.",
                       "Add app role assignment grant to user.")
| where RawEventData has "[usuario@dominio]"
| project Timestamp, ActionType, AccountDisplayName, ObjectName, IPAddress, RawEventData
| order by Timestamp desc
```

### 3.4 Aplicaciones OAuth de alto privilegio (candidatas a deshabilitar)
```kusto
OAuthAppInfo
| where PrivilegeLevel == "High"
| project OAuthAppId, AppName, VerifiedPublisher, PrivilegeLevel, Permissions
| order by AppName asc
```

### 3.5 Inicios de sesión exitosos recientes (justifica revocar sesiones)
```kusto
let Usuario = "[usuario@dominio]";
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where AccountUpn =~ Usuario and ErrorCode == 0
| project Timestamp, Application, IPAddress, Country, ClientAppUsed, DeviceName, ConditionalAccessStatus
| order by Timestamp desc
```

---

## Fase 4 — Verificación post-contención

Confirma que las acciones surtieron efecto. **El resultado esperado suele ser 0 filas.**

### 4.1 Sin nuevos inicios de sesión exitosos tras revocar/deshabilitar
```kusto
let Usuario = "[usuario@dominio]";
let MomentoContencion = datetime([YYYY-MM-DDTHH:MM:SSZ]);
AADSignInEventsBeta
| where Timestamp > MomentoContencion
| where AccountUpn =~ Usuario and ErrorCode == 0
| project Timestamp, Application, IPAddress, Country, ConditionalAccessStatus
| order by Timestamp desc
// Filas > 0  →  la cuenta sigue autenticando: reforzar contención.
```

### 4.2 Confirmar aislamiento del dispositivo (sin salida a Internet)
```kusto
let Dispositivo = "[nombre-dispositivo]";
let MomentoContencion = datetime([YYYY-MM-DDTHH:MM:SSZ]);
DeviceNetworkEvents
| where Timestamp > MomentoContencion
| where DeviceName =~ Dispositivo
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| project Timestamp, RemoteIP, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
// Filas > 0  →  el aislamiento no está activo o hay excepción.
```

### 4.3 Sin nuevas detecciones del indicador (campaña erradicada)
```kusto
let Indicador = "[dominio-o-sha256]";
AlertEvidence
| where Timestamp > ago(2d)
| where RemoteUrl has Indicador or SHA256 == Indicador or RemoteIP == Indicador
| join kind=inner AlertInfo on AlertId
| project Timestamp, Title, Severity, ServiceSource, DetectionSource
| order by Timestamp desc
// Filas > 0  →  aún hay actividad asociada al indicador.
```

---

## Mapa de queries por playbook

| Playbook | Queries de apoyo |
|---|---|
| **Phishing y BEC (MDO)** | 2.7, 2.8, 3.1, 3.2, 4.3 |
| **Ransomware y Endpoint (MDE)** | 2.2, 2.4, 2.6, 4.2, 4.3 |
| **Compromiso de Identidad (MDI + Entra)** | 2.1, 2.2, 2.5, 3.5, 4.1 |
| **OAuth y Shadow IT (MDA)** | 2.3, 3.3, 3.4 |
| **Triage inicial (todos)** | 1.1, 1.2 |

---

## Referencias

- **Portal:** [Advanced Hunting](https://security.microsoft.com/v2/advanced-hunting) · [Incidentes](https://security.microsoft.com/incidents) · [Alertas](https://security.microsoft.com/alerts) · [Action Center](https://security.microsoft.com/action-center/pending)
- **Paquetes KQL por pilar (repositorio GOL):** MDO · MDE · MDI · Entra ID · MDA (usar para la investigación específica de cada dominio).
- **Documentos relacionados del pilar IR:** `Plan de Respuesta a Incidentes CSIRT.md` y los 4 playbooks en `IR/Playbooks/`.
- **Nota de retención:** los datos de Advanced Hunting tienen ~30 días de retención interactiva; para incidentes más antiguos, apóyate en Microsoft Sentinel.

---

*Proyecto GOL — Guía Operacional de Seguridad Microsoft 365 Defender XDR · Pilar IR (Respuesta a Incidentes).*
