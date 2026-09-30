<!-- AI-SOC Playbook v2.0 · Arturo Mandujano (Cloud Solution Architect) · 28 de septiembre de 2026 -->
[← 5. Catálogo de agentes y agentes personalizados en Copilot Studio](05-agentes.md) | [Índice](README.md) | [7. Requisitos, prerequisitos y readiness →](07-requisitos-readiness.md)

---

# 6. Artefactos técnicos: biblioteca de consultas KQL

Esta sección entrega veintitrés consultas listas para ejecutar, dieciocho de la versión original y cinco nuevas (6.4.9 a 6.4.13) que cubren viaje imposible, cuentas dormidas, picos de fallas de MFA, correlación de indicadores de amenaza y cobertura frente a la matriz MITRE ATT&CK. Las que operan sobre tablas de Defender XDR (prefijos Alert, Device, Email, Identity, Url, CloudAppEvents y ExposureGraph) se ejecutan en advanced hunting dentro del portal de Defender. Las que operan sobre tablas del espacio de trabajo (SecurityIncident, SecurityAlert, SigninLogs, AuditLogs, Usage, Heartbeat, ThreatIntelligenceIndicator) se ejecutan en Microsoft Sentinel o, a través de la herramienta query_lake del Sentinel MCP server, desde un agente de Copilot Studio. Todas las ventanas temporales y los umbrales están parametrizados al inicio de cada consulta para facilitar su ajuste. Cada bloque inicia con un encabezado de comentario estándar (nombre, objetivo, tablas, tier sugerido, validación y autor) para que pueda copiarse directamente a la carpeta /kql del repositorio descrita en el anexo E.

Convención: los valores entre corchetes deben sustituirse con datos de la organización (anexo D). Donde una columna depende de la versión del esquema o del conjunto de productos habilitados, se incluye una nota de validación en el entorno antes de operacionalizar la consulta.

## 6.1 Medición de desempeño del SOC

### 6.1.1 MTTA y MTTR por severidad

Objetivo: establecer la línea base de tiempo de atención y de resolución, que es el numerador de los indicadores de la sección 11.

Tablas: SecurityIncident (Microsoft Sentinel).

```kql
// Nombre: 6.1.1 MTTA y MTTR por severidad
// Objetivo: Línea base de tiempo de atención y de resolución por severidad (últimos 30 días)
// Tablas: SecurityIncident
// Tier sugerido: analytics tier (Microsoft Sentinel)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-01-01-mtta-mttr-por-severidad.kql
// MTTA y MTTR por severidad - ultimos 30 dias
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status == "Closed"
| extend MTTA_min = datetime_diff('minute', FirstModifiedTime, CreatedTime)
| extend MTTR_min = datetime_diff('minute', ClosedTime, CreatedTime)
| where MTTA_min >= 0 and MTTR_min >= 0
| summarize Incidentes = count(),
    MTTA_p50 = percentile(MTTA_min, 50),
    MTTA_p90 = percentile(MTTA_min, 90),
    MTTR_p50 = percentile(MTTR_min, 50),
    MTTR_p90 = percentile(MTTR_min, 90)
    by Severity
| extend OrdenSeveridad = case(Severity == "High", 1, Severity == "Medium", 2,
    Severity == "Low", 3, 4)
| order by OrdenSeveridad asc
| project-away OrdenSeveridad
```

*Nota de validación: arg_max por IncidentNumber conserva la última versión de cada incidente, ya que SecurityIncident es una tabla de instantáneas sucesivas. Confirme que FirstModifiedTime se poble en el entorno; si el SOC trabaja incidentes exclusivamente desde el portal de Defender, sustituya el cálculo de MTTA por la primera transición de estado registrada.*

### 6.1.2 Tendencia semanal de MTTR con serie temporal

Objetivo: mostrar la evolución del MTTR en el comité mensual y validar el efecto de cada fase del proyecto.

Tablas: SecurityIncident (Microsoft Sentinel).

```kql
// Nombre: 6.1.2 Tendencia semanal de MTTR
// Objetivo: Evolución semanal del MTTR para el comité mensual (últimos 180 días)
// Tablas: SecurityIncident
// Tier sugerido: analytics tier (Microsoft Sentinel)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-01-02-tendencia-semanal-mttr.kql
// Tendencia de MTTR por semana - ultimos 180 dias
SecurityIncident
| where TimeGenerated > ago(180d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status == "Closed"
| extend MTTR_min = datetime_diff('minute', ClosedTime, CreatedTime)
| where MTTR_min >= 0
| make-series MTTR_prom = avg(MTTR_min) default = 0
    on ClosedTime from ago(180d) to now() step 7d by Severity
| render timechart
```

### 6.1.3 Volumen y tasa de falsos positivos por origen de detección

Objetivo: identificar qué productos y reglas generan el ruido que consume capacidad del equipo, insumo directo de SOC optimization.

Tablas: SecurityIncident (Microsoft Sentinel).

```kql
// Nombre: 6.1.3 Falsos positivos por origen de detección
// Objetivo: Volumen y tasa de falsos positivos por producto y regla (90 días)
// Tablas: SecurityIncident
// Tier sugerido: analytics tier (Microsoft Sentinel)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-01-03-falsos-positivos-por-origen.kql
// Tasa de falsos positivos por producto de deteccion - 90 dias
SecurityIncident
| where TimeGenerated > ago(90d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status == "Closed"
| mv-expand Producto = todynamic(AdditionalData).alertProductNames
    to typeof(string)
| summarize Total = count(),
    FalsosPositivos = countif(Classification == "FalsePositive"),
    BenignosPositivos = countif(Classification == "BenignPositive"),
    VerdaderosPositivos = countif(Classification == "TruePositive")
    by Producto
| extend TasaFP_pct = round(100.0 * FalsosPositivos / Total, 1)
| extend TasaRuido_pct = round(100.0 * (FalsosPositivos + BenignosPositivos) / Total, 1)
| where Total >= 10
| order by TasaRuido_pct desc
```

*Nota de validación: la ruta AdditionalData.alertProductNames existe en los incidentes generados por Sentinel; valide la presencia del campo antes de publicar el reporte y, si el entorno trabaja incidentes en el portal de Defender, complemente con la consulta 6.2.1 sobre AlertInfo.*

## 6.2 Actividad y contribución de los agentes

### 6.2.1 Alertas generadas por el Dynamic Threat Detection Agent

Objetivo: cuantificar las detecciones aportadas por el agente de detección dinámica, que se publican con origen de detección "Security Copilot".

Tablas: AlertInfo y AlertEvidence (advanced hunting, Defender XDR).

```kql
// Nombre: 6.2.1 Alertas del Dynamic Threat Detection Agent
// Objetivo: Detecciones publicadas con origen Security Copilot (30 días)
// Tablas: AlertInfo, AlertEvidence
// Tier sugerido: advanced hunting (Defender XDR)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-02-01-alertas-dynamic-threat-detection.kql
// Alertas con origen Security Copilot - 30 dias
AlertInfo
| where Timestamp > ago(30d)
| where DetectionSource == "Security Copilot"
    or ServiceSource == "Security Copilot"
| join kind=leftouter (
AlertEvidence
| where Timestamp > ago(30d)
| summarize Entidades = dcount(EntityType),
    Dispositivos = dcountif(DeviceId, isnotempty(DeviceId)),
    Cuentas = dcountif(AccountUpn, isnotempty(AccountUpn))
    by AlertId
) on AlertId
| summarize Alertas = count(),
    EntidadesProm = round(avg(Entidades), 1),
    DispositivosProm = round(avg(Dispositivos), 1),
    CuentasProm = round(avg(Cuentas), 1),
    Titulos = make_set(Title, 25)
    by bin(Timestamp, 1d), Severity, Category
| order by Timestamp desc, Alertas desc
```

### 6.2.2 Incidentes atendidos o etiquetados por agentes

Objetivo: medir la contribución del Phishing Triage Agent y de cualquier otro agente que etiquete incidentes con "Agent" o que actúe con una cuenta agéntica.

Tablas: SecurityIncident (Microsoft Sentinel).

```kql
// Nombre: 6.2.2 Incidentes atendidos o etiquetados por agentes
// Objetivo: Contribución de los agentes sobre incidentes con etiqueta Agent o cuenta agéntica (30 días)
// Tablas: SecurityIncident
// Tier sugerido: analytics tier (Microsoft Sentinel)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-02-02-incidentes-atendidos-por-agentes.kql
// Contribucion de agentes sobre incidentes - 30 dias
let Ventana = 30d;
SecurityIncident
| where TimeGenerated > ago(Ventana)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend Etiquetas = tostring(Labels),
    Propietario = tostring(todynamic(Owner).userName),
    Comentarios = tostring(Comments)
| extend EsAgente = Etiquetas has "Agent"
    or Propietario has "SecurityCopilotAgentUser"
    or Comentarios has "SecurityCopilotAgentUser"
| summarize Incidentes = count(),
    Cerrados = countif(Status == "Closed"),
    MTTR_p50_min = percentile(datetime_diff('minute', ClosedTime, CreatedTime), 50)
    by EsAgente, Severity
| extend Segmento = iff(EsAgente, "Atendido por agente", "Atendido por analista")
| project Segmento, Severity, Incidentes, Cerrados, MTTR_p50_min
| order by Segmento asc, Severity asc
```

*Nota de validación: Labels, Owner y Comments son columnas dinámicas; la conversión con tostring permite el operador has. Confirme el formato exacto de la cuenta agéntica creada en el tenant (SecurityCopilotAgentUser-...@`<dominio>`) y sustitúyalo si difiere.*

### 6.2.3 Auditoría de la actividad de agentes en CloudAppEvents

Objetivo: auditar qué agentes se ejecutaron, sobre qué carga de trabajo y con qué resultado, como evidencia para el proceso de gobierno.

Tablas: CloudAppEvents (advanced hunting, Defender XDR).

```kql
// Nombre: 6.2.3 Auditoría de agentes en CloudAppEvents
// Objetivo: Qué agentes se ejecutaron, sobre qué carga y con qué resultado (30 días)
// Tablas: CloudAppEvents
// Tier sugerido: advanced hunting (Defender XDR)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-02-03-auditoria-agentes-cloudappevents.kql
// Auditoria de actividad de agentes de Security Copilot - 30 dias
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has "CopilotAgent"
| extend Raw = todynamic(RawEventData)
| extend AgentName = tostring(Raw.AgentName),
    Workload = tostring(Raw.Workload),
    Resultado = tostring(Raw.ResultStatus)
| summarize Eventos = count(),
    Exitosos = countif(Resultado =~ "Success"),
    Fallidos = countif(Resultado !~ "Success" and isnotempty(Resultado)),
    Acciones = make_set(ActionType, 20)
    by AgentName, Workload, bin(Timestamp, 1d)
| extend TasaExito_pct = round(100.0 * Exitosos / Eventos, 1)
| order by Timestamp desc, Eventos desc
```

*Nota de validación: CloudAppEvents registra actividad únicamente del Phishing Triage Agent y del Conditional Access Optimization Agent. Para el resto de los agentes, la evidencia de uso debe obtenerse del monitoreo de uso en el portal de Security Copilot.*

### 6.2.4 Gobierno de las identidades agénticas

Objetivo: verificar que las cuentas de agente no acumulen privilegios ni se utilicen fuera del patrón esperado.

Tablas: AuditLogs (Microsoft Sentinel).

```kql
// Nombre: 6.2.4 Gobierno de identidades agénticas
// Objetivo: Operaciones de directorio asociadas a cuentas de agente (30 días)
// Tablas: AuditLogs
// Tier sugerido: analytics tier (Microsoft Sentinel)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-02-04-gobierno-identidades-agenticas.kql
// Operaciones de directorio asociadas a identidades agenticas - 30 dias
AuditLogs
| where TimeGenerated > ago(30d)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName),
    Objetivo = tostring(TargetResources[0].displayName),
    TipoObjetivo = tostring(TargetResources[0].type)
| where Actor has "SecurityCopilotAgentUser"
    or Objetivo has "SecurityCopilotAgentUser"
| project TimeGenerated, OperationName, Category,
    Resultado = tostring(Result), Actor, Objetivo, TipoObjetivo
| order by TimeGenerated desc
```

## 6.3 Higiene de la plataforma de datos

### 6.3.1 Costo e higiene de ingesta por tabla

Objetivo: priorizar el tiering y detectar tablas cuyo costo de ingesta no se corresponde con su valor de detección.

Tablas: Usage (Microsoft Sentinel).

```kql
// Nombre: 6.3.1 Costo e higiene de ingesta por tabla
// Objetivo: Volumen facturable y costo estimado por tabla para priorizar el tiering (30 días)
// Tablas: Usage
// Tier sugerido: analytics tier (Microsoft Sentinel)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-03-01-costo-ingesta-por-tabla.kql
// Volumen facturable y costo estimado por tabla - 30 dias
let PrecioPorGB = 0.0; // sustituir por [precio negociado por GB]
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize GB = round(sum(Quantity) / 1024.0, 2) by DataType
| extend CostoEstimadoUSD = round(GB * PrecioPorGB, 2)
| extend GB_por_dia = round(GB / 30.0, 2)
| order by GB desc
| take 30
```

### 6.3.2 Fuentes en silencio: latido de los agentes de datos

Objetivo: detectar equipos o recolectores que dejaron de reportar, una de las causas más frecuentes de puntos ciegos.

Tablas: Heartbeat (Microsoft Sentinel).

```kql
// Nombre: 6.3.2 Fuentes en silencio
// Objetivo: Equipos y recolectores que dejaron de reportar latido
// Tablas: Heartbeat
// Tier sugerido: analytics tier (Microsoft Sentinel)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-03-02-fuentes-en-silencio.kql
// Equipos sin latido en las ultimas horas
let UmbralHoras = 2.0;
Heartbeat
| where TimeGenerated > ago(7d)
| summarize UltimoLatido = max(TimeGenerated), Latidos = count()
    by Computer, Category, OSType, Version
| extend HorasSinReportar = round(datetime_diff('minute', now(), UltimoLatido) / 60.0, 1)
| where HorasSinReportar > UmbralHoras
| order by HorasSinReportar desc
```

### 6.3.3 Cobertura de conectores por proveedor de alertas

Objetivo: verificar que cada producto conectado siga produciendo alertas y detectar conectores rotos sin esperar al incidente que los revele.

Tablas: SecurityAlert (Microsoft Sentinel).

```kql
// Nombre: 6.3.3 Cobertura de conectores por proveedor
// Objetivo: Proveedores de alertas que dejaron de producir señal (30 días)
// Tablas: SecurityAlert
// Tier sugerido: analytics tier (Microsoft Sentinel)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-03-03-cobertura-conectores-por-proveedor.kql
// Actividad de alertas por proveedor - 30 dias
SecurityAlert
| where TimeGenerated > ago(30d)
| summarize Alertas = count(),
    Primera = min(TimeGenerated),
    Ultima = max(TimeGenerated),
    Severidades = make_set(AlertSeverity, 10)
    by ProviderName, ProductName
| extend DiasSinAlertas = round(datetime_diff('hour', now(), Ultima) / 24.0, 1)
| order by DiasSinAlertas desc, Alertas asc
```

## 6.4 Detección y cacería

### 6.4.1 Password spray sobre inicios de sesión

Objetivo: detectar un origen único que intenta pocas contraseñas contra muchas cuentas, patrón consistente con el 99% de ataques de identidad basados en contraseña (Microsoft Digital Defense Report, 2024).

Tablas: SigninLogs (Microsoft Sentinel).

```kql
// Nombre: 6.4.1 Password spray sobre inicios de sesión
// Objetivo: Un origen que intenta pocas contraseñas contra muchas cuentas (24 horas)
// Tablas: SigninLogs
// Tier sugerido: analytics tier (Microsoft Sentinel)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-04-01-password-spray.kql
// Password spray: muchos usuarios, mismo origen - 24 horas
let UmbralUsuarios = 10;
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType in ("50126", "50053", "50055", "50056", "50076")
| extend Pais = tostring(LocationDetails.countryOrRegion)
| summarize IntentosFallidos = count(),
    UsuariosDistintos = dcount(UserPrincipalName),
    Usuarios = make_set(UserPrincipalName, 100),
    Apps = make_set(AppDisplayName, 20)
    by IPAddress, Pais, bin(TimeGenerated, 1h)
| where UsuariosDistintos >= UmbralUsuarios
| order by UsuariosDistintos desc, IntentosFallidos desc
```

### 6.4.2 Adversary-in-the-middle: clic en URL seguido de sesión exitosa

Objetivo: correlacionar el clic en una URL de phishing con un inicio de sesión no interactivo exitoso en una ventana corta, patrón característico de AiTM, cuyos ataques crecieron 46% (Microsoft Digital Defense Report, 2024).

Tablas: UrlClickEvents (Defender XDR) y AADNonInteractiveUserSignInLogs (Microsoft Sentinel).

```kql
// Nombre: 6.4.2 Adversary-in-the-middle
// Objetivo: Clic en URL de phishing seguido de sesión no interactiva exitosa en 30 minutos (7 días)
// Tablas: UrlClickEvents, AADNonInteractiveUserSignInLogs
// Tier sugerido: analytics tier (Microsoft Sentinel) con datos de Defender XDR
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-04-02-aitm-clic-y-sesion.kql
// AiTM: clic en URL y sesion exitosa dentro de 30 minutos - 7 dias
let Ventana = 30m;
let Clics =
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType == "ClickAllowed"
| project ClickTime = Timestamp,
    Usuario = tolower(AccountUpn),
    Url, NetworkMessageId, IPAddress;
Clics
| join kind=inner (
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| project SignInTime = TimeGenerated,
    Usuario = tolower(UserPrincipalName),
    SignInIP = IPAddress, AppDisplayName, UserAgent
) on Usuario
| where SignInTime between (ClickTime .. ClickTime + Ventana)
| project Usuario, ClickTime, SignInTime, Url, IPAddress,
    SignInIP, AppDisplayName, UserAgent
| order by ClickTime desc
```

*Nota de validación: UrlClickEvents reside en advanced hunting y AADNonInteractiveUserSignInLogs en el espacio de trabajo de Sentinel; la correlación entre ambas requiere que Defender XDR esté conectado al espacio de trabajo o que la consulta se ejecute en el portal unificado. Valide los valores de ActionType disponibles en el entorno.*

### 6.4.3 Movimiento lateral por volumen de destinos

Objetivo: identificar cuentas que autentican contra un número inusual de dispositivos destino en un día, señal temprana de movimiento lateral.

Tablas: DeviceLogonEvents (advanced hunting, Defender XDR).

```kql
// Nombre: 6.4.3 Movimiento lateral por volumen de destinos
// Objetivo: Cuentas que autentican contra un número inusual de dispositivos en un día (7 días)
// Tablas: DeviceLogonEvents
// Tier sugerido: advanced hunting (Defender XDR)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-04-03-movimiento-lateral-destinos.kql
// Movimiento lateral: una cuenta hacia muchos destinos - 7 dias
let UmbralDestinos = 5;
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where LogonType in ("Network", "RemoteInteractive")
| where isnotempty(RemoteIP)
| summarize DispositivosDestino = dcount(DeviceId),
    Destinos = make_set(DeviceName, 50),
    OrigenesIP = make_set(RemoteIP, 20),
    Intentos = count()
    by AccountName, AccountDomain, bin(Timestamp, 1d)
| where DispositivosDestino >= UmbralDestinos
| order by DispositivosDestino desc
```

*Nota de validación: excluya de la salida las cuentas de servicio y de administración de inventario de la organización mediante una lista de exclusión, para evitar un volumen alto de falsos positivos operativos.*

### 6.4.4 Ransomware temprano: destrucción de respaldos y copias sombra

Objetivo: detectar la fase previa al cifrado, donde el atacante elimina mecanismos de recuperación; es el escenario que attack disruption interrumpe en un promedio de tres minutos (Microsoft, Coordinated Defense, 2025).

Tablas: DeviceProcessEvents (advanced hunting, Defender XDR).

```kql
// Nombre: 6.4.4 Ransomware temprano
// Objetivo: Comandos de destrucción de respaldos y copias sombra previos al cifrado (7 días)
// Tablas: DeviceProcessEvents
// Tier sugerido: advanced hunting (Defender XDR)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-04-04-ransomware-destruccion-respaldos.kql
// Comandos de destruccion de respaldos - 7 dias
let Destructivos = dynamic([
    "vssadmin delete shadows", "vssadmin resize shadowstorage",
    "wbadmin delete catalog", "wbadmin delete systemstatebackup",
    "wmic shadowcopy delete", "bcdedit /set", "cipher /w"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any (Destructivos)
| project Timestamp, DeviceName, DeviceId, AccountDomain, AccountName,
    FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 6.4.5 Concentración de detecciones de antivirus por dispositivo

Objetivo: complementar la consulta anterior con la señal de detección masiva en un mismo equipo, indicio de cifrado en curso.

Tablas: DeviceEvents (advanced hunting, Defender XDR).

```kql
// Nombre: 6.4.5 Ráfagas de detección de antivirus
// Objetivo: Concentración de detecciones de antivirus por dispositivo, indicio de cifrado en curso (24 horas)
// Tablas: DeviceEvents
// Tier sugerido: advanced hunting (Defender XDR)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-04-05-rafagas-antivirus-por-dispositivo.kql
// Rafagas de deteccion de antivirus por dispositivo - 24 horas
let UmbralDetecciones = 5;
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "AntivirusDetection"
| extend Amenaza = tostring(todynamic(AdditionalFields).ThreatName)
| summarize Detecciones = count(),
    Amenazas = make_set(Amenaza, 25),
    Archivos = dcount(FileName),
    Primera = min(Timestamp), Ultima = max(Timestamp)
    by DeviceId, DeviceName, bin(Timestamp, 1h)
| where Detecciones >= UmbralDetecciones
| extend DuracionMin = datetime_diff('minute', Ultima, Primera)
| order by Detecciones desc
```

*Nota de validación: el nombre de la amenaza se publica en AdditionalFields y su clave puede variar según la versión del sensor; valide la estructura con una consulta exploratoria antes de fijar la extracción.*

### 6.4.6 Rutas de exposición hacia activos críticos

Objetivo: hacer explícitas las relaciones que un atacante podría recorrer hasta un activo crítico, aprovechando que el 22% de las organizaciones tenía una ruta de ataque identificada en la nube (Microsoft Digital Defense Report, 2024).

Tablas: ExposureGraphNodes y ExposureGraphEdges (advanced hunting, Defender XDR).

```kql
// Nombre: 6.4.6 Rutas de exposición hacia activos críticos
// Objetivo: Relaciones entrantes del grafo de exposición hacia activos críticos
// Tablas: ExposureGraphNodes, ExposureGraphEdges
// Tier sugerido: advanced hunting (Defender XDR)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-04-06-rutas-exposicion-activos-criticos.kql
// Relaciones entrantes hacia activos criticos
let Criticos =
ExposureGraphNodes
| where set_has_element(Categories, "critical_asset")
| project TargetNodeId = NodeId,
    ActivoCritico = NodeName,
    TipoCritico = NodeLabel;
ExposureGraphEdges
| where EdgeLabel in ("can authenticate to", "has permissions to",
    "can remote interactive logon to", "contains")
| join kind=inner Criticos on TargetNodeId
| join kind=inner (
ExposureGraphNodes
| project SourceNodeId = NodeId,
    Origen = NodeName, TipoOrigen = NodeLabel
) on SourceNodeId
| summarize Rutas = count(), Origenes = make_set(Origen, 50)
    by ActivoCritico, TipoCritico, EdgeLabel, TipoOrigen
| order by Rutas desc
```

*Nota de validación: el conjunto de valores de EdgeLabel y de Categories evoluciona con el servicio; ejecute primero un resumen exploratorio (ExposureGraphEdges | summarize count() by EdgeLabel) y ajuste la lista a los valores presentes en el tenant.*

### 6.4.7 Cobertura de detección por técnica de MITRE ATT&CK

Objetivo: medir qué técnicas están efectivamente cubiertas por detecciones activas y alimentar al agente de validación de cobertura descrito en la sección 5.3.

Tablas: AlertInfo (advanced hunting, Defender XDR).

```kql
// Nombre: 6.4.7 Cobertura observada por técnica ATT&CK
// Objetivo: Técnicas cubiertas por detecciones activas observadas en alertas (90 días)
// Tablas: AlertInfo
// Tier sugerido: advanced hunting (Defender XDR)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-04-07-cobertura-tecnicas-attck.kql
// Cobertura observada por tecnica ATT&CK - 90 dias
AlertInfo
| where Timestamp > ago(90d)
| where isnotempty(AttackTechniques)
| extend Tecnicas = extract_all(@"T\d{4}(?:\.\d{3})?",
    tostring(AttackTechniques))
| mv-expand Tecnica = Tecnicas to typeof(string)
| summarize Alertas = count(),
    Fuentes = make_set(DetectionSource, 20),
    Categorias = make_set(Category, 20),
    Ultima = max(Timestamp)
    by Tecnica
| order by Alertas desc
```

### 6.4.8 Correo de phishing entregado y remediado después de la entrega

Objetivo: medir la eficacia de la remediación posterior a la entrega sobre el flujo de correo malicioso, en un contexto de 775 millones de correos con malware detectados en el último año (Microsoft Digital Defense Report, 2024).

Tablas: EmailEvents y EmailPostDeliveryEvents (advanced hunting, Defender XDR).

```kql
// Nombre: 6.4.8 Phishing entregado y remediado
// Objetivo: Eficacia de la remediación posterior a la entrega sobre correo malicioso (7 días)
// Tablas: EmailEvents, EmailPostDeliveryEvents
// Tier sugerido: advanced hunting (Defender XDR)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-04-08-phishing-entregado-remediado.kql
// Phishing entregado y remediacion posterior - 7 dias
let Post =
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| summarize AccionesPost = make_set(ActionType, 10),
    ResultadoPost = make_set(ActionResult, 10)
    by NetworkMessageId;
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish" or ThreatTypes has "Malware"
| join kind=leftouter Post on NetworkMessageId
| summarize Mensajes = count(),
    Entregados = countif(DeliveryAction == "Delivered"),
    Bloqueados = countif(DeliveryAction == "Blocked"),
    Remediados = countif(DeliveryAction == "Delivered"
        and array_length(AccionesPost) > 0)
    by bin(Timestamp, 1d), ThreatTypes
| extend TasaRemediacion_pct =
    iff(Entregados > 0, round(100.0 * Remediados / Entregados, 1), 0.0)
| order by Timestamp desc
```

### 6.4.9 Viaje imposible entre inicios de sesión consecutivos

Objetivo: detectar cuentas con dos autenticaciones exitosas consecutivas cuya distancia geográfica es incompatible con el tiempo transcurrido, señal de sesión robada o credencial compartida. Es uno de los casos documentados para el Sentinel MCP server y el agente CS-2 lo usa como evidencia previa a analyze_user_entity.

Tablas: SigninLogs (Microsoft Sentinel).

```kql
// Nombre: 6.4.9 Viaje imposible
// Objetivo: Dos inicios exitosos consecutivos incompatibles con la distancia recorrida (24 horas)
// Tablas: SigninLogs
// Tier sugerido: analytics tier (Microsoft Sentinel) o data lake
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-04-09-viaje-imposible.kql
// Viaje imposible: dos inicios exitosos consecutivos incompatibles con la distancia - 24 horas
let VelocidadMaxKmh = 900;
let DistanciaMinKm = 500;
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "0"
| extend Lat = toreal(LocationDetails.geoCoordinates.latitude),
    Lon = toreal(LocationDetails.geoCoordinates.longitude),
    Pais = tostring(LocationDetails.countryOrRegion),
    Ciudad = tostring(LocationDetails.city)
| where isnotnull(Lat) and isnotnull(Lon)
| sort by UserPrincipalName asc, TimeGenerated asc
| extend PrevUsuario = prev(UserPrincipalName), PrevTiempo = prev(TimeGenerated),
    PrevLat = prev(Lat), PrevLon = prev(Lon),
    PrevPais = prev(Pais), PrevCiudad = prev(Ciudad), PrevIP = prev(IPAddress)
| where PrevUsuario == UserPrincipalName
| extend DistanciaKm = geo_distance_2points(PrevLon, PrevLat, Lon, Lat) / 1000.0,
    Horas = datetime_diff('second', TimeGenerated, PrevTiempo) / 3600.0
| where DistanciaKm >= DistanciaMinKm and Horas > 0
| extend VelocidadKmh = DistanciaKm / Horas
| where VelocidadKmh > VelocidadMaxKmh
| project TimeGenerated, UserPrincipalName, PrevTiempo, PrevCiudad, PrevPais, PrevIP,
    Ciudad, Pais, IPAddress, AppDisplayName,
    DistanciaKm = round(DistanciaKm), Horas = round(Horas, 2),
    VelocidadKmh = round(VelocidadKmh)
| order by VelocidadKmh desc
```

*Nota de validación: geoCoordinates se llena a partir de la geolocalización de la IP y puede faltar en direcciones de proveedores de nube o en redes privadas; la consulta descarta esos registros. Excluya con una watchlist las IP de VPN corporativa y de proxy en la nube de la organización, que producen viajes imposibles legítimos. Como alternativa cuando geoCoordinates no esté disponible, compare Pais con PrevPais y exija Horas menor a 2.*

### 6.4.10 Cuentas dormidas que reviven

Objetivo: identificar cuentas sin autenticación exitosa durante 90 días que volvieron a autenticar en los últimos 7, patrón de reactivación de cuentas olvidadas o de personal que ya no debería tener acceso. Es la base del agente CS-9 y devuelve el UserId (identificador de objeto de Entra) que requiere analyze_user_entity.

Tablas: SigninLogs (Microsoft Sentinel; recomendado sobre el data lake tier por la retención requerida).

```kql
// Nombre: 6.4.10 Cuentas dormidas que reviven
// Objetivo: Cuentas sin inicio exitoso en 90 días que autenticaron en los últimos 7
// Tablas: SigninLogs
// Tier sugerido: data lake tier (Microsoft Sentinel, via query_lake) por la retención requerida
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-04-10-cuentas-dormidas-reviven.kql
// Cuentas dormidas que reviven: sin inicio exitoso en 90 dias, activas en los ultimos 7
let Dormida = 90d;
let Reciente = 7d;
let Activas = SigninLogs
| where TimeGenerated > ago(Reciente)
| where ResultType == "0"
| summarize PrimerRegreso = min(TimeGenerated), IniciosRecientes = count(),
    IPs = make_set(IPAddress, 20),
    Apps = make_set(AppDisplayName, 20),
    Paises = make_set(tostring(LocationDetails.countryOrRegion), 10)
    by UserPrincipalName, UserId;
let Previas = SigninLogs
| where TimeGenerated between (ago(Dormida + Reciente) .. ago(Reciente))
| where ResultType == "0"
| summarize UltimoInicioPrevio = max(TimeGenerated) by UserPrincipalName;
Activas
| join kind=leftanti Previas on UserPrincipalName
| project UserPrincipalName, UserId, PrimerRegreso, IniciosRecientes, IPs, Apps, Paises
| order by PrimerRegreso asc
```

*Nota de validación: la consulta necesita 97 días de historia; si el analytics tier retiene [90] días, ejecútela con query_lake sobre el data lake tier o promueva SigninLogs temporalmente. Excluya las cuentas creadas en los últimos 97 días (AuditLogs, OperationName "Add user") para no confundir altas nuevas con reactivaciones, y cruce el resultado con el estado de la cuenta en Entra (AccountEnabled) y con la fecha de baja en el sistema de recursos humanos de la organización.*

### 6.4.11 Picos de fallas de MFA por usuario

Objetivo: detectar ráfagas anómalas de fallas de autenticación multifactor por usuario, patrón de fatiga de MFA (el atacante ya tiene la contraseña y bombardea al usuario con solicitudes) o de bloqueo intencional. La descomposición de series aísla los picos respecto al comportamiento habitual de cada cuenta en lugar de usar un umbral fijo.

Tablas: SigninLogs (Microsoft Sentinel).

```kql
// Nombre: 6.4.11 Picos de fallas de MFA por usuario
// Objetivo: Ráfagas anómalas de fallas de MFA por descomposición de series (14 días)
// Tablas: SigninLogs
// Tier sugerido: analytics tier (Microsoft Sentinel)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-04-11-picos-fallas-mfa.kql
// Picos de fallas de MFA por usuario - 14 dias, series por hora
let Ventana = 14d;
let Paso = 1h;
SigninLogs
| where TimeGenerated > ago(Ventana)
| where ResultType == "500121"
| make-series Fallas = count() default = 0
    on TimeGenerated from ago(Ventana) to now() step Paso by UserPrincipalName
| extend (Anomalias, Puntaje, LineaBase) = series_decompose_anomalies(Fallas, 2.5, -1, 'linefit')
| mv-expand TimeGenerated to typeof(datetime), Fallas to typeof(long),
    Anomalias to typeof(double), Puntaje to typeof(double)
| where Anomalias > 0 and Fallas >= 5
| project TimeGenerated, UserPrincipalName, Fallas, Puntaje = round(Puntaje, 2)
| order by Puntaje desc
```

*Nota de validación: el código 500121 corresponde a una falla durante la solicitud de autenticación fuerte. Para la vista por origen sustituya UserPrincipalName por IPAddress en la cláusula by; para detectar el ataque en curso reduzca Ventana a 2d y Paso a 10m. Un pico seguido de un inicio exitoso desde la misma IP es la señal que debe escalarse al runbook 9.2 y al agente CS-2.*

### 6.4.12 Correlación de indicadores de amenaza contra telemetría de red

Objetivo: verificar si los indicadores del boletín semanal (IP, dominios y URL) aparecen en las conexiones de los endpoints o en los registros de firewall y proxy, cerrando el ciclo entre inteligencia y detección. Es la consulta que el agente CS-5 ejecuta con query_lake después de generar el boletín.

Tablas: ThreatIntelligenceIndicator, CommonSecurityLog (Microsoft Sentinel) y DeviceNetworkEvents (Defender XDR, ingerida en el espacio de trabajo mediante el conector de Defender XDR).

```kql
// Nombre: 6.4.12 Correlación de indicadores contra telemetría de red
// Objetivo: Indicadores del boletín (IP, dominio, URL) observados en endpoints y CEF (7 días)
// Tablas: ThreatIntelligenceIndicator, CommonSecurityLog, DeviceNetworkEvents
// Tier sugerido: data lake tier (Microsoft Sentinel, via query_lake)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-04-12-correlacion-indicadores-red.kql
// Correlacion de indicadores (IP, dominio, URL) contra red de endpoints y CEF - 7 dias
let Ventana = 7d;
let IOC = ThreatIntelligenceIndicator
| where TimeGenerated > ago(90d)
| where Active == true and ExpirationDateTime > now()
| extend Indicador = tolower(coalesce(NetworkDestinationIP, NetworkIP, DomainName, Url))
| where isnotempty(Indicador)
| summarize arg_max(TimeGenerated, *) by Indicador
| project Indicador, Descripcion = Description, Confianza = ConfidenceScore,
    TipoAmenaza = ThreatType, FuenteTI = SourceSystem;
let RedEndpoints = DeviceNetworkEvents
| where TimeGenerated > ago(Ventana)
| extend Indicador = tolower(iff(isnotempty(RemoteUrl), RemoteUrl, RemoteIP))
| where isnotempty(Indicador)
| project Hora = TimeGenerated, Origen = "DeviceNetworkEvents", Equipo = DeviceName,
    Cuenta = InitiatingProcessAccountName, Detalle = InitiatingProcessFileName, Indicador;
let CEF = CommonSecurityLog
| where TimeGenerated > ago(Ventana)
| extend Indicador = tolower(coalesce(DestinationIP, RequestURL, DestinationHostName))
| where isnotempty(Indicador)
| project Hora = TimeGenerated, Origen = DeviceVendor, Equipo = DeviceName,
    Cuenta = SourceUserName, Detalle = DeviceProduct, Indicador;
union RedEndpoints, CEF
| join kind=inner IOC on Indicador
| summarize Coincidencias = count(), Primera = min(Hora), Ultima = max(Hora),
    Equipos = make_set(Equipo, 20), Cuentas = make_set(Cuenta, 20)
    by Indicador, TipoAmenaza, Confianza, Descripcion, FuenteTI, Origen
| order by Confianza desc, Coincidencias desc
```

*Nota de validación: la coincidencia es exacta; RemoteUrl y RequestURL suelen incluir esquema y ruta, por lo que para dominios conviene extraer el host con parse_url antes de comparar. Si el espacio de trabajo ya migró al nuevo esquema de inteligencia de amenazas (tabla ThreatIntelIndicators), sustituya la fuente y las columnas de indicador conforme a la documentación vigente. El volumen de CommonSecurityLog justifica ejecutar esta consulta sobre el data lake tier con query_lake.*

### 6.4.13 Cobertura de detecciones frente a la matriz MITRE ATT&CK priorizada

Objetivo: comparar las técnicas efectivamente observadas en alertas de los últimos 90 días contra la matriz de técnicas que el perfil de amenazas de la organización considera prioritarias, y clasificar cada técnica como cubierta, detectada pero inactiva o sin detección observada. Complementa la consulta 6.4.7 (que sólo enumera lo observado) y es el insumo mensual del agente CS-7 y del reporte de cobertura de la tabla 32.

Tablas: SecurityAlert (Microsoft Sentinel).

```kql
// Nombre: 6.4.13 Cobertura frente a la matriz ATT&CK priorizada
// Objetivo: Técnicas prioritarias cubiertas, inactivas o sin detección observada (90 días)
// Tablas: SecurityAlert
// Tier sugerido: analytics tier (Microsoft Sentinel)
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/06-04-13-cobertura-matriz-priorizada.kql
// Cobertura frente a la matriz priorizada de MITRE ATT&CK - 90 dias
// Sustituya la matriz por el perfil de amenazas de la organización (parámetro del anexo D)
let Matriz = datatable(Tecnica:string, Tactica:string, Prioridad:string) [
    "T1566", "InitialAccess", "1-Alta",
    "T1078", "DefenseEvasion", "1-Alta",
    "T1110", "CredentialAccess", "1-Alta",
    "T1557", "CredentialAccess", "1-Alta",
    "T1021", "LateralMovement", "1-Alta",
    "T1490", "Impact", "1-Alta",
    "T1486", "Impact", "1-Alta",
    "T1098", "Persistence", "2-Media",
    "T1114", "Collection", "2-Media",
    "T1567", "Exfiltration", "2-Media"
];
let Observadas = SecurityAlert
| where TimeGenerated > ago(90d)
| where isnotempty(Techniques)
| mv-expand Tecnica = todynamic(Techniques) to typeof(string)
| extend Tecnica = extract(@"(T\d{4})", 1, Tecnica)
| where isnotempty(Tecnica)
| summarize Alertas = count(), Reglas = dcount(AlertName),
    Proveedores = make_set(ProviderName, 10), Ultima = max(TimeGenerated)
    by Tecnica;
Matriz
| join kind=leftouter Observadas on Tecnica
| extend Estado = case(isnull(Alertas) or Alertas == 0, "Sin deteccion observada",
    Ultima < ago(30d), "Detectada pero inactiva 30 dias",
    "Cubierta")
| project Prioridad, Tactica, Tecnica, Estado, Alertas = coalesce(Alertas, 0),
    Reglas, Proveedores, Ultima
| order by Prioridad asc, Estado desc
```

*Nota de validación: la columna Techniques de SecurityAlert la llenan los proveedores que mapean sus detecciones a ATT&CK (Defender XDR, Sentinel, Defender for Cloud); las reglas analíticas propias deben llevar el mapeo configurado para aparecer. Una técnica sin detección observada no implica ausencia de regla, sino ausencia de disparo: confirme con el inventario de reglas de Sentinel y de Defender antes de abrir un backlog. Para técnicas con subtécnicas ajuste la expresión regular a `T\d{4}(\.\d{3})?`, como en la consulta 6.4.7.*


---

[← 5. Catálogo de agentes y agentes personalizados en Copilot Studio](05-agentes.md) | [Índice](README.md) | [7. Requisitos, prerequisitos y readiness →](07-requisitos-readiness.md)
