# Guía de Seguridad Operacional Semanal: Microsoft Defender for Endpoint 🛡️
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

Esta guía establece los procedimientos semanales para analizar tendencias de amenazas, ejecutar hunting proactivo, gestionar vulnerabilidades y revisar la postura de seguridad de endpoints en Microsoft Defender for Endpoint (MDE).


## Alcance

Esta guía describe actividades **operativas semanales** para Microsoft Defender for Endpoint (MDE), enfocadas en:

---
## Índice
- [Análisis de Tendencias de Amenazas](https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#an%C3%A1lisis-de-tendencias-de-amenazas)
- [Advanced Hunting Semanal](https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#advanced-hunting-semanal)
- [Exposición y Vulnerabilidades](https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#exposici%C3%B3n-y-vulnerabilidades)
- [Revisión de Configuraciones de Seguridad](https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#revisi%C3%B3n-de-configuraciones-de-seguridad)
- [Dispositivos Reincidentes](https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#dispositivos-reincidentes)
- [Reporte Operativo / Ejecutivo](https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#reporte-operativo--ejecutivo)

---
# Análisis de Tendencias de Amenazas

## Acceso a Threat Analytics

1. Ir a: https://security.microsoft.com/threatanalytics3
2. Revisar amenazas marcadas como **Active** o **Trending**
3. Filtrar por **Service source:** Microsoft Defender for Endpoint

El panel muestra:
* Amenazas activas y emergentes
* Dispositivos expuestos vs. mitigados
* TTPs utilizadas por los actores de amenaza
* IOCs asociados

## Identificar Patrones Recurrentes

Revisar las amenazas de la última semana y buscar:
* Familias de malware recurrentes (Emotet, QakBot, Cobalt Strike, etc.)
* Técnicas prevalentes (LOLBins, PowerShell abuse, DLL sideloading)
* Patrones de persistencia detectados (RunKeys, Scheduled Tasks, WMI)
* Vectores de entrada comunes (phishing → endpoint, USB, RDP expuesto)

## Evaluar Impacto y Estado de Mitigaciones

Para cada amenaza de alto impacto:

1. Abrir el **Analyst report** para revisar:
    * Descripción técnica del ataque
    * TTPs mapeadas a MITRE ATT&CK
    * Indicadores de compromiso (IOCs)
2. Revisar la pestaña **Impacted assets**:
    * Dispositivos expuestos (sin mitigación)
    * Dispositivos mitigados
    * Usuarios potencialmente afectados
3. Revisar la pestaña **Mitigations & detections**:
    * Estado de reglas ASR
    * Firmas de antivirus
    * Detecciones EDR activas

## Acciones Derivadas

* Si hay dispositivos expuestos → Aplicar las mitigaciones recomendadas
* Si hay nuevos IOCs → Crear indicadores en **Settings** → **Endpoints** → **Rules** → **Indicators**
* Si hay tendencia creciente → Notificar al equipo y evaluar endurecimiento de ASR
* Documentar hallazgos en el reporte semanal

---

# Advanced Hunting Semanal

## Objetivo del Hunting Proactivo

Ejecutar consultas KQL semanales para detectar actividad sospechosa que no generó alertas automáticas, enfocándose en técnicas de evasión y persistencia.

1. Ir a: https://security.microsoft.com/v2/advanced-hunting

## Procesos Anómalos

Detectar ejecución de procesos inusuales o sospechosos:

```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe")
| where ProcessCommandLine has_any ("Invoke-Expression", "IEX", "DownloadString", "DownloadFile", "EncodedCommand", "-enc", "bypass", "hidden")
| summarize ExecutionCount = count(), Devices = dcount(DeviceName) by FileName, ProcessCommandLine
| where ExecutionCount <= 3
| order by ExecutionCount asc
```

Revisar:
* Comandos con codificación Base64
* Ejecución desde rutas inusuales (Temp, AppData, ProgramData)
* Procesos legítimos usados para evasión (LOLBins)

## Persistencia (RunKeys y Scheduled Tasks)

Detectar mecanismos de persistencia creados en la última semana:

```kql
DeviceRegistryEvents
| where Timestamp >= ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

```kql
DeviceEvents
| where Timestamp >= ago(7d)
| where ActionType == "ScheduledTaskCreated"
| project Timestamp, DeviceName, InitiatingProcessFileName, AdditionalFields
| order by Timestamp desc
```

Revisar:
* Tareas programadas creadas por procesos no estándar
* Valores de registro apuntando a scripts o binarios no firmados
* Patrones de persistencia asociados a familias de malware conocidas

## Descargas desde Dominios Sospechosos

Detectar conexiones a dominios de baja reputación o recién registrados:

```kql
DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemoteUrl !has_any ("microsoft.com", "windows.com", "office.com", "azure.com", "windowsupdate.com")
| summarize ConnectionCount = count(), Devices = dcount(DeviceName) by RemoteUrl
| where ConnectionCount <= 5
| order by ConnectionCount asc
| take 50
```

Revisar:
* Dominios con patrón DGA (Domain Generation Algorithm)
* Conexiones a servicios de hosting gratuito (pastebin, discord CDN, etc.)
* Tráfico outbound en puertos no estándar

## Documentar Hallazgos

1. Registrar consultas ejecutadas y resultados relevantes
2. Crear alertas personalizadas (**Custom detection rules**) para hallazgos recurrentes
3. Incluir resultados en el reporte semanal

> Si un hallazgo requiere acción inmediata, escalar como incidente y no esperar al ciclo semanal.

---

# Exposición y Vulnerabilidades

## Acceso a Microsoft Defender Vulnerability Management (MDVM)

1. Ir a: https://security.microsoft.com/tvm_dashboard
2. Revisar el **Exposure Score** actual y comparar con la semana anterior

El dashboard muestra:
* Exposure Score (puntuación de exposición del tenant)
* Dispositivos con mayor exposición
* Recomendaciones de seguridad priorizadas
* Software vulnerable con exploits conocidos

## Identificar Software Vulnerable Explotable

1. Ir a **Vulnerability management** → **Weaknesses**
2. Filtrar por:
    * **Exploit available:** Yes
    * **Severity:** Critical, High
3. Revisar las CVEs con exploit público disponible
4. Correlacionar con Threat Analytics para verificar si alguna amenaza activa explota la vulnerabilidad

Para análisis detallado vía KQL:

```kql
DeviceTvmSoftwareVulnerabilities
| where VulnerabilitySeverityLevel in ("Critical", "High")
| where IsExploitAvailable == 1
| summarize DeviceCount = dcount(DeviceId) by CveId, SoftwareName, VulnerabilitySeverityLevel
| order by DeviceCount desc
| take 25
```

## Dispositivos con Mayor Exposición

1. Ir a **Vulnerability management** → **Exposed devices**
2. Ordenar por **Exposure level:** High, Critical
3. Para cada dispositivo de alta exposición, revisar:
    * Vulnerabilidades sin parchear
    * Configuraciones inseguras
    * Software EOL (End of Life)
    * Recomendaciones pendientes

## Priorizar Remediaciones

1. Ir a **Vulnerability management** → **Recommendations**
2. Ordenar por **Exposure impact** y **Remediation type**
3. Para recomendaciones críticas:
    * Crear **Remediation request** asignada al equipo de infraestructura
    * Establecer fecha objetivo de remediación
    * Documentar excepciones con justificación si aplica
4. Verificar el estado de remediaciones previas en la pestaña **Remediation**

---

# Revisión de Configuraciones de Seguridad

## Validar Reglas de Attack Surface Reduction (ASR)

1. Ir a: https://security.microsoft.com/asr
2. Revisar el estado de cada regla ASR:
    * **Block:** Regla activa bloqueando
    * **Audit:** Regla registrando sin bloquear
    * **Not configured:** Regla no habilitada

Verificaciones clave:
* Todas las reglas recomendadas deben estar en modo **Block** o al menos **Audit**
* Revisar reglas en modo Audit que reportaron detecciones → Evaluar migración a Block
* Confirmar que no se agregaron exclusiones innecesarias

Reglas críticas que deben estar en Block:
* Block executable content from email client and webmail
* Block Office applications from creating child processes
* Block credential stealing from LSASS
* Block process creations originating from PSExec and WMI commands
* Use advanced protection against ransomware

## Revisar Configuraciones de Antivirus

1. Ir a **Settings** → **Endpoints** → **Configuration management** → **Device configuration**
2. Verificar:
    * **Real-time protection:** Habilitado
    * **Cloud-delivered protection:** Habilitado
    * **Automatic sample submission:** Habilitado
    * **Tamper protection:** Habilitado
    * **PUA protection:** Habilitado (al menos en modo Audit)

## Revisar Exploit Protection

1. Ir a **Settings** → **Endpoints** → **Configuration management** → **Exploit protection**
2. Validar que las protecciones de sistema estén activas:
    * DEP (Data Execution Prevention)
    * ASLR (Address Space Layout Randomization)
    * SEHOP (Structured Exception Handler Overwrite Protection)
    * CFG (Control Flow Guard)
3. Revisar anulaciones por aplicación y validar que sean justificadas

## Confirmar Alineación con Baselines

Comparar las configuraciones actuales contra:
* [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-guard/windows-defender-application-control/design/microsoft-recommended-block-rules)
* Políticas definidas por el equipo de seguridad
* Recomendaciones de Microsoft Secure Score

> Documentar desviaciones encontradas y crear plan de remediación si aplica.

---

# Dispositivos Reincidentes

## Identificar Endpoints con Incidentes Repetidos

Buscar dispositivos que han generado múltiples incidentes en los últimos 7 días:

```kql
AlertInfo
| where Timestamp >= ago(7d)
| where ServiceSource has "Endpoint"
| join kind=inner (AlertEvidence | where Timestamp >= ago(7d) | where EntityType == "Machine") on AlertId
| summarize 
    IncidentCount = dcount(Title),
    AlertCount = count(), 
    Severities = make_set(Severity),
    AlertTitles = make_set(Title)
    by DeviceName
| where IncidentCount >= 3
| order by IncidentCount desc
```

## Evaluar Causa Raíz

Para cada dispositivo reincidente, revisar:

1. **Patrones de alerta**
    * ¿Son las mismas alertas recurrentes? → Posible FP o exclusión mal configurada
    * ¿Son alertas diferentes? → Posible compromiso activo o usuario de alto riesgo
2. **Estado del dispositivo**
    * Nivel de riesgo y exposición
    * Software desactualizado o vulnerable
    * Exclusiones de antivirus configuradas
3. **Actividad del usuario**
    * Comportamiento de alto riesgo (descargas, navegación, USBs)
    * Permisos elevados innecesarios

## Acciones Correctivas

Según la causa raíz identificada:

* **Exclusión mal configurada:** Ajustar o eliminar la exclusión y monitorear
* **Software vulnerable:** Priorizar parche o actualización con infraestructura
* **Compromiso activo:** Aislar dispositivo, recopilar evidencia, iniciar investigación
* **Reimagen necesaria:** Coordinar con infraestructura para reimagen del equipo
* **Hardening adicional:** Aplicar políticas de ASR, AppLocker o WDAC
* **Usuario de alto riesgo:** Notificar, capacitar y considerar restricciones adicionales

> Documentar cada caso y la acción tomada. Incluir en el reporte semanal.

---

# Reporte Operativo / Ejecutivo

## Consolidar Información Semanal

Recopilar los datos de la semana para generar el reporte:

## Incidentes por Severidad

Ir a **Incidents** y filtrar por los últimos 7 días:
* Total de incidentes: Critical, High, Medium, Low, Informational
* Incidentes resueltos vs. pendientes
* Tiempo promedio de resolución (MTTR)

## Dispositivos Afectados

Desde el inventario de dispositivos y Advanced Hunting:
* Total de dispositivos con alertas en la semana
* Dispositivos aislados o con acciones de contención
* Dispositivos con nivel de riesgo High/Critical

## Amenazas Detectadas

Desde Threat Analytics y la cola de alertas:
* Familias de malware detectadas
* Técnicas MITRE ATT&CK más frecuentes
* Campañas activas relevantes para el entorno

## Acciones Ejecutadas y Pendientes

Desde el Action Center y los incidentes:
* Acciones de respuesta ejecutadas (aislamientos, escaneos, investigaciones)
* Acciones de AIR aprobadas/rechazadas
* Remediaciones de vulnerabilidades completadas
* Acciones pendientes con justificación

## Métricas Clave para el Reporte

| Métrica | Descripción |
|---|---|
| Total Incidentes | Cantidad de incidentes por severidad |
| MTTD (Mean Time to Detect) | Tiempo promedio desde la primera alerta hasta la detección |
| MTTR (Mean Time to Respond) | Tiempo promedio desde la detección hasta la resolución |
| Dispositivos en Riesgo | Cantidad de endpoints con Risk Level High/Critical |
| Exposure Score | Puntuación de exposición del tenant (comparar semana a semana) |
| Cobertura de Sensor | Porcentaje de dispositivos con sensor activo y reportando |
| Reglas ASR en Block | Porcentaje de reglas ASR en modo Block vs. Audit |
| Vulnerabilidades Críticas | CVEs críticas con exploit disponible sin parchear |

## Generar y Distribuir el Reporte

1. Utilizar el script `New-DefenderXDRWeeklyReport.ps1` para generar el reporte automatizado
2. Complementar con hallazgos manuales de hunting y análisis de tendencias
3. Distribuir a:
    * **CISO / Director de Seguridad:** Resumen ejecutivo con métricas clave
    * **Equipo de Infraestructura:** Remediaciones pendientes y dispositivos problemáticos
    * **Equipo SOC:** Lecciones aprendidas y ajustes de detecciones
4. Archivar el reporte para auditoría y línea base

> El reporte semanal es el insumo principal para la toma de decisiones de seguridad y la mejora continua de la postura de protección endpoint.
---