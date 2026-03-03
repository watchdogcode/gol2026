# 🛡️ Guía de Seguridad Operacional Diaria: Microsoft Defender for Endpoint

Esta guía establece los procedimientos diarios para monitorear alertas, gestionar dispositivos en riesgo, validar la salud del sensor EDR y responder a incidentes en Microsoft Defender for Endpoint (MDE).

---

# Monitoreo de Incidentes y Alertas

## Revisar la cola de Incidentes

Ir al portal [Incidents - Microsoft Defender](https://security.microsoft.com/incidents)
En el panel de Incidentes configurar los siguientes filtros:
* **Periodo:** 1 Día
* **Estado:** Nuevo y En curso
* **Severidad de alerta:** Ordenar descendente (Critical → High → Medium → Low)
* **Service sources:** Microsoft Defender for Endpoint

Guardar la vista personalizada para uso futuro

Revisar columnas clave:
* **Severity** (Gravedad)
* **Status** (Estado)
* **Assigned to** (Asignado a)
* **Impacted assets** (Dispositivos y usuarios afectados)
* **Alerts** (Número de alertas correlacionadas)

## Priorizar incidentes Critical y High

1. Revisar los incidentes con severidad **Critical** y **High** en las últimas 24 horas
2. Evaluar el número de alertas correlacionadas, dispositivos afectados y usuarios involucrados
3. Asignar el incidente al analista correspondiente si no está asignado

## Validar correlación cross-workload

Verificar si el incidente tiene alertas correlacionadas de otros workloads:
* **MDO:** Correos maliciosos con adjuntos o URLs que detonaron en el endpoint
* **MDI:** Movimiento lateral, escalamiento de privilegios desde identidad comprometida
* **MDA:** Aplicaciones OAuth sospechosas conectadas al dispositivo

Documentar hallazgos de correlación en los comentarios del incidente

> Si se detecta impacto activo, escalar inmediatamente al equipo de respuesta.

---

# Gestión y Clasificación de Alertas

## Revisar alertas nuevas y recurrentes

Ir al portal [Alerts - Microsoft Defender](https://security.microsoft.com/alerts)
Aplicar los siguientes filtros:
* **Status:** New
* **Service source:** Microsoft Defender for Endpoint
* **Time range:** Últimas 24 horas

## Clasificar cada alerta

Los analistas deben clasificar cada alerta como:
* **True Positive (TP):** Actividad maliciosa confirmada → Investigar y remediar
* **Benign True Positive (BTP):** Actividad legítima que detonó la alerta → Documentar justificación
* **False Positive (FP):** Detección incorrecta → Crear exclusión controlada
* **Informational:** Alerta de baja relevancia → Resolver con nota

Seleccione **Manage alert** para aplicar la clasificación y agregar comentarios.

## Ajustar reglas y exclusiones

Cuando una alerta sea clasificada como FP:

1. Ir a **Settings** → **Endpoints** → **Rules** → **Indicators** o **Custom detection rules**
2. Crear la exclusión con el alcance mínimo necesario
3. Documentar cada exclusión con justificación, fecha y responsable
4. Verificar que la exclusión no afecte cobertura de ASR o Antivirus

> **Nunca** crear exclusiones amplias (ej. excluir un directorio completo como `C:\`). Mantener la cola de alertas sin pendientes mayores a 24 horas.

---

# Dispositivos en Riesgo

## Identificar dispositivos con riesgo elevado

Ir al portal [Device inventory - Microsoft Defender](https://security.microsoft.com/machines)
Aplicar los siguientes filtros:
* **Risk level:** High, Critical
* Ordenar por **Risk level** descendente

Para cada dispositivo de alto riesgo, revisar:
* Alertas activas asociadas
* Usuarios que iniciaron sesión
* Vulnerabilidades de software detectadas
* Nivel de exposición

## Detectar equipos con múltiples alertas en 24 horas

1. Ir a **Advanced Hunting**: https://security.microsoft.com/v2/advanced-hunting
2. Ejecutar la siguiente consulta:

```kql
AlertInfo
| where Timestamp >= ago(24h)
| where ServiceSource has "Endpoint"
| join kind=inner (AlertEvidence | where Timestamp >= ago(24h) | where EntityType == "Machine") on AlertId
| summarize AlertCount = count(), Severities = make_set(Severity) by DeviceName
| where AlertCount >= 3
| order by AlertCount desc
```

3. Evaluar si las alertas son parte de un ataque coordinado (kill chain)

## Revisar acciones de contención pendientes

Verificar si existen acciones recomendadas no ejecutadas:
* Aislamiento de red
* Ejecución de análisis antivirus
* Recolección de paquete de investigación

> Si la contención requiere aprobación, escalar al responsable del equipo.

---

# Salud del Sensor y Cobertura EDR

## Verificar estado de onboarding

Ir al portal [Device inventory - Microsoft Defender](https://security.microsoft.com/machines)
Filtrar por **Onboarding status** y revisar:
* Dispositivos con estado `Can be onboarded` o `Insufficient info`
* Dispositivos que dejaron de reportar telemetría

Reportar dispositivos no onboarded al equipo de infraestructura.

## Revisar alertas de salud del sensor

Ir a **Settings** → **Endpoints** → **Device health** → **Sensor health & OS**
Verificar dispositivos con:
* **Impaired communications:** El sensor no reporta telemetría
* **No sensor data:** Sin datos del sensor por más de 7 días
* **Misconfigured:** Configuración incompleta o incorrecta

> Escalar dispositivos con comunicación comprometida por más de 48 horas.

## Validar estado de Microsoft Defender Antivirus

Revisar en el inventario de dispositivos:
* Que las firmas estén actualizadas (no más de 3 días de antigüedad)
* Que el motor de antivirus esté activo y en modo **real-time protection**
* Identificar dispositivos con antivirus de terceros que pueda estar causando conflictos

Para validar mediante Advanced Hunting:

```kql
DeviceInfo
| where Timestamp >= ago(24h)
| summarize arg_max(Timestamp, *) by DeviceId
| where OnboardingStatus != "Onboarded" or SensorHealthState != "Active"
| project Timestamp, DeviceName, OSPlatform, OnboardingStatus, SensorHealthState, ExposureLevel
| order by Timestamp desc
```

---

# Acciones de Respuesta a Incidentes

## Evaluar la acción de respuesta apropiada

Antes de ejecutar cualquier acción:
* Revisar la severidad, el tipo de amenaza y el impacto del incidente
* Confirmar que el dispositivo tiene sensor activo y comunicación estable

## Ejecutar acciones de respuesta

Desde la página del dispositivo, seleccionar **Response actions** y elegir según el caso:

1. **Isolate device**
    * Cuándo: Amenaza activa confirmada, riesgo de propagación lateral
    * Impacto: El dispositivo pierde conectividad de red excepto con el servicio MDE
    * Programar revisión de liberación en <24 horas
2. **Run antivirus scan**
    * Cuándo: Detección de malware, archivo sospechoso en disco
    * Impacto: Escaneo completo o rápido bajo demanda
3. **Collect investigation package**
    * Cuándo: Se necesita evidencia forense (logs, procesos, conexiones)
    * Impacto: Genera un paquete ZIP descargable con artefactos del endpoint
4. **Initiate automated investigation**
    * Cuándo: Múltiples alertas en el mismo dispositivo
    * Impacto: Desencadena investigación y remediación automática
5. **Live Response**
    * Cuándo: Análisis forense avanzado en tiempo real
    * Impacto: Sesión remota al endpoint para ejecutar comandos, recopilar archivos

## Revisar y aprobar acciones de AIR

1. Ir a [Action center - Microsoft Defender](https://security.microsoft.com/action-center/pending)
2. Revisar acciones en espera de aprobación:
    * Quarantine file
    * Stop and quarantine process
    * Isolate device
    * Block URL / IP
3. Para cada acción pendiente:
    * Click en la acción para ver detalles
    * Revisar **Investigation details** y **Evidence**
4. Tomar decisión:
    * **Aprobar:** Si la evidencia es concluyente
    * **Rechazar:** Si es falso positivo
5. Verificar pestaña **History** para confirmar ejecución

## Consideraciones de Live Response

* Requiere rol de **Security Operator** o superior
* Habilitar en: **Settings** → **Endpoints** → **Advanced features** → **Live Response**
* Usar solo cuando las acciones automatizadas no son suficientes
* Documentar todos los comandos ejecutados durante la sesión

> Todas las acciones deben documentarse en el incidente: acción tomada, hora, analista y justificación.

---

# Revisión de Threat Analytics

## Revisar amenazas activas y emergentes

Ir al portal [Threat analytics - Microsoft Defender](https://security.microsoft.com/threatanalytics3)
Revisar las amenazas marcadas como **Active** o **Trending**, priorizando:
* Ransomware
* Malware prevalente
* Amenazas de día cero
* Campañas dirigidas

## Evaluar impacto para el entorno

Para cada amenaza relevante, revisar:
* **Analyst report:** Descripción técnica de la amenaza, TTPs e IOCs
* **Impacted assets:** Dispositivos y usuarios expuestos o afectados en el tenant
* **Mitigations & detections:** Estado de las protecciones (reglas ASR, AV signatures, EDR detections)

Priorizar amenazas que muestren dispositivos expuestos o mitigaciones incompletas.

## Ejecutar acciones según evaluación

Si hay dispositivos expuestos:
* Ejecutar las mitigaciones recomendadas por Microsoft

Si hay nuevos IOCs:
1. Ir a **Settings** → **Endpoints** → **Rules** → **Indicators**
2. Crear indicadores personalizados (hashes, URLs, IPs)
3. Seleccionar la acción: **Block**, **Alert**, o **Alert and block**

Si hay campañas activas de ransomware o malware prevalente:
* Notificar al equipo de seguridad
* Considerar endurecimiento temporal de reglas ASR en modo bloqueo

## Documentar la revisión

1. Registrar en el log operativo: amenazas revisadas, impacto evaluado, acciones tomadas
2. Incluir hallazgos relevantes en el reporte diario

> La revisión diaria de Threat Analytics no debe exceder 15 minutos. Documentar usuarios y dispositivos críticos para monitoreo continuo.
