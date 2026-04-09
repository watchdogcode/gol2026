# Guía de Seguridad Operacional Diaria: Microsoft Defender for Cloud Apps 🛡️

## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

Esta guía establece los procedimientos diarios para analizar tendencias, identificar usuarios de alto riesgo y gestionar campañas de amenazas en Microsoft Defender for Cloud Apps


---

## Objetivo
Establecer rutinas operativas claras para analistas SOC que permitan:

- Detectar amenazas en **SaaS y aplicaciones OAuth**
- Gobernar aplicaciones y **Shadow IT**
- Mantener la **postura de seguridad (SSPM)**
- Asegurar **trazabilidad y auditoría**

---
#Índice
- [Review Alerts and Incidents](#review-alerts-and-incidents)
- [Triage desde Microsoft Defender XDR](#triage-desde-microsoft-defender-xdr)
- [Review Threat Detection Data](#review-threat-detection-data)
- [Application Governance – OAuth Risk](#application-governance--oauth-risk)
- [App Governance – Overview](#app-governance--overview)
- [Review OAuth App Data](#review-oauth-app-data)
- [App Governance Policies](#app-governance-policies)
- [Conditional Access App Control](#conditional-access-app-control)
- [Shadow IT – Cloud Discovery](#shadow-it--cloud-discovery)
- [Cloud Discovery Dashboard](#cloud-discovery-dashboard)

---

## Review Alerts and Incidents

### Objetivo
Detectar y priorizar amenazas activas relacionadas con Cloud Apps.

### Procedimiento
1. Acceder a **https://security.microsoft.com**
2. Navegar a **Incidents & Alerts > Incidents**
3. Aplicar filtros:
   - Status: `New`, `In progress`
   - Service source: `Defender for Cloud Apps`
   - Severity: `High`, `Medium`

4. Abrir cada incidente y revisar:
   - Timeline
   - Evidence and response
   - Alertas correlacionadas

### Clasificación
- True Positive
- False Positive
- Informational

### Acciones
- Asignar propietario
- Cambiar estado:
  - `In progress` (si requiere análisis)
  - `Resolved` (si fue contenido)

---

## Triage desde Microsoft Defender XDR

### Objetivo
Correlación XDR para entender impacto transversal.

### Procedimiento
- Revisar:
  - Usuarios afectados
  - Cloud Apps impactadas
- Evidence and Response → **Investigate**
- Usar:
  - Activity Log
  - Advanced Hunting (si aplica)

### Registro
- Documentar hipótesis, evidencia y conclusión

---

## Review Threat Detection Data

### Objetivo
Analizar detecciones de MDCA (anomalías, malware, OAuth).

### Procedimiento
- Cloud Apps > Alerts
- Filtros:
  - Category: `Threat detection`
  - Status: `Open`

### Validar
- Tipo de alerta
- Aplicación afectada
- Usuario implicado

### Remediación
- Disable app
- Revoke OAuth consent

---

## Application Governance – OAuth Risk

### Objetivo
Controlar riesgo de aplicaciones OAuth.

### Procedimiento
- Cloud Apps > App Governance
- Revisar:
  - Apps **High Risk**
  - Actividad anómala

### Validaciones clave
- Permissions (Graph scopes)
- Publisher
- Activity timeline

---

## App Governance – Overview

### Objetivo
Visibilidad global del abuso OAuth.

### Revisar dashboards
- Active apps
- Alerts
- Compliance posture
- Sign‑in activity

### Acción
- Identificar cambios recientes y picos anómalos

---

## Review OAuth App Data

### Objetivo
Detectar consent phishing y persistencia OAuth.

### Revisar
- Timestamps de consentimiento
- Nivel de permisos (Mail.Read, Files.ReadWrite)
- Usuarios que otorgaron acceso

### Respuesta
- Disable app
- Revoke permissions

---

## App Governance Policies

### Objetivo
Automatizar detección y respuesta OAuth.

### Procedimiento
- Settings > Cloud Apps > App governance policies
- Validar políticas predefinidas:
  - Suspicious OAuth App

### Confirmar
- Scope
- Alerting
- Automatic remediation

---

## Conditional Access App Control

### Objetivo
Validar control de sesión en tiempo real.

### Revisar
- Active sessions
- Blocked activities

### Validación
- Alineación con Conditional Access policies

---

## Shadow IT – Cloud Discovery

### Objetivo
Identificar aplicaciones no sancionadas.

### Procedimiento
- Cloud Apps > Cloud Discovery
- Revisar:
  - Nuevas apps descubiertas
  - Risk score

### Clasificación
- Sanctioned
- Unsanctioned

---

## Cloud Discovery Dashboard

### Objetivo
Identificar tendencias de uso y riesgo SaaS.

### Revisar
- High‑level usage
- Top risky apps
- Discovery alerts

### Investigación
- Apps con alto uso y baja compliance

---

## Checklist Diario SOC
- Incidentes revisados
- Alertas OAuth validadas
- Apps riesgosas mitigadas
- Evidencia documentada

---

## Auditoría y Trazabilidad
- Todos los incidentes deben:
  - Tener owner asignado
  - Evidencia adjunta
  - Comentarios de cierre claros

---

