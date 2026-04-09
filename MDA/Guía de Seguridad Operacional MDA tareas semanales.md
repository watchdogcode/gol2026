# Guía de Seguridad Operacional Semanal: Microsoft Defender for Cloud Apps 🛡️

## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

Esta guía establece los procedimientos diarios para analizar tendencias, identificar usuarios de alto riesgo y gestionar campañas de amenazas en Microsoft Defender for Cloud Apps

---

> **Objetivo general:** Asegurar postura continua de seguridad, salud operativa de integraciones y alineación con cambios de producto.
>
> **Roles:**
> - **L1:** Revisión y validación básica
> - **L2:** Análisis de impacto y coordinación de remediación
> - **L3:** Ajustes de arquitectura, gobierno y runbooks

---
# Índice
- [Review SaaS Security Posture Management (SSPM)](#review-saas-security-posture-management-sspm)
- [Health Check – App Connectors, Log Collectors y SIEM](#health-check--app-connectors-log-collectors-y-siem)
- [Review Governance Log](#review-governance-log)
- [Track New Changes – Defender XDR & MDCA](#track-new-changes--defender-xdr--mdca)

---

## Review SaaS Security Posture Management (SSPM)

### Objetivo
Mantener una postura segura de aplicaciones SaaS monitoreadas por MDCA.

### Procedimiento
1. Ir a **Cloud Apps > SaaS security posture**
2. Revisar recomendaciones activas
3. Validar impacto en:
   - Secure Score
   - Controles afectados
4. Identificar brechas de configuración recurrentes

### Acciones
- Priorizar recomendaciones **High / Medium impact**
- Coordinar remediación con:
  - Equipos SaaS
  - Identity / Platform teams

### Evidencia
- Registrar cambios aplicados
- Documentar aceptación de riesgo si no se remedia

---

## Health Check – App Connectors, Log Collectors y SIEM

### Objetivo
Asegurar ingestión continua y confiable de datos hacia MDCA y SIEM.

### Procedimiento
1. Ir a **Settings > Cloud Apps > App connectors**
2. Validar:
   - Estado: `Connected`
   - Última sincronización
3. Revisar **Log collectors**:
   - Activos
   - Sin errores
4. Confirmar integración con **Microsoft Sentinel**

### Acciones
- Escalar conectores en estado `Error` o `Disconnected`
- Validar impacto de ingestión incompleta

---

## Review Governance Log

### Objetivo
Auditoría de acciones administrativas y de gobierno.

### Procedimiento
1. Ir a **Cloud Apps > Governance log**
2. Revisar eventos:
   - Policy changes
   - App actions
   - Admin actions

### Validaciones
- Cambios autorizados vs no planeados
- Acciones fuera de ventana de cambio

### Registro
- Documentar cambios relevantes
- Asociar ticket / change request si aplica

---

## Track New Changes – Defender XDR & MDCA

### Objetivo SOC
Mantener la operación alineada a cambios del producto.

### Procedimiento
1. Revisar **Microsoft Learn – What’s new**
2. Identificar:
   - Nuevas detecciones
   - Cambios de UI / flujos
   - Funcionalidades en GA / Preview

### Análisis
- Evaluar impacto operacional
- Identificar ajustes necesarios en:
  - Runbooks
  - Playbooks
  - Capacitación SOC

### Acción
- Actualizar documentación si aplica
- Comunicar cambios al equipo SOC

---

## Checklist Semanal SOC
- SSPM revisado
- Conectores y SIEM saludables
- Governance log auditado
- Cambios de producto evaluados

---

## Auditoría y Evidencia
- Mantener evidencia semanal de:
  - Revisiones realizadas
  - Hallazgos
  - Acciones correctivas

---

