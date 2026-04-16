# Guía de Seguridad Operacional Semanal: Microsoft Defender for Cloud Apps 🛡️

## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

Esta guía establece los procedimientos diarios para analizar tendencias, identificar usuarios de alto riesgo y gestionar campañas de amenazas en Microsoft Defender for Cloud Apps

**Autores:** Ernesto Cobos Roqueñí, Arturo Mandujano

---

## Índice

- [Review policy assessments](#review-policy-assessments)
- [Review activity logs](#review-activity-logs)


---

## Review policy assessments
**Objetivo:** Eficacia de políticas.

### Paso a paso

Acceder a https://security.microsoft.com/cloudapps/policies/management

- **Ruta:** `Cloud Apps > Policies`
- **Evaluar:**
  - **Alert volume** (tendencias vs. meses anteriores)
  - **False positives** (impacto operacional y ruido)

### Recomendaciones aplicadas
- Definir **baselines mensuales** de alertas por política.
- Documentar políticas con **>20% de falsos positivos** para ajuste.
- Priorizar políticas críticas alineadas a riesgos del negocio.

### Acción
- **Ajustar thresholds** de forma incremental y registrar cambios.

---

## Review activity logs
**Objetivo:** Investigación y cumplimiento.

### Paso a paso

Acceder a https://security.microsoft.com/cloudapps/activity-log

- **Ruta:** `Cloud Apps > Activity log`
- **Aplicar filtros por:**
  - **App** (enfocar en aplicaciones de alto riesgo)
  - **User** (usuarios privilegiados o con anomalías)
  - **Activity type** (acciones sensibles)

### Recomendaciones aplicadas
- Usar **ventanas de tiempo estándar** (30 días) para consistencia.
- Correlacionar actividades con alertas activas del periodo.
- Validar retención de logs según requisitos de compliance.

### Acción
- **Exportar logs** cuando:
  - Exista incidente activo
  - Sea requerido por auditoría
  - Se necesite análisis forense

---

## Notas operativas
- Registrar resultados en el backlog SOC.
- Escalar hallazgos recurrentes para mejora continua de políticas.
