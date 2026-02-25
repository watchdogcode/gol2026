# 🛡️ Guía de Seguridad Operacional Diaria: Microsoft EntraID

La guía de EntraID ayuda a tener una operación continua, reducción de riesgo de identidad y estabilidad del servicio  

---

## 4. Revisión de cambios administrativos

### Objetivo
Detectar configuraciones riesgosas o cambios no planeados que puedan afectar la postura de seguridad de identidad.

### Pasos operativos
1. Acceder a los **Audit Logs** de Microsoft Entra ID:
   - https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuditLogList.ReactView
2. Revisar específicamente:
   - Cambios en **roles administrativos**.
   - Cambios en **políticas de Conditional Access**.
3. Validar que todos los cambios:
   - Estén **aprobados**.
   - Estén **documentados** conforme a los procesos internos.

### Impacto de no hacerlo
- Escalación de privilegios.
- Exposición de recursos críticos.
- Pérdida de control administrativo.

---

## 5. Seguimiento del Identity Secure Score

### Objetivo
Medir la postura de seguridad de identidad y priorizar acciones de mejora continua.

### Pasos operativos
1. Acceder a **Identity Secure Score**:
   - https://entra.microsoft.com/#view/Microsoft_AAD_IAM/EntraRecommendationsIdentitySecureScore.ReactView
2. Revisar recomendaciones activas.
3. Priorizar acciones clave, tales como:
   - Habilitar **MFA para roles privilegiados**.
   - Proteger cuentas **break‑glass**.
4. Registrar avances o retrocesos respecto a semanas anteriores.

### Impacto de no hacerlo
- Estancamiento en la postura de seguridad.
- Exposición prolongada a riesgos conocidos.
- Falta de priorización basada en riesgo.

---

## 6. Revisión de errores de sincronización antiguos

### Objetivo
Evitar **deuda técnica** en identidades y problemas persistentes de sincronización.

### Acción recomendada
1. Acceder a la configuración de sincronización:
   - https://entra.microsoft.com/#view/Microsoft_AAD_Connect_Provisioning/CrossTenantSynchronizationConfiguration.ReactView
2. Identificar:
   - Errores de sincronización con más de **90–100 días**.
3. Ejecutar acciones correctivas:
   - Limpiar objetos obsoletos.
   - Corregir objetos problemáticos.

### Impacto de no hacerlo
- Inconsistencias de identidad.
- Errores recurrentes de acceso.
- Incremento de incidentes operativos.
