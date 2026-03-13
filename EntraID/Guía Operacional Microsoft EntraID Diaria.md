# Guía de Seguridad Operacional Diaria: Microsoft EntraID 🛡️

## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

La operación efectiva de Microsoft Entra ID requiere monitoreo continuo, control de cambios y revisión periódica de privilegios para reducir riesgos de identidad y garantizar continuidad del negocio.

---
## Índice
- [Monitorear eventos de inicio de sesión y autenticación](#monitorear-eventos-de-inicio-de-sesión-y-autenticación)
- [Revisión de Usuarios con Riesgo (Alto / Medio)](#revisión-de-usuarios-con-riesgo-alto--medio)
- [Revisión de Inicios de Sesión con Riesgo](#revisión-de-inicios-de-sesión-con-riesgo)
- [Revisar alertas de Microsoft Entra Connect Health (entornos híbridos)](#revisar-alertas-de-microsoft-entra-connect-health-entornos-híbridos)
- [Validar estado de componentes híbridos](#validar-estado-de-componentes-híbridos)

---

### Monitorear eventos de inicio de sesión y autenticación

**Objetivo**  
Detectar accesos anómalos o fallos que puedan impactar la continuidad del negocio.

**Pasos operativos**
1. Ir a  https://entra.microsoft.com/#view/Microsoft_AAD_IAM/SignInLogsList.ReactView e inicia sesión
2. Identificar:
   - Picos de fallos de autenticación.
   - Inicios de sesión desde ubicaciones inusuales.
   - Cambios en patrones de MFA.
3. Correlacionar los hallazgos con alertas de **Identity Protection** (si aplica).

**Impacto de no hacerlo**  
- Accesos no autorizados.
- Fraude de identidad.
- Bypass de controles de seguridad.

---

### Revisión de Usuarios con Riesgo (Alto / Medio)

**Paso 1 – Acceso**
Portal Microsoft Entra  
`Protección > Identity Protection`

**Paso 2 – Usuarios en Riesgo**
URL directa:  https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskyUsers

**Paso 3 – Filtros recomendados**
- Nivel de riesgo: **Alto, Medio**
- Estado del riesgo: **Activo**
- (Opcional) Tipo de riesgo, ubicación, fecha

**Paso 4 – Análisis por usuario**
Revisar:
- Nivel de riesgo actual
- Tipo de riesgo:
  - Password Spray
  - Anonymous IP
  - Impossible Travel
  - Leaked Credentials
- Última actividad riesgosa
- Estado: Active / Remediated / Dismissed

**Paso 5 – Acciones operativas**
- Forzar cambio de contraseña
- Requerir MFA
- Confirmar actividad con el usuario
- Marcar como **Remediated** si fue mitigado

---

### Revisión de Inicios de Sesión con Riesgo

**Paso 1 – Inicios con Riesgo**
URL directa:  https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskySignIns


**Paso 2 – Filtros**
- Nivel de riesgo: **Alto, Medio**
- Estado: Activo
- Aplicación, IP, Ubicación

**Paso 3 – Análisis del evento**
Revisar:
- Usuario afectado
- Aplicación objetivo
- Dirección IP / País
- Tipo de riesgo
- Resultado: Success / Failure / Interrupted

---
### Revisar alertas de Microsoft Entra Connect Health (entornos híbridos)

**Objetivo**  
Garantizar una sincronización saludable entre **Active Directory on‑premises** y **Microsoft Entra ID**.

**Pasos operativos**
- Accede al portal https://entra.microsoft.com inicia sesión
- En el menú izquierdo, selecciona: Identity → Hybrid management
- Haz clic en: Microsoft Entra Connect Health
- O ir a https://entra.microsoft.com/#view/Microsoft_AAD_Connect_Health/ConnectHealthMenuBlade/~/overview

**Revisar el estado general del servicio**
1. En la vista Overview, valida:
   - Estado general (Healthy / Warning / Critical).
   - Componentes registrados (Sync, AD FS, PTA, etc.).   
2. Si el estado no es Healthy, continúa con el análisis detallado.


**Verificar alertas de sincronización (Sync errors)**
1. Selecciona el servicio: **Azure AD Connect Sync**
2. Revisa la sección **Alerts**
3. Identifica alertas relacionadas con:
   - Object synchronization errors.
   - Export / Import errors. 
   -  Connector space issues

**Acción inmediata:**

- Abrir cada alerta y revisar:
    - Hora de inicio
    - Número de objetos afectados
    - Severidad


**Validar latencia de sincronización**
1. Dentro de Azure AD Connect Sync, revisa:
   -Última sincronización exitosa
   - Tiempo desde la última sincronización

2. Confirma que:
   - La sincronización ocurre dentro del intervalo esperado (ej. < 30 min).

**Señal de alerta:**
   - Sincronizaciones retrasadas o detenidas por varias horas


**Revisar fallas de agentes (Agents health)**

1. Regresa a Entra Connect Health.
2. Revisa el estado de:
   - Entra Connect Sync Agent
   - Pass‑Through Authentication Agents (si aplica)
   - AD FS / otros agentes híbridos

Confirma que:
   - Todos los agentes estén Active
   - No existan alertas de desconexión o heartbeat perdido


**Confirmar que no existan errores persistentes**

1. Revisa la antigüedad de las alertas:
  - Identifica alertas con más de 24–48 horas

Verifica si:
  - El error ya fue mitigado
  - El error sigue reapareciendo

Marca como **prioridad alta:**
  - Errores repetitivos
  - Errores con impacto en usuarios productivos

**Impacto de no hacerlo**  
- Usuarios sin acceso.
- Inconsistencias de identidad.
- Incremento de incidentes de soporte.

---

### Validar estado de componentes híbridos

**Aplica si se utilizan los siguientes componentes**
- Pass‑Through Authentication Agents.
- Private Network Connectors.
- Password Writeback.
- MFA NPS Extension.

**Acción diaria**
- Confirmar que todos los agentes estén **activos**, **saludables** y **reportando correctamente**.

**Impacto de no hacerlo**  
- Fallas de autenticación híbrida.
- Interrupciones en MFA o acceso a aplicaciones.
- Riesgos operativos y de seguridad elevados.
