# 🛡️ Guía de Seguridad Operacional Diaria: Microsoft EntraID

La guía diaria de EntraID ayuda a tener una operación continua, reducción de riesgo de identidad y estabilidad del servicio  

---

## 🟢 Tareas Diarias (Daily Operations)

### 1. Monitorear eventos de inicio de sesión y autenticación

**Objetivo**  
Detectar accesos anómalos o fallos que puedan impactar la continuidad del negocio.

**Pasos operativos**
1. Ir a  https://entra.microsoft.com/#view/Microsoft_AAD_IAM/SignInLogsList.ReactView/timeRangeType/last24hours/showApplicationSignIns~/true e inicia sesión
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

### 2. Revisar alertas de Microsoft Entra Connect Health (entornos híbridos)

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



**Impacto de no hacerlo**  
- Usuarios sin acceso.
- Inconsistencias de identidad.
- Incremento de incidentes de soporte.

---

### 3. Validar estado de componentes híbridos

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
