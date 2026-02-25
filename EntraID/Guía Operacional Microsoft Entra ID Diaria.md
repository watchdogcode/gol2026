# 🛡️ Guía de Seguridad Operacional Diaria: Microsoft Defender for Identity

La guía diaria de EntraID ayuda a tener una operación continua, reducción de riesgo de identidad y estabilidad del servicio  

---

## 🟢 Tareas Diarias (Daily Operations)

### 1. Monitorear eventos de inicio de sesión y autenticación

**Objetivo**  
Detectar accesos anómalos o fallos que puedan impactar la continuidad del negocio.

**Pasos operativos**
1. Revisar **Sign-in logs** en Microsoft Entra ID.
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
1. Revisar alertas relacionadas con:
   - Errores de sincronización (Sync errors).
   - Latencia de sincronización.
   - Fallas de agentes.
2. Confirmar que no existan errores persistentes o recurrentes.

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
