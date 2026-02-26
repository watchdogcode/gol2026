# 🛡️ Guía de Seguridad Operacional Diaria: Microsoft Defender for Identity

La guía diaria de MDI asegura que las amenazas a identidades se detecten y contengan antes de que impacten la operación del negocio.

---

Guía oficial:
https://learn.microsoft.com/en-us/defender-for-identity/ops-guide/ops-guide-daily

### Qué cubre (alineado a la guía)

- ITDR Dashboard
- Triage de incidentes
- Tuning para benign / false positives
- Proactive hunting
- Health issues (Global / Sensor)

---

## Revisar ITDR Dashboard (Identities > Dashboard)

**Propósito:** tomar el pulso diario del riesgo de identidades y priorizar trabajo.

### Paso a paso

1. Entra a https://security.microsoft.com/identities/dashboard e inicia sesión.
2. Revisa específicamente los widgets recomendados:
   - Top insights
   - Identity related incidents
   - Entra ID users at risk
3. Documenta en tu bitácora / ITSM:
   - Insights nuevos o cambios relevantes vs. ayer.
   - Incidentes de identidad que ameriten atención inmediata.

### Salida / Definition of Done (DoD)

- Se registró el “estado ITDR del día” y una lista breve de prioridades.

---

## Triage de incidentes por prioridad (Incidents & alerts)

**Propósito:** priorizar, clasificar y enrutar investigación con correlación XDR.

### Paso a paso

1. Abre **Incidents & alerts**: https://security.microsoft.com/incidents
2. Aplica filtros recomendados:
   - Status: New, In progress
   - Severity: High, Medium, Low
   - Service source: mantener todos para máxima correlación; opcionalmente filtra a Defender for Identity si necesitas foco.
3. Para cada incidente relevante:
   1. Ábrelo y revisa todas las pestañas + Activity log + Advanced hunting.
   2. En **Evidence and response**, abre cada evidencia (usuario / host / IP).
   3. En cada evidencia usa **… > Investigate** y elige *Activity log* o *Go hunt* según sea necesario.
4. Clasifica el incidente:
   - True positive
   - False positive
   - Informational / expected activity
5. Si es **True positive**:
   - Especifica *threat type*.
   - Asigna a un analista y cambia el estado a **In progress**.
6. Si ya fue remediado:
   - **Resolve** el incidente para cerrar alertas relacionadas y dejar clasificación final.

### Salida / DoD

- No quedan incidentes *High* sin revisar/accionar; los *In progress* quedan asignados con próximos pasos.

---

## Configurar tuning para benign / false positives (Advanced hunting)

**Propósito:** reducir ruido y alinear alertas al apetito de riesgo.

### Dónde (URL directo)

- Advanced hunting: https://security.microsoft.com/advanced-hunting

> Nota: el artículo oficial indica **Hunting > Advanced hunting**.

### Paso a paso

1. Ve a **Hunting > Advanced hunting**.
2. Usa datos del incidente / evidencia para definir condiciones del tuning (por entidad, comportamiento, origen, etc.).
3. Crea o ajusta la regla de tuning correspondiente para reducir triage innecesario.
4. Documenta: objetivo, alcance, owner, fecha y criterio de reversión.

### Ejemplo concreto (muy realista)

**Escenario**

Defender for Identity genera alertas de *Suspicious authentication attempts* que siempre involucran:

- Cuenta: `svc_sqlbackup`
- Hosts: `DC01`, `DC02`
- Horario: 02:00–03:00 AM
- Frecuencia: todos los días

Usas **Advanced Hunting** para validar el patrón:

```kql
IdentityLogonEvents
| where AccountName == "svc_sqlbackup"
| summarize Count=count() by ActionType, DeviceName
```
[MDI KQL Queries](https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Paquete%20MDI%20KQL%20Advance%20Hunting.md#recomendaciones-r%C3%A1pidas-antes-de-ejecutar)

**Resultado**
- 100% eventos esperados
- Ningún indicio de compromiso

Confirmado: *Benign true positive*

---

## Proactive hunting (diario o semanal, según madurez)

**Propósito:** encontrar señales tempranas en datos crudos / correlacionados (últimos 30 días).

### Paso a paso

1. Abre **Advanced hunting**: https://security.microsoft.com/v2/advanced-hunting
2. Si eres principiante, usa *guided advanced hunting* (query builder).
3. Ejecuta hunts enfocados, por ejemplo:
   - Usuarios con actividad anómala
   - Movimientos laterales sospechosos
   - Patrones repetitivos en credenciales / NTLM / Kerberos (según detecciones existentes)
4. Crea *casos* (work items) con hallazgos:
   - Indicador
   - Entidad
   - Evidencia
   - Severidad sugerida
   - Acción

### Criterios de salida

- Al menos 1–3 hunts de alto valor ejecutados (según capacidad).
- Hallazgos accionables registrados.

### Ejemplo de KQL – Proactive Hunting

**Cuenta autenticando en demasiados equipos (posible lateral movement)**

- **Qué detecta:** usuarios con logons exitosos en muchos dispositivos dentro de una ventana de 1 hora.
- **Por qué sirve:** patrón común de movimiento lateral o uso de credenciales comprometidas.

```kql
// Proactive hunt: una misma cuenta con logons exitosos en muchos dispositivos en poco tiempo
let Lookback = 1d;
let Window = 1h;
let MinDevices = 6;
DeviceLogonEvents
| where Timestamp >= ago(Lookback)
| where ActionType in ("LogonSuccess", "Logon", "LogonAttempted")
| summarize
    Devices = dcount(DeviceName),
    DeviceList = make_set(DeviceName, 25),
    TotalLogons = count(),
    SrcIPs = make_set(RemoteIP, 25)
  by AccountName, AccountDomain, bin(Timestamp, Window)
| where Devices >= MinDevices
| order by Devices desc, TotalLogons desc
```

[MDI KQL Queries](https://github.com/watchdogcode/gol2026/blob/V2.1/MDI/Paquete%20MDI%20KQL%20Advance%20Hunting.md#recomendaciones-r%C3%A1pidas-antes-de-ejecutar)


---

## Revisar Health issues (Global y Sensor)

**Propósito:** evitar gaps de cobertura por fallas de sensores o conectividad.

### Paso a paso

1. Entra a **Identities > Health issues**:
   https://security.microsoft.com/identities/health-issues
2. Revisa las pestañas:
   - Global
   - Sensor (por DC / servidor)
3. Para cada issue:
   - Evalúa impacto (¿afecta recolección o detección?).
   - Asigna owner y abre ticket si depende de AD / Infraestructura.
4. Verifica que existan notificaciones por correo para issues de servicio (si aplica).

### Salida / DoD

- No hay issues críticos sin dueño ni plan; se registra el estado de salud diario.
