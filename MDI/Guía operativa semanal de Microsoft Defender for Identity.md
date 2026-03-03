# 🛡️ Guía de Seguridad Operacional Diaria: Microsoft Defender for Identity

La guía semanal de MDI permite identificar y ajustar proactivamente riesgos emergentes de identidad antes de que se conviertan en incidentes críticos para el negocio.

---
## Índice
- [Revisar recomendaciones de Secure Score (por producto)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-recomendaciones-de-secure-score-por-producto)
- [Revisar y responder a amenazas emergentes (custom detections)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-y-responder-a-amenazas-emergentes-custom-detections)
- [Ejemplo Custom Detection: Password spraying / brute force distribuido (señal temprana)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md#ejemplo-custom-detection-password-spraying--brute-force-distribuido-se%C3%B1al-temprana)

---

## Revisar recomendaciones de Secure Score (por producto)
**Propósito:** mejorar postura de identidad e infraestructura on‑premises.

### Paso a paso
1. Abre Secure Score: https://security.microsoft.com/securescore
2. Ve a **Recommended actions** y agrupa por **Product**.
3. Prioriza acciones relacionadas con **Defender for Identity / identidades**.
4. Para cada acción prioritaria:
   - Define **owner** (SOC / Identity / AD).
   - Crea tarea/plan con **fecha objetivo**.

### Salida / DoD
- Backlog priorizado y asignado; avance semanal medible.

---

## Revisar y responder a amenazas emergentes (custom detections)
**Propósito:** crear y operar detecciones personalizadas basadas en Advanced Hunting.

### Paso a paso
1. Revisa **temas de riesgo emergentes** relevantes para tu organización (input interno).
2. En **Advanced Hunting**, crea o ajusta consultas que cubran esos escenarios:
   https://security.microsoft.com/advanced-hunting
3. Configura **custom detection rules** basadas en esas consultas para generar alertas/acciones.
4. Ejecuta y valida que las reglas funcionen como se espera y documenta ajustes.

### Salida
- Reglas activas, documentadas y validadas regularmente.

---

## Ejemplo Custom Detection: Password spraying / brute force distribuido (señal temprana)

### Qué busca
Detecta cuentas que reciben múltiples fallos de inicio de sesión desde **múltiples IPs** en una ventana corta, típico de:
- Password spraying
- Intentos automatizados con credenciales filtradas

Útil como **amenaza emergente**, ya que estos ataques suelen aumentar durante campañas activas y tras filtraciones recientes.

### KQL (ajustable a tu ambiente)
```kql
// Custom detection candidate: Password spraying against identities
let Lookback = 7d;
let Window = 30m;
let MinFailures = 25;
let MinSrcIPs = 8;
IdentityLogonEvents
| where Timestamp >= ago(Lookback)
| where ActionType has_any ("Fail", "LogonFailed", "InvalidPassword", "UserLoginFailed")
| summarize
    Failures = count(),
    SrcIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 25),
    Apps = make_set(Application, 15)
  by AccountUpn, AccountName, AccountDomain, bin(Timestamp, Window)
| where Failures >= MinFailures and SrcIPs >= MinSrcIPs
| project Timestamp, AccountUpn, AccountName, AccountDomain, Failures, SrcIPs, IPList, Apps
| order by Failures desc, SrcIPs desc
```
[Paquete MDI KQL Queries](https://github.com/watchdogcode/gol2026/blob/main/MDI/Paquete%20MDI%20KQL%20Advance%20Hunting.md#recomendaciones-r%C3%A1pidas-antes-de-ejecutar)