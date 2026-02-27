# Recomendaciones rápidas (antes de ejecutar)

- Ajusta `TimeRange` y/o filtros (`AccountName`, `DeviceName`, `DomainName`) para reducir ruido.
- Si una tabla no existe en tu tenant (depende de licenciamiento/ingesta), usa la alternativa indicada en cada query.
- Para convertir una query en **Custom Detection**, Microsoft recomienda basarla en **Advanced Hunting** y ejecutarla regularmente.

---
## Detección: Cuentas privilegiadas con múltiples fallos de autenticación

**Objetivo**  
Detectar abuso de credenciales contra cuentas privilegiadas (admins, operadores, service accounts críticas).

**Escenarios cubiertos**
- Password spraying dirigido a administradores
- Ataques de fuerza bruta contra cuentas privilegiadas
- Uso indebido de credenciales filtradas

---

## Query KQL (Advanced Hunting – Microsoft Defender for Identity)

```kql
let TimeRange = 1d;
let FailureThreshold = 8;
IdentityLogonEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has "Fail"
| summarize Failures = count() by AccountUpn, AccountName
| where Failures >= FailureThreshold
| join kind=leftouter IdentityAccountInfo on AccountUpn
| where IsPrivileged == true
| project AccountUpn, AccountName, Failures, IsPrivileged
| order by Failures desc
```

---

## Tablas utilizadas
- IdentityLogonEvents
- IdentityAccountInfo

---

## Uso recomendado
- **Tipo**: Custom Detection Rule (Defender XDR)
- **Cadencia**: Diaria o semanal
- **Marco**: ITDR (Identity Threat Detection & Response)

---

## Acciones sugeridas
- Validar si la cuenta es:
  - Administrador humano
  - Cuenta de servicio
- Correlacionar con:
  - Horarios inusuales
  - Alertas MDI asociadas
- Acciones de respuesta:
  - Reset de credenciales
  - Forzar MFA
  - Revisar exclusiones / tuning

---

## Clasificación esperada
- **True Positive**: Ataque activo contra cuentas privilegiadas
- **Benign / False Positive**: Scripts o procesos mal configurados

---

## Integración operativa
- Incluir en guía operacional **diaria / semanal MDI**
- Unificar en librería de detecciones MDI
- Base para documentación de detecciones personalizadas

