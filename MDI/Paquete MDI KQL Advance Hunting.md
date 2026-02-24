# Recomendaciones rápidas (antes de ejecutar)

- Ajusta `TimeRange` y/o filtros (`AccountName`, `DeviceName`, `DomainName`) para reducir ruido.
- Si una tabla no existe en tu tenant (depende de licenciamiento/ingesta), usa la alternativa indicada en cada query.
- Para convertir una query en **Custom Detection**, Microsoft recomienda basarla en **Advanced Hunting** y ejecutarla regularmente.

---

## Hunting base (MDI/XDR) — incidentes/alertas relacionadas con identidad

### Alertas que provienen de Defender for Identity (últimos X días)

```kql
let TimeRange = 7d;
AlertInfo
| where Timestamp >= ago(TimeRange)
| where ServiceSource has_any ("MicrosoftDefenderForIdentity", "Defender for Identity", "MDI")
| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, DetectionSource, ProviderName
| order by Timestamp desc
```

### Incidentes que incluyen evidencias de identidad (vista rápida)

```kql
let TimeRange = 7d;
IncidentInfo
| where Timestamp >= ago(TimeRange)
| project Timestamp, IncidentId, Title, Severity, Status, Classification, Determination
| order by Timestamp desc
```

## Accesos anómalos y abuso de credenciales

### Password spraying

```kql
let TimeRange = 1d;
let FailureThreshold = 15;
IdentityLogonEvents
| where Timestamp >= ago(TimeRange)
| where ActionType in ("LogonFailed", "InvalidPassword", "UserLoginFailed", "Failure")
| summarize FailedLogons=count(), SrcIPs=dcount(IPAddress), IPs=make_set(IPAddress, 20)
    by AccountUpn, AccountName, AccountDomain
| where FailedLogons >= FailureThreshold and SrcIPs >= 3
| order by FailedLogons desc
```

## Custom Detection – Cuenta privilegiada con múltiples fallos

```kql
let TimeRange = 1d;
let FailureThreshold = 8;
IdentityLogonEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has "Fail"
| summarize Failures=count() by AccountUpn, AccountName
| where Failures >= FailureThreshold
| join kind=leftouter (
    IdentityAccountInfo
    | where IsPrivileged == true
    | project AccountUpn, IsPrivileged
) on AccountUpn
| where IsPrivileged == true
| order by Failures desc
```
