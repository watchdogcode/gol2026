# Paquete de Consultas KQL (Advanced Hunting) 🛡️
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

## Recomendaciones rápidas (antes de ejecutar)

- Ajusta `TimeRange` y/o filtros (`AccountName`, `DeviceName`, `DomainName`) para reducir ruido.
- Si una tabla no existe en tu tenant (depende de licenciamiento/ingesta), usa la alternativa indicada en cada query.
- Para convertir una query en **Custom Detection**, Microsoft recomienda basarla en **Advanced Hunting** y ejecutarla regularmente.

Este documento recopila una serie de consultas KQL (Kusto Query Language) diseñadas para la detección, triaje e investigación de amenazas en Microsoft Defender XDR.

**Autores:** Ernesto Cobos Roqueñí, Arturo Mandujano

---

## Índice

- [OAuth – Nuevos Consentimientos Otorgados](#oauth--nuevos-consentimientos-otorgados)
- [Shadow IT – Aplicaciones Cloud por Volumen de Uso](#shadow-it--aplicaciones-cloud-por-volumen-de-uso)
- [OAuth – Nuevos Consentimientos (últimos 7 días)](#oauth--nuevos-consentimientos-últimos-7-días)
- [OAuth – Apps con Permisos Potencialmente de Alto Riesgo](#oauth--apps-con-permisos-potencialmente-de-alto-riesgo)
- [Uso General – Top Aplicaciones Cloud por Actividad](#uso-general--top-aplicaciones-cloud-por-actividad)
- [Descubrimiento – Aplicaciones Nuevas Detectadas (7d vs 60d)](#descubrimiento--aplicaciones-nuevas-detectadas-7d-vs-60d)
- [Gobierno – Operaciones Administrativas en Apps Cloud](#gobierno--operaciones-administrativas-en-apps-cloud)
- [Riesgo – Eliminaciones Masivas de Objetos](#riesgo--eliminaciones-masivas-de-objetos)
- [Exfiltración – Descargas Masivas desde Apps Cloud](#exfiltración--descargas-masivas-desde-apps-cloud)
- [Colaboración – Compartición Excesiva con Externos](#colaboración--compartición-excesiva-con-externos)
- [Geolocalización – Actividad desde Países No Habituales](#geolocalización--actividad-desde-países-no-habituales)
- [Geolocalización – Viaje Imposible (<2h entre países)](#geolocalización--viaje-imposible-2h-entre-países)

---

## Queries operativas 

### OAuth – Nuevos Consentimientos Otorgados

```kusto
CloudAppEvents
| where Timestamp >= ago(24h)
| where ActionType in ("Consent to application","Grant consent")
| summarize Consents=count(), Users=dcount(AccountId) by Application, ApplicationId
| top 20 by Consents desc
```

### Shadow IT – Aplicaciones Cloud por Volumen de Uso

```kusto
CloudAppEvents
| where Timestamp >= ago(24h)
| summarize Events=count(), Users=dcount(AccountId) by Application
| top 20 by Events desc
```

---

## Catálogo MDA – Advanced Hunting (10 detecciones)

### OAuth – Nuevos Consentimientos (últimos 7 días)

```kusto
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType in ("Consent to application","Grant consent")
| summarize Consents=count(), Users=dcount(AccountId) by Application, ApplicationId
| top 20 by Consents desc
```

### OAuth – Apps con Permisos Potencialmente de Alto Riesgo

> **Nota:** Esta query es funcionalmente equivalente a OAuth – Nuevos Consentimientos
> Para identificar *alto riesgo real*, se requiere enriquecer con permisos OAuth (p.ej. `Permissions`, `OAuthAppId`, `Scope`).

```kusto
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType in ("Consent to application","Grant consent")
| summarize Consents=count(), Users=dcount(AccountId) by Application, ApplicationId
| top 20 by Consents desc
```

### Uso General – Top Aplicaciones Cloud por Actividad

```kusto
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| summarize Events=count(), Users=dcount(AccountId) by Application
| top 25 by Events desc
```

### Descubrimiento – Aplicaciones Nuevas Detectadas (7d vs 60d)

```kusto
let Lookback = 7d;
let Baseline = 60d;
let recent = CloudAppEvents
| where Timestamp >= ago(Lookback)
| summarize FirstSeen=min(Timestamp), Events=count() by Application;
let historical = CloudAppEvents
| where Timestamp between (ago(Baseline) .. ago(Lookback))
| summarize PrevEvents=count() by Application;
recent
| join kind=leftanti historical on Application
| order by Events desc
```

### Gobierno – Operaciones Administrativas en Apps Cloud

```kusto
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where IsAdminOperation == true
| summarize Events=count(), IPs=make_set(IPAddress, 20) by Application, ActionType, AccountDisplayName
| order by Events desc
```

### Riesgo – Eliminaciones Masivas de Objetos

```kusto
let TimeRange = 7d;
let DeletionThreshold = 10;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("Delete","Remove","Purge")
| summarize Deletions=count(), Users=dcount(AccountId) by Application, ActionType
| where Deletions > DeletionThreshold
| order by Deletions desc
```

### Exfiltración – Descargas Masivas desde Apps Cloud

```kusto
let TimeRange = 7d;
let DownloadThreshold = 50;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("Download","FileDownloaded","Export")
| summarize Downloads=count(), Apps=dcount(Application) by AccountDisplayName, AccountObjectId
| where Downloads > DownloadThreshold
| order by Downloads desc
```

### Colaboración – Compartición Excesiva con Externos

```kusto
let TimeRange = 14d;
let ShareThreshold = 20;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("SharingSet","SharingInvitationCreated","Anonymous")
| summarize Shares=count(), Apps=dcount(Application) by AccountDisplayName, AccountObjectId
| where Shares > ShareThreshold
| order by Shares desc
```

### Geolocalización – Actividad desde Países No Habituales

```kusto
let TimeRange = 7d;
let Baseline = 60d;
let known = CloudAppEvents
| where Timestamp between (ago(Baseline) .. ago(TimeRange))
| where isnotempty(CountryCode)
| summarize KnownCountries=make_set(CountryCode, 200) by AccountId;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where isnotempty(CountryCode)
| summarize RecentCountries=make_set(CountryCode, 50), Events=count() by AccountId, AccountDisplayName
| join kind=leftouter known on AccountId
| extend NewCountries = set_difference(RecentCountries, KnownCountries)
| where array_length(NewCountries) > 0
| project AccountDisplayName, NewCountries, Events
| order by array_length(NewCountries) desc
```

### Geolocalización – Viaje Imposible (<2h entre países)

```kusto
let TimeRange = 1d;
let Window = 2h;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where isnotempty(CountryCode)
| summarize Countries=make_set(CountryCode, 10), MinTime=min(Timestamp), MaxTime=max(Timestamp)
  by AccountId, AccountDisplayName, bin(Timestamp, Window)
| where array_length(Countries) >= 2
| project AccountDisplayName, Countries, MinTime, MaxTime
| order by MaxTime desc
```

---

## Notas de operación

- **Ventanas de tiempo**:
  - `1d`: detecciones de alta inmediatez (viaje imposible).
  - `7d`: comportamiento anómalo estándar.
  - `14d`: patrones de colaboración gradual.
- **Umbrales** definidos como variables para facilitar tuning por entorno.

