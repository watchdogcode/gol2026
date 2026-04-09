# Paquete de Consultas KQL (Advanced Hunting) 🛡️
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

## Recomendaciones rápidas (antes de ejecutar)

- Ajusta `TimeRange` y/o filtros (`AccountName`, `DeviceName`, `DomainName`) para reducir ruido.
- Si una tabla no existe en tu tenant (depende de licenciamiento/ingesta), usa la alternativa indicada en cada query.
- Para convertir una query en **Custom Detection**, Microsoft recomienda basarla en **Advanced Hunting** y ejecutarla regularmente.

Este documento recopila una serie de consultas KQL (Kusto Query Language) diseñadas para la detección, triaje e investigación de amenazas en Microsoft Defender XDR.

**Autores:** Ernesto Cobos Roqueñí, Arturo Mandujano

---

## 1) Queries “operativas” en el hashtable `$Queries` (ejecución directa por API)

> **Nota del script:** cualquier `ago(24h)` se reemplaza por `ago(<TimeWindowHours>h)` antes de ejecutar la consulta:

```powershell
$FinalQuery = $Query -replace "ago\(24h\)", "ago($($TimeWindowHours)h)"
```

### 1.1 `MDA_OAuth`

```kusto
CloudAppEvents
| where Timestamp >= ago(24h)
| where ActionType in ("Consent to application","Grant consent")
| summarize Consents=count(), Users=dcount(AccountId) by Application, ApplicationId
| top 20 by Consents desc
```

### 1.2 `MDA_ShadowIT`

```kusto
CloudAppEvents
| where Timestamp >= ago(24h)
| summarize Events=count(), Users=dcount(AccountId) by Application
| top 20 by Events desc
```

---

## 2) Catálogo “MDA (Advanced Hunting – Cloud App Security)” en `$MdaKqlCatalog` (10 queries)

### 2.1 (Id=1) Nuevos Consentimientos OAuth (Últimos 7d)

```kusto
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType in ("Consent to application","Grant consent")
| summarize Consents=count(), Users=dcount(AccountId) by Application, ApplicationId
| top 20 by Consents desc
```

### 2.2 (Id=2) Apps OAuth con Permisos de Alto Riesgo

```kusto
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType in ("Consent to application","Grant consent")
| summarize Consents=count(), Users=dcount(AccountId) by Application, ApplicationId
| top 20 by Consents desc
```

### 2.3 (Id=3) Top Aplicaciones Cloud por Actividad

```kusto
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| summarize Events=count(), Users=dcount(AccountId) by Application
| top 25 by Events desc
```

### 2.4 (Id=4) Aplicaciones Nuevas (Primera Vez Vistas en 7d)

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

### 2.5 (Id=5) Operaciones Admin en Aplicaciones Cloud

```kusto
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where IsAdminOperation == true
| summarize Events=count(), IPs=make_set(IPAddress, 20) by Application, ActionType, AccountDisplayName
| order by Events desc
```

### 2.6 (Id=6) Acciones de Eliminación Masiva

```kusto
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("Delete","Remove","Purge")
| summarize Deletions=count(), Users=dcount(AccountId) by Application, ActionType
| where Deletions > 10
| order by Deletions desc
```

### 2.7 (Id=7) Descargas Masivas desde Cloud Apps

```kusto
let TimeRange = 7d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("Download","FileDownloaded","Export")
| summarize Downloads=count(), Apps=dcount(Application) by AccountDisplayName, AccountObjectId
| where Downloads > 50
| order by Downloads desc
```

### 2.8 (Id=8) Compartir Archivos con Externos

```kusto
let TimeRange = 14d;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("SharingSet","SharingInvitationCreated","Anonymous")
| summarize Shares=count(), Apps=dcount(Application) by AccountDisplayName, AccountObjectId
| where Shares > 20
| order by Shares desc
```

### 2.9 (Id=9) Actividad desde Países Poco Comunes

```kusto
let TimeRange = 7d;
let Baseline = 60d;
let known = CloudAppEvents
| where Timestamp between (ago(Baseline) .. ago(TimeRange))
| summarize KnownCountries=make_set(CountryCode, 200) by AccountId;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| summarize RecentCountries=make_set(CountryCode, 50), Events=count() by AccountId, AccountDisplayName
| join kind=leftouter known on AccountId
| extend NewCountries = set_difference(RecentCountries, KnownCountries)
| where array_length(NewCountries) > 0
| project AccountDisplayName, NewCountries, Events
| order by array_length(NewCountries) desc
```

### 2.10 (Id=10) Viaje Imposible (Actividad en 2+ Países en <2h)

```kusto
let TimeRange = 1d;
let Window = 2h;
CloudAppEvents
| where Timestamp >= ago(TimeRange)
| summarize Countries=make_set(CountryCode, 10), MinTime=min(Timestamp), MaxTime=max(Timestamp) by AccountId, AccountDisplayName, bin(Timestamp, Window)
| where array_length(Countries) >= 2
| project AccountDisplayName, Countries, MinTime, MaxTime
| order by MaxTime desc
```

---

## 3) Duplicados / equivalencias dentro del texto

*(Sección listada en el texto original sin detalle adicional.)*

---

## Sugerencias de mejora (sin cambiar la intención)

1. **Eliminar “Show more lines”**: aparece pegado al final de varias queries; si es un artefacto de copia/pegado del portal, conviene removerlo para evitar errores al ejecutar.
2. **Normalizar prefijos “KQL”**: en el texto original se ve `KQLCloudAppEvents` y `KQLlet ...`; si ese `KQL` no es parte real del query, debería quitarse. En la versión formateada asumí que es un prefijo accidental.
3. **Id=2 (Alto riesgo) está duplicado de Id=1**: si realmente busca “permisos de alto riesgo”, faltaría un filtro adicional (p.ej. por `Permissions`, `OAuthAppId`, o campos equivalentes según el esquema disponible). Tal como está, devuelve lo mismo que Id=1.
4. **Parámetros/umbrales (10, 50, 20)**: conviene convertirlos en variables (`let Threshold=...;`) para facilitar ajuste y reutilización.
5. **Consistencia de ventanas de tiempo**: documentar por qué algunas queries usan 7d, otras 14d y otras 1d; ayuda a operación y tuning.
6. **CountryCode nulo**: en queries 2.9 y 2.10 podría agregarse `| where isnotempty(CountryCode)` para evitar falsos positivos.

