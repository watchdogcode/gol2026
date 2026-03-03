# 🛡️ Paquete de Consultas KQL (Advanced Hunting)

## Recomendaciones rápidas (antes de ejecutar)

- Ajusta `TimeRange` y/o filtros (`AccountName`, `DeviceName`, `DomainName`) para reducir ruido.
- Si una tabla no existe en tu tenant (depende de licenciamiento/ingesta), usa la alternativa indicada en cada query.
- Para convertir una query en **Custom Detection**, Microsoft recomienda basarla en **Advanced Hunting** y ejecutarla regularmente.

Este documento recopila una serie de consultas KQL (Kusto Query Language) diseñadas para la detección, triaje e investigación de amenazas en Microsoft Defender XDR.

**Autores:** Ernesto Cobos Roqueñí, Arturo Mandujano


---
## Índice
- [A) Detección – Usuarios (EntraIdSignInEvents)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a-detecci%C3%B3n--usuarios-entraidsigninevents)
  - [A1) Top fallos de inicio de sesión por usuario](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a1-top-fallos-de-inicio-de-sesi%C3%B3n-por-usuario)
  - [A2) Top fallos por IP (brute force / spray)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a2-top-fallos-por-ip-brute-force--spray)
  - [A3) Password spraying (una IP → muchos usuarios)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a3-password-spraying-una-ip--muchos-usuarios)
  - [A4) Intentos contra un mismo usuario desde muchas IPs (spray distribuido)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a4-intentos-contra-un-mismo-usuario-desde-muchas-ips-spray-distribuido)
  - [A5) Picos de fallos por ventana (detección de ráfagas)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a5-picos-de-fallos-por-ventana-detecci%C3%B3n-de-r%C3%A1fagas)
  - [A6) Sign-ins de alto riesgo (RiskLevelAggregated)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a6-sign-ins-de-alto-riesgo-risklevelaggregated-lowmediumhigh)
  - [A7) Riesgo: "at risk" o "confirmed compromised" (RiskState)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a7-riesgo-at-risk-o-confirmed-compromised-riskstate)
  - [A8) Sign-in sin MFA cuando se esperaba MFA](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a8-sign-in-sin-mfa-cuando-se-esperaba-mfa-authenticationrequirement)
  - [A9) Sign-in con MFA requerido pero CA no aplicado / falló](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a9-sign-in-con-mfa-requerido-pero-ca-no-aplicado--fall%C3%B3)
  - [A10) Token issuer ADFS (TokenIssuerType)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a10-token-issuer-adfs-tokenissuertype)
  - [A11) Sign-ins desde países nuevos por usuario](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a11-sign-ins-desde-pa%C3%ADses-nuevos-por-usuario-baseline-simple)
  - [A12) Nuevos dispositivos (EntraIdDeviceId) por usuario](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a12-nuevos-dispositivos-entraiddeviceid-por-usuario)
  - [A13) Acceso desde dispositivos no gestionados o no compliant](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a13-acceso-desde-dispositivos-no-gestionados-o-no-compliant)
  - [A14) Invitados / externos con actividad](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a14-invitados--externos-con-actividad-isguestuser--isexternaluser)
  - [A15) Sign-ins con UserAgent "raro"](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#a15-sign-ins-con-useragent-raro-top-user-agents-por-usuario)
- [B) Detección – Workload Identities (EntraIdSpnSignInEvents)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#b-detecci%C3%B3n--workload-identities-entraidspnsigninevents)
  - [B1) Fallos de autenticación de Service Principals / Managed Identity](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#b1-fallos-de-autenticaci%C3%B3n-de-service-principals--managed-identity)
  - [B2) Un SPN con muchos IPs (posible abuso / token theft)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#b2-un-spn-con-muchos-ips-posible-abuso--token-theft)
  - [B3) Nuevos países para un SPN (baseline)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#b3-nuevos-pa%C3%ADses-para-un-spn-baseline)
  - [B4) Managed identity sign-ins (inventario rápido)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#b4-managed-identity-sign-ins-inventario-r%C3%A1pido)
- [C) Detección – Abuso de Microsoft Graph (GraphApiAuditEvents)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#c-detecci%C3%B3n--abuso-de-microsoft-graph-graphapiauditevents)
  - [C1) Fallos 401/403 en Microsoft Graph](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#c1-fallos-401403-en-microsoft-graph-enumeraci%C3%B3nabuso-de-permisos)
  - [C2) Volumen anómalo de llamadas Graph por identidad](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#c2-volumen-an%C3%B3malo-de-llamadas-graph-por-identidad-descubrimiento)
  - [C3) "Read-heavy" (alto ratio GET)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#c3-read-heavy-alto-ratio-get)
  - [C4) Scopes sensibles](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#c4-scopes-sensibles-ajusta-tu-lista)
- [D) Triaje – "Pivots" rápidos (de señal a contexto)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#d-triaje--pivots-r%C3%A1pidos-de-se%C3%B1al-a-contexto)
  - [D1) Pivote por CorrelationId](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#d1-pivote-por-correlationid-sign-in-espec%C3%ADfico)
  - [D2) Pivote por RequestId](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#d2-pivote-por-requestid-sign-in)
  - [D3) Pivote por AccountUpn (timeline de 24h)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#d3-pivote-por-accountupn-timeline-de-24h)
  - [D4) Pivote por IP](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#d4-pivote-por-ip-todas-las-cuentas-y-apps-impactadas)
  - [D5) Pivote por Device (EntraIdDeviceId)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#d5-pivote-por-device-entraiddeviceid)
- [E) Investigación – Correlaciones útiles (Entra ↔ Graph ↔ UEBA)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#e-investigaci%C3%B3n--correlaciones-%C3%BAtiles-entra--graph--ueba)
  - [E1) Sign-ins de alto riesgo → actividad Graph en ±30 min](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#e1-sign-ins-de-alto-riesgo--actividad-graph-en-30-min)
  - [E2) Password spraying detectado (A3) → ver si hubo éxitos posteriores](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#e2-password-spraying-detectado-a3--ver-si-hubo-%C3%A9xitos-posteriores)
  - [E3) CA no aplicado → qué apps y qué usuarios](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#e3-ca-no-aplicado-conditionalaccessstatus2--qu%C3%A9-apps-y-qu%C3%A9-usuarios)
  - [E4) "New country" (A11) → enriquecer con UEBA](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#e4-new-country-a11--enriquecer-con-ueba-behavioranalytics)
  - [E5) Behaviors (BehaviorInfo) asociados a identidad](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#e5-behaviors-behaviorinfo-asociados-a-identidad-accountupn)
- [F) Investigación – "Checklist" por entidad](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#f-investigaci%C3%B3n--checklist-por-entidad)
  - [F1) "Cuenta bajo investigación" (vista integral en 7 días)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#f1-cuenta-bajo-investigaci%C3%B3n-vista-integral-en-7-d%C3%ADas)
  - [F2) "Service principal bajo investigación" (7 días)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#f2-service-principal-bajo-investigaci%C3%B3n-7-d%C3%ADas)
  - [F3) "Graph activity por AccountObjectId" (7 días)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#f3-graph-activity-por-accountobjectid-7-d%C3%ADas)
- [G) Eventos de gestión de Entra vía CloudAppEvents](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#g-eventos-de-gesti%C3%B3n-de-entra-config--administraci%C3%B3n-v%C3%ADa-cloudappevents-si-tienes-defender-for-cloud-apps)
  - [G1) Descubrir cómo se "llama" Entra en tu tenant](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#g1-descubrir-c%C3%B3mo-se-llama-entra-en-tu-tenant-application--actiontype)
  - [G2) Top acciones administrativas (IsAdminOperation)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#g2-top-acciones-administrativas-isadminoperation-para-la-app-de-entra-ajusta-appname)
  - [G3) Búsqueda de acciones "consent / permission / role"](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#g3-b%C3%BAsqueda-de-acciones-consent--permission--role-string-match-ajusta-t%C3%A9rminos)
  - [G4) "Nueva IP" para operaciones admin](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#g4-nueva-ip-para-operaciones-admin-baseline-simple)
- [Referencias (tablas)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md#referencias-tablas)

---

# A) Detección – Usuarios (EntraIdSignInEvents)

## A1) Top fallos de inicio de sesión por usuario
```kql
let Lookback = 1d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), Apps=dcount(Application), IPs=dcount(IPAddress) by AccountUpn
| order by Failures desc
```

## A2) Top fallos por IP (brute force / spray)
```kql
let Lookback = 1d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), Users=dcount(AccountUpn), Apps=dcount(Application) by IPAddress, Country
| order by Users desc, Failures desc
```

## A3) Password spraying (una IP → muchos usuarios)
```kql
let Lookback = 1d;
let MinUsers = 15;
let MinFailures = 50;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), Users=dcount(AccountUpn), SampleUsers=make_set(AccountUpn, 20) by IPAddress, Country
| where Users >= MinUsers and Failures >= MinFailures
| order by Users desc, Failures desc
```

## A4) Intentos contra un mismo usuario desde muchas IPs (spray distribuido)
```kql
let Lookback = 1d;
let MinIPs = 10;
let MinFailures = 30;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), IPs=dcount(IPAddress), SampleIPs=make_set(IPAddress, 20) by AccountUpn
| where IPs >= MinIPs and Failures >= MinFailures
| order by IPs desc, Failures desc
```

## A5) Picos de fallos por ventana (detección de ráfagas)
```kql
let Lookback = 1d;
let Window = 10m;
let Spike = 30;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count() by IPAddress, AccountUpn, bin(Timestamp, Window)
| where Failures >= Spike
| order by Failures desc
```

## A6) Sign-ins de alto riesgo (RiskLevelAggregated: low/medium/high)
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where RiskLevelAggregated in (50, 100)   // medium, high
| project Timestamp, AccountUpn, RiskLevelAggregated, RiskState, RiskDetails, Application, ResourceDisplayName, IPAddress, Country
| order by Timestamp desc
```

## A7) Riesgo: “at risk” o “confirmed compromised” (RiskState)
```kql
let Lookback = 14d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where RiskState in (4, 5)
| project Timestamp, AccountUpn, RiskState, RiskDetails, Application, ResourceDisplayName, IPAddress, Country
| order by Timestamp desc
```

## A8) Sign-in sin MFA cuando se esperaba MFA (AuthenticationRequirement)
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where AuthenticationRequirement == "singleFactorAuthentication"
| summarize SignIns=count(), Apps=dcount(Application), Countries=dcount(Country) by AccountUpn
| order by SignIns desc
```

## A9) Sign-in con MFA requerido pero CA no aplicado / falló
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ConditionalAccessStatus in (1,2)   // 1=falló aplicar; 2=no aplicado
| project Timestamp, AccountUpn, Application, ConditionalAccessStatus, ConditionalAccessPolicies, IPAddress, Country
| order by Timestamp desc
```

## A10) Token issuer ADFS (TokenIssuerType)
```kql
let Lookback = 14d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where TokenIssuerType == 1
| summarize SignIns=count(), Users=dcount(AccountUpn), Apps=dcount(Application) by Application, ResourceDisplayName
| order by SignIns desc
```

## A11) Sign-ins desde países nuevos por usuario (baseline simple)
```kql
let Lookback = 30d;
let Recent = 2d;
let historical = EntraIdSignInEvents
| where Timestamp between (ago(Lookback) .. ago(Recent))
| summarize KnownCountries=make_set(Country, 200) by AccountUpn;
EntraIdSignInEvents
| where Timestamp >= ago(Recent)
| summarize RecentCountries=make_set(Country, 50), RecentIPs=make_set(IPAddress, 50) by AccountUpn
| join kind=leftouter historical on AccountUpn
| extend NewCountries = set_difference(RecentCountries, KnownCountries)
| where array_length(NewCountries) > 0
| project AccountUpn, NewCountries, RecentIPs
| order by array_length(NewCountries) desc
```

## A12) Nuevos dispositivos (EntraIdDeviceId) por usuario
```kql
let Lookback = 30d;
let Recent = 2d;
let historical = EntraIdSignInEvents
| where Timestamp between (ago(Lookback) .. ago(Recent))
| summarize KnownDevices=make_set(EntraIdDeviceId, 500) by AccountUpn;
EntraIdSignInEvents
| where Timestamp >= ago(Recent)
| summarize RecentDevices=make_set(EntraIdDeviceId, 100), SampleApps=make_set(Application, 20) by AccountUpn
| join kind=leftouter historical on AccountUpn
| extend NewDevices = set_difference(RecentDevices, KnownDevices)
| where array_length(NewDevices) > 0
| project AccountUpn, NewDevices, SampleApps
```

## A13) Acceso desde dispositivos no gestionados o no compliant
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where IsManaged == 0 or IsCompliant == 0
| summarize SignIns=count(), Apps=dcount(Application), Countries=dcount(Country) by AccountUpn, IsManaged, IsCompliant
| order by SignIns desc
```

## A14) Invitados / externos con actividad (IsGuestUser / IsExternalUser)
```kql
let Lookback = 14d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where IsGuestUser == true or IsExternalUser == 1
| summarize SignIns=count(), Apps=make_set(Application, 20), Countries=make_set(Country, 20) by AccountUpn
| order by SignIns desc
```

## A15) Sign-ins con UserAgent “raro” (top user agents por usuario)
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| summarize SignIns=count() by AccountUpn, UserAgent
| top 200 by SignIns
```

---

# B) Detección – Workload Identities (EntraIdSpnSignInEvents)

## B1) Fallos de autenticación de Service Principals / Managed Identity
```kql
let Lookback = 7d;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), IPs=dcount(IPAddress), Countries=dcount(Country) by ServicePrincipalName, ServicePrincipalId, IsManagedIdentity
| order by Failures desc
```

## B2) Un SPN con muchos IPs (posible abuso / token theft)
```kql
let Lookback = 7d;
let MinIPs = 10;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Lookback)
| summarize SignIns=count(), IPs=dcount(IPAddress), SampleIPs=make_set(IPAddress, 25) by ServicePrincipalName, ServicePrincipalId
| where IPs >= MinIPs
| order by IPs desc, SignIns desc
```

## B3) Nuevos países para un SPN (baseline)
```kql
let Lookback = 30d;
let Recent = 2d;
let historical = EntraIdSpnSignInEvents
| where Timestamp between (ago(Lookback) .. ago(Recent))
| summarize KnownCountries=make_set(Country, 200) by ServicePrincipalId;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Recent)
| summarize RecentCountries=make_set(Country, 50), RecentIPs=make_set(IPAddress, 50) by ServicePrincipalId, ServicePrincipalName
| join kind=leftouter historical on ServicePrincipalId
| extend NewCountries = set_difference(RecentCountries, KnownCountries)
| where array_length(NewCountries) > 0
| project ServicePrincipalName, ServicePrincipalId, NewCountries, RecentIPs
```

## B4) Managed identity sign-ins (inventario rápido)
```kql
let Lookback = 7d;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Lookback)
| where IsManagedIdentity == true
| summarize SignIns=count(), Resources=make_set(ResourceDisplayName, 50) by ServicePrincipalName, ServicePrincipalId
| order by SignIns desc
```

---

# C) Detección – Abuso de Microsoft Graph (GraphApiAuditEvents)

## C1) Fallos 401/403 en Microsoft Graph (enumeración/abuso de permisos)
```kql
let Lookback = 1d;
GraphApiAuditEvents
| where Timestamp >= ago(Lookback)
| where ResponseStatusCode in ("401","403")
| summarize Attempts=count(), URIs=make_set(RequestUri, 25) by AccountObjectId, ApplicationId, IPAddress, Scopes
| order by Attempts desc
```

## C2) Volumen anómalo de llamadas Graph por identidad (descubrimiento)
```kql
let Lookback = 1d;
let Spike = 500;
GraphApiAuditEvents
| where Timestamp >= ago(Lookback)
| summarize Requests=count(), DistinctUris=dcount(RequestUri) by AccountObjectId, ApplicationId
| where Requests >= Spike
| order by Requests desc
```

## C3) “Read-heavy” (alto ratio GET)
```kql
let Lookback = 1d;
GraphApiAuditEvents
| where Timestamp >= ago(Lookback)
| summarize Total=count(), Gets=countif(RequestMethod == "GET"), Ratio=round(todouble(Gets)/todouble(Total), 3) by AccountObjectId, ApplicationId
| where Total > 200 and Ratio > 0.9
| order by Total desc
```

## C4) Scopes sensibles (ajusta tu lista)
```kql
let Lookback = 7d;
let HighRiskScopes = dynamic([
  "Mail.Read", "Mail.ReadWrite", "Mail.ReadWrite.All",
  "Files.Read", "Files.ReadWrite", "Files.ReadWrite.All",
  "Sites.Read.All", "Sites.ReadWrite.All",
  "Directory.Read.All", "Directory.ReadWrite.All",
  "User.Read.All", "Group.Read.All"
]);
GraphApiAuditEvents
| where Timestamp >= ago(Lookback)
| where Scopes has_any (HighRiskScopes)
| summarize Requests=count(), IPs=dcount(IPAddress), URIs=make_set(RequestUri, 25) by AccountObjectId, ApplicationId, Scopes
| order by Requests desc
```

---

# D) Triaje – “Pivots” rápidos (de señal a contexto)

## D1) Pivote por CorrelationId (sign-in específico)
```kql
let Correlation = "<paste-correlation-id>";
EntraIdSignInEvents
| where CorrelationId == Correlation
| project Timestamp, AccountUpn, Application, ResourceDisplayName, IPAddress, Country, City,
          LogonType, ErrorCode, AuthenticationRequirement, ConditionalAccessStatus, ConditionalAccessPolicies,
          RiskLevelAggregated, RiskState, RiskDetails, UserAgent, ClientAppUsed, EntraIdDeviceId, DeviceName
| order by Timestamp desc
```

## D2) Pivote por RequestId (sign-in)
```kql
let ReqId = "<paste-request-id>";
EntraIdSignInEvents
| where RequestId == ReqId
| project *
```

## D3) Pivote por AccountUpn (timeline de 24h)
```kql
let User = "user@contoso.com";
let Lookback = 1d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where AccountUpn =~ User
| project Timestamp, Application, ResourceDisplayName, IPAddress, Country, ErrorCode, AuthenticationRequirement, ConditionalAccessStatus, RiskLevelAggregated
| order by Timestamp desc
```

## D4) Pivote por IP (todas las cuentas y apps impactadas)
```kql
let Ip = "1.2.3.4";
let Lookback = 1d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where IPAddress == Ip
| summarize Events=count(), Users=make_set(AccountUpn, 50), Apps=make_set(Application, 50), Errors=make_set(tostring(ErrorCode), 20)
```

## D5) Pivote por Device (EntraIdDeviceId)
```kql
let DeviceId = "<entra-device-id>";
let Lookback = 14d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where EntraIdDeviceId == DeviceId
| project Timestamp, AccountUpn, DeviceName, OSPlatform, DeviceTrustType, IsManaged, IsCompliant, Application, ResourceDisplayName, IPAddress, Country
| order by Timestamp desc
```

---

# E) Investigación – Correlaciones útiles (Entra ↔ Graph ↔ UEBA)

## E1) Sign-ins de alto riesgo → actividad Graph en ±30 min
```kql
let Lookback = 7d;
let PivotWindow = 30m;
let risky = EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where RiskLevelAggregated in (50,100) or RiskState in (4,5)
| project SignInTime=Timestamp, AccountUpn, AccountObjectId, IPAddress, Country, Application, CorrelationId;
GraphApiAuditEvents
| join kind=inner (risky) on AccountObjectId
| where Timestamp between (SignInTime - PivotWindow .. SignInTime + PivotWindow)
| project SignInTime, Timestamp, AccountUpn, ApplicationId, IPAddress, RequestMethod, RequestUri, Scopes, ResponseStatusCode
| order by SignInTime desc, Timestamp desc
```

## E2) Password spraying detectado (A3) → ver si hubo éxitos posteriores
```kql
let Lookback = 1d;
let Window = 1h;
let MinUsers = 15;
let suspects = EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), Users=dcount(AccountUpn) by IPAddress
| where Users >= MinUsers
| project IPAddress;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| join kind=inner (suspects) on IPAddress
| summarize Failures=countif(ErrorCode!=0), Success=countif(ErrorCode==0), Users=dcount(AccountUpn) by IPAddress, bin(Timestamp, Window)
| order by Success desc
```

## E3) CA no aplicado (ConditionalAccessStatus=2) → qué apps y qué usuarios
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ConditionalAccessStatus == 2
| summarize Events=count(), Users=dcount(AccountUpn) by Application, ResourceDisplayName
| order by Events desc
```

## E4) “New country” (A11) → enriquecer con UEBA (BehaviorAnalytics)
> Ejemplo de UEBA para fallos desde país “primera vez” y poco común entre pares citeturn7search157
```kql
BehaviorAnalytics
| where ActivityType == "FailedLogOn"
| where ActivityInsights.FirstTimeUserConnectedFromCountry == True
| where ActivityInsights.CountryUncommonlyConnectedFromAmongPeers == True
```

## E5) Behaviors (BehaviorInfo) asociados a identidad (AccountUpn)
```kql
let Lookback = 14d;
BehaviorInfo
| where Timestamp >= ago(Lookback)
| where isnotempty(AccountUpn)
| project Timestamp, Title, Categories, AttackTechniques, AccountUpn, ServiceSource, DetectionSource, StartTime, EndTime
| order by Timestamp desc
```

---

# F) Investigación – “Checklist” por entidad

## F1) “Cuenta bajo investigación” (vista integral en 7 días)
```kql
let User = "user@contoso.com";
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where AccountUpn =~ User
| summarize SignIns=count(), Failures=countif(ErrorCode!=0), HighRisk=countif(RiskLevelAggregated in (50,100) or RiskState in (4,5)),
          Countries=make_set(Country, 50), IPs=make_set(IPAddress, 50), Apps=make_set(Application, 50)
```

## F2) “Service principal bajo investigación” (7 días)
```kql
let SpId = "<service-principal-id>";
let Lookback = 7d;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Lookback)
| where ServicePrincipalId == SpId
| summarize SignIns=count(), Failures=countif(ErrorCode!=0), Countries=make_set(Country, 50), IPs=make_set(IPAddress, 50), Resources=make_set(ResourceDisplayName, 50)
```

## F3) “Graph activity por AccountObjectId” (7 días)
```kql
let ObjId = "<account-object-id>";
let Lookback = 7d;
GraphApiAuditEvents
| where Timestamp >= ago(Lookback)
| where AccountObjectId == ObjId
| summarize Requests=count(), Methods=make_set(RequestMethod, 10), Targets=make_set(TargetWorkload, 20), URIs=make_set(RequestUri, 50) by ApplicationId, IPAddress
| order by Requests desc
```

---



---

# G) Eventos de gestión de Entra (config / administración) vía CloudAppEvents (si tienes Defender for Cloud Apps)

> La tabla `CloudAppEvents` se alimenta desde **Microsoft Defender for Cloud Apps** y requiere que el conector esté habilitado; si no está desplegado, las queries no devolverán datos. citeturn7search194

## G1) Descubrir cómo se “llama” Entra en tu tenant (Application / ActionType)
```kql
let Lookback = 30d;
CloudAppEvents
| where Timestamp >= ago(Lookback)
| summarize Events=count(), SampleActions=make_set(ActionType, 20) by Application
| order by Events desc
```

## G2) Top acciones administrativas (IsAdminOperation) para la app de Entra (ajusta AppName)
```kql
let Lookback = 14d;
let AppName = "Azure Active Directory";   // cambia según G1
CloudAppEvents
| where Timestamp >= ago(Lookback)
| where Application == AppName
| where IsAdminOperation == true
| summarize Events=count(), Actors=make_set(AccountDisplayName, 20), IPs=make_set(IPAddress, 20) by ActionType
| order by Events desc
```

## G3) Búsqueda de acciones “consent / permission / role” (string match, ajusta términos)
```kql
let Lookback = 30d;
let AppName = "Azure Active Directory";   // cambia según G1
CloudAppEvents
| where Timestamp >= ago(Lookback)
| where Application == AppName
| where ActionType has_any ("consent", "permission", "role", "grant", "app")
| project Timestamp, ActionType, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, RawEventData, AdditionalFields
| order by Timestamp desc
```

## G4) “Nueva IP” para operaciones admin (baseline simple)
```kql
let Lookback = 60d;
let Recent = 3d;
let AppName = "Azure Active Directory";   // cambia según G1
let hist = CloudAppEvents
| where Timestamp between (ago(Lookback) .. ago(Recent))
| where Application == AppName and IsAdminOperation == true
| summarize KnownIPs=make_set(IPAddress, 500) by AccountObjectId;
CloudAppEvents
| where Timestamp >= ago(Recent)
| where Application == AppName and IsAdminOperation == true
| summarize RecentIPs=make_set(IPAddress, 100), Actions=make_set(ActionType, 25) by AccountObjectId, AccountDisplayName
| join kind=leftouter hist on AccountObjectId
| extend NewIPs = set_difference(RecentIPs, KnownIPs)
| where array_length(NewIPs) > 0
| project AccountDisplayName, AccountObjectId, NewIPs, Actions
```

## Referencias (tablas)
- Entra sign-ins (`EntraIdSignInEvents`) citeturn7search172
- Entra SPN sign-ins (`EntraIdSpnSignInEvents`) citeturn7search176
- Graph API audit (`GraphApiAuditEvents`) citeturn7search166
- Schema tables overview (para validar columnas en tu tenant) citeturn7search177
