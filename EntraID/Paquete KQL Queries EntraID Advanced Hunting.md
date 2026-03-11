# 🛡️ Paquete de Consultas KQL (Advanced Hunting)

## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

## Recomendaciones rápidas (antes de ejecutar)

- Ajusta `TimeRange` y/o filtros (`AccountName`, `DeviceName`, `DomainName`) para reducir ruido.
- Si una tabla no existe en tu tenant (depende de licenciamiento/ingesta), usa la alternativa indicada en cada query.
- Para convertir una query en **Custom Detection**, Microsoft recomienda basarla en **Advanced Hunting** y ejecutarla regularmente.

Este documento recopila una serie de consultas KQL (Kusto Query Language) diseñadas para la detección, triaje e investigación de amenazas en Microsoft Defender XDR.

**Autores:** Ernesto Cobos Roqueñí, Arturo Mandujano


---
## Índice
- [1) Detección – Usuarios (EntraIdSignInEvents)](#1-detección--usuarios-entraidsigninevents)
  - [1.1) Top fallos de inicio de sesión por usuario](#11-top-fallos-de-inicio-de-sesión-por-usuario)
  - [1.2) Top fallos por IP (brute force / spray)](#12-top-fallos-por-ip-brute-force--spray)
  - [1.3) Password spraying (una IP → muchos usuarios)](#13-password-spraying-una-ip--muchos-usuarios)
  - [1.4) Intentos contra un mismo usuario desde muchas IPs (spray distribuido)](#14-intentos-contra-un-mismo-usuario-desde-muchas-ips-spray-distribuido)
  - [1.5) Picos de fallos por ventana (detección de ráfagas)](#15-picos-de-fallos-por-ventana-detección-de-ráfagas)
  - [1.6) Sign-ins de alto riesgo (RiskLevelAggregated)](#16-sign-ins-de-alto-riesgo-risklevelaggregated-lowmediumhigh)
  - [1.7) Riesgo: "at risk" o "confirmed compromised" (RiskState)](#17-riesgo-at-risk-o-confirmed-compromised-riskstate)
  - [1.8) Sign-in sin MFA cuando se esperaba MFA](#18-sign-in-sin-mfa-cuando-se-esperaba-mfa-authenticationrequirement)
  - [1.9) Sign-in con MFA requerido pero CA no aplicado / falló](#19-sign-in-con-mfa-requerido-pero-ca-no-aplicado--falló)
  - [1.10) Token issuer ADFS (TokenIssuerType)](#110-token-issuer-adfs-tokenissuertype)
  - [1.11) Sign-ins desde países nuevos por usuario](#111-sign-ins-desde-países-nuevos-por-usuario-baseline-simple)
  - [1.12) Nuevos dispositivos (EntraIdDeviceId) por usuario](#112-nuevos-dispositivos-entraiddeviceid-por-usuario)
  - [1.13) Acceso desde dispositivos no gestionados o no compliant](#113-acceso-desde-dispositivos-no-gestionados-o-no-compliant)
  - [1.14) Invitados / externos con actividad](#114-invitados--externos-con-actividad-isguestuser--isexternaluser)
  - [1.15) Sign-ins con UserAgent "raro"](#115-sign-ins-con-useragent-raro-top-user-agents-por-usuario)
- [2) Detección – Workload Identities (EntraIdSpnSignInEvents)](#2-detección--workload-identities-entraidspnsigninevents)
  - [2.1) Fallos de autenticación de Service Principals / Managed Identity](#21-fallos-de-autenticación-de-service-principals--managed-identity)
  - [2.2) Un SPN con muchos IPs (posible abuso / token theft)](#22-un-spn-con-muchos-ips-posible-abuso--token-theft)
  - [2.3) Nuevos países para un SPN (baseline)](#23-nuevos-países-para-un-spn-baseline)
  - [2.4) Managed identity sign-ins (inventario rápido)](#24-managed-identity-sign-ins-inventario-rápido)
- [3) Detección – Abuso de Microsoft Graph (GraphApiAuditEvents)](#3-detección--abuso-de-microsoft-graph-graphapiauditevents)
  - [3.1) Fallos 401/403 en Microsoft Graph](#31-fallos-401403-en-microsoft-graph-enumeraciónabuso-de-permisos)
  - [3.2) Volumen anómalo de llamadas Graph por identidad](#32-volumen-anómalo-de-llamadas-graph-por-identidad-descubrimiento)
  - [3.3) "Read-heavy" (alto ratio GET)](#33-read-heavy-alto-ratio-get)
  - [3.4) Scopes sensibles](#34-scopes-sensibles-ajusta-tu-lista)
- [4) Triaje – "Pivots" rápidos (de señal a contexto)](#4-triaje--pivots-rápidos-de-señal-a-contexto)
  - [4.1) Pivote por CorrelationId](#41-pivote-por-correlationid-sign-in-específico)
  - [4.2) Pivote por RequestId](#42-pivote-por-requestid-sign-in)
  - [4.3) Pivote por AccountUpn (timeline de 24h)](#43-pivote-por-accountupn-timeline-de-24h)
  - [4.4) Pivote por IP](#44-pivote-por-ip-todas-las-cuentas-y-apps-impactadas)
  - [4.5) Pivote por Device (EntraIdDeviceId)](#45-pivote-por-device-entraiddeviceid)
- [5) Investigación – Correlaciones útiles (Entra ↔ Graph ↔ UEBA)](#5-investigación--correlaciones-útiles-entra--graph--ueba)
  - [5.1) Sign-ins de alto riesgo → actividad Graph en ±30 min](#51-sign-ins-de-alto-riesgo--actividad-graph-en-30-min)
  - [5.2) Password spraying detectado (1.3) → ver si hubo éxitos posteriores](#52-password-spraying-detectado-13--ver-si-hubo-éxitos-posteriores)
  - [5.3) CA no aplicado → qué apps y qué usuarios](#53-ca-no-aplicado-conditionalaccessstatus2--qué-apps-y-qué-usuarios)
  - [5.4) "New country" (1.11) → enriquecer con UEBA](#54-new-country-111--enriquecer-con-ueba-behavioranalytics)
  - [5.5) Behaviors (BehaviorInfo) asociados a identidad](#55-behaviors-behaviorinfo-asociados-a-identidad-accountupn)
- [6) Investigación – "Checklist" por entidad](#6-investigación--checklist-por-entidad)
  - [6.1) "Cuenta bajo investigación" (vista integral en 7 días)](#61-cuenta-bajo-investigación-vista-integral-en-7-días)
  - [6.2) "Service principal bajo investigación" (7 días)](#62-service-principal-bajo-investigación-7-días)
  - [6.3) "Graph activity por AccountObjectId" (7 días)](#63-graph-activity-por-accountobjectid-7-días)
- [7) Eventos de gestión de Entra vía CloudAppEvents](#7-eventos-de-gestión-de-entra-config--administración-vía-cloudappevents-si-tienes-defender-for-cloud-apps)
  - [7.1) Descubrir cómo se "llama" Entra en tu tenant](#71-descubrir-cómo-se-llama-entra-en-tu-tenant-application--actiontype)
  - [7.2) Top acciones administrativas (IsAdminOperation)](#72-top-acciones-administrativas-isadminoperation-para-la-app-de-entra-ajusta-appname)
  - [7.3) Búsqueda de acciones "consent / permission / role"](#73-búsqueda-de-acciones-consent--permission--role-string-match-ajusta-términos)
  - [7.4) "Nueva IP" para operaciones admin](#74-nueva-ip-para-operaciones-admin-baseline-simple)
- [Referencias (tablas)](#referencias-tablas)

---

# 1) Detección – Usuarios (EntraIdSignInEvents)

## 1.1) Top fallos de inicio de sesión por usuario
```kql
let Lookback = 1d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), Apps=dcount(Application), IPs=dcount(IPAddress) by AccountUpn
| order by Failures desc
```

## 1.2) Top fallos por IP (brute force / spray)
```kql
let Lookback = 1d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), Users=dcount(AccountUpn), Apps=dcount(Application) by IPAddress, Country
| order by Users desc, Failures desc
```

## 1.3) Password spraying (una IP → muchos usuarios)
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

## 1.4) Intentos contra un mismo usuario desde muchas IPs (spray distribuido)
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

## 1.5) Picos de fallos por ventana (detección de ráfagas)
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

## 1.6) Sign-ins de alto riesgo (RiskLevelAggregated: low/medium/high)
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

## 1.8) Sign-in sin MFA cuando se esperaba MFA (AuthenticationRequirement)
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where AuthenticationRequirement == "singleFactorAuthentication"
| summarize SignIns=count(), Apps=dcount(Application), Countries=dcount(Country) by AccountUpn
| order by SignIns desc
```

## 1.9) Sign-in con MFA requerido pero CA no aplicado / falló
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ConditionalAccessStatus in (1,2)   // 1=falló aplicar; 2=no aplicado
| project Timestamp, AccountUpn, Application, ConditionalAccessStatus, ConditionalAccessPolicies, IPAddress, Country
| order by Timestamp desc
```

## 1.10) Token issuer ADFS (TokenIssuerType)
```kql
let Lookback = 14d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where TokenIssuerType == 1
| summarize SignIns=count(), Users=dcount(AccountUpn), Apps=dcount(Application) by Application, ResourceDisplayName
| order by SignIns desc
```

## 1.11) Sign-ins desde países nuevos por usuario (baseline simple)
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

## 1.12) Nuevos dispositivos (EntraIdDeviceId) por usuario
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

## 1.13) Acceso desde dispositivos no gestionados o no compliant
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where IsManaged == 0 or IsCompliant == 0
| summarize SignIns=count(), Apps=dcount(Application), Countries=dcount(Country) by AccountUpn, IsManaged, IsCompliant
| order by SignIns desc
```

## 1.14) Invitados / externos con actividad (IsGuestUser / IsExternalUser)
```kql
let Lookback = 14d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where IsGuestUser == true or IsExternalUser == 1
| summarize SignIns=count(), Apps=make_set(Application, 20), Countries=make_set(Country, 20) by AccountUpn
| order by SignIns desc
```

## 1.15) Sign-ins con UserAgent "raro" (top user agents por usuario)
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| summarize SignIns=count() by AccountUpn, UserAgent
| top 200 by SignIns
```

---

# 2) Detección – Workload Identities (EntraIdSpnSignInEvents)

## 2.1) Fallos de autenticación de Service Principals / Managed Identity
```kql
let Lookback = 7d;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Lookback)
| where ErrorCode != 0
| summarize Failures=count(), IPs=dcount(IPAddress), Countries=dcount(Country) by ServicePrincipalName, ServicePrincipalId, IsManagedIdentity
| order by Failures desc
```

## 2.2) Un SPN con muchos IPs (posible abuso / token theft)
```kql
let Lookback = 7d;
let MinIPs = 10;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Lookback)
| summarize SignIns=count(), IPs=dcount(IPAddress), SampleIPs=make_set(IPAddress, 25) by ServicePrincipalName, ServicePrincipalId
| where IPs >= MinIPs
| order by IPs desc, SignIns desc
```

## 2.3) Nuevos países para un SPN (baseline)
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

## 2.4) Managed identity sign-ins (inventario rápido)
```kql
let Lookback = 7d;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Lookback)
| where IsManagedIdentity == true
| summarize SignIns=count(), Resources=make_set(ResourceDisplayName, 50) by ServicePrincipalName, ServicePrincipalId
| order by SignIns desc
```

---

# 3) Detección – Abuso de Microsoft Graph (GraphApiAuditEvents)

## 3.1) Fallos 401/403 en Microsoft Graph (enumeración/abuso de permisos)
```kql
let Lookback = 1d;
GraphApiAuditEvents
| where Timestamp >= ago(Lookback)
| where ResponseStatusCode in ("401","403")
| summarize Attempts=count(), URIs=make_set(RequestUri, 25) by AccountObjectId, ApplicationId, IPAddress, Scopes
| order by Attempts desc
```

## 3.2) Volumen anómalo de llamadas Graph por identidad (descubrimiento)
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

## 3.4) Scopes sensibles (ajusta tu lista)
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

# 4) Triaje – "Pivots" rápidos (de señal a contexto)

## 4.1) Pivote por CorrelationId (sign-in específico)
```kql
let Correlation = "<paste-correlation-id>";
EntraIdSignInEvents
| where CorrelationId == Correlation
| project Timestamp, AccountUpn, Application, ResourceDisplayName, IPAddress, Country, City,
          LogonType, ErrorCode, AuthenticationRequirement, ConditionalAccessStatus, ConditionalAccessPolicies,
          RiskLevelAggregated, RiskState, RiskDetails, UserAgent, ClientAppUsed, EntraIdDeviceId, DeviceName
| order by Timestamp desc
```

## 4.2) Pivote por RequestId (sign-in)
```kql
let ReqId = "<paste-request-id>";
EntraIdSignInEvents
| where RequestId == ReqId
| project *
```

## 4.3) Pivote por AccountUpn (timeline de 24h)
```kql
let User = "user@contoso.com";
let Lookback = 1d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where AccountUpn =~ User
| project Timestamp, Application, ResourceDisplayName, IPAddress, Country, ErrorCode, AuthenticationRequirement, ConditionalAccessStatus, RiskLevelAggregated
| order by Timestamp desc
```

## 4.4) Pivote por IP (todas las cuentas y apps impactadas)
```kql
let Ip = "1.2.3.4";
let Lookback = 1d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where IPAddress == Ip
| summarize Events=count(), Users=make_set(AccountUpn, 50), Apps=make_set(Application, 50), Errors=make_set(tostring(ErrorCode), 20)
```

## 4.5) Pivote por Device (EntraIdDeviceId)
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

# 5) Investigación – Correlaciones útiles (Entra ↔ Graph ↔ UEBA)

## 5.1) Sign-ins de alto riesgo → actividad Graph en ±30 min
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

## 5.2) Password spraying detectado (1.3) → ver si hubo éxitos posteriores
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

## 5.3) CA no aplicado (ConditionalAccessStatus=2) → qué apps y qué usuarios
```kql
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where ConditionalAccessStatus == 2
| summarize Events=count(), Users=dcount(AccountUpn) by Application, ResourceDisplayName
| order by Events desc
```

## 5.4) "New country" (1.11) → enriquecer con UEBA (BehaviorAnalytics)
> Ejemplo de UEBA para fallos desde país “primera vez” y poco común entre pares citeturn7search157
```kql
BehaviorAnalytics
| where ActivityType == "FailedLogOn"
| where ActivityInsights.FirstTimeUserConnectedFromCountry == True
| where ActivityInsights.CountryUncommonlyConnectedFromAmongPeers == True
```

## 5.5) Behaviors (BehaviorInfo) asociados a identidad (AccountUpn)
```kql
let Lookback = 14d;
BehaviorInfo
| where Timestamp >= ago(Lookback)
| where isnotempty(AccountUpn)
| project Timestamp, Title, Categories, AttackTechniques, AccountUpn, ServiceSource, DetectionSource, StartTime, EndTime
| order by Timestamp desc
```

---

# 6) Investigación – "Checklist" por entidad

## 6.1) "Cuenta bajo investigación" (vista integral en 7 días)
```kql
let User = "user@contoso.com";
let Lookback = 7d;
EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where AccountUpn =~ User
| summarize SignIns=count(), Failures=countif(ErrorCode!=0), HighRisk=countif(RiskLevelAggregated in (50,100) or RiskState in (4,5)),
          Countries=make_set(Country, 50), IPs=make_set(IPAddress, 50), Apps=make_set(Application, 50)
```

## 6.2) "Service principal bajo investigación" (7 días)
```kql
let SpId = "<service-principal-id>";
let Lookback = 7d;
EntraIdSpnSignInEvents
| where Timestamp >= ago(Lookback)
| where ServicePrincipalId == SpId
| summarize SignIns=count(), Failures=countif(ErrorCode!=0), Countries=make_set(Country, 50), IPs=make_set(IPAddress, 50), Resources=make_set(ResourceDisplayName, 50)
```

## 6.3) "Graph activity por AccountObjectId" (7 días)
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

# 7) Eventos de gestión de Entra (config / administración) vía CloudAppEvents (si tienes Defender for Cloud Apps)

> La tabla `CloudAppEvents` se alimenta desde **Microsoft Defender for Cloud Apps** y requiere que el conector esté habilitado; si no está desplegado, las queries no devolverán datos. citeturn7search194

## 7.1) Descubrir cómo se "llama" Entra en tu tenant (Application / ActionType)
```kql
let Lookback = 30d;
CloudAppEvents
| where Timestamp >= ago(Lookback)
| summarize Events=count(), SampleActions=make_set(ActionType, 20) by Application
| order by Events desc
```

## 7.2) Top acciones administrativas (IsAdminOperation) para la app de Entra (ajusta AppName)
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

## 7.3) Búsqueda de acciones "consent / permission / role" (string match, ajusta términos)
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

## 7.4) "Nueva IP" para operaciones admin (baseline simple)
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

  > Internal Tools 2026