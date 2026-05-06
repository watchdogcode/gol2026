# 🛡️ Paquete de Consultas KQL (Advanced Hunting)

## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

**Autores:** Ernesto Cobos Roqueñí, Arturo Mandujano

## Recomendaciones rápidas (antes de ejecutar)

- Ajusta `TimeRange` y/o filtros (`AccountName`, `DeviceName`, `DomainName`) para reducir ruido.
- Si una tabla no existe en tu tenant (depende de licenciamiento/ingesta), usa la alternativa indicada en cada query.
- Para convertir una query en **Custom Detection**, Microsoft recomienda basarla en **Advanced Hunting** y ejecutarla regularmente.

Este documento recopila una serie de consultas KQL (Kusto Query Language) diseñadas para la detección, triaje e investigación de amenazas en Microsoft Defender XDR.

**Autores:** Ernesto Cobos Roqueñí, Arturo Mandujano
---

## Índice

1. [Alertas de Microsoft Defender for Identity (últimos X días)](#1-alertas-de-microsoft-defender-for-identity-últimos-x-días)
2. [Validar estado de salud de Sensores de MDI](#2-validar-estado-de-salud-de-sensores-de-mdi)
3. [Password spraying – múltiples fallos por cuenta](#3-password-spraying--múltiples-fallos-por-cuenta)
4. [Cuentas privilegiadas con múltiples fallos de autenticación](#4-cuentas-privilegiadas-con-múltiples-fallos-de-autenticación)
5. [Enumeración LDAP / SAM-R anómala](#5-enumeración-ldap--sam-r-anómala)
6. [Enumeración de objetos AD (usuarios / grupos)](#6-enumeración-de-objetos-ad-usuarios--grupos)
7. [Lateral movement – logons exitosos en múltiples equipos](#7-lateral-movement--logons-exitosos-en-múltiples-equipos)
8. [sAMAccountName spoofing / noPac](#8-samaccountname-spoofing--nopac)
9. [Cambios de UPN sospechosos](#9-cambios-de-upn-sospechosos)
10. [Actividad PowerShell en Domain Controllers](#10-actividad-powershell-en-domain-controllers)
11. [DNS tunneling / exfiltración](#11-dns-tunneling--exfiltración)

---

## 1. Alertas de Microsoft Defender for Identity (últimos X días)

### Descripción del query

Este query consulta la tabla **AlertInfo** en Microsoft 365 Defender Advanced Hunting para:

   - Analizar **alertas generadas en los últimos X días**
   - Filtrar **únicamente alertas cuya fuente de detección sea Microsoft Defender for Identity (MDI)**

```kql
let TimeRange = ago(1d);
AlertInfo
| where Timestamp >= TimeRange
| where DetectionSource has "Defender for Identity"
| project
    Timestamp,
    AlertId,
    Title,
    Severity,
    Category,
    ServiceSource,
    DetectionSource
| sort by Timestamp desc
```

### Campos en los que deberías enfocarte

Dependiendo de tu objetivo (SOC, hunting, arquitectura), estos son los más importantes:
**Severity**
**Prioridad número uno**

- Te indica el nivel de riesgo de la alerta (High, Medium, Low).
- Útil para:

   - Triage rápido
   - Detección de picos de alertas críticas
   - Priorización de investigación

---

## 2. Validar estado de salud de Sensores de MDI

### Este query sirve para:

Detecta eventos de salud/estado de sensores (MDI) reportados en las últimas 24 h para identificar sensores con problemas o cambios de estado


```kql
IdentityDirectoryEvents
| where Timestamp > ago(24h)
| where ActionType has "Health" or ActionType has "Sensor" or ActionType has "Status"
| extend State = tostring(AdditionalFields.State), 
         Message = tostring(AdditionalFields.Message),
         SensorName = DeviceName
| summarize 
    LastUpdate = max(Timestamp), 
    TotalAlerts = count(), 
    CurrentState = make_set(State),
    ErrorDetails = make_set(Message) 
    by SensorName, ActionType
| sort by LastUpdate desc
```

### Campos en los que deberías enfocarte

   - CurrentState: estados distintos a “Running”
   - ErrorDetails: mensajes de error o advertencia
   - SensorName: sensor afectado
   - LastUpdate: si es reciente (problema activo)

---

## 3. Password spraying – múltiples fallos por cuenta

### Descripción del query

Detecta posibles ataques de fuerza bruta / password spraying contra identidades, buscando:

   - Muchos intentos de login fallidos
   - Desde múltiples direcciones IP
   - Contra la misma cuenta
   - En una ventana de 1 día

```kql
let FailureThreshold = 15;
IdentityLogonEvents
| where Timestamp >= ago(7d)
| where ActionType in ("LogonFailed", "InvalidPassword")
| summarize
    FailedLogons = count(),
    SrcIPs = dcount(IPAddress),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountName, AccountDomain
| where FailedLogons >= FailureThreshold and SrcIPs >= 3
| sort by FailedLogons desc
```

### Campos en los que deberías enfocarte

**FailedLogons**

   - Indicador principal de ataque
   - Valores altos = alta probabilidad de automatización

**SrcIPs**

≥ 3 IPs → fuerte señal de:

   - Password spraying
   - Botnet
   - Proxy/TOR

**LastSeen**

Si es reciente → ataque activo
Si no → evento histórico

**AccountName / AccountDomain**

   - ¿Cuenta privilegiada?
   - ¿Cuenta de servicio?
   - ¿Usuario real?


---

## 4. Cuentas privilegiadas con múltiples fallos de autenticación

### Este query sirve para:

   - Detectar actividad sospechosa contra cuentas con roles asignados
   - Priorizar investigaciones de autenticación fallida
   - Identificar posibles ataques dirigidos a cuentas sensibles

```kql
let PrivilegedAccounts = IdentityInfo
| where TimeGenerated > ago(14d)
| where isnotempty(AssignedRoles)
| summarize arg_max(TimeGenerated, *) by AccountUpn
| project AccountUpn, AssignedRoles;
IdentityLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonFailed"
| where FailureReason !in ("UserNotFound", "UnknownUser")
| join kind=inner PrivilegedAccounts on $left.AccountUpn == $right.AccountUpn
| summarize 
    FailureCount = count(), 
    FailureReasons = make_set(FailureReason), 
    UniqueIPs = dcount(IPAddress), 
    IPList = make_set(IPAddress),
    AppList = make_set(Application)
    by TargetDeviceName, Roles = tostring(AssignedRoles) 
| where FailureCount >= 5 
| sort by FailureCount desc
```
### Campos en los que deberías enfocarte

   - FailureCount (volumen)
   - UniqueIPs / IPList (distribución)
   - Roles (impacto)
   - FailureReasons (patrón)
   - TargetDeviceName y AppList (vector)


---

## 5. Enumeración LDAP / SAM-R anómala

### Este query sirve para:

   - Detectar reconnaissance en AD
   - Enfocado en LDAP / SAMR enumeration
   - Muy útil como hunting proactivo
   - Prioriza:
         - QueryCount
         - AccountUpn
         - DeviceName

```kql
let TimeRange = 1d;
IdentityQueryEvents
| where Timestamp >= ago(TimeRange)
| where ActionType in ("SamR query", "Ldap query")
| summarize QueryCount = count() by DeviceName, AccountUpn, bin(Timestamp, 1h)
| where QueryCount > 500
| order by QueryCount desc
```
### Campos en los que deberías enfocarte

  - Correlacionar esto con logons exitosos posteriores
  - Cruzarlo con alertas MDI

---

## 6. Enumeración de objetos AD (usuarios / grupos)

### Este query sirve para:

Este query sirve para identificar cuentas que realizan un volumen elevado de consultas de identidad (LDAP, SAMR u otras incluidas en IdentityQueryEvents) durante los últimos X días, con el objetivo de detectar:

   - Reconnaissance en Active Directory
   - Enumeración de objetos (usuarios, grupos, equipos)
   - Uso de scripts o herramientas automatizadas (ej. BloodHound, PowerView, AdFind)

```kql
let TimeRange = 7d;
IdentityQueryEvents
| where Timestamp >= ago(TimeRange)
| where isnotempty(AccountUpn)
| summarize 
    TotalQueries = count(), 
    DistinctTargetResources = dcount(TargetDeviceName), 
    DistinctIPs = dcount(IPAddress),
    ActionTypes = make_set(ActionType), // Para saber qué tipo de consultas hacen
    IPList = make_set(IPAddress, 5) // Muestra hasta 5 IPs de origen
    by AccountUpn
| extend QueryIntensity = TotalQueries / DistinctIPs
| order by TotalQueries desc
```
### Campos en los que deberías enfocarte

   - TotalQueries: cuentas con volumen anormalmente alto → posible reconnaissance.
   - DistinctIPs: varias IPs = automatización / movimiento lateral.
   - QueryIntensity: alto = muchas consultas desde pocas IPs (herramientas).
   - ActionTypes: presencia repetida de LDAP / SAMR es señal clara.
   - AccountUpn: si es cuenta admin o sensible → prioridad alta.


---

## 7. Lateral movement – logons exitosos en múltiples equipos

### Este query sirve para:

  - Detectar uso anómalo de credenciales
  - Ideal para hunting de account compromise
  - Enfócate en:

       - Devices
       - AccountUpn
       - DeviceList
       - Ventanas de 1 hora

```kql
let Lookback = 1d;
let Window = 1h;
let MinDevices = 6;
IdentityLogonEvents
| where Timestamp >= ago(Lookback)
| where ActionType in ("LogonSuccess", "LogonAttempted")
| summarize Devices = dcount(DeviceName), DeviceList = make_set(DeviceName, 25), TotalLogons = count() 
    by AccountUpn, AccountName, AccountDomain, bin(Timestamp, Window)
| where Devices >= MinDevices
| order by Devices desc
```
### Campos en los que deberías enfocarte

   - Devices
   - AccountUpn / AccountName
   - DeviceList
   - bin(Timestamp, 1h)
   - TotalLogons

---

## 8. sAMAccountName spoofing / noPac

### Este query sirve para:

Detecta cambios sospechosos de cuentas en Active Directory, específicamente cuando una cuenta es renombrada para parecer una cuenta de equipo (nombre terminado en $), lo cual puede indicar evasión, persistencia o abuso de AD

```kql
IdentityDirectoryEvents
| where Timestamp >= ago(7d)
| where ActionType contains "Account"
| extend OldSamAccount = tostring(parse_json(AdditionalFields).OldValue)
| extend NewSamAccount = tostring(parse_json(AdditionalFields).NewValue)
| where OldSamAccount != NewSamAccount and NewSamAccount endswith "$"
| project Timestamp, AccountUpn, TargetAccountUpn, OldSamAccount, NewSamAccount, DeviceName
| order by Timestamp desc
```
### Campos en los que deberías enfocarte

   - OldSamAccount → NewSamAccount: cambio a nombre con $ = alerta alta
   - TargetAccountUpn: cuenta que fue modificada (¿usuario o admin?)
   - AccountUpn: quién realizó el cambio
   - DeviceName: desde dónde se hizo (workstation vs DC)
   - Timestamp: cuándo ocurrió (para correlación)

---

## 9. Cambios de UPN sospechosos

### Este query sirve para:

Detecta renombrados sospechosos de cuentas en Active Directory, cuando una cuenta pasa a tener un nombre que termina en $ (simulando una cuenta de equipo), lo que puede indicar evasión o persistencia.

```kql
let TimeRange = 7d;
IdentityDirectoryEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("UPN", "User principal name", "UserPrincipalName")
| project Timestamp, AccountUpn, TargetAccountUpn, ActionType, AdditionalFields, DeviceName
| order by Timestamp desc
```
### Campos en los que deberías enfocarte

   - OldSamAccount → NewSamAccount: si termina en $, es alerta alta
   - TargetAccountUpn: cuenta afectada
   - AccountUpn: quién hizo el cambio
   - DeviceName: desde dónde se ejecutó
   - Timestamp: momento del cambio

---

## 10. Actividad PowerShell en Domain Controllers

### Este query sirve para:
Detecta uso de PowerShell asociado a eventos de identidad en los últimos 7 días, útil para identificar automatización, abuso administrativo o actividad post‑explotación.


```kql
let TimeRange = 7d;
IdentityDirectoryEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has "PowerShell"
| project Timestamp, AccountUpn, ActionType, AdditionalFields, DeviceName, DestinationDeviceName
| order by Timestamp desc
```
### Campos en los que deberías enfocarte

   - AccountUpn: quién ejecutó PowerShell (¿admin o cuenta sensible?)
   - ActionType: qué tipo de acción PowerShell se realizó
   - DeviceName / DestinationDeviceName: desde dónde y hacia dónde
   - AdditionalFields: detalles del comando/acción
   - Timestamp: si es reciente (actividad activa)

---

## 11. DNS tunneling / exfiltración

### Este query sirve para:
Detecta comportamiento DNS anómalo (muchas consultas DNS o a muchos dominios) desde un dispositivo/proceso en las últimas 24 h, típico de malware, beaconing o DGA.

```kql
let TimeRange = 1d;
DeviceNetworkEvents
| where Timestamp >= ago(TimeRange)
| where RemotePort == 53
| summarize DNSQueries = count(), DistinctDomains = dcount(RemoteUrl) 
    by DeviceName, InitiatingProcessAccountName
| where DNSQueries > 1000 or DistinctDomains > 500
| order by DNSQueries desc
```
### Campos en los que deberías enfocarte

   - DNSQueries: volumen muy alto = automatización/malware
   - DistinctDomains: muchos dominios = DGA/exfiltración
   - DeviceName: equipo afectado
   - InitiatingProcessAccountName: proceso/cuenta que origina el tráfico

---

**Total de queries únicas**: 11  
**Listo para**: Hunting diario/semanal, Custom Detections, ITDR, SOC Runbooks