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

1. [Alertas de Microsoft Defender for Identity (últimos X días)](#1-alertas-de-microsoft-defender-for-identity-últimos-x-días)
2. [Incidentes con evidencias de identidad (vista rápida)](#2-incidentes-con-evidencias-de-identidad-vista-rápida)
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
```kql
let TimeRange = 7d;
AlertInfo
| where Timestamp >= ago(TimeRange)
| where ServiceSource has_any ("MicrosoftDefenderForIdentity", "Defender for Identity", "MDI")
| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, DetectionSource, ProviderName
| order by Timestamp desc
```

---

## 2. Incidentes con evidencias de identidad (vista rápida)
```kql
let TimeRange = 7d;
IncidentInfo
| where Timestamp >= ago(TimeRange)
| project Timestamp, IncidentId, Title, Severity, Status, Classification, Determination
| order by Timestamp desc
```

---

## 3. Password spraying – múltiples fallos por cuenta
```kql
let TimeRange = 1d;
let FailureThreshold = 15;
IdentityLogonEvents
| where Timestamp >= ago(TimeRange)
| where ActionType in ("LogonFailed", "InvalidPassword", "UserLoginFailed", "Failure")
| summarize FailedLogons = count(), SrcIPs = dcount(IPAddress) by AccountUpn, AccountName, AccountDomain
| where FailedLogons >= FailureThreshold and SrcIPs >= 3
| order by FailedLogons desc
```

---

## 4. Cuentas privilegiadas con múltiples fallos de autenticación
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

## 5. Enumeración LDAP / SAM-R anómala
```kql
let TimeRange = 1d;
IdentityQueryEvents
| where Timestamp >= ago(TimeRange)
| where ActionType in ("SamR query", "Ldap query")
| summarize QueryCount = count() by DeviceName, AccountUpn, bin(Timestamp, 1h)
| where QueryCount > 500
| order by QueryCount desc
```

---

## 6. Enumeración de objetos AD (usuarios / grupos)
```kql
let TimeRange = 7d;
IdentityQueryEvents
| where Timestamp >= ago(TimeRange)
| summarize Events = count(), SrcIPs = dcount(IPAddress) by AccountUpn, AccountName, AccountDomain
| order by Events desc
```

---

## 7. Lateral movement – logons exitosos en múltiples equipos
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

---

## 8. sAMAccountName spoofing / noPac
```kql
let TimeRange = 7d;
IdentityDirectoryEvents
| where Timestamp >= ago(TimeRange)
| where ActionType contains "Account"
| extend OldSamAccount = tostring(parse_json(AdditionalFields).OldValue)
| extend NewSamAccount = tostring(parse_json(AdditionalFields).NewValue)
| where OldSamAccount != NewSamAccount and NewSamAccount endswith "$"
| project Timestamp, AccountUpn, TargetAccountUpn, OldSamAccount, NewSamAccount, DeviceName
| order by Timestamp desc
```

---

## 9. Cambios de UPN sospechosos
```kql
let TimeRange = 7d;
IdentityDirectoryEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has_any ("UPN", "User principal name", "UserPrincipalName")
| project Timestamp, AccountUpn, TargetAccountUpn, ActionType, AdditionalFields, DeviceName
| order by Timestamp desc
```

---

## 10. Actividad PowerShell en Domain Controllers
```kql
let TimeRange = 7d;
IdentityDirectoryEvents
| where Timestamp >= ago(TimeRange)
| where ActionType has "PowerShell"
| project Timestamp, AccountUpn, ActionType, AdditionalFields, DeviceName, DestinationDeviceName
| order by Timestamp desc
```

---

## 11. DNS tunneling / exfiltración
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

---

**Total de queries únicas**: 11  
**Listo para**: Hunting diario/semanal, Custom Detections, ITDR, SOC Runbooks