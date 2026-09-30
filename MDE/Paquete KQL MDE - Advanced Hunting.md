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

- [LOLBins – Ejecución sospechosa](#lolbins-ejecución-sospechosa)
- [PowerShell ofuscado / Base64](#powershell-ofuscado--base64)
- [Descarga de binarios desde Internet](#descarga-de-binarios-desde-internet)
- [Persistencia – Tareas programadas](#persistencia-tareas-programadas)
- [Creación de usuarios locales](#creación-de-usuarios-locales)
- [Actividad tipo ransomware](#actividad-tipo-ransomware)
- [Credential Dumping](#credential-dumping)
- [Conexiones sospechosas (C2)](#conexiones-sospechosas-c2)
- [Ejecución desde rutas inusuales](#ejecución-desde-rutas-inusuales)
- [Instalación de servicios](#instalación-de-servicios)

---

## LOLBins – Ejecución sospechosa
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName in~ (
    "powershell.exe","cmd.exe","mshta.exe","rundll32.exe",
    "regsvr32.exe","wscript.exe","cscript.exe"
)
| where ProcessCommandLine has_any (
    "-enc","DownloadString","IEX","Invoke-WebRequest",
    "FromBase64String","http","https"
)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

## PowerShell ofuscado / Base64
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)(-enc\s+[A-Za-z0-9+/=]{20,})"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

## Descarga de binarios desde Internet
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where ProcessCommandLine has_any ("http://","https://")
| where FileName in~ ("powershell.exe","curl.exe","wget.exe","bitsadmin.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
```

## Persistencia – Tareas programadas
```kql
DeviceScheduledTaskEvents
| where Timestamp >= ago(14d)
| where ActionType in ("ScheduledTaskCreated","ScheduledTaskUpdated")
| project Timestamp, DeviceName, TaskName, TaskPath, Author, ActionType
| order by Timestamp desc
```

## Creación de usuarios locales
```kql
DeviceEvents
| where Timestamp >= ago(14d)
| where ActionType == "UserAccountCreated"
| project Timestamp, DeviceName, AccountName, InitiatingProcessAccountName
| order by Timestamp desc
```

## Actividad tipo ransomware
```kql
DeviceFileEvents
| where Timestamp >= ago(1d)
| where ActionType == "FileRenamed"
| summarize FileCount = count() by DeviceName, InitiatingProcessFileName
| where FileCount > 100
| order by FileCount desc
```

## Credential Dumping
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where ProcessCommandLine has_any ("mimikatz","sekurlsa","lsadump","procdump")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

## Conexiones sospechosas (C2)
```kql
DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("powershell.exe","cmd.exe","mshta.exe","rundll32.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| order by Timestamp desc
```

## Ejecución desde rutas inusuales
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FolderPath has_any ("\Users\Public\","\AppData\Local\Temp\","\ProgramData\")
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine
```

## Instalación de servicios
```kql
DeviceEvents
| where Timestamp >= ago(14d)
| where ActionType == "ServiceInstalled"
| project Timestamp, DeviceName, ServiceName, FolderPath, InitiatingProcessAccountName
| order by Timestamp desc
```

---

