# Requisitos y Dependencias

Este documento describe los requisitos de licenciamiento, infraestructura, módulos de PowerShell y permisos necesarios para ejecutar los scripts de este repositorio.

---

## 1. Licenciamiento Microsoft 365

Se requieren licencias que incluyan los servicios de Microsoft Defender XDR y Exchange Online Protection.

| Licencia recomendada | Servicios incluidos |
|---|---|
| Microsoft 365 E5 | MDE, MDO, MDI, MDA, Exchange Online |
| Licencias independientes | Defender for Endpoint P2, Defender for Office 365 P2, Defender for Identity |

> **Nota:** Sin estas licencias las tablas de Advanced Hunting (p. ej. `EmailEvents`, `AlertInfo`, `DeviceTvmSoftwareVulnerabilities`) estarán vacías y los reportes no mostrarán información.

---

## 2. Entorno de Ejecución

| Requisito | Detalle |
|---|---|
| **PowerShell** | 5.1 o superior (se recomienda PowerShell 7+) |
| **Sistema Operativo** | Windows 10/11 o Windows Server 2016+ |
| **Privilegios de administrador** | Requerido únicamente para `Domain-Health-Check.ps1` (`#Requires -RunAsAdministrator`) |

---

## 3. App Registration en Microsoft Entra ID

Todos los scripts de reportería XDR/MDE se autentican contra la API de Microsoft 365 Defender y requieren un registro de aplicación:

1. Crear un **App Registration** en Microsoft Entra ID.
2. Asignar el permiso de API: **`AdvancedHunting.Read.All`** (Tipo: Application).
3. Generar un **Client Secret** (o certificado, según el modo de autenticación).
4. Tener a mano: **Tenant ID**, **Client ID** y **Client Secret**.

### Modos de autenticación soportados

| Modo | Módulos adicionales requeridos | Scripts compatibles |
|---|---|---|
| `Secret` | Ninguno (usa `Invoke-RestMethod` nativo) | Todos |
| `DeviceCode` | Ninguno (usa `Invoke-RestMethod` nativo) | Daily, Weekly, Vulnerability |
| `Interactive` | `Az.Accounts` **o** `Microsoft.Graph.Authentication` | Daily, Weekly, Vulnerability |
| `Certificate` | `MSAL.PS` | Weekly, Vulnerability |

---

## 4. Módulos de PowerShell

### 4.1 Módulos por script

| Script | Módulos requeridos | Obligatorio |
|---|---|---|
| `XDR/New-DefenderXDRDailyReport.ps1` | Ninguno (modo `Secret`) | — |
| | `Az.Accounts` **o** `Microsoft.Graph.Authentication` (modo `Interactive`/`DeviceCode`) | Condicional |
| `XDR/New-DefenderXDRWeeklyReport.ps1` | Ninguno (modo `Secret`/`DeviceCode`) | — |
| | `Az.Accounts` (modo `Interactive`) | Condicional |
| | `MSAL.PS` (modo `Certificate`) | Condicional |
| `XDR/Setup-DefenderXDRReportServer.ps1` | Ninguno | — |
| `MDE/New-DefenderVulnerabilityReport.ps1` | Ninguno (modo `Secret`/`DeviceCode`) | — |
| | `Az.Accounts` (modo `Interactive`) | Condicional |
| | `MSAL.PS` (modo `Certificate`) | Condicional |
| `MDO/Scripts/Block-OnMicrosoftEmails.ps1` | `ExchangeOnlineManagement` | **Sí** |
| `MDO/Scripts/Quarantine Attachments Can't be inspected.ps1` | `ExchangeOnlineManagement` | **Sí** |
| `MDO/Scripts/Domain-Health-Check.ps1` | `DomainHealthChecker`, `MailAuthDnsTools`, `EmailAuthChecker` | **Sí** (se instalan automáticamente si faltan) |

### 4.2 Instalación de módulos

```powershell
# Módulos para scripts MDO (Exchange Online)
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force

# Módulos para Domain Health Check (se instalan automáticamente por el script, pero pueden pre-instalarse)
Install-Module -Name DomainHealthChecker   -Scope CurrentUser -Force
Install-Module -Name MailAuthDnsTools      -Scope CurrentUser -Force
Install-Module -Name EmailAuthChecker      -Scope CurrentUser -Force

# Módulos opcionales según modo de autenticación
Install-Module -Name Az.Accounts                      -Scope CurrentUser -Force   # Interactive
Install-Module -Name Microsoft.Graph.Authentication    -Scope CurrentUser -Force   # Interactive (alternativa)
Install-Module -Name MSAL.PS                           -Scope CurrentUser -Force   # Certificate
```

---

## 5. Conectividad de Red

El equipo o servidor donde se ejecuten los scripts debe tener acceso HTTPS (443) a los siguientes endpoints:

| Endpoint | Propósito |
|---|---|
| `login.microsoftonline.com` | Autenticación OAuth 2.0 (todos los scripts XDR/MDE) |
| `api.security.microsoft.com` | API de Advanced Hunting - Microsoft 365 Defender |
| `outlook.office365.com` | Exchange Online PowerShell remoto (scripts MDO) |
| `*.protection.outlook.com` | Exchange Online Protection |
| Servidores DNS públicos | Resolución DNS para `Domain-Health-Check.ps1` (SPF, DKIM, DMARC, MTA-STS) |

> Si el entorno utiliza proxy, los scripts XDR Weekly y Vulnerability soportan el parámetro `-ProxyUrl`.

---

## 6. Permisos de Usuario

### Ejecución automatizada (recomendado)
Se utiliza el App Registration con `AdvancedHunting.Read.All` (Application). No se requieren permisos de usuario adicionales.

### Ejecución manual/interactiva
La cuenta de usuario que ejecute los scripts debe tener asignado uno de los siguientes roles en el portal de Microsoft Defender:

- **Security Reader** (Lector de seguridad) — lectura de reportes.
- **Security Administrator** — lectura y acciones de respuesta.

### Scripts MDO (Exchange Online)
Se requiere una sesión activa con `Connect-ExchangeOnline` y el rol:

- **Organization Management** o **Mail Flow Administrator** — para crear/modificar Transport Rules.

---

## 7. Variables de Entorno (Opcional)

El script `New-DefenderXDRDailyReport.ps1` soporta credenciales vía variables de entorno como alternativa a parámetros:

```powershell
$env:AZURE_TENANT_ID     = "<tu-tenant-id>"
$env:AZURE_CLIENT_ID     = "<tu-client-id>"
$env:AZURE_CLIENT_SECRET = "<tu-client-secret>"
```

---

## 8. Estructura de Directorios para Reportes

El script `Setup-DefenderXDRReportServer.ps1` crea automáticamente la siguiente estructura:

```
<ScriptsPath>\
├── Config\          # Credenciales cifradas (DPAPI)
├── Reports\         # Reportes HTML generados
│   └── Logs\        # Archivos de log
```

`Domain-Health-Check.ps1` genera reportes en `C:\Scripts\MDO\` (se crea automáticamente si no existe).

---

## Resumen rápido de dependencias

```
Scripts XDR/MDE (Secret/DeviceCode)
  └── Sin módulos adicionales (usa Invoke-RestMethod nativo)

Scripts XDR/MDE (Interactive)
  └── Az.Accounts  ─ó─  Microsoft.Graph.Authentication

Scripts XDR/MDE (Certificate)
  └── MSAL.PS

Scripts MDO (Transport Rules)
  └── ExchangeOnlineManagement

Domain Health Check
  ├── DomainHealthChecker
  ├── MailAuthDnsTools
  └── EmailAuthChecker
```
