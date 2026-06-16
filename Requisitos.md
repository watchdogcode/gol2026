# Requisitos y Dependencias

Este documento describe los requisitos de licenciamiento, infraestructura, módulos de PowerShell y permisos necesarios para ejecutar los scripts de este repositorio.

---

## 1. Licenciamiento Microsoft 365

Se requieren licencias que incluyan los servicios de Microsoft Defender XDR

| Licencia recomendada | Servicios incluidos |
|---|---|
| Microsoft 365 E5 | MDA, MDE, MDI, MDO|
| Licencias independientes | Defender for Cloud Apps, Defender for Endpoint P2, Defender for Identity, Defender for Office 365 P2 |

> **Nota:** Sin estas licencias las tablas de Advanced Hunting (p. ej. `EmailEvents`, `AlertInfo`, `DeviceTvmSoftwareVulnerabilities`) estarán vacías y los reportes no mostrarán información.

---

## 2. Entorno de Ejecución

| Requisito | Detalle |
|---|---|
| **PowerShell** | PowerShell 7+ **Requerido** ver punto 4 **Crítico**|
| **Sistema Operativo** | Windows 11 o Windows Server 2016+ |
| **Privilegios de administrador** | Requerido únicamente para `Domain-Health-Check.ps1` (`#Requires -RunAsAdministrator`) |
| **Global Administrator** | Permiso requerido para registro de Aplicación |

---

## 3. App Registration en Microsoft Entra ID

Todos los scripts de reportería XDR/MDE se autentican contra la API de Microsoft 365 Defender y requieren un registro de aplicación.

### 3.1 Crear el App Registration

1. Iniciar sesión en el portal de Azure: [https://entra.microsoft.com/](https://entra.microsoft.com/).
2. Navegar a **Microsoft Entra ID** > **App registrations** > **+ New registration**.
3. Configurar los campos:
   - **Name:** Un nombre descriptivo, por ejemplo **`SecOps-Defender-Reports`**.
   - **Supported account types:** Seleccionar *Single tenant only - [Tenant]*.
   - **Redirect URI:** Dejar en blanco (no se requiere para autenticación con Client Secret).
4. Hacer clic en **Register**.
5. Una vez creado, en la página **Overview** del App Registration, copiar y guardar:
   - **Application (client) ID** → Este es el `ClientId`.
   - **Directory (tenant) ID** → Este es el `TenantId`.

### 3.2 Asignar permisos de API

1. En el App Registration, ir a **API permissions** > **+ Add a permission**.
2. Seleccionar **APIs my organization uses** y buscar **`Microsoft Threat Protection`.**
3. Seleccionar **Application permissions**.
4. Marcar el permiso **`AdvancedHunting.Read.All`**.
5. Hacer clic en **Add permissions**.
6. **Importante:** Hacer clic en **Grant admin consent for [Tenant]** y confirmar. Sin este paso, la aplicación no podrá ejecutar consultas de Advanced Hunting.

> **Nota:** El botón de *Grant admin consent* requiere el rol de **Global Administrator** o **Privileged Role Administrator**.

### 3.3 Crear un Client Secret (Opcional)

1. En el App Registration, ir a **Certificates & secrets** > **Client secrets** > **+ New client secret**.
2. Configurar:
   - **Description:** Un nombre descriptivo, por ejemplo `SecOps-Reports-Key`.
   - **Expires:** Seleccionar la duración adecuada (se recomienda **6 meses** o **12 meses** según la política de seguridad de la organización).
3. Hacer clic en **Add**.
4. **Copiar inmediatamente el valor del secreto** (columna **Value**). Este valor solo se muestra una vez y no podrá consultarse después. Este es el `ClientSecret`.

> ⚠️ **Advertencia:** Trate el Client Secret como una contraseña. No lo almacene en texto plano en scripts ni repositorios. Los scripts de este repositorio soportan variables de entorno y credenciales cifradas con DPAPI (ver sección 7 y 8).

### 3.4 Resumen de datos necesarios

Una vez completados los pasos anteriores, debe tener los siguientes tres valores:

| Dato | Dónde encontrarlo | Ejemplo |
|---|---|---|
| **Tenant ID** | App Registration > Overview > Directory (tenant) ID | `7cbaabe5-dbcd-431d-8ea3-826b85b28c2b` |
| **Client ID** | App Registration > Overview > Application (client) ID | `846e446d-6748-4da8-924c-de9b9e3d60d4` |
| **Client Secret** (Opcional) | App Registration > Certificates & secrets > Value | `2EV8Q~7vwnHG8f2pZTA3...` |

### 3.5 Modos de autenticación soportados

| Modo | Módulos adicionales requeridos | Scripts compatibles |
|---|---|---|
| `Secret` | Ninguno (usa `Invoke-RestMethod` nativo) | Todos |
| `DeviceCode` | Ninguno (usa `Invoke-RestMethod` nativo) | Daily, Weekly, Vulnerability |
| `Interactive` | `Az.Accounts` **o** `Microsoft.Graph.Authentication` | Daily, Weekly, Vulnerability |
| `Certificate` | `MSAL.PS` | Weekly, Vulnerability |

---

## 4. Módulos de PowerShell

### 4.1 Instalar PowerShell 7 (Crítico instalarlo desde el archivo PowerShell-7.x.x-win-x64.msi o PowerShell-7.x.x-win-arm64.msi)

1. Ir a https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows?view=powershell-7.6#install-the-msi-package

2. Selecciona la version que corresponda a la arquitectura de CPU

3. Haz doble clic sobre el archivo .msi

4. Se abrirá el asistente → haz clic en Next.

5. Una vez instalado ejecuta este comando para validar la ruta de instalación **Ruta critica**

```PowerShell
Get-Command pwsh
```
6. Salida esperada 
```PowerShell
Source
------
C:\Program Files\PowerShell\7\pwsh.exe
```

### 4.2 Módulos por script

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

### 4.3 Instalación de módulos

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
| `entra.microsoft.com` | Registro de aplicacción | 
| `login.microsoftonline.com` | Autenticación OAuth 2.0 (todos los scripts XDR/MDE) |
| `api.security.microsoft.com` | API de Advanced Hunting - Microsoft 365 Defender |
| `outlook.office365.com` | Exchange Online PowerShell remoto (scripts MDO) |
| `*.protection.outlook.com` | Exchange Online Protection |
| Servidores DNS públicos | Resolución DNS para `Domain-Health-Check.ps1` (SPF, DKIM, DMARC, MTA-STS) |

> Si el entorno utiliza proxy, los scripts XDR Weekly y Vulnerability soportan el parámetro `-ProxyUrl`.

---

## 6. Estructura de Directorios para Reportes

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
