# GOL2026 — Wiki: Guías Operacionales de Seguridad Microsoft Defender XDR

## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

---

## Descripción General

**GOL2026** (Guías Operacionales de Línea base 2026) es un repositorio de guías operacionales, scripts de automatización, líneas base de seguridad y consultas KQL diseñadas para operar y mantener la postura de seguridad de un tenant Microsoft 365 utilizando el ecosistema Microsoft Defender XDR.

El repositorio cubre las siguientes plataformas:

| Plataforma | Descripción |
|---|---|
| **EntraID** | Microsoft Entra ID — Identidad, acceso condicional, roles privilegiados |
| **MDE** | Microsoft Defender for Endpoint — Protección de endpoints, EDR, ASR, TVM |
| **MDI** | Microsoft Defender for Identity — Protección de identidad on-premises, AD DS |
| **MDO** | Microsoft Defender for Office 365 — Protección de correo, anti-phishing, Safe Links/Attachments |
| **MDA** | Microsoft Defender for Cloud Apps — Protección de aplicaciones en la nube (en desarrollo) |
| **XDR** | Microsoft Defender XDR — Correlación cross-workload, reportería automatizada |

---

## Requisitos Previos (Aplica a TODAS las secciones)

Antes de ejecutar cualquier script de este repositorio, asegúrese de cumplir con los siguientes requisitos.

### PowerShell 7+ (Recomendado)

Se recomienda **PowerShell 7** o superior para compatibilidad completa con todos los módulos y scripts.

```powershell
# Verificar versión actual
$PSVersionTable.PSVersion

# Si es inferior a 7.0, instalar PowerShell 7
winget install --id Microsoft.PowerShell --source winget
```

> Después de instalar, abrir una nueva terminal de **PowerShell 7** (`pwsh.exe`) en lugar de Windows PowerShell (`powershell.exe`).

### Validación de Módulos de PowerShell

Aunque la mayoría de los scripts validan e instalan módulos automáticamente, se recomienda **pre-instalar todos los módulos** para evitar interrupciones durante la ejecución.

```powershell
# ─────────────────────────────────────────────
# Módulos para EntraID (Microsoft Graph)
# ─────────────────────────────────────────────
Install-Module -Name Microsoft.Graph.Authentication -MinimumVersion 2.0.0 -Scope CurrentUser -Force
Install-Module -Name Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser -Force
Install-Module -Name Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Force

# ─────────────────────────────────────────────
# Módulos para MDO / Exchange Online
# ─────────────────────────────────────────────
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force

# ─────────────────────────────────────────────
# Módulos para Domain Health Check (MDO)
# ─────────────────────────────────────────────
Install-Module -Name DomainHealthChecker -Scope CurrentUser -Force
Install-Module -Name MailAuthDnsTools    -Scope CurrentUser -Force
Install-Module -Name EmailAuthChecker    -Scope CurrentUser -Force

# ─────────────────────────────────────────────
# Módulos opcionales para reportería XDR/MDE
# (según modo de autenticación)
# ─────────────────────────────────────────────
Install-Module -Name Az.Accounts                   -Scope CurrentUser -Force   # Modo Interactive
Install-Module -Name MSAL.PS                       -Scope CurrentUser -Force   # Modo Certificate
```

**Verificar que todos los módulos estén instalados:**

```powershell
$modules = @(
    'Microsoft.Graph.Authentication',
    'ExchangeOnlineManagement',
    'DomainHealthChecker',
    'MailAuthDnsTools',
    'EmailAuthChecker',
    'Az.Accounts',
    'MSAL.PS'
)

foreach ($mod in $modules) {
    $installed = Get-Module -ListAvailable -Name $mod | Sort-Object Version -Descending | Select-Object -First 1
    if ($installed) {
        Write-Host "[OK] $mod v$($installed.Version)" -ForegroundColor Green
    } else {
        Write-Host "[X]  $mod — NO INSTALADO" -ForegroundColor Red
    }
}
```

### Licenciamiento

| Licencia recomendada | Servicios incluidos |
|---|---|
| Microsoft 365 E5 | MDE, MDO, MDI, MDA, Exchange Online, Entra ID P2 |
| Licencias independientes | Defender for Endpoint P2, Defender for Office 365 P2, Defender for Identity |

> Sin estas licencias las tablas de Advanced Hunting estarán vacías y los scripts de reportería no mostrarán información.

### App Registration (Scripts XDR/MDE)

Los scripts de reportería requieren un App Registration con el permiso `AdvancedHunting.Read.All`. Consulte la guía completa en [Requisitos.md](../Requisitos.md).

### Conectividad de Red

| Endpoint | Propósito |
|---|---|
| `login.microsoftonline.com` | Autenticación OAuth 2.0 |
| `api.security.microsoft.com` | API de Advanced Hunting |
| `outlook.office365.com` | Exchange Online PowerShell |
| `graph.microsoft.com` | Microsoft Graph API (EntraID) |
| Servidores DNS públicos | Domain Health Check |

---

## Índice de Secciones

1. [EntraID — Microsoft Entra ID](#entraid--microsoft-entra-id)
2. [MDE — Microsoft Defender for Endpoint](#mde--microsoft-defender-for-endpoint)
3. [MDI — Microsoft Defender for Identity](#mdi--microsoft-defender-for-identity)
4. [MDO — Microsoft Defender for Office 365](#mdo--microsoft-defender-for-office-365)
5. [XDR — Microsoft Defender XDR](#xdr--microsoft-defender-xdr)

---

# EntraID — Microsoft Entra ID

Guías operacionales para gestión de identidad, acceso condicional, roles privilegiados y monitoreo de riesgos en Microsoft Entra ID.

## Estructura de la carpeta

```
EntraID/
├── Guía Operacional Microsoft EntraID Diaria.md
├── Guía Operacional EntraID Tareas Semanales.md
├── Guía Operacional EntraID Tareas Mensuales AdHoc.md
├── Paquete KQL Queries EntraID Advanced Hunting.md
├── Linea base/
│   └── Principio de Menor Privilegio.md
├── Políticas/
│   └── Linea base Conditional Access Policies.md
└── Scripts/
    ├── Get-ConditionalAccessPolicies.ps1
    ├── Get-InactiveUsers.ps1
    └── Get-M365RoleReport.ps1
```

## Guías Operacionales

| Guía | Frecuencia | Descripción |
|---|---|---|
| [Guía Operacional Microsoft EntraID Diaria](../EntraID/Guía%20Operacional%20Microsoft%20EntraID%20Diaria.md) | Diaria | Monitoreo de inicios de sesión riesgosos, usuarios comprometidos, alertas de identidad |
| [Guía Operacional EntraID Tareas Semanales](../EntraID/Guía%20Operacional%20EntraID%20Tareas%20Semanales.md) | Semanal | Revisión de acceso condicional, roles, aplicaciones OAuth, tendencias de riesgo |
| [Guía Operacional EntraID Tareas Mensuales AdHoc](../EntraID/Guía%20Operacional%20EntraID%20Tareas%20Mensuales%20AdHoc.md) | Mensual/Ad-Hoc | Revisión de novedades, auditoría de roles, revisión de políticas |

## Líneas Base

| Documento | Descripción |
|---|---|
| [Principio de Menor Privilegio](../EntraID/Linea%20base/Principio%20de%20Menor%20Privilegio.md) | No más de 4 Global Admins, separación de cuentas, MFA resistente a phishing, validación semestral |
| [Línea base Conditional Access Policies](../EntraID/Políticas/Linea%20base%20Conditional%20Access%20Policies.md) | MFA para todos, MFA phishing-resistant para admins, bloqueo de legacy auth, MFA para sign-ins riesgosos |

## Consultas KQL

| Documento | Descripción |
|---|---|
| [Paquete KQL Queries EntraID Advanced Hunting](../EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md) | Consultas de hunting para identidad: inicios de sesión anómalos, cambios de roles, aplicaciones OAuth |

## Scripts

| Script | Módulos requeridos | Conexión | Descripción |
|---|---|---|---|
| [Get-ConditionalAccessPolicies.ps1](../EntraID/Scripts/Get-ConditionalAccessPolicies.ps1) | `Microsoft.Graph.Authentication` | `Connect-MgGraph` | Exporta todas las políticas de Conditional Access del tenant |
| [Get-InactiveUsers.ps1](../EntraID/Scripts/Get-InactiveUsers.ps1) | `Microsoft.Graph.Authentication` (v2.0.0+) | `Connect-MgGraph` | Identifica usuarios inactivos que no han iniciado sesión |
| [Get-M365RoleReport.ps1](../EntraID/Scripts/Get-M365RoleReport.ps1) | `Microsoft.Graph.Authentication` (v2.0.0+), `ExchangeOnlineManagement` | `Connect-MgGraph`, `Connect-ExchangeOnline`, `Connect-IPPSSession` | Genera reporte HTML de todos los roles administrativos en Entra ID, Exchange y SCC |

### Cómo ejecutar los scripts de EntraID

```powershell
# ─── Paso 1: Abrir PowerShell 7 ───
pwsh

# ─── Paso 2: Validar módulos ───
Get-Module -ListAvailable -Name Microsoft.Graph.Authentication
Get-Module -ListAvailable -Name ExchangeOnlineManagement

# ─── Paso 3: Conectar a Microsoft Graph ───
Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All","RoleManagement.Read.All"

# ─── Paso 4: Ejecutar scripts ───
.\EntraID\Scripts\Get-ConditionalAccessPolicies.ps1
.\EntraID\Scripts\Get-InactiveUsers.ps1
.\EntraID\Scripts\Get-M365RoleReport.ps1
```

---

# MDE — Microsoft Defender for Endpoint

Guías operacionales para monitoreo de alertas, gestión de dispositivos, hunting proactivo y postura de seguridad de endpoints.

## Estructura de la carpeta

```
MDE/
├── Guia de Seguridad Operacional MDE tareas diarias.md
├── Guia de Seguridad Operacional MDE tareas semanales.md
├── Guia de Seguridad Operacional MDE tareas mensuales ad-hoc.md
└── New-DefenderVulnerabilityReport.ps1
```

## Guías Operacionales

| Guía | Frecuencia | Descripción |
|---|---|---|
| [Guía Operacional MDE Diaria](../MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20diarias.md) | Diaria | Monitoreo de incidentes y alertas, dispositivos en riesgo, salud del sensor EDR, acciones de respuesta, Threat Analytics |
| [Guía Operacional MDE Semanal](../MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md) | Semanal | Tendencias de amenazas, Advanced Hunting proactivo, vulnerabilidades (TVM), configuraciones ASR, dispositivos reincidentes, reporte ejecutivo |
| [Guía Operacional MDE Mensual/Ad-Hoc](../MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20mensuales%20ad-hoc.md) | Mensual/Ad-Hoc | Revisión de novedades (What's new), revisión de configuraciones de endpoint y políticas |

## Scripts

| Script | Módulos requeridos | Conexión | Descripción |
|---|---|---|---|
| [New-DefenderVulnerabilityReport.ps1](../MDE/New-DefenderVulnerabilityReport.ps1) | Ninguno (modo Secret/DeviceCode), `Az.Accounts` (modo Interactive), `MSAL.PS` (modo Certificate) | API `api.security.microsoft.com` | Genera reporte HTML de vulnerabilidades del tenant con datos de TVM |

### Cómo ejecutar los scripts de MDE

```powershell
# ─── Paso 1: Abrir PowerShell 7 ───
pwsh

# ─── Paso 2: Validar módulos (opcional según modo de autenticación) ───
Get-Module -ListAvailable -Name Az.Accounts
Get-Module -ListAvailable -Name MSAL.PS

# ─── Paso 3: Ejecutar con Client Secret (recomendado para automatización) ───
.\MDE\New-DefenderVulnerabilityReport.ps1 `
    -TenantId   "<tu-tenant-id>" `
    -ClientId   "<tu-client-id>" `
    -AuthMethod Secret `
    -ClientSecret "<tu-client-secret>"

# ─── Alternativa: Ejecutar con Device Code (interactivo) ───
.\MDE\New-DefenderVulnerabilityReport.ps1 `
    -TenantId   "<tu-tenant-id>" `
    -ClientId   "<tu-client-id>" `
    -AuthMethod DeviceCode
```

> Requiere App Registration con permiso `AdvancedHunting.Read.All`. Ver [Requisitos.md](../Requisitos.md).

---

# MDI — Microsoft Defender for Identity

Guías operacionales para monitoreo de amenazas de identidad on-premises, detección de movimiento lateral, monitoreo de sensores y análisis de Active Directory.

## Estructura de la carpeta

```
MDI/
├── Guía operativa diaria de Microsoft Defender for Identity.md
├── Guía operativa semanal de Microsoft Defender for Identity.md
├── Guía opertiva mensualad-hoc de Microsoft Defender for Identity.md
└── Paquete MDI KQL Advance Hunting.md
```

## Guías Operacionales

| Guía | Frecuencia | Descripción |
|---|---|---|
| [Guía Operativa MDI Diaria](../MDI/Guía%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md) | Diaria | Alertas de identidad, movimiento lateral, pass-the-hash/ticket, reconocimiento, salud de sensores |
| [Guía Operativa MDI Semanal](../MDI/Guía%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md) | Semanal | Tendencias de amenazas de identidad, análisis de LSASS, rutas de movimiento lateral, revisión de cuentas sensibles |
| [Guía Operativa MDI Mensual/Ad-Hoc](../MDI/Guía%20opertiva%20mensualad-hoc%20de%20Microsoft%20Defender%20for%20Identity.md) | Mensual/Ad-Hoc | Revisión de novedades, auditoría de configuración de sensores, evaluación de postura de Active Directory |

## Consultas KQL

| Documento | Descripción |
|---|---|
| [Paquete MDI KQL Advance Hunting](../MDI/Paquete%20MDI%20KQL%20Advance%20Hunting.md) | Consultas de hunting para identidad on-premises: brute force, spray attacks, honey tokens, LDAP, Kerberoasting |

### Cómo usar las guías de MDI

MDI se opera principalmente desde la consola de Microsoft Defender Portal. No requiere módulos de PowerShell adicionales para las tareas operacionales.

```
Consola principal: https://security.microsoft.com
Sección: Identities → Health issues (salud de sensores)
Sección: Identities → Identity posture (postura de identidad)
Advanced Hunting: https://security.microsoft.com/v2/advanced-hunting
```

> Las consultas KQL del paquete MDI se ejecutan directamente en el portal de Advanced Hunting.

---

# MDO — Microsoft Defender for Office 365

Guías operacionales para protección de correo electrónico, anti-phishing, Safe Links, Safe Attachments, ZAP y líneas base de seguridad de Exchange Online.

## Estructura de la carpeta

```
MDO/
├── Guia de Seguridad Operacional MDO tareas diarias.md
├── Guia de Seguridad Operacional MDO Semanal.md
├── Guia de Seguridad Operacional MDO Mensual Ad-Hoc.md
├── Paquete MDO KQL Advance Hunting.md
├── Línea Base/
│   ├── Linea base de proteccion contra Business Email Compromise (BEC).md
│   └── Línea base para mejorar la postura de seguridad en Exchange online.md
├── Políticas/
│   ├── Política Anti-Phishing MDO.md
│   ├── Politica Safe links.md
│   └── Política de Safe Attachments.md
└── Scripts/
    ├── Attachmentscannotbeinspected.ps1
    ├── Block-OnMicrosoftEmails.ps1
    ├── Domain-Health-Check.ps1
    ├── Validate-EXOSecurityBaseline.ps1
    ├── Validate-MDOPolicies.ps1
    └── Validate-ZAPConfiguration.ps1
```

## Guías Operacionales

| Guía | Frecuencia | Descripción |
|---|---|---|
| [Guía Operacional MDO Diaria](../MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md) | Diaria | Monitoreo de correos maliciosos, campañas de phishing, acciones de ZAP, Threat Explorer, alertas MDO |
| [Guía Operacional MDO Semanal](../MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md) | Semanal | Tendencias de phishing, análisis de campañas, revisión de políticas, usuarios objetivo, reporte ejecutivo |
| [Guía Operacional MDO Mensual/Ad-Hoc](../MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20Mensual%20Ad-Hoc.md) | Mensual/Ad-Hoc | Revisión de novedades, auditoría de políticas, revisión de configuraciones |

## Líneas Base

| Documento | Descripción |
|---|---|
| [Protección contra BEC](../MDO/Línea%20Base/Linea%20base%20de%20proteccion%20contra%20Business%20Email%20Compromise%20(BEC).md) | Modelo de protección multicapa contra Business Email Compromise: SPF/DKIM/DMARC, anti-phishing, Safe Links/Attachments, ZAP, Zero Trust, controles de proceso |
| [Postura de seguridad en Exchange Online](../MDO/Línea%20Base/Línea%20base%20para%20mejorar%20la%20postura%20de%20seguridad%20en%20Exchange%20online.md) | Reglas de transporte, RejectDirectSend, estándares SPF/DKIM/DMARC/MTA-STS, dominios estacionados |

## Políticas paso a paso

| Documento | Descripción |
|---|---|
| [Política Anti-Phishing MDO](../MDO/Políticas/Política%20Anti-Phishing%20MDO.md) | Paso a paso para crear y configurar la política anti-phishing con impersonation protection |
| [Política Safe Links](../MDO/Políticas/Politica%20Safe%20links.md) | Paso a paso para configurar Safe Links con click-time scanning |
| [Política Safe Attachments](../MDO/Políticas/Política%20de%20Safe%20Attachments.md) | Paso a paso para configurar Safe Attachments con Dynamic Delivery |

## Consultas KQL

| Documento | Descripción |
|---|---|
| [Paquete MDO KQL Advance Hunting](../MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md) | Consultas de hunting para correo: phishing entregado, campañas, URLs maliciosas, adjuntos detonados |

## Scripts

| Script | Módulos requeridos | Conexión | Descripción |
|---|---|---|---|
| [Block-OnMicrosoftEmails.ps1](../MDO/Scripts/Block-OnMicrosoftEmails.ps1) | `ExchangeOnlineManagement` | `Connect-ExchangeOnline` | Crea regla de transporte para bloquear correos a dominios *.onmicrosoft.com |
| [Attachmentscannotbeinspected.ps1](../MDO/Scripts/Attachmentscannotbeinspected.ps1) | `ExchangeOnlineManagement` | `Connect-ExchangeOnline` | Crea regla de transporte para poner en cuarentena adjuntos que no pueden ser inspeccionados |
| [Domain-Health-Check.ps1](../MDO/Scripts/Domain-Health-Check.ps1) | `DomainHealthChecker`, `MailAuthDnsTools`, `EmailAuthChecker` | DNS (sin conexión a M365) | Valida SPF, DKIM, DMARC y MTA-STS para un dominio. **Requiere ejecutar como Administrador** |
| [Validate-EXOSecurityBaseline.ps1](../MDO/Scripts/Validate-EXOSecurityBaseline.ps1) | `ExchangeOnlineManagement` | `Connect-ExchangeOnline` | Valida reglas de transporte, RejectDirectSend y registros DNS contra mejores prácticas |
| [Validate-MDOPolicies.ps1](../MDO/Scripts/Validate-MDOPolicies.ps1) | `ExchangeOnlineManagement` | `Connect-ExchangeOnline`, `Connect-IPPSSession` | Valida TODAS las políticas MDO (Anti-Spam, Anti-Malware, Anti-Phishing, Safe Links, Safe Attachments, Connection Filter, Preset Policies) |
| [Validate-ZAPConfiguration.ps1](../MDO/Scripts/Validate-ZAPConfiguration.ps1) | `ExchangeOnlineManagement` | `Connect-ExchangeOnline` | Valida configuración de ZAP en Anti-Spam, Anti-Malware, Anti-Phishing, reglas de transporte y cuarentena |

### Cómo ejecutar los scripts de MDO

```powershell
# ─── Paso 1: Abrir PowerShell 7 ───
pwsh

# ─── Paso 2: Validar módulo ───
Get-Module -ListAvailable -Name ExchangeOnlineManagement

# Si no está instalado:
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force

# ─── Paso 3: Conectar a Exchange Online ───
Connect-ExchangeOnline

# ─── Paso 4: Ejecutar scripts de validación ───
.\MDO\Scripts\Validate-MDOPolicies.ps1
.\MDO\Scripts\Validate-ZAPConfiguration.ps1
.\MDO\Scripts\Validate-EXOSecurityBaseline.ps1

# ─── Scripts de reglas de transporte ───
.\MDO\Scripts\Block-OnMicrosoftEmails.ps1
.\MDO\Scripts\Attachmentscannotbeinspected.ps1

# ─── Domain Health Check (requiere Admin) ───
# Abrir PowerShell 7 como Administrador
.\MDO\Scripts\Domain-Health-Check.ps1 -Domain "tudominio.com"
```

> **Validate-MDOPolicies.ps1** también requiere `Connect-IPPSSession` para acceder a las políticas de Safe Links y Safe Attachments (se conecta automáticamente si los cmdlets no están disponibles).

---

# XDR — Microsoft Defender XDR

Scripts de reportería automatizada que correlacionan datos de todos los workloads (MDE, MDO, MDI, MDA) para generar reportes diarios y semanales.

## Estructura de la carpeta

```
XDR/
├── Instrucciones New-DefenderXDRDailyReport.ps1.md
├── Instrucciones New-DefenderXDRWeeklyReport.ps1.md
├── Instrucciones New-DefenderVulnerabilityReport.ps1.md
├── New-DefenderXDRDailyReport.ps1
├── New-DefenderXDRWeeklyReport.ps1
└── Setup-DefenderXDRReportServer.ps1
```

## Scripts

| Script | Módulos requeridos | Descripción |
|---|---|---|
| [New-DefenderXDRDailyReport.ps1](../XDR/New-DefenderXDRDailyReport.ps1) | Ninguno (modo Secret), `Az.Accounts` (modo Interactive) | Genera reporte diario HTML con KPIs de todos los workloads XDR |
| [New-DefenderXDRWeeklyReport.ps1](../XDR/New-DefenderXDRWeeklyReport.ps1) | Ninguno (modo Secret/DeviceCode), `Az.Accounts` (modo Interactive), `MSAL.PS` (modo Certificate) | Genera reporte semanal HTML con tendencias, vulnerabilidades y métricas consolidades |
| [Setup-DefenderXDRReportServer.ps1](../XDR/Setup-DefenderXDRReportServer.ps1) | Ninguno | Configura la estructura de directorios, credenciales cifradas (DPAPI) y tareas programadas para automatizar la generación de reportes |

## Instrucciones detalladas

| Documento | Descripción |
|---|---|
| [Instrucciones Daily Report](../XDR/Instrucciones%20New-DefenderXDRDailyReport.ps1.md) | Guía paso a paso para configurar y ejecutar el reporte diario |
| [Instrucciones Weekly Report](../XDR/Instrucciones%20New-DefenderXDRWeeklyReport.ps1.md) | Guía paso a paso para configurar y ejecutar el reporte semanal |
| [Instrucciones Vulnerability Report](../XDR/Instrucciones%20New-DefenderVulnerabilityReport.ps1.md) | Guía paso a paso para configurar y ejecutar el reporte de vulnerabilidades |

### Cómo ejecutar los scripts de XDR

```powershell
# ─── Paso 1: Abrir PowerShell 7 ───
pwsh

# ─── Paso 2: Configurar el servidor de reportes (primera vez) ───
.\XDR\Setup-DefenderXDRReportServer.ps1

# ─── Paso 3: Ejecutar reporte diario ───
.\XDR\New-DefenderXDRDailyReport.ps1 `
    -TenantId     "<tu-tenant-id>" `
    -ClientId     "<tu-client-id>" `
    -AuthMethod   Secret `
    -ClientSecret "<tu-client-secret>"

# ─── Paso 4: Ejecutar reporte semanal ───
.\XDR\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId     "<tu-tenant-id>" `
    -ClientId     "<tu-client-id>" `
    -AuthMethod   Secret `
    -ClientSecret "<tu-client-secret>"
```

> Para automatización con tareas programadas y credenciales cifradas, consulte las [instrucciones detalladas](../XDR/Instrucciones%20New-DefenderXDRDailyReport.ps1.md).

---

## Resumen de Módulos de PowerShell por Sección

| Módulo | EntraID | MDE | MDI | MDO | XDR |
|---|:---:|:---:|:---:|:---:|:---:|
| `Microsoft.Graph.Authentication` | **Sí** | — | — | — | — |
| `ExchangeOnlineManagement` | Sí (RoleReport) | — | — | **Sí** | — |
| `DomainHealthChecker` | — | — | — | Sí (DNS) | — |
| `MailAuthDnsTools` | — | — | — | Sí (DNS) | — |
| `EmailAuthChecker` | — | — | — | Sí (DNS) | — |
| `Az.Accounts` | — | Opcional | — | — | Opcional |
| `MSAL.PS` | — | Opcional | — | — | Opcional |

---

## Estructura de Reportes Generados

Los scripts generan reportes HTML en las siguientes carpetas:

```
C:\Scripts\
├── EntraID\          # Reportes de roles y usuarios inactivos
├── MDO\              # Validación de políticas MDO, ZAP, baseline EXO
├── SecurityBaseline\ # Reportes de Validate-EXOSecurityBaseline
└── (personalizado)\  # Reportes XDR (configurable con Setup script)
```

---

## Calendario Operacional Recomendado

| Día | EntraID | MDE | MDI | MDO | XDR |
|---|---|---|---|---|---|
| **Lunes–Viernes** | Guía diaria | Guía diaria | Guía diaria | Guía diaria | Reporte diario |
| **Viernes/Lunes** | Guía semanal | Guía semanal | Guía semanal | Guía semanal | Reporte semanal |
| **Mensual** | Guía mensual | Guía mensual | Guía mensual | Guía mensual | — |

---

> **Nota:** Este wiki es un documento vivo. Se actualiza conforme se agregan nuevos scripts, guías y líneas base al repositorio.
