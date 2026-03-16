# Guía Operacional de Seguridad  Microsoft 365 Defender XDR

> Marco de operaciones de seguridad (SecOps) para Microsoft Defender XDR con guías operativas, scripts de automatización, líneas base de configuración y paquetes de consultas KQL.

---

## Descripción del Proyecto

Este repositorio contiene el marco completo de operaciones de seguridad para organizaciones que utilizan **Microsoft 365 Defender XDR**. Proporciona:

- **Guías operativas** diarias, semanales y mensuales para cada pilar de Defender (MDO, MDE, MDI, MDA, Entra ID).
- **Scripts de automatización** en PowerShell para reportes ejecutivos, validación de configuraciones y creación de políticas de alerta.
- **Líneas base de seguridad** alineadas con las recomendaciones de Microsoft (Standard/Strict).
- **Paquetes de consultas KQL** para Advanced Hunting orientados a detección, triaje e investigación.
- **Reportes HTML automatizados** (diarios y semanales) que transforman telemetría técnica en información accionable para el CISO y el equipo de SecOps.

### Valor de Negocio

| Audiencia | Beneficio |
|---|---|
| **CISO / Dirección** | KPIs claros de exposición y riesgo, visibilidad ejecutiva sin necesidad de acceder a consolas técnicas |
| **Equipo de SecOps** | Guías paso a paso para operaciones diarias, scripts automatizados para reducir trabajo manual |
| **Administradores de Infraestructura** | Validación de configuraciones contra líneas base recomendadas, reportes de higiene del tenant |

---

## Tabla de Contenidos

- [Requisitos y Dependencias](#requisitos-y-dependencias)
- [Microsoft Entra ID (Identidad)](#microsoft-entra-id-identidad)
- [Microsoft Defender for Office 365 (MDO)](#microsoft-defender-for-office-365-mdo)
- [Microsoft Defender for Endpoint (MDE)](#microsoft-defender-for-endpoint-mde)
- [Microsoft Defender for Identity (MDI)](#microsoft-defender-for-identity-mdi)
- [Microsoft Defender for Cloud Apps (MDA)](#microsoft-defender-for-cloud-apps-mda)
- [Microsoft Defender XDR (Reportes Cross-Domain)](#microsoft-defender-xdr-reportes-cross-domain)
- [Estructura del Repositorio](#estructura-del-repositorio)

---

## Requisitos y Dependencias

Consulte [Requisitos.md](Requisitos.md) para la guía completa de:

- Licenciamiento Microsoft 365 (E5 o licencias independientes de Defender)
- Entorno de ejecución (PowerShell 5.1+, módulos necesarios)
- Registro de aplicación en Entra ID (App Registration, permisos de API, modos de autenticación)
- Configuración de credenciales y Task Scheduler para automatización

---

## Microsoft Entra ID (Identidad)

Guías operativas y herramientas para la gestión de seguridad de identidades.

### Guías Operativas

| Cadencia | Documento |
|---|---|
| Diaria | [Guía Operacional Microsoft EntraID Diaria](EntraID/Guía%20Operacional%20Microsoft%20EntraID%20Diaria.md) |
| Semanal | [Guía Operacional EntraID Tareas Semanales](EntraID/Guía%20Operacional%20EntraID%20Tareas%20Semanales.md) |
| Mensual / Ad-hoc | [Guía Operacional EntraID Tareas Mensuales AdHoc](EntraID/Guía%20Operacional%20EntraID%20Tareas%20Mensuales%20AdHoc.md) |

### Líneas Base

| Documento | Descripción |
|---|---|
| [Línea base Conditional Access Policies](EntraID/Linea%20base%20Conditional%20Access%20Policies.md) | Plantillas de políticas de Conditional Access (MFA para todos los usuarios, exclusiones break-glass, Report-only) |

### Consultas KQL

| Documento | Descripción |
|---|---|
| [Paquete KQL Queries EntraID](EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md) | Consultas de Advanced Hunting enfocadas en detección e investigación de amenazas de identidad |

### Scripts

| Script | Descripción |
|---|---|
| [Get-ConditionalAccessPolicies.ps1](EntraID/Scripts/Get-ConditionalAccessPolicies.ps1) | Exporta reporte detallado de todas las Conditional Access Policies (consola + CSV + HTML) |
| [Get-InactiveUsers.ps1](EntraID/Scripts/Get-InactiveUsers.ps1) | Lista usuarios sin actividad de inicio de sesión en los últimos N días vía Microsoft Graph |
| [Get-M365RoleReport.ps1](EntraID/Scripts/Get-M365RoleReport.ps1) | Enumera miembros de roles administrativos en Entra ID, Security & Compliance y Exchange Online |
| [Get-MFAAuthenticationMethodsReport.ps1](EntraID/Scripts/Get-MFAAuthenticationMethodsReport.ps1) | Audita métodos de autenticación MFA de todos los usuarios — [Documentación](EntraID/Scripts/Reporte%20MFA%20con%20Microsoft%20Graph.md) |

---

## Microsoft Defender for Office 365 (MDO)

Guías, líneas base, políticas y scripts para la seguridad del correo electrónico y colaboración.

### Guías Operativas

| Cadencia | Documento |
|---|---|
| Diaria | [Guía de Seguridad Operacional MDO Diaria](MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md) |
| Semanal | [Guía de Seguridad Operacional MDO Semanal](MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md) |
| Mensual / Ad-hoc | [Guía de Seguridad Operacional MDO Mensual Ad-Hoc](MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20Mensual%20Ad-Hoc.md) |

### Líneas Base

| Documento | Descripción |
|---|---|
| [Protección contra BEC](MDO/Linea%20base%20de%20proteccion%20contra%20Business%20Email%20Compromise%20(BEC).md) | Estrategia de defensa en capas contra suplantación de identidad y compromiso de correo empresarial |
| [Postura de seguridad Exchange Online](MDO/Línea%20base%20para%20mejorar%20la%20postura%20de%20seguridad%20en%20Exchange%20online.md) | Configuración de seguridad del flujo de correo bajo Zero Trust (SPF, DKIM, DMARC, MTA-STS) |

### Políticas

| Documento | Descripción |
|---|---|
| [Política Anti-Phishing MDO](MDO/Políticas/Política%20Anti-Phishing%20MDO.md) | Guía paso a paso para crear política Anti-Phishing con protección BEC para ejecutivos |
| [Política de Safe Attachments](MDO/Políticas/Política%20de%20Safe%20Attachments.md) | Guía para crear política de Safe Attachments (detonación en sandbox) |
| [Política Safe Links](MDO/Políticas/Politica%20Safe%20links.md) | Guía para crear política de Safe Links enfocada en protección BEC de URLs |

### Consultas KQL

| Documento | Descripción |
|---|---|
| [Paquete MDO KQL Advanced Hunting](MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md) | Consultas de detección, triaje e investigación de amenazas de correo electrónico |

### Scripts

| Script | Descripción |
|---|---|
| [New-CustomAlertPolicies.ps1](MDO/Scripts/New-CustomAlertPolicies.ps1) | Crea 23 Alert Policies personalizadas (Threat Management, DLP, Access Governance, SharePoint) |
| [New-MailboxAuditBypassAlert.ps1](MDO/Scripts/New-MailboxAuditBypassAlert.ps1) | Crea alerta para detectar ejecución de `Set-MailboxAuditBypassAssociation` |
| [Validate-MDOPolicies.ps1](MDO/Scripts/Validate-MDOPolicies.ps1) | Valida todas las políticas MDO contra recomendaciones Microsoft Standard/Strict |
| [Validate-EXOSecurityBaseline.ps1](MDO/Scripts/Validate-EXOSecurityBaseline.ps1) | Valida la línea base de seguridad de Exchange Online (transport rules, SPF/DKIM/DMARC/MTA-STS) |
| [Validate-ZAPConfiguration.ps1](MDO/Scripts/Validate-ZAPConfiguration.ps1) | Valida configuración de Zero-hour Auto Purge (ZAP) y genera dashboard HTML |
| [Domain-Health-Check.ps1](MDO/Scripts/Domain-Health-Check.ps1) | Verifica registros DNS de autenticación (SPF, DKIM, DMARC, MTA-STS) y genera reporte HTML |
| [Attachmentscannotbeinspected.ps1](MDO/Scripts/Attachmentscannotbeinspected.ps1) | Crea transport rule para poner en cuarentena correos con adjuntos no inspeccionables |
| [Block-OnMicrosoftEmails.ps1](MDO/Scripts/Block-OnMicrosoftEmails.ps1) | Crea transport rule para bloquear correos enviados a direcciones `*.onmicrosoft.com` |

---

## Microsoft Defender for Endpoint (MDE)

Guías operativas y reportes de vulnerabilidades para la seguridad de endpoints.

### Guías Operativas

| Cadencia | Documento |
|---|---|
| Diaria | [Guía de Seguridad Operacional MDE Diaria](MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20diarias.md) |
| Semanal | [Guía de Seguridad Operacional MDE Semanal](MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md) |

### Scripts

| Script | Descripción |
|---|---|
| [New-DefenderVulnerabilityReport.ps1](MDE/New-DefenderVulnerabilityReport.ps1) | Genera reporte ejecutivo HTML de vulnerabilidades vía API de M365 Defender (CVEs, distribución de severidad, explotabilidad) |

---

## Microsoft Defender for Identity (MDI)

Guías operativas y consultas KQL para la protección de identidades on-premises y detección de movimiento lateral.

### Guías Operativas

| Cadencia | Documento |
|---|---|
| Diaria | [Guía operativa diaria MDI](MDI/Guía%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md) |
| Semanal | [Guía operativa semanal MDI](MDI/Guía%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md) |
| Mensual / Ad-hoc | [Guía operativa mensual/ad-hoc MDI](MDI/Guía%20opertiva%20mensualad-hoc%20de%20Microsoft%20Defender%20for%20Identity.md) |

### Consultas KQL

| Documento | Descripción |
|---|---|
| [Paquete MDI KQL Advanced Hunting](MDI/Paquete%20MDI%20KQL%20Advance%20Hunting.md) | Consultas de detección e investigación de amenazas de identidad para MDI |

---

## Microsoft Defender for Cloud Apps (MDA)

> Sección en desarrollo. Próximamente se incluirán guías operativas, líneas base y scripts para MDA.

---

## Microsoft Defender XDR (Reportes Cross-Domain)

Reportes automatizados que consolidan telemetría de MDO, MDE, MDI y MDA en reportes ejecutivos HTML.

### Scripts

| Script | Descripción | Instrucciones |
|---|---|---|
| [New-DefenderXDRDailyReport.ps1](XDR/New-DefenderXDRDailyReport.ps1) | Genera reporte diario HTML vía Advanced Hunting API | [Instrucciones](XDR/Instrucciones%20New-DefenderXDRDailyReport.ps1.md) |
| [New-DefenderXDRWeeklyReport.ps1](XDR/New-DefenderXDRWeeklyReport.ps1) | Genera reporte semanal ejecutivo HTML con KPIs y tendencias | [Instrucciones](XDR/Instrucciones%20New-DefenderXDRWeeklyReport.ps1.md) |
| [New-DefenderVulnerabilityReport.ps1](MDE/New-DefenderVulnerabilityReport.ps1) | Genera reporte de vulnerabilidades (TVM) en HTML | [Instrucciones](XDR/Instrucciones%20New-DefenderVulnerabilityReport.ps1.md) |
| [Setup-DefenderXDRReportServer.ps1](XDR/Setup-DefenderXDRReportServer.ps1) | Setup inicial del servidor: estructura de carpetas, credenciales DPAPI/cert, Task Scheduler para automatización | — |

### Características de los Reportes

- **Grid de KPIs**: Métricas clave (Alertas MDE, Phishing, High Risk Users) en la parte superior
- **Secciones por dominio**: MDO (campañas y usuarios objetivo), MDE (severidad de alertas), MDI (fuerza bruta y riesgo), MDA (OAuth y cloud apps)
- **Diseño ejecutivo**: Interfaz basada en Segoe UI, coherente con el ecosistema Microsoft
- **Automatización**: Task Scheduler para ejecución diaria (7:00 AM) y semanal (lunes 7:30 AM)

---

## Estructura del Repositorio

```
gol2026/
├── README.md                          ← Este archivo
├── Requisitos.md                      ← Requisitos, licenciamiento y configuración
│
├── EntraID/                           ← Microsoft Entra ID (Identidad)
│   ├── Guías operativas (diaria, semanal, mensual)
│   ├── Línea base Conditional Access Policies
│   ├── Paquete KQL Advanced Hunting
│   ├── Políticas/
│   └── Scripts/                       ← 4 scripts (CA policies, inactive users, roles, MFA)
│
├── MDO/                               ← Microsoft Defender for Office 365
│   ├── Guías operativas (diaria, semanal, mensual)
│   ├── Líneas base (BEC, Exchange Online)
│   ├── Paquete KQL Advanced Hunting
│   ├── Políticas/                     ← Anti-Phishing, Safe Attachments, Safe Links
│   ├── Línea Base/
│   └── Scripts/                       ← 8 scripts (alertas, validaciones, transport rules)
│
├── MDE/                               ← Microsoft Defender for Endpoint
│   ├── Guías operativas (diaria, semanal)
│   └── New-DefenderVulnerabilityReport.ps1
│
├── MDI/                               ← Microsoft Defender for Identity
│   ├── Guías operativas (diaria, semanal, mensual)
│   └── Paquete KQL Advanced Hunting
│
├── MDA/                               ← Microsoft Defender for Cloud Apps (en desarrollo)
│
├── XDR/                               ← Reportes Cross-Domain
│   ├── Instrucciones de ejecución (.md)
│   ├── Scripts de reportería (daily, weekly, setup)
│   └── Reportes generados (.html)
│
└── wiki/                              ← Wiki (en desarrollo)
```

---

## Tecnologías Utilizadas

| Tecnología | Uso |
|---|---|
| **PowerShell 5.1+ / 7+** | Scripts de automatización, validación y reportería |
| **KQL (Kusto Query Language)** | Consultas de Advanced Hunting en Microsoft 365 Defender |
| **Microsoft Graph API** | Consultas de identidad, roles y métodos de autenticación |
| **Microsoft 365 Defender API** | Advanced Hunting, reportes de vulnerabilidades |
| **Exchange Online PowerShell** | Validación de políticas MDO y configuración de Exchange |
| **HTML5 / CSS3** | Reportes ejecutivos visuales |

---

## Inicio Rápido

```powershell
# 1. Instalar módulos necesarios
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module Microsoft.Graph -Scope CurrentUser

# 2. Conectar a los servicios
Connect-ExchangeOnline
Connect-IPPSSession

# 3. Configurar variables de entorno para reportes XDR
$env:AZURE_TENANT_ID     = "<tu-tenant-id>"
$env:AZURE_CLIENT_ID     = "<tu-client-id>"
$env:AZURE_CLIENT_SECRET  = "<tu-client-secret>"

# 4. Generar un reporte diario
.\XDR\New-DefenderXDRDailyReport.ps1

# 5. Validar políticas MDO
.\MDO\Scripts\Validate-MDOPolicies.ps1
```

> Para la configuración completa incluyendo App Registration, certificados y Task Scheduler, consulte [Requisitos.md](Requisitos.md).



PowerShell / Graph API (Opcional): Para la automatización y generación del archivo.





## ⚙️ Configuración y Uso

### Opción 1: Configuración Automatizada (Recomendado para Servidores)

```powershell
# 1. Ejecutar script de setup
.\Setup-DefenderReportServer.ps1

# 2. Seguir el asistente de configuración
# - Ingresa Tenant ID y Client ID
# - Configura Client Secret (encriptado con DPAPI)
# - Valida permisos de API

# 3. Ejecutar reporte
.\Run-DefenderXDRWeeklyReport.ps1
```

### Opción 2: Configuración Manual

```powershell
# Clonar el repositorio
git clone https://github.com/watchdogcode/gol2026

# Crear SecureString para Client Secret
$Secret = Read-Host "Client Secret" -AsSecureString
$Secret | ConvertFrom-SecureString | Out-File "C:\Config\Secret.txt"

# Ejecutar reporte
$SecureSecret = Get-Content "C:\Config\Secret.txt" | ConvertTo-SecureString
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -AuthMode Secret `
    -ClientSecret $SecureSecret `
    -UseParallel `
    -ExportCsv
```

### Requisitos Previos

- **Azure AD App Registration** con permisos:
  - `AdvancedHunting.Read.All` (Application)
  - Admin Consent otorgado
- **PowerShell 5.1** o superior (7+ recomendado para ejecución paralela)
- **Licencias requeridas**: Microsoft 365 E5 o Microsoft Defender XDR

## 🆕 Nuevas Características (v2.0)

### 🔒 Seguridad Mejorada
- ✅ **SecureString** para Client Secret (encriptación DPAPI local)
- ✅ **Enmascaramiento** de Tenant ID en reportes
- ✅ **Limpieza automática** de variables sensibles en memoria
- ✅ **Cache de tokens** con expiración automática

### ⚡ Rendimiento
- ✅ **Ejecución paralela** de queries (hasta 5x más rápido)
- ✅ **Cache de autenticación** (reutiliza tokens válidos)
- ✅ **Reintentos exponenciales** con backoff inteligente

### 📊 Funcionalidad
- ✅ **Exportación CSV** de todas las tablas
- ✅ **Comparación con período anterior** (KPI trends)
- ✅ **Logging estructurado** con niveles (INFO/WARN/ERROR/DEBUG)
- ✅ **Modo test** para pruebas sin API

### 🛡️ Robustez
- ✅ **Manejo de errores granular** (no falla todo por un query)
- ✅ **Validación de datos** antes de generar reporte
- ✅ **Timeout mejorado** en Device Code flow
- ✅ **Variables configurables** (retry limits, thresholds)

Ver [MEJORAS_IMPLEMENTADAS.md](MEJORAS_IMPLEMENTADAS.md) para documentación detallada.

## 📁 Estructura del Proyecto

```
gol2026/
├── New-DefenderXDRWeeklyReport.ps1      # Script principal (v2.0)
├── New-DefenderXDRDailyReport.ps1       # Reporte diario
├── Setup-DefenderReportServer.ps1       # Setup automatizado
├── Run-DefenderXDRWeeklyReport.ps1      # Wrapper (generado por setup)
├── MEJORAS_IMPLEMENTADAS.md             # Documentación de mejoras
├── Paquete KQL Advance Hunting.md       # Queries KQL de referencia
├── Guia de Seguridad Operacional MDO... # Guías operacionales
└── README.md                            # Este archivo
```

## 🔧 Ejemplos de Uso

### Ejecución Programada (Task Scheduler)
```powershell
# Crear tarea semanal (Lunes 7 AM)
$Action = New-ScheduledTaskAction -Execute 'PowerShell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Run-DefenderXDRWeeklyReport.ps1"'
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 7am
Register-ScheduledTask -TaskName "DefenderXDR-WeeklyReport" `
    -Action $Action -Trigger $Trigger
```

### Uso Avanzado
```powershell
# Con todas las características
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "xxx" `
    -ClientId "yyy" `
    -AuthMode Secret `
    -ClientSecret $SecureSecret `
    -TimeWindowDays 14 `
    -UseParallel `
    -ExportCsv `
    -SendMail `
    -SmtpServer "smtp.office365.com" `
    -To "soc-team@empresa.com" `
    -LogPath "D:\Logs\Defender.log"
```

## ⚠️ Disclaimer

Este reporte es una herramienta de visualización. Los datos mostrados dependen de la correcta configuración de las licencias y conectores de Microsoft Defender XDR en tu entorno.

**Creado por:** Ernesto Cobos Roqueñi y Jose Arturo Mandujano  
**Versión:** 2.0  
**Última actualización:** Marzo 2026

