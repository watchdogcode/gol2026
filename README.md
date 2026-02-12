# Microsoft Defender XDR: SecOps Report

📋 Descripción General

Este proyecto proporciona una plantilla de reporte diario y semanal automatizado diseñada para sintetizar datos críticos de Microsoft Defender XDR. El objetivo es cerrar la brecha de comunicación entre el equipo técnico y la alta gerencia (CISO), transformando telemetría compleja en información accionable.



Nota: Este reporte está diseñado para cubrir periodos de actividad de hasta 24 horas, permitiendo una visión clara de incidentes y tendencias recientes.



## 🎯 Valor de Negocio

Para el CISO (Executive View)

Visibilidad de Alto Nivel: KPIs claros sobre exposición y riesgo.



Indicadores de Salud: Resumen de higiene de identidades y aplicaciones OAuth.



Eficiencia: Visualización rápida de si existen incidentes críticos sin necesidad de entrar a la consola.



Para Administradores de Infraestructura (Operational View)

Accionabilidad: Listado de actividades diarias recomendadas para el mantenimiento del tenant.



Foco en Identidad: Reporte detallado de intentos de fuerza bruta y usuarios de alto riesgo (MDI).



Higiene de Email: Seguimiento de campañas de phishing entregadas y usuarios objetivo (MDO).



## 🚀 Características Principales

Diseño Limpio: Interfaz basada en Segoe UI para coherencia visual con el ecosistema Microsoft.



Grid de KPIs: Métricas clave (Alertas MDE, Phishing, High Risk Users) en la parte superior para lectura rápida.



Secciones por Dominio:



MDO: Email y colaboración (campañas y usuarios objetivo).



MDE: Seguridad de endpoints y severidad de alertas.



MDI: Seguridad de identidad (fuerza bruta y riesgo de inicio de sesión).



MDA: Aplicaciones en la nube y consentimientos OAuth.



## 🛠️ Tecnologías Utilizadas

KQL (Kusto Query Language): Para la extracción de datos de Microsoft Defender y Sentinel.



HTML5 / CSS3: Para la estructura y el diseño visual del reporte.



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
**Última actualización:** Febrero 2026

