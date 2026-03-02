# Guía de Ejecución de Reportes de Seguridad (PowerShell)

Este documento detalla las instrucciones de uso para los scripts de generación de reportes de seguridad, comenzando con el reporte diario de Microsoft 365 Defender.

---

## 1. New-DefenderXDRDailyReport.ps1

**Descripción:**  
Este script se conecta a la API de Microsoft 365 Defender para ejecutar consultas de caza avanzadas (Advanced Hunting KQL) y genera un reporte ejecutivo en formato HTML. Cubre los pilares de MDO (Office 365), MDE (Endpoint), MDI (Identity) y MDA (Cloud Apps).

### Requisitos Previos

1.  **Permisos de API:**
    *   La identidad (Usuario o Service Principal) debe tener el permiso `AdvancedHunting.Read.All` asignado en Microsoft Graph o la API de Windows Defender ATP.
2.  **Conectividad:**
    *   Acceso HTTPS a `https://api.security.microsoft.com`.
3.  **Módulos de PowerShell (Solo para modo Interactivo):**
    *   `Az.Accounts` o `Microsoft.Graph.Authentication`.

### Parámetros Principales

| Parámetro | Tipo | Descripción | Valor por Defecto |
| :--- | :--- | :--- | :--- |
| `AuthMode` | String | Método de autenticación: `Secret` (App Registration), `Interactive` (Login manual), o `DeviceCode`. | `Secret` |
| `TimeWindowHours` | Int | Ventana de tiempo en horas para el análisis de datos. | `24` |
| `OutputPath` | String | Ruta completa donde se guardará el archivo HTML. | `.\Daily_SecOps_Report_YYYYMMDD.html` |
| `SendMail` | Bool | Si se establece en `$true`, intenta enviar el reporte por correo SMTP. | `$false` |
| `TenantId` | String | ID del Tenant de Azure AD (Requerido para modo `Secret`). | `$env:AZURE_TENANT_ID` |
| `ClientId` | String | ID de la Aplicación (Requerido para modo `Secret`). | `$env:AZURE_CLIENT_ID` |
| `ClientSecret` | String | Secreto del Cliente (Requerido para modo `Secret`). | `$env:AZURE_CLIENT_SECRET` |

---

### Ejemplos de Ejecución

#### A. Ejecución Manual (Modo Interactivo)
Ideal para ejecutar bajo demanda con tu propia cuenta de administrador. Se abrirá una ventana de login o usará una sesión existente.

```powershell
.\New-DefenderXDRDailyReport.ps1 -AuthMode Interactive -TimeWindowHours 48
```

#### B. Ejecución Automatizada (Service Principal / App Registration)
Ideal para tareas programadas (Task Scheduler, Azure Automation).

**Opción 1: Usando Variables de Entorno (Recomendado)**
Asegúrate de que las variables `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` y `AZURE_CLIENT_SECRET` estén configuradas en el sistema.

```powershell
.\New-DefenderXDRDailyReport.ps1 -AuthMode Secret
```

**Opción 2: Pasando credenciales explícitas**
```powershell
.\New-DefenderXDRDailyReport.ps1 -AuthMode Secret `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -ClientSecret "tu_client_secret_aqui"
```

#### C. Generar Reporte y Enviar por Correo
Genera el reporte y lo envía a una lista de distribución usando un servidor SMTP relay.

```powershell
.\New-DefenderXDRDailyReport.ps1 -AuthMode Secret `
    -SendMail $true `
    -SmtpServer "smtp.tuempresa.com" `
    -From "security-reports@tuempresa.com" `
    -To "ciso@tuempresa.com" `
    -Subject "Reporte Diario de Seguridad - M365"
```

### Solución de Problemas Comunes

*   **Error "Unauthorized" (401):** Verifica que el App Registration tenga permisos de aplicación (Application Permissions) y no solo delegados, y que se haya otorgado el "Admin Consent".
*   **Error "Modules not found":** Si usas `-AuthMode Interactive`, ejecuta `Install-Module Az.Accounts` antes de correr el script.
*   **Reporte vacío:** Verifica si `TimeWindowHours` es suficiente. Si es un entorno de prueba con poca actividad, intenta aumentar a 72 horas o 168 (una semana).

---

## 2. New-DefenderXDRWeeklyReport.ps1

**Descripción:**
Este script genera un reporte ejecutivo semanal, consolidando tendencias de alertas, incidentes de identidad y cobertura de dispositivos. A diferencia del reporte diario, este se enfoca en métricas agregadas de los últimos 7 días para análisis de tendencias y postura de seguridad.

### Requisitos Previos

Los mismos que para el reporte diario (`AdvancedHunting.Read.All` y acceso a la API).

### Parámetros Principales

| Parámetro | Tipo | Descripción | Valor por Defecto |
| :--- | :--- | :--- | :--- |
| `AuthMode` | String | Método de autenticación: `Secret`, `Interactive`, o `DeviceCode`. | `Secret` |
| `TimeWindowDays` | Int | Ventana de tiempo en días para el análisis. | `7` |
| `OutputPath` | String | Ruta completa donde se guardará el archivo HTML. | `.\Weekly_SecOps_Report_YYYYMMDD.html` |
| `SendMail` | Bool | Si se establece en `$true`, intenta enviar el reporte por correo SMTP. | `$false` |
| `TenantId` | String | ID del Tenant de Azure AD. | `$env:AZURE_TENANT_ID` |
| `ClientId` | String | ID de la Aplicación. | `$env:AZURE_CLIENT_ID` |
| `ClientSecret` | String | Secreto del Cliente. | `$env:AZURE_CLIENT_SECRET` |

---

### Ejemplos de Ejecución

#### A. Ejecución Manual (Revisión Semanal)
```powershell
.\New-DefenderXDRWeeklyReport.ps1 -AuthMode Interactive -TimeWindowDays 7
```

#### B. Ejecución Automatizada (Programada)
```powershell
.\New-DefenderXDRWeeklyReport.ps1 -AuthMode Secret
```

#### C. Envío de Resumen Semanal por Correo
```powershell
.\New-DefenderXDRWeeklyReport.ps1 -AuthMode Secret `
    -SendMail $true `
    -SmtpServer "smtp.tuempresa.com" `
    -From "security-reports@tuempresa.com" `
    -To "ciso@tuempresa.com" `
    -Subject "Reporte Semanal de Seguridad - M365"
```