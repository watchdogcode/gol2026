# Guía de Ejecución de Reportes de Seguridad (PowerShell)

Este documento detalla las instrucciones de uso para los scripts de generación de reportes de seguridad, comenzando con el reporte diario de Microsoft 365 Defender.

---

## 1. New-DefenderXDRDailyReport.ps1

**Descripción:**  
Este script se conecta a la API de Microsoft 365 Defender para ejecutar consultas de caza avanzadas (Advanced Hunting KQL) y genera un reporte ejecutivo en formato HTML. Cubre los pilares de MDO (Office 365), MDE (Endpoint), MDI (Identity) y MDA (Cloud Apps). Además, incluye una sección de **Tareas Operativas** con enlaces directos a los portales de administración y documentación de referencia para MDO, MDI y Entra ID.

### Requisitos Previos

1.  **Permisos de API:**
    *   La identidad (Usuario o Service Principal) debe tener el permiso `AdvancedHunting.Read.All` asignado en la API de Windows Defender ATP (Microsoft Threat Protection).
2.  **Conectividad:**
    *   Acceso HTTPS a `https://api.security.microsoft.com` y `https://login.microsoftonline.com`.
3.  **Módulos de PowerShell (Recomendado para modo Interactivo/DeviceCode):**
    *   `Az.Accounts` — compatible con versiones 2.x y >= 3.0 (SecureString).
    *   Si `Az.Accounts` **no** está instalado, el script usa un fallback Device Code vía REST que no requiere módulos adicionales (necesita `ClientId` y `TenantId`).

### Métodos de Autenticación

| Modo | Descripción | Requisitos |
| :--- | :--- | :--- |
| `Secret` | Client Credentials (App Registration). Ideal para automatización sin intervención humana. | `TenantId`, `ClientId`, `ClientSecret` |
| `Interactive` | Login interactivo vía browser (popup). Ideal para ejecución manual por un administrador. | `Az.Accounts` instalado |
| `DeviceCode` | Genera un código que el usuario ingresa en [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin). Ideal para sesiones remotas o sin browser local. | `Az.Accounts` (recomendado) o `ClientId` + `TenantId` (fallback REST) |

### Parámetros Principales

| Parámetro | Tipo | Descripción | Valor por Defecto |
| :--- | :--- | :--- | :--- |
| `AuthMode` | String | Método de autenticación: `Secret`, `Interactive` o `DeviceCode`. | `Secret` |
| `TimeWindowHours` | Int | Ventana de tiempo en horas para el análisis de datos. | `24` |
| `OutputPath` | String | Ruta completa donde se guardará el archivo HTML. | `.\Daily_SecOps_Report_YYYYMMDD.html` |
| `SendMail` | Bool | Si se establece en `$true`, intenta enviar el reporte por correo SMTP. | `$false` |
| `TenantId` | String | ID del Tenant de Azure AD. Requerido para modo `Secret` y fallback `DeviceCode`. | `$env:AZURE_TENANT_ID` |
| `ClientId` | String | ID de la Aplicación. Requerido para modo `Secret` y fallback `DeviceCode`. | `$env:AZURE_CLIENT_ID` |
| `ClientSecret` | String | Secreto del Cliente (Solo requerido para modo `Secret`). | `$env:AZURE_CLIENT_SECRET` |
| `TimeoutSec` | Int | Tiempo máximo de espera en segundos para cada consulta KQL. | `120` |
| `FailFast` | Bool | Si es `$true`, el script se detiene ante la primera consulta fallida. | `$false` |

---

### Ejemplos de Ejecución

#### A. Ejecución Manual (Modo Interactivo)
Ideal para ejecutar bajo demanda con tu propia cuenta de administrador. Se abrirá una ventana de login del browser o usará una sesión existente de `Az.Accounts`.

```powershell
# Instalar el módulo si no lo tienes
Install-Module Az.Accounts -Scope CurrentUser -Force

# Ejecutar con login interactivo
.\New-DefenderXDRDailyReport.ps1 -AuthMode Interactive -TimeWindowHours 48
```

#### B. Ejecución con Device Code (Sesiones remotas / SSH / sin browser local)
El script mostrará un código y una URL. Ingresa el código en otro dispositivo que tenga browser.

```powershell
# Con Az.Accounts instalado (recomendado):
.\New-DefenderXDRDailyReport.ps1 -AuthMode DeviceCode

# Sin Az.Accounts (fallback REST — requiere ClientId y TenantId):
.\New-DefenderXDRDailyReport.ps1 -AuthMode DeviceCode `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111"
```

#### C. Ejecución Automatizada (Service Principal / App Registration)
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

#### D. Generar Reporte y Enviar por Correo
Genera el reporte y lo envía a una lista de distribución usando un servidor SMTP relay.

```powershell
.\New-DefenderXDRDailyReport.ps1 -AuthMode Secret `
    -SendMail $true `
    -SmtpServer "smtp.tuempresa.com" `
    -From "security-reports@tuempresa.com" `
    -To "ciso@tuempresa.com" `
    -Subject "Reporte Diario de Seguridad - M365"
```

### Contenido del Reporte HTML

El reporte generado incluye las siguientes secciones:

| Sección | Descripción |
| :--- | :--- |
| **KPIs** | Tarjetas con métricas clave: alertas MDE, phishing entregado, usuarios de alto riesgo, fuerza bruta, OAuth. |
| **MDO** | Campañas de phishing entregadas, usuarios más atacados, actividades diarias con KQL recomendado. |
| **MDE** | Alertas por severidad. |
| **MDI** | Ataques de fuerza bruta, usuarios con inicio de sesión de alto riesgo. |
| **MDA** | Consentimientos OAuth y Shadow IT. |
| **Recomendaciones** | Acciones sugeridas basadas en los datos del periodo. |
| **Tareas Operativas** | Tabla agrupada por producto (MDO, MDI, Entra ID) con enlaces a portales y documentación de las guías operativas. |

### Solución de Problemas Comunes

*   **Error "Unauthorized" (401):** Verifica que el App Registration tenga permisos de aplicación (Application Permissions) y no solo delegados, y que se haya otorgado el "Admin Consent".
*   **Error "No hay sesión activa de Azure":** El script intentará conectar automáticamente con `Connect-AzAccount`. Si usas DeviceCode, sigue las instrucciones en pantalla para autenticarte.
*   **Error "Módulo Az.Accounts no encontrado" (modo DeviceCode):** El script usará un flujo Device Code vía REST automáticamente. Solo necesitas proporcionar `-TenantId` y `-ClientId`. Para mejor experiencia, instala el módulo: `Install-Module Az.Accounts -Scope CurrentUser`.
*   **Error con `SecureString` en Token:** Si tienes Az.Accounts >= 3.0, el script maneja automáticamente la conversión de `SecureString` a texto plano. No se requiere acción.
*   **Reporte vacío:** Verifica si `TimeWindowHours` es suficiente. Si es un entorno de prueba con poca actividad, intenta aumentar a 72 horas o 168 (una semana).