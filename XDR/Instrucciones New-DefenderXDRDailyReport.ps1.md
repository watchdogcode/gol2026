# Guía de Uso — New-DefenderXDRDailyReport.ps1

Esta guía está alineada con el estado actual del script `XDR/New-DefenderXDRDailyReport.ps1`.

---

## 1) Descripción

`New-DefenderXDRDailyReport.ps1` genera un reporte HTML diario de operaciones de seguridad para Microsoft Defender XDR con foco en:

- MDO (campañas, URLs y usuarios más atacados)
- MDE (alertas por severidad y estado de salud endpoint)
- MDI (fuerza bruta y usuarios de alto riesgo)
- MDA (OAuth y Shadow IT)
- XDR consolidado (alertas por servicio/severidad y top de alertas recientes)

Además incluye:

- KPIs ejecutivos con **coloración dinámica por severidad máxima** detectada en cada workload
- Tareas operativas con enlaces directos al portal (MDO, MDI, Entra ID)
- Recomendación KQL diaria por carga de trabajo (rotatoria, extraída de los catálogos del repositorio)
- Carga dinámica de catálogos KQL desde GitHub o archivo local (con fallback hardcoded)
- Soporte para ejecutar **solo los workloads seleccionados** mediante switches por producto

---

## 2) Requisitos Previos

1. **Permisos de API**
   - `AdvancedHunting.Read.All` con consentimiento de administrador.

2. **Conectividad**
   - `https://api.security.microsoft.com`
   - `https://login.microsoftonline.com`

3. **Módulos (según método de auth)**
   - `Az.Accounts` para `Interactive` y (recomendado) `DeviceCode`.
   - Si `Az.Accounts` no está instalado, el script puede usar fallback REST en `DeviceCode` (requiere `TenantId` y `ClientId`).

---

## 3) Autenticación

Métodos soportados:

- `Secret` (predeterminado)
- `Interactive`
- `DeviceCode`

### Comportamiento importante

- Si no envías `-AuthMode`, se usa `Secret`.
- En `Secret`, debes proporcionar `TenantId`, `ClientId` y `ClientSecret` (directos o por variables de entorno).
- En `DeviceCode` sin módulos, debes proporcionar `TenantId` y `ClientId`.

---

## 4) Parámetros Principales

| Parámetro | Tipo | Descripción | Default |
| :--- | :--- | :--- | :--- |
| `TimeWindowHours` | Int | Ventana de análisis en horas | `720` |
| `OutputPath` | String | Ruta de salida del HTML | `XDR\Daily_SecOps_Report_YYYYMMDD.html` |
| `TenantId` | String | Tenant ID de Entra ID | `$env:AZURE_TENANT_ID` |
| `ClientId` | String | App/Client ID | `$env:AZURE_CLIENT_ID` |
| `ClientSecret` | String | Secreto de la app | `$env:AZURE_CLIENT_SECRET` |
| `AuthMode` | String | Método de autenticación: `Secret`, `Interactive`, `DeviceCode` | `Secret` |
| `SendMail` | Bool | Envía reporte por SMTP | `$false` |
| `SmtpServer` | String | Servidor SMTP | N/A |
| `From` | String | Remitente de correo | N/A |
| `To` | String | Destinatario(s) | N/A |
| `Subject` | String | Asunto del correo | `Reporte Diario de Seguridad - M365 Defender XDR` |
| `TimeoutSec` | Int | Timeout por consulta API | `120` |
| `FailFast` | Bool | Detener ejecución ante el primer fallo de consulta | `$false` |
| `IncludeMDO` | Switch | Incluir secciones de Defender for Office 365 | — |
| `IncludeMDE` | Switch | Incluir secciones de Defender for Endpoint | — |
| `IncludeMDI` | Switch | Incluir secciones de Defender for Identity y Entra ID | — |
| `IncludeMDA` | Switch | Incluir secciones de Defender for Cloud Apps | — |

> **Nota:** Si no se especifica ningún switch de producto (`-IncludeMDO/MDE/MDI/MDA`), el script incluye **todos** los workloads automáticamente.

---

## 5) Ejemplos de Ejecución

### A. Ejecución estándar — todos los workloads (Secret por defecto)

```powershell
.\New-DefenderXDRDailyReport.ps1 `
  -TenantId "00000000-0000-0000-0000-000000000000" `
  -ClientId "11111111-1111-1111-1111-111111111111" `
  -ClientSecret "tu_client_secret"
```

### B. Solo workloads seleccionados

```powershell
# Solo MDO y MDE
.\New-DefenderXDRDailyReport.ps1 `
  -TenantId "..." -ClientId "..." -ClientSecret "..." `
  -IncludeMDO -IncludeMDE

# Solo Identidades (MDI + Entra ID)
.\New-DefenderXDRDailyReport.ps1 `
  -TenantId "..." -ClientId "..." -ClientSecret "..." `
  -IncludeMDI

# Solo Cloud Apps
.\New-DefenderXDRDailyReport.ps1 `
  -TenantId "..." -ClientId "..." -ClientSecret "..." `
  -IncludeMDA
```

### C. Interactivo (requiere Az.Accounts)

```powershell
Install-Module Az.Accounts -Scope CurrentUser -Force

.\New-DefenderXDRDailyReport.ps1 -AuthMode Interactive -TimeWindowHours 48
```

### D. Device Code (sin browser local)

```powershell
# Recomendado con Az.Accounts:
.\New-DefenderXDRDailyReport.ps1 -AuthMode DeviceCode

# Fallback REST (sin Az.Accounts):
.\New-DefenderXDRDailyReport.ps1 -AuthMode DeviceCode `
  -TenantId "00000000-0000-0000-0000-000000000000" `
  -ClientId "11111111-1111-1111-1111-111111111111"
```

### E. Envío por correo SMTP

```powershell
.\New-DefenderXDRDailyReport.ps1 `
  -AuthMode Secret `
  -TenantId "00000000-0000-0000-0000-000000000000" `
  -ClientId "11111111-1111-1111-1111-111111111111" `
  -ClientSecret "tu_client_secret" `
  -SendMail $true `
  -SmtpServer "smtp.tuempresa.com" `
  -From "security-reports@tuempresa.com" `
  -To "ciso@tuempresa.com" `
  -Subject "Reporte Diario de Seguridad - M365"
```

> Nota: para enviar correo deben venir `SmtpServer`, `From` y `To`.

---

## 6) Contenido del Reporte HTML

| Sección | Descripción |
| :--- | :--- |
| **KPIs** | Incidentes Activos (XDR), Alertas MDO, Alertas MDE, Usuarios en Riesgo Entra ID, Alertas MDI, Consentimientos OAuth MDA. Cada KPI muestra el badge **"Máx: [severidad]"** y se colorea según la alerta de mayor severidad detectada en el workload. |
| **Tareas Operativas MDO** | Checklist de tareas diarias MDO con enlaces al portal. |
| **KQL diario MDO** | Recomendación KQL rotatoria del día para Defender for Office 365. |
| **XDR Consolidado** | Alertas por servicio/severidad y top de incidentes recientes. |
| **MDE — Endpoints** | Alertas por severidad + recomendación KQL diaria de Defender for Endpoint. |
| **MDI — Identidades** | Tareas operativas MDI + fuerza bruta + usuarios de alto riesgo + recomendación KQL diaria. |
| **Entra ID — Gobernanza** | Tareas operativas Entra ID + recomendación KQL diaria. |
| **MDA — Cloud Apps** | Nuevos consentimientos OAuth + recomendación KQL diaria. |

### Coloración de KPIs por severidad

El color del borde superior de cada KPI card refleja la criticidad máxima detectada:

| Color | Clase CSS | Severidad |
| :--- | :--- | :--- |
| Guinda oscuro | `critical` | Critical |
| Rojo | `high` | High |
| Naranja | `medium` | Medium |
| Morado | `low` | Low |
| Azul | `info` | Informational |
| Verde | `none` | Sin alertas |

Para Entra ID (usuarios en riesgo), la clase se deriva del campo numérico `RiskLevelAggregated`: ≥100 → `critical`, ≥50 → `high`, >0 → `medium`, 0 → `none`.

---

## 7) Catálogos KQL Dinámicos

El script carga los catálogos KQL de consultas avanzadas en el siguiente orden de prioridad:

1. **GitHub** (rama `main` del repositorio): descarga automática vía HTTPS.
2. **Archivo local**: ruta relativa `../MDO/`, `../MDI/` o `../EntraID/` respecto al directorio del script.
3. **Fallback hardcoded**: catálogo embebido en el script si ninguna fuente anterior está disponible. Se emite un `[WARN]` en el log.

Los catálogos soportados son:

| Formato | Archivo fuente | URL GitHub |
| :--- | :--- | :--- |
| MDO | `MDO/Paquete MDO KQL Advance Hunting.md` | `watchdogcode/gol2026` rama `main` |
| MDI | `MDI/Paquete MDI KQL Advance Hunting.md` | `watchdogcode/gol2026` rama `main` |
| EntraID | `EntraID/Paquete KQL Queries EntraID Advanced Hunting.md` | `watchdogcode/gol2026` rama `main` |

La consulta KQL mostrada en cada sección es la del día: `(Get-Date).DayOfYear % $Catalog.Count`.

---

## 8) Solución de Problemas Rápida

- **401 Unauthorized**
  - Validar permisos `AdvancedHunting.Read.All` + Admin Consent.

- **Fallo en autenticación Secret**
  - Confirmar `TenantId`, `ClientId`, `ClientSecret` válidos.

- **Sin sesión Azure en Interactive/DeviceCode**
  - Instalar `Az.Accounts` o usar `DeviceCode` fallback REST con `TenantId` y `ClientId`.

- **Consultas vacías / sin datos**
  - Ajustar `-TimeWindowHours` (ej. `24`, `72`, `168`, `720` según necesidad).

- **No envía correo**
  - Revisar que `-SendMail $true` y parámetros `-SmtpServer`, `-From`, `-To` estén completos.

- **`[WARN] Cargando catálogo [X] desde fallback hardcoded...`**
  - El script no pudo descargar el catálogo KQL desde GitHub ni encontrarlo en ruta local.
  - Verificar conectividad a `https://raw.githubusercontent.com`.
  - Verificar que los archivos `.md` existan en `../MDO/`, `../MDI/` o `../EntraID/` relativos al script.
  - El catálogo hardcoded se usará como respaldo sin afectar la ejecución.

---

## 9) Ejecución recomendada para automatización

```powershell
.\New-DefenderXDRDailyReport.ps1 `
  -TenantId $env:AZURE_TENANT_ID `
  -ClientId $env:AZURE_CLIENT_ID `
  -ClientSecret $env:AZURE_CLIENT_SECRET `
  -TimeWindowHours 24
```

Para entorno SOC diario, se recomienda programar ejecución cada mañana y almacenar el HTML en una ruta compartida de reportes.
