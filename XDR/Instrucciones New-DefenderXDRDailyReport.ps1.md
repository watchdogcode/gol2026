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

- KPIs ejecutivos
- Tareas operativas con enlaces (MDO, MDI y Entra ID)
- Recomendaciones KQL diarias por carga de trabajo

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
| `AuthMode` | String | Método de autenticación | `Secret` |
| `SendMail` | Bool | Envía reporte por SMTP | `$false` |
| `SmtpServer` | String | Servidor SMTP | N/A |
| `From` | String | Remitente de correo | N/A |
| `To` | String | Destinatario(s) | N/A |
| `Subject` | String | Asunto del correo | `Reporte Diario de Seguridad - M365 Defender XDR` |
| `TimeoutSec` | Int | Timeout por consulta | `120` |
| `FailFast` | Bool | Detener ejecución ante primer fallo | `$false` |

---

## 5) Ejemplos de Ejecución

### A. Ejecución estándar (Secret por defecto)

```powershell
.\New-DefenderXDRDailyReport.ps1 `
  -TenantId "00000000-0000-0000-0000-000000000000" `
  -ClientId "11111111-1111-1111-1111-111111111111" `
  -ClientSecret "tu_client_secret"
```

### B. Interactivo (requiere Az.Accounts)

```powershell
Install-Module Az.Accounts -Scope CurrentUser -Force

.\New-DefenderXDRDailyReport.ps1 -AuthMode Interactive -TimeWindowHours 48
```

### C. Device Code (sin browser local)

```powershell
# Recomendado con Az.Accounts:
.\New-DefenderXDRDailyReport.ps1 -AuthMode DeviceCode

# Fallback REST (sin Az.Accounts):
.\New-DefenderXDRDailyReport.ps1 -AuthMode DeviceCode `
  -TenantId "00000000-0000-0000-0000-000000000000" `
  -ClientId "11111111-1111-1111-1111-111111111111"
```

### D. Envío por correo SMTP

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
| **KPIs** | Total Alertas XDR, Incidentes Activos, Phishing Entregado, Usuarios Alto Riesgo, Fuerza Bruta, OAuth. |
| **MDO** | Tareas operativas diarias + recomendación KQL diaria. |
| **XDR Consolidado** | Alertas por servicio/severidad y top de alertas recientes. |
| **MDE** | Alertas por severidad + recomendación KQL diaria. |
| **MDI** | Tareas operativas + fuerza bruta + usuarios de alto riesgo + recomendación KQL diaria. |
| **Entra ID** | Tareas operativas + recomendación KQL diaria. |
| **MDA** | Nuevos consentimientos OAuth + recomendación KQL diaria. |
| **Recomendaciones** | Acciones operativas sugeridas para el día. |

---

## 7) Solución de Problemas Rápida

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

---

## 8) Ejecución recomendada para automatización

```powershell
.\New-DefenderXDRDailyReport.ps1 `
  -TenantId $env:AZURE_TENANT_ID `
  -ClientId $env:AZURE_CLIENT_ID `
  -ClientSecret $env:AZURE_CLIENT_SECRET `
  -TimeWindowHours 24
```

Para entorno SOC diario, se recomienda programar ejecución cada mañana y almacenar el HTML en una ruta compartida de reportes.
