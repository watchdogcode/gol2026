# Guía de Uso — New-DefenderXDRWeeklyReport.ps1

Esta guía está alineada con el estado actual del script `XDR/New-DefenderXDRWeeklyReport.ps1`.

---

## 1) Descripción

`New-DefenderXDRWeeklyReport.ps1` genera un reporte HTML semanal de seguridad para Microsoft Defender XDR con foco en:

- MDO (campañas y usuarios más atacados)
- MDE (severidad de alertas, hosts en riesgo y salud de dispositivos)
- MDI (spray/fuerza bruta y ubicaciones atípicas)
- MDA (OAuth y Shadow IT)

Incluye KPIs, resumen ejecutivo y lista de verificación operativa semanal.

---

## 2) Requisitos Previos

1. **Permisos de API**
     - `AdvancedHunting.Read.All` con consentimiento de administrador.

2. **Conectividad**
     - `https://api.security.microsoft.com`
     - `https://login.microsoftonline.com`

3. **Módulos (solo según método de auth)**
     - `Az.Accounts` para `Interactive`.
     - `MSAL.PS` para `Certificate` (según implementación actual del script).

---

## 3) Autenticación (estado actual)

- **Predeterminado:** `Secret`
- **Alias disponible:** `-Auth` (equivalente a `-AuthMode`)
- Métodos soportados: `Secret`, `DeviceCode`, `Interactive`, `Certificate`

### Comportamiento importante

- Si no envías `-Auth` o `-AuthMode`, el script usa `Secret`.
- En modo `Secret`, `ClientSecret` es obligatorio.
- `TenantId` y `ClientId` son obligatorios en el script.

---

## 4) Parámetros Principales

| Parámetro | Tipo | Descripción | Default |
| :--- | :--- | :--- | :--- |
| `TimeWindowDays` | Int | Ventana de análisis semanal (`7`, `14`, `30`) | `7` |
| `OutputPath` | String | Ruta de salida del HTML | `XDR\Weekly_SecOps_Report_YYYYMMDD.html` |
| `AuthMode` / `Auth` | String | Método de autenticación | `Secret` |
| `TenantId` | String | Tenant ID de Entra ID | Requerido |
| `ClientId` | String | App/Client ID | Requerido |
| `ClientSecret` | String | Secreto (solo `Secret`) | N/A |
| `CertThumbprint` | String | Huella cert (solo `Certificate`) | N/A |
| `SendMail` | Bool | Envía reporte por SMTP | `$false` |
| `SmtpServer` | String | Servidor SMTP | N/A |
| `To` | String | Destinatario(s) de correo | N/A |
| `Subject` | String | Asunto de correo | `Defender XDR - Reporte Semanal de Amenazas` |
| `ProxyUrl` | String | Proxy HTTP/HTTPS | N/A |
| `TimeoutSec` | Int | Timeout por consulta | `120` |
| `FailFast` | Switch | Detiene ejecución ante primer fallo | `False` |
| `ExportCsv` | Switch | Exporta datasets a CSV | `False` |
| `UseParallel` | Switch | Ejecuta consultas en paralelo (si aplica en lógica) | `False` |
| `LogPath` | String | Ruta del log | `C:\Reports\Logs\DefenderXDR.log` |
| `TestMode` | Switch | Modo prueba (según lógica del script) | `False` |

---

## 5) Ejemplos de Ejecución

### A. Ejecución estándar (Secret por defecto)

```powershell
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -ClientSecret "tu_client_secret"
```

### B. Mismo escenario usando alias `-Auth`

```powershell
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -ClientSecret "tu_client_secret" `
    -Auth Secret
```

### C. Device Code (sesión remota / sin browser local)

```powershell
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -AuthMode DeviceCode
```

### D. Interactivo (requiere `Az.Accounts`)

```powershell
Install-Module Az.Accounts -Scope CurrentUser -Force

.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -AuthMode Interactive
```

### E. Certificado (requiere `MSAL.PS`)

```powershell
Install-Module MSAL.PS -Scope CurrentUser -Force

.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -AuthMode Certificate `
    -CertThumbprint "THUMBPRINT_DEL_CERT"
```

### F. Exportar CSV + envío por correo

```powershell
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -ClientSecret "tu_client_secret" `
    -TimeWindowDays 14 `
    -ExportCsv `
    -SendMail $true `
    -SmtpServer "smtp.tuempresa.com" `
    -To "ciso@tuempresa.com;soc@tuempresa.com" `
    -Subject "Reporte Semanal de Seguridad - M365"
```

> Nota: El script usa remitente automático `DefenderReport@<COMPUTERNAME>` en `Send-MailMessage`.

---

## 6) Salidas

- **HTML principal:** `Weekly_SecOps_Report_YYYYMMDD.html`
- **Log de ejecución:** según `-LogPath`
- **CSV opcionales:** carpeta `CSV_Export` junto al HTML (si `-ExportCsv`)

---

## 7) Solución de Problemas Rápida

- **401 Unauthorized**
    - Validar permisos `AdvancedHunting.Read.All` + Admin Consent.

- **`ClientSecret es requerido`**
    - Ocurre cuando usas default `Secret` sin `-ClientSecret`.

- **`Az.Accounts` no encontrado**
    - Instalar módulo o usar `Secret`/`DeviceCode`.

- **Error en certificado**
    - Validar que el cert exista en `Cert:\CurrentUser\My\<thumbprint>` y que `MSAL.PS` esté disponible.

- **Reporte vacío o con pocos datos**
    - Aumentar `-TimeWindowDays` a `14` o `30`.

---

## 8) Ejecución recomendada para automatización

Para tarea programada, usar `Secret` (default) con credenciales desde variable segura o secret store, por ejemplo:

```powershell
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId $env:AZURE_TENANT_ID `
    -ClientId $env:AZURE_CLIENT_ID `
    -ClientSecret $env:AZURE_CLIENT_SECRET `
    -TimeWindowDays 7
```