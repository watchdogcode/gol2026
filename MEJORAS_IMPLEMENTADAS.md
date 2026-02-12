# Mejoras Implementadas - New-DefenderXDRWeeklyReport.ps1

## Resumen de Cambios

### 🔒 Seguridad

#### 1. **SecureString para ClientSecret**
El parámetro `ClientSecret` ahora acepta `[SecureString]` en lugar de texto plano.

**Crear SecureString desde servidor:**

```powershell
# Opción 1: Crear y almacenar encriptado con DPAPI (recomendado para servidores)
$SecretText = 'tu-client-secret-aqui'
$SecureSecret = ConvertTo-SecureString $SecretText -AsPlainText -Force
$SecureSecret | ConvertFrom-SecureString | Out-File 'C:\Config\SecureSecret.txt'

# Opción 2: Crear interactivamente
$SecureSecret = Read-Host "Ingrese Client Secret" -AsSecureString
$SecureSecret | ConvertFrom-SecureString | Out-File 'C:\Config\SecureSecret.txt'
```

**Usar en el script:**

```powershell
# Cargar desde archivo encriptado (solo funciona en la misma máquina/usuario)
$SecureSecret = Get-Content 'C:\Config\SecureSecret.txt' | ConvertTo-SecureString

# Ejecutar script
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -AuthMode Secret `
    -ClientSecret $SecureSecret
```

#### 2. **Enmascaramiento de Tenant ID**
Solo se muestran los últimos 8 caracteres en el reporte HTML (ej: `****abcd1234`)

#### 3. **Limpieza de memoria**
Variables sensibles (`Token`, `ClientSecret`) se limpian al finalizar el script.

---

### ⚡ Rendimiento

#### 4. **Ejecución Paralela de Queries (PowerShell 7+)**
```powershell
# Activar modo paralelo (requiere PS 7+)
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "xxx" `
    -ClientId "yyy" `
    -UseParallel
```

**Beneficios:**
- Reduce tiempo de ejecución hasta 5x
- Ejecuta hasta 5 queries simultáneas
- Compatible con PS 5.1 (modo secuencial automático)

#### 5. **Cache de Token de Autenticación**
- Los tokens se almacenan en `$env:TEMP\DefenderXDR_TokenCache.xml`
- Reutiliza tokens válidos (evita re-autenticación)
- Expira automáticamente antes de los 60 minutos

---

### 📊 Funcionalidad

#### 6. **Exportación CSV**
Exporta todas las tablas a archivos CSV individuales:

```powershell
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "xxx" `
    -ClientId "yyy" `
    -ExportCsv
```

Archivos generados en: `C:\Reports\CSV_Export\`
- `MDO_Trend.csv`
- `MDE_Severity.csv`
- `MDI_Spray.csv`
- etc.

#### 7. **Comparación con Período Anterior**
- Almacena KPIs en `$env:TEMP\DefenderXDR_KPICache.json`
- Muestra tendencias automáticamente en logs (↑↓%)
- Útil para análisis de evolución

#### 8. **Modo Test (Sin API)**
Para pruebas sin conectar a Defender:

```powershell
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "test" `
    -ClientId "test" `
    -TestMode
```

---

### 📝 Logging Estructurado

#### 9. **Sistema de Logs con Niveles**
Log predeterminado: `C:\Reports\Logs\DefenderXDR.log`

```powershell
# Cambiar ubicación del log
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "xxx" `
    -ClientId "yyy" `
    -LogPath "D:\MyLogs\Defender.log"
```

**Niveles de log:**
- `INFO`: Operaciones normales
- `WARN`: Advertencias (reintentos, datos faltantes)
- `ERROR`: Errores críticos
- `DEBUG`: Información detallada (duraciones, cache hits)

**Formato:**
```
[2026-02-12 14:30:45] [INFO] Starting Weekly Defender XDR Report Generation
[2026-02-12 14:30:46] [DEBUG] Token cached successfully
[2026-02-12 14:30:50] [DEBUG] Query 'MDO_Trend' completed in 1245ms - Rows: 7
[2026-02-12 14:31:05] [INFO] Total rows retrieved: 156
```

---

### 🛡️ Manejo de Errores

#### 10. **Try-Catch Granular**
- `$ErrorActionPreference` cambiado de `"Stop"` a `"Continue"`
- Cada función maneja sus propios errores
- Stack trace en logs para debugging

#### 11. **Timeout Mejorado en Device Code**
- Contador de intentos máximos (no solo tiempo)
- Mensajes claros de progreso
- Previene bucles infinitos

#### 12. **Validación de Datos**
- Verifica que se recibieron datos de las queries
- Logs de advertencia si alguna query falla
- Continúa generando reporte con datos parciales

---

### 🔧 Configuración

#### 13. **Variables Constantes**
Definidas al inicio del script, fáciles de personalizar:

```powershell
$MAX_RETRIES = 3                    # Reintentos API
$RETRY_DELAY_BASE = 2               # Base para backoff exponencial
$MIN_FAILURES_SPRAY = 10            # Mínimo fallos para spray attack
$MIN_ALERTS_RISKY_HOST = 3          # Alertas para marcar host riesgoso
```

---

## Ejemplos de Uso en Servidor

### Ejecución Programada con Task Scheduler

**Script wrapper** (`C:\Scripts\Run-DefenderReport.ps1`):

```powershell
#Requires -Version 5.1

# Cargar secreto desde archivo encriptado
$SecureSecret = Get-Content 'C:\Config\DefenderSecret.txt' | ConvertTo-SecureString

# Ejecutar reporte
& 'C:\Scripts\New-DefenderXDRWeeklyReport.ps1' `
    -TenantId "12345678-1234-1234-1234-123456789abc" `
    -ClientId "87654321-4321-4321-4321-abcdef123456" `
    -AuthMode Secret `
    -ClientSecret $SecureSecret `
    -TimeWindowDays 7 `
    -OutputPath "C:\Reports\Weekly\DefenderXDR_$(Get-Date -Format 'yyyyMMdd').html" `
    -ExportCsv `
    -UseParallel `
    -LogPath "C:\Reports\Logs\DefenderXDR_$(Get-Date -Format 'yyyyMMdd').log" `
    -SendMail `
    -SmtpServer "smtp.office365.com" `
    -To "soc-team@empresa.com" `
    -Subject "Defender XDR - Reporte Semanal $(Get-Date -Format 'dd/MM/yyyy')"

# Limpiar reportes antiguos (mantener últimos 30 días)
Get-ChildItem 'C:\Reports\Weekly\*.html' | 
    Where-Object LastWriteTime -lt (Get-Date).AddDays(-30) | 
    Remove-Item -Force
```

**Crear Tarea Programada:**

```powershell
$Action = New-ScheduledTaskAction -Execute 'PowerShell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Run-DefenderReport.ps1"'

$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 7am

$Principal = New-ScheduledTaskPrincipal -UserId "DOMAIN\ServiceAccount" `
    -LogonType Password -RunLevel Highest

Register-ScheduledTask -TaskName "DefenderXDR-WeeklyReport" `
    -Action $Action -Trigger $Trigger -Principal $Principal `
    -Description "Genera reporte semanal de Defender XDR"
```

---

### Ejecución Manual Rápida

```powershell
# Con Device Code (interactivo, para primera ejecución)
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -AuthMode DeviceCode

# Con Secret (automatizado)
$Secret = Get-Content 'C:\Config\DefenderSecret.txt' | ConvertTo-SecureString
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -AuthMode Secret `
    -ClientSecret $Secret `
    -UseParallel `
    -ExportCsv
```

---

## Troubleshooting

### Error: "Authentication failed"
```powershell
# Verificar permisos de la App Registration:
# - AdvancedHunting.Read.All (Application permission)
# - Asegurarse que está granted y con admin consent

# Limpia cache de token
Remove-Item "$env:TEMP\DefenderXDR_TokenCache.xml" -Force
```

### Error: "Query exceeded max retries"
```powershell
# Aumentar timeout y reintentos temporalmente
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "xxx" `
    -ClientId "yyy" `
    -TimeoutSec 300 `
    -UseParallel:$false
```

### Logs no se generan
```powershell
# Crear directorio manualmente
New-Item -ItemType Directory -Path "C:\Reports\Logs" -Force

# Verificar permisos de escritura
Test-Path "C:\Reports\Logs" -PathType Container
```

---

## Próximas Mejoras Recomendadas

1. **Integración con SIEM**: Exportar JSON para Sentinel/Splunk
2. **Power BI Dataset**: Generar archivo para dashboard
3. **Alertas Proactivas**: Enviar email solo si Critical Status
4. **Comparación Histórica en HTML**: Mostrar gráficos de tendencia
5. **Multi-Tenant**: Soportar múltiples tenants en una ejecución

---

## Cambios no Implementados (Requieren Dependencias Externas)

❌ Azure Key Vault (requiere módulo Az.KeyVault)  
❌ Gráficos Chart.js embebidos (requieren CDN/internet)  
❌ Módulos separados .psm1 (mantener script único para portabilidad)  
❌ Tests Pester (requieren módulo Pester)  

---

## Compatibilidad

- ✅ PowerShell 5.1 (Windows Server 2016+)
- ✅ PowerShell 7+ (Parallelismo mejorado)
- ✅ Windows Server Core
- ✅ Sin dependencias de módulos externos (excepto Az.Accounts para AuthMode Interactive)
- ✅ DPAPI nativo para encriptación local

---

**Última actualización:** 2026-02-12  
**Versión script:** 2.0  
**Autor:** MDO Security Operations
