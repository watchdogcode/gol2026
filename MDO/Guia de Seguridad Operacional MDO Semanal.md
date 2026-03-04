# 🛡️ Guía de Seguridad Operacional Semanal: Microsoft Defender for Office 365

Esta guía establece los procedimientos semanales para analizar tendencias, identificar usuarios de alto riesgo y gestionar campañas de amenazas en Microsoft Defender for Office 365 (MDO).

---

## Índice
- [Revisar Tendencias de Detección de Correo en Microsoft Defender for Office 365](https://github.com/watchdogcode/gol2026/blob/main/MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md#revisar-tendencias-de-detecci%C3%B3n-de-correo-en-microsoft-defender-for-office-365)
- [Identificar Usuarios Más Atacados por Malware y Phishing](https://github.com/watchdogcode/gol2026/blob/main/MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md#identificar-usuarios-m%C3%A1s-atacados-por-malware-y-phishing)
- [Revisar Campañas de Malware y Phishing](https://github.com/watchdogcode/gol2026/blob/main/MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md#revisar-campa%C3%B1as-de-malware-y-phishing)
-[Validar correos entregados con amenazas](https://github.com/watchdogcode/gol2026/blob/main/MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md#validar-correos-entregados-con-amenazas)

---
# Revisar Tendencias de Detección de Correo en Microsoft Defender for Office 365

### Email & Collaboration Reporting

### Acceso al reporte principal
1. Ir a: https://security.microsoft.com/emailandcollabreport
2. Seleccionar **Threat protection status report**

El panel muestra gráficas de tendencias para:
- Detecciones de malware
- Detecciones de phishing
- Detecciones de spam
- Veredictos de URLs y adjuntos
- Acciones de políticas (bloqueado, entregado, ZAP)

---

## Ajustar Filtros para Analizar Tendencias

Utiliza la barra de filtros superior:
- **Time range**: 24 horas, 7 días, 30 días, 90 días
- **Detection type**: Malware, Phish, Spam, High‑confidence Phish
- **Delivery location**: Inbox, Junk, Quarantine, Removed
- **Workload**: Exchange Online, Teams, SharePoint, OneDrive

Esto permite aislar anomalías y comparar periodos.

---

## Profundizar en Categorías Específicas

Al seleccionar un punto de la gráfica se muestra detalle con:
- Message IDs
- IP / dominio del remitente
- Políticas activadas
- Acciones ejecutadas (Blocked, Quarantine, ZAP)
- Usuarios impactados

Útil para identificar campañas y fallas de configuración.

---

## Revisar Reportes de Email Security

Desde **Email & collaboration reports**:

### Mail Latency Report
- Vista agregada de latencia de entrega y detonación.

### Post-delivery Activities Report
- Mensajes eliminados tras la entrega mediante ZAP.

### Threat Protection Status Report
- Vista unificada de amenazas detectadas y bloqueadas.

### Top Senders and Recipients Report
- Principales remitentes y destinatarios.

### URL Protection Report
- Tendencias y acciones de Safe Links.

---

## Otros Reportes vía PowerShell

- **Top senders / recipients**: [Get-MailTrafficSummaryReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-mailtrafficsummaryreport?view=exchange-ps)
- **Top malware**: [Get-MailTrafficSummaryReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-mailtrafficsummaryreport?view=exchange-ps)
- **Threat protection status**: [Get-MailTrafficATPReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-mailtrafficatpreport?view=exchange-ps)
- **Threat protection status**: [Get-MailDetailATPReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-maildetailatpreport?view=exchange-ps)
- **Safe Links**: [Get-SafeLinksAggregateReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-safelinksaggregatereport?view=exchange-ps)
- **Safe Links**: [Get-SafeLinksDetailReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-safelinksdetailreport?view=exchange-ps)
- **Compromised users**: [Get-CompromisedUserAggregateReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-compromiseduseraggregatereport?view=exchange-ps)
- **Compromised users**: [Get-CompromisedUserDetailReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-compromiseduserdetailreport?view=exchange-ps)
- **Mail flow status**: [Get-MailflowStatusReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-mailflowstatusreport?view=exchange-ps)
- **Spoofed users**: [Get-SpoofMailReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-spoofmailreport?view=exchange-ps)
- **Post-delivery activity**: [Get-AggregateZapReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-aggregatezapreport?view=exchange-ps)
- **Post-delivery activity**: [Get-DetailZapReport](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-detailzapreport?view=exchange-ps)

Referencia: [*View Defender for Office 365 reports in the Microsoft Defender portal*](https://learn.microsoft.com/en-us/defender-office-365/reports-defender-for-office-365)

---

## Exportar Datos para Análisis

Los reportes permiten:
- Exportar a CSV
- Exportar gráficas como imagen
- Abrir en Advanced Hunting (KQL)

Usos comunes:
- Revisiones semanales SOC
- KPIs
- Resúmenes ejecutivos
- Líneas base de tendencias

---

# Identificar Usuarios Más Atacados por Malware y Phishing

## Threat Protection Status Report

1. Acceder a: https://security.microsoft.com/emailandcollabreport
2. Seleccionar **Threat Protection Status Report**

Muestra:
- Malware detectado
- Intentos de phishing
- Spoofing / impersonación
- Mensajes bloqueados o en cuarentena
- Acciones ZAP

---

## Filtrar por Tipo de Amenaza

### Malware
- Threat Type → Malware
- Revisar columnas Recipient, Detection Technology y Action Taken

### Phishing
- Threat Type → Phishing
- Revisar spoofing, impersonation y acciones

---

## Identificar Top Targets

1. Ir a **Top targeted recipients**
2. Ordenar por número de detecciones
3. Exportar resultados si es necesario

---

## Correlación con Otros Reportes

- **Compromised Users Report**
- **Top Malware Report**
- **Spoof / Impersonation Reports**

---

## Análisis SOC Recomendado

Para cada usuario:
- Validar rol sensible
- Revisar clics, reportes y fallos de autenticación
- Verificar políticas de protección y MFA
- Revisar incidentes correlacionados

---

## Acciones Derivadas (Runbook Rápido)

- Notificar al usuario
- Entrenamiento anti-phishing dirigido
- Revisar reglas sospechosas
- Endurecer políticas
- Investigar dominios y URLs

---

# Revisar Campañas de Malware y Phishing

## Acceso a Campaigns

1. Ir a: https://security.microsoft.com/threatexplorerv3
2. Seleccionar **Campaigns** (Plan 2)

---

## Análisis de Campañas

Microsoft agrupa campañas según:
- Fuente del ataque
- Contenido del mensaje
- Relación entre destinatarios
- Payloads maliciosos

---

## Top Malware Campaigns

- Filtrar por Threat Type: Malware
- Ordenar por impacto
- Revisar adjuntos, familias, origen y acciones automáticas

---

## Top Phishing Campaigns

- Filtrar por Phishing
- Analizar narrativa, payload y usuarios objetivo

---

## Vista Detallada de Campaña

Incluye:
- Attack source
- Payload
- Recipients
- Timeline

---

## Acciones SOC desde Campaigns

- Correlacionar incidentes
- Priorizar respuesta
- Endurecer postura defensiva
- Revisar movimientos posteriores
---

# Validar correos entregados con amenazas

## Acceder a Advanced Hunting
1. Ir a https://security.microsoft.com/v2/advanced-hunting

---

## Identificar correos entregados con detección de amenaza
**Objetivo:** confirmar correos que **NO fueron bloqueados** y llegaron al buzón del usuario.

### Query base (imprescindible)
```kql
EmailEvents
| where DeliveryAction == "Delivered"
| where ThreatTypes != ""
| project
    Timestamp,
    NetworkMessageId,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    ThreatTypes,
    DetectionMethods,
    ConfidenceLevel,
    DeliveryLocation
| order by Timestamp desc
```

### 🔍 Qué valida esta consulta
- ✅ El correo **sí se entregó**
- ✅ Defender detectó **algún tipo de amenaza**
- ✅ Puedes ver **qué tipo** y **cómo fue detectada**

---

## Validar tipo de amenaza entregada
Para entender qué se escapó, filtra por tipo:

### Malware
```kql
| where ThreatTypes has "Malware"
```

### Phishing
```kql
| where ThreatTypes has "Phish"
```

### Spam de alto riesgo
```kql
| where ThreatTypes has "Spam"
```

---

## Confirmar si fue Safe Attachments o Safe Links

### Adjuntos maliciosos entregados
```kql
EmailAttachmentInfo
| where MalwareFilterVerdict != "Clean"
| project
    Timestamp,
    NetworkMessageId,
    FileName,
    MalwareFilterVerdict,
    DetectionMethods
```

### Enlaces maliciosos entregados
```kql
EmailUrlInfo
| where UrlThreatType != "None"
| project
    Timestamp,
    NetworkMessageId,
    Url,
    UrlThreatType,
    DetectionMethods
```
