# 🛡️ Guía de Seguridad Operacional Semanal: Microsoft Defender for Office 365

Esta guía establece los procedimientos semanales para analizar tendencias, identificar usuarios de alto riesgo y gestionar campañas de amenazas en Microsoft Defender for Office 365 (MDO).

---

## 1. 📈 Análisis de Tendencias de Detección

### A. Revisar el "Threat Protection Status Report"
Este es el reporte principal para evaluar la eficacia de las políticas de seguridad.

1.  **Navegar a:** `Email & collaboration` > `Reports` > `Threat protection status`.
2.  **Analizar las gráficas:**
    *   Detecciones de Malware, Phishing y Spam.
    *   Veredictos de URLs y adjuntos.
    *   Acciones de políticas (Bloqueado, Entregado, ZAP).

### B. Ajustar Filtros y Profundizar
Utiliza la barra superior para refinar la investigación:
*   **Time range:** Comparar últimos 7 días vs 30 días.
*   **Detection type:** Filtrar por `Phish` o `High-confidence Phish`.
*   **Drill-down:** Al hacer clic en un pico de la gráfica, se abre una vista detallada con:
    *   IDs de mensajes.
    *   IP/Dominio del remitente.
    *   Usuarios impactados.

---

## 2. 📑 Reportes de Seguridad Adicionales

Revisa estos reportes complementarios en la sección de **Email & collaboration reports**:

| Reporte | Descripción |
| :--- | :--- |
| **Mail latency report** | Vista agregada de la latencia de entrega y detonación. |
| **Post-delivery activities** | Mensajes eliminados post-entrega mediante ZAP (Zero-Hour Auto Purge). |
| **Top senders and recipients** | Identifica quién envía y recibe más volumen (útil para anomalías). |
| **URL protection report** | Tendencias sobre amenazas detectadas y clics en Safe Links. |

### 💻 Comandos de PowerShell Equivalentes
Si prefieres automatizar la extracción de datos, utiliza estos cmdlets:

```powershell
# Tráfico y Top Senders/Malware
Get-MailTrafficSummaryReport

# Estado de Protección
Get-MailTrafficATPReport
Get-MailDetailATPReport

# Safe Links
Get-SafeLinksAggregateReport
Get-SafeLinksDetailReport

# Usuarios Comprometidos
Get-CompromisedUserAggregateReport
Get-CompromisedUserDetailReport

# Actividad Post-Entrega (ZAP)
Get-AggregateZapReport
Get-DetailZapReport
```

> **Tip:** Exporta los datos a CSV para revisiones semanales del SOC o para establecer líneas base de KPIs.

---

## 3. 🎯 Identificación de Usuarios Más Atacados (Top Targets)

### Pasos para el Análisis
1.  Ir a **Threat Protection Status Report**.
2.  Filtrar por **Threat Type**:
    *   **Malware:** Revisar `Detection Technology` (Anti-malware / Safe Attachments).
    *   **Phishing:** Revisar `Phish detections` y `Spoofing`.
3.  Desplazarse a la tabla **Top targeted recipients** y ordenar por conteo de detecciones.

### 🕵️ Análisis SOC Recomendado
Para cada usuario en el "Top 10":
*   **Validar Rol:** ¿Es VIP (C-Level, Finanzas, RRHH)?
*   **Verificar Interacción:** ¿Hubo clics en enlaces maliciosos o reportes manuales?
*   **Revisar Identidad:** Buscar fallos de autenticación anómalos en los logs de Azure AD.
*   **Postura:** Confirmar que tienen MFA habilitado y políticas estrictas de Safe Links.

### ⚡ Runbook de Respuesta Rápida

| Escenario | Acción SOC Recomendada |
| :--- | :--- |
| **Objetivo repetido (>10 eventos)** | Notificar al usuario y aumentar vigilancia. |
| **Usuario recurrente** | Asignar entrenamiento de simulación de phishing. |
| **Anomalía detectada** | Revisar reglas de transporte o inbox rules sospechosas. |
| **Evasión de controles** | Endurecer políticas Anti-phishing y Safe Links. |
| **Campaña activa** | Investigar dominios/URLs y bloquear en Tenant Allow/Block List. |

---

## 4. 🦠 Análisis de Campañas (Campaigns View)

*Disponible en Defender for Office 365 Plan 2.*

### ¿Qué es una Campaña?
Microsoft agrupa ataques coordinados basándose en la fuente (IPs/Dominios), propiedades del mensaje (contenido/estilo) y payloads (URLs/Archivos).

### Procedimiento de Revisión
1.  **Acceder:** Ir a `Email & collaboration` > `Explorer` > `Campaigns`.
2.  **Identificar Top Malware Campaigns:**
    *   Filtrar `Threat Type` = **Malware**.
    *   Ordenar por `Impacted recipients`.
    *   Analizar: Familia de malware y acciones automáticas (ZAP/Cuarentena).
3.  **Identificar Top Phishing Campaigns:**
    *   Filtrar `Threat Type` = **Phishing**.
    *   Buscar indicadores de **BEC** o **Whaling**.
    *   Analizar: Narrativa del ataque y similitudes entre correos.

### Anatomía de una Campaña
Al abrir una campaña, revisa las 4 dimensiones clave:

1.  **Attack Source:** IPs y dominios de origen.
2.  **Attack Payload:** URLs maliciosas y adjuntos.
3.  **Recipients:** Usuarios y roles afectados.
4.  **Timeline:** Inicio, fin y picos de actividad.

### 🛡️ Acciones de Respuesta

*   **Correlacionar:** Abrir incidentes vinculados y revisar acciones de AIR.
*   **Priorizar:** Contactar inmediatamente a usuarios críticos afectados.
*   **Endurecer:** Bloquear URLs/Dominios y reforzar MFA.
*   **Investigar:** Buscar reglas de reenvío maliciosas o actividad sospechosa en la identidad.