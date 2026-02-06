# 🛡️ Guía de Seguridad Operacional Diaria: Microsoft Defender for Office 365

Esta guía detalla las tareas diarias recomendadas para el monitoreo, triaje y respuesta ante amenazas en el entorno de Microsoft Defender for Office 365 (MDO).

---

## 1. 🚨 Monitoreo de Alertas e Incidentes

### A. Monitoreo de Alertas
**Objetivo:** Identificar y priorizar alertas activas de alta severidad.

1.  **Navegar a:** `Incidents & alerts` > `Alerts`.
2.  **Filtrar:** Usar el botón **Filter** para segregar por Severidad (High/Medium), Servicio o Estado.
3.  **Analizar:** Seleccionar una alerta para ver el panel lateral:
    *   Severidad y Categoría.
    *   Activos impactados (Usuarios/Dispositivos).
    *   Acciones recomendadas.
4.  **Investigar:**
    *   Clic en **View full details**.
    *   Revisar el **Alert Storyline** (línea de tiempo).
    *   Si está disponible, seleccionar **Investigate** para iniciar una investigación automática.

### B. Monitoreo de Incidentes
**Objetivo:** Gestionar ataques correlacionados en lugar de alertas aisladas.

1.  **Navegar a:** `Incidents & alerts` > `Incidents`.
2.  **Configurar Filtros (Vista Diaria):**
    *   **Time range:** Últimas 24 horas.
    *   **Status:** `New` y `In progress`.
    *   **Severity:** Ordenar descendente (High → Low).
3.  **Revisión Rápida:**
    *   Verificar columnas: `Severity`, `Status`, `Assigned to`, `Tags`.
    *   Priorizar incidentes con múltiples alertas correlacionadas.

---

## 2. 💬 Triage de Mensajes de Teams (User Reported)

### A. Prerrequisitos
Asegurar que la función de reporte esté activa:
*   **Teams Admin Center:** `Messaging policies` > `Global` > Activar "Report inappropriate content" y "Report a security concern".
*   **Defender Portal:** `Settings` > `Email & collaboration` > `User reported settings` > Activar monitoreo para Teams.

### B. Ubicación de Mensajes
*   **Opción A (Submissions):** Ir a `Submissions` > `User reported` > Filtrar por **Teams messages**.
*   **Opción B (Incidentes):** Buscar incidentes titulados *"Teams message reported by user as a security risk"*.

### C. Análisis y Acción
1.  **Revisar:** Remitente, contenido, URLs y adjuntos. Consultar el panel de entidad para ver metadatos.
2.  **Clasificar:** Determinar si es Phishing, Spam, Malware o No malicioso.
3.  **Enviar a Microsoft:** Seleccionar **Submit to Microsoft for analysis** (requerido para el feedback loop).
4.  **Remediar:**
    *   Bloquear URLs/Dominios en la *Tenant Allow/Block List*.
    *   Si el mensaje está en cuarentena (ZAP habilitado), decidir si liberar o mantener.
5.  **Cerrar:** Documentar el veredicto en el incidente y notificar al usuario (si está configurado).

---

## 3. 🤖 Investigación y Respuesta Automatizada (AIR)

**Objetivo:** Validar y aprobar acciones de remediación pendientes.

1.  **Navegar a:** `Actions & submissions` > `Action center` > Pestaña **Pending**.
2.  **Revisar Acciones:**
    *   *Soft/Hard delete email*
    *   *Block URL / Sender*
    *   *Turn off external mail forwarding*
3.  **Evaluar Evidencia:**
    *   Clic en la acción para ver **Investigation details** y **Evidence** (capturas, detonaciones).
    *   Verificar **Affected items** (alcance del impacto).
4.  **Decisión:**
    *   ✅ **Approve:** Si la evidencia confirma la amenaza.
    *   ❌ **Reject:** Si es un falso positivo.
5.  **Historial:** Verificar la ejecución en la pestaña **History**.

---

## 4. 📈 Tendencias de Detección de Correo

### A. Mailflow Status Summary
*   **Ubicación:** `Reports` > `Email & collaboration` > `Mailflow status summary`.
*   **Qué buscar:** Volúmenes inusuales de Malware, Phishing o Spam comparado con "Good email".

### B. Threat Protection Status Report
*   **Ubicación:** `Reports` > `Email & collaboration` > `Threat protection status`.
*   **Análisis:**
    *   Revisar desglose por tecnología (Anti-malware, Safe Links, Impersonation).
    *   Filtrar por **Inbound** / **Outbound**.
    *   Identificar picos repentinos o caídas en la eficacia de detección.

> **Recomendación:** Programar este reporte semanalmente (`Create schedule`) para mantener visibilidad constante.

---

## 5. 🎣 Análisis de Campañas (Phishing & Malware)

**Objetivo:** Identificar ataques coordinados que lograron entregar correos (`Delivered`).

1.  **Filtrar (Threat Explorer):**
    *   `Delivery action`: **Delivered**.
    *   `Campaign Type`: **Phish** & **Malware**.
2.  **Priorizar:** Campañas con alto número de usuarios impactados o alta severidad.
3.  **Analizar:**
    *   **Resumen:** Revisar línea de tiempo y totales.
    *   **Usuarios:** Identificar si hay VIPs afectados en `Impacted assets`.
    *   **Muestras:** Abrir un correo para ver encabezados, autenticación (SPF/DKIM) y ruta de entrega.
4.  **Verificar ZAP:** ¿El sistema eliminó el correo post-entrega (ZAP)? Si no, ¿por qué?
5.  **Identificar Brechas:** ¿Qué política falló? (Safe Links, Allow List, Override de usuario).
6.  **Respuesta:**
    *   Purgar correos (Hard delete).
    *   Bloquear remitente/dominio/URL.
    *   Enviar muestra a Microsoft.

---

## 6. 🎯 Usuarios Más Atacados (Top Targets)

**Objetivo:** Proteger a los usuarios que están siendo el foco de los ataques.

1.  **Navegar a:** `Explorer` > Pestaña **Phishing** o **All email**.
2.  **Filtrar:** `Time range`: 24 horas.
3.  **Visualizar:** Seleccionar **Top targeted users** en las estadísticas inferiores.
4.  **Acciones:**
    *   **VIPs:** Agregar a "Priority Accounts".
    *   **Compromiso:** Si hay clics o comportamiento extraño, forzar cambio de contraseña y revisar logs de Azure AD.
    *   **Reglas:** Verificar si se crearon reglas de reenvío sospechosas.