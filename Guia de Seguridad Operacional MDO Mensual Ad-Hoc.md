# 🏹 Guía de Hunting Proactivo en Microsoft Defender for Office 365

Esta guía detalla los procedimientos para la búsqueda proactiva de amenazas, análisis de detecciones y remediación en el entorno de Microsoft Defender for Office 365 (MDO).

---

## 1. 🛠️ Acceso a las Herramientas de Hunting

Utilizarás dos portales principales para la investigación:

### A. Threat Explorer
*   **URL:** [security.microsoft.com/threatexplorer](https://security.microsoft.com/threatexplorer)
*   **Uso:** Visualizar detecciones en tiempo real, correos maliciosos, actividades posteriores a la entrega y patrones de amenaza.

### B. Advanced Hunting
*   **URL:** [security.microsoft.com/v2/advanced-hunting](https://security.microsoft.com/v2/advanced-hunting)
*   **Uso:** Entorno de cacería basado en consultas usando **KQL (Kusto Query Language)** para análisis profundo.

---

## 2. 🔍 Realizar Cacería Manual de Amenazas

### Buscar Indicadores de Compromiso (IoCs)
En **Threat Explorer** puedes:
*   Filtrar correos o artefactos por remitente, archivo, URL, familia de malware, campañas o tiempo de entrega.
*   Ajustar el rango de fechas (hasta 30 días) para identificar patrones.

### Usar Consultas de Advanced Hunting
En **Advanced Hunting**, ejecuta consultas KQL para identificar:
*   Flujos de correo anómalos.
*   URLs o adjuntos sospechosos.
*   Comportamientos de compromiso de usuarios.
*   Desviaciones en tendencias históricas.

---

## 3. 📡 Utilizar Threat Trackers

Usa **Threat Trackers** para monitorear:
*   Campañas de malware emergentes.
*   Exploits *zero‑day*.
*   Amenazas específicas por industria.

> **Tip:** Esto permite orientar la cacería y priorizar adecuadamente los esfuerzos del SOC.

---

## 4. 🤝 Compartir y Reutilizar Consultas

Para mejorar la eficiencia del equipo de seguridad:
*   Comparte consultas KQL usadas frecuentemente.
*   Construye una biblioteca de hunting del equipo.
*   Utiliza la función **Shared Queries** dentro de Advanced Hunting.

---

## 5. 🚨 Crear Reglas de Detección Personalizadas

Convierte tus hallazgos de hunting manual en alertas automáticas.

1.  **Navegar a Custom Detections:** [security.microsoft.com/custom_detection](https://security.microsoft.com/custom_detection)
2.  **Construir una Regla:**
    *   Pega tu consulta de Advanced Hunting validada.
    *   Define la lógica de alerta (frecuencia, umbral, entidades afectadas).
    *   Asigna acciones automáticas (ej. aislar dispositivo, suspender usuario, borrar correo).

---

## 6. 🤖 Revisión y Remediación con AIR

Si el hunting revela actividad sospechosa:
*   Activa alertas de **Automated Investigation and Response (AIR)**.
*   AIR evalúa la evidencia, amplía el alcance de la investigación y sugiere acciones de remediación.

---

# 🛡️ Gestión de Spoofing e Impersonation

Procedimientos para revisar y ajustar las políticas de inteligencia contra suplantación.

## 1. Revisar Detecciones de Spoofing (Spoof Intelligence Insight)

Microsoft 365 detecta automáticamente remitentes que parecen ser de tu organización o dominios externos, pero fallan las validaciones SPF/DKIM/DMARC.

### Pasos de Revisión:
1.  **Abrir Insight:** Ir a [Spoof Intelligence Insight](https://security.microsoft.com/spoofintelligence) y revisar los últimos 7 días.
2.  **Analizar cada remitente:**
    *   **Legítimo:** Apps internas, proveedores autorizados, listas de correo (mailing lists).
    *   **Malicioso:** Dominios desconocidos, fallos de autenticación sin justificación.
3.  **Decisión (Action):**
    *   ✅ **Allow:** Si es legítimo (evita falsos positivos).
    *   🚫 **Block:** Si es malicioso o sospechoso.
4.  **Documentar:** Registra fecha, remitente, razón y el impacto esperado.

> **Nota:** Las acciones se reflejan en la *Tenant Allow/Block List*.

## 2. Analizar Impersonation Insight

### Pasos de Revisión:
1.  **Abrir Insight:** Ir a [Impersonation Insight](https://security.microsoft.com/impersonationinsight).
2.  **Domain Impersonation:**
    *   Busca cambios sutiles en dominios (typosquatting).
    *   Revisa el volumen y los usuarios objetivo.
3.  **User Impersonation:**
    *   Evalúa diferencias en alias vs. nombres reales.
    *   Identifica objetivos de alto valor (VIPs: Ejecutivos, Finanzas, RRHH).
4.  **Validar Políticas:**
    *   Asegura que los dominios y usuarios afectados estén cubiertos por las políticas Anti-Phishing.

## 3. Acciones Recomendadas

### Para Spoofing
*   **Allow** si es remitente legítimo.
*   **Block** si hay riesgo (BEC, cuentas comprometidas).
*   **Remediación:** Reforzar registros DNS (SPF/DKIM/DMARC) del dominio afectado.

### Para Impersonación
*   **Ajustar Anti-Phishing Policy:**
    *   Agregar dominios confiables.
    *   Agregar usuarios protegidos (VIPs).
    *   Ajustar el umbral de phishing (*phishing threshold*).
*   **Hunting Adicional:** Buscar variaciones del dominio y actividad anómala en los usuarios atacados.