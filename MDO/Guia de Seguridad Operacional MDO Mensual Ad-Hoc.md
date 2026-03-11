# 🛡️ Guía de Seguridad Operacional Mensual/Ad-Hoc: Microsoft Defender for Office 365

## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

Esta guía establece los procedimientos mensual/Ad-Hoc para analizar tendencias, identificar usuarios de alto riesgo y gestionar campañas de amenazas en Microsoft Defender for Office 365 (MDO).

---
## Índice
- [Acceso a las Herramientas de Hunting](#acceso-a-las-herramientas-de-hunting)
- [Gestión de Spoofing e Impersonation](#gestión-de-spoofing-e-impersonation)
- [Borrar Correos Sospechosos en Exchange Online (Ad-Hoc)](#borrar-correos-sospechosos-en-exchange-online-ad-hoc)
- [Detección histórica de Direct Send (Ad-Hoc)](#detección-histórica-de-direct-send-ad-hoc)
- [Revisar las políticas de Microsoft Defender for Office 365](#revision-de-políticas-de-microsoft-defender-for-office-365)

---

# Acceso a las Herramientas de Hunting

Utilizarás dos portales principales para la investigación:

### A. Threat Explorer
*   **URL:** [security.microsoft.com/threatexplorer](https://security.microsoft.com/threatexplorer)
*   **Uso:** Visualizar detecciones en tiempo real, correos maliciosos, actividades posteriores a la entrega y patrones de amenaza.

### B. Advanced Hunting
*   **URL:** [security.microsoft.com/v2/advanced-hunting](https://security.microsoft.com/v2/advanced-hunting)
*   **Uso:** Entorno de cacería basado en consultas usando **KQL (Kusto Query Language)** para análisis profundo.

---

## Realizar Cacería Manual de Amenazas

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

## Utilizar Threat Trackers

Usa **Threat Trackers** para monitorear:
*   Campañas de malware emergentes.
*   Exploits *zero‑day*.
*   Amenazas específicas por industria.

> **Tip:** Esto permite orientar la cacería y priorizar adecuadamente los esfuerzos del SOC.

---

## Compartir y Reutilizar Consultas

Para mejorar la eficiencia del equipo de seguridad:
*   Comparte consultas KQL usadas frecuentemente.
*   Construye una biblioteca de hunting del equipo.
*   Utiliza la función **Shared Queries** dentro de Advanced Hunting.

---

## Crear Reglas de Detección Personalizadas

Convierte tus hallazgos de hunting manual en alertas automáticas.

1.  **Navegar a Custom Detections:** [security.microsoft.com/custom_detection](https://security.microsoft.com/custom_detection)
2.  **Construir una Regla:**
    *   Pega tu consulta de Advanced Hunting validada.
    *   Define la lógica de alerta (frecuencia, umbral, entidades afectadas).
    *   Asigna acciones automáticas (ej. aislar dispositivo, suspender usuario, borrar correo).

---

## Revisión y Remediación con AIR

Si el hunting revela actividad sospechosa:
*   Activa alertas de **Automated Investigation and Response (AIR)**.
*   AIR evalúa la evidencia, amplía el alcance de la investigación y sugiere acciones de remediación.

---

# Gestión de Spoofing e Impersonation

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
---

# Borrar Correos Sospechosos en Exchange Online (Ad-Hoc)

## Opción A (RECOMENDADA): Portal Microsoft 365 Defender

### Prerrequisitos
- Rol: Security Administrator / Compliance Administrator / Global Administrator

### Pasos
1. https://security.microsoft.com/threatexplorerv3
2. Definir rango de fechas
3. Buscar por Subject, Sender, IP, Message ID, URL, Hash
4. Validar resultados
5. **Take action** → Move or delete
6. Soft Delete (recomendado) o Hard Delete
7. Monitorear:
   - https://security.microsoft.com/action-center/history

### Prevención posterior
- Bloquear sender
- Bloquear URLs
- Ajustar políticas
- Verificar SPF / DKIM / DMARC

---

## Opción B: PowerShell (Compliance Search) 
### Útil para IR avanzada, scripting o automatización

### Conectar
```
Connect-IPPSSession
```

### Crear búsqueda
```
New-ComplianceSearch  -Name "Purge-Phishing-25022026"  -ExchangeLocation All  -ContentMatchQuery 'Subject:"Factura pendiente"'
```

### Ejecutar
```
Start-ComplianceSearch -Identity "Purge-Phishing-25022026"
```

### Purgar
**Soft Delete**
```
New-ComplianceSearchAction  -SearchName "Purge-Phishing-25022026"  -Purge -PurgeType SoftDelete
```

**Hard Delete (casos críticos)**
```
New-ComplianceSearchAction  -SearchName "Purge-Phishing-25022026"  -Purge -PurgeType HardDelete
```

---

## Buenas Prácticas Clave
- Usar SoftDelete primero
- Validar resultados
- Documentar criterios, fecha e impacto
- Combinar con bloqueos y DMARC enforcement
- No purgar sin validación
- HardDelete solo con aprobación IR/Legal


---


# Detección histórica de Direct Send (Ad-Hoc)

## 1. Correos internos anónimos (indicador Direct Send)

```kql
EmailEvents
| where SenderFromDomain == RecipientEmailDomain
| where isempty(ConnectorId)
| where isempty(AuthenticationDetails)
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, SenderIPv4, Subject
```

## 2. Intentos bloqueados por RejectDirectSend

```kql
EmailEvents
| where ActionType == "Reject"
| where ErrorCode has "5.7.68"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, SenderIPv4, ErrorCode
```

## 3. Top IPs intentando Direct Send

```kql
EmailEvents
| where SenderFromDomain == RecipientEmailDomain
| where isempty(ConnectorId)
| summarize Attempts=count() by SenderIPv4
| order by Attempts desc
```

---
# Revision de políticas de Microsoft Defender for Office 365

## Opción 1, ejecutar script de validación: [MDO/Scripts/Validate-MDOPolicies.ps1](https://github.com/watchdogcode/gol2026/blob/main/MDO/Scripts/Validate-MDOPolicies.ps1)

## Opción 2, paso a paso:

### 1. Acceder al portal correcto de Microsoft Defender for Office 365 (MDO)

1. Abre el portal de Microsoft Defender:
   - https://security.microsoft.com

2. Navega a la siguiente ruta:
   - **Email & collaboration**
   - **Policies & rules**
   - **Threat policies**
   - **Safe Attachments**

👉 **Acceso directo:**
- https://security.microsoft.com/safeattachmentv2

---

## 2. Identificar todas las políticas de Safe Attachments existentes

En la vista principal de **Safe Attachments**, revisa los siguientes campos:

- **Name**: Nombre de la política  
- **Status**: On / Off  
- **Priority**: Orden de aplicación  

### Acciones disponibles:
- Buscar políticas por nombre  
- Exportar la lista de políticas a CSV  
- Abrir el **Threat protection status report**

---

## 3. Distinguir el tipo de políticas (crítico para la revisión)

Valida qué tipo de políticas existen en el tenant:

### Tipos de políticas:
1. **Preset Security Policies**
   - Strict Preset Security Policy  
   - Standard Preset Security Policy  

2. **Built‑in protection (Microsoft)**

3. **Custom Safe Attachments policies**

⚠️ **Importante:**
- Las políticas **Preset** y **Built‑in** **no se pueden editar directamente** desde Safe Attachments.
- **Solo las políticas Custom** pueden modificarse desde esta sección.

Referencia:
- Microsoft Learn – Set up Safe Attachments policies

---

## 4. Revisar el detalle de una política específica

1. Haz clic sobre el **nombre de la política** (no el checkbox).
2. Se abrirá el **panel de detalles (details flyout)**.

Revisa cuidadosamente los siguientes apartados:

---

### a) Alcance (Users and domains)

Verifica a quién aplica la política:

- Usuarios  
- Grupos  
- Dominios  
- Exclusiones (**exceptions**)

✅ Validaciones clave:
- Si la política aplica a **todos los usuarios**
- Si existen **excepciones críticas** (por ejemplo: ejecutivos, cuentas sin licencia, cuentas técnicas)

---

### b) Configuración de protección (Settings)

Valida explícitamente los siguientes parámetros:

- **Safe Attachments unknown malware response**
  - Off  
  - Monitor  
  - Block *(valor por defecto y recomendado en Standard / Strict)*

- **Dynamic Delivery**

- **Quarantine policy**
  - Valor por defecto: `AdminOnlyAccessPolicy`

- **Redirect messages**
  - Solo disponible si la política está en **Monitor**

---

## 5. Verificar el orden de precedencia (Priority)

Revisa el orden exacto de aplicación de las políticas:

1. **Strict Preset Security Policy** (si está habilitada)
2. **Standard Preset Security Policy**
3. **Custom policies**  
   - *Priority 0 = mayor prioridad*
4. **Built‑in protection (Microsoft)**  
   - *Lowest priority, no modificable*

⚠️ **Nota crítica:**
- Safe Attachments **se detiene en la primera política que aplica al destinatario**.

---

## 6. Confirmar estado de habilitación

### Para políticas Custom:
- Verifica que el **Status** esté en **On**
- Desde el panel de detalles:
  - **Turn on / Turn off**
- Desde la vista de lista:
  - **More actions > Enable / Disable selected policies**

### Para políticas Preset:
- Se gestionan exclusivamente desde:
  - https://security.microsoft.com/presetSecurityPolicies