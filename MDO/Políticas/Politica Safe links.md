# Paso a paso para crear una política de Safe Links enfocada en BEC
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*
Esta configuración fortalece la protección contra URLs maliciosas utilizadas en ataques BEC, especialmente en escenarios de impersonación, secuestro de hilos y fraude de proveedores.

---

## 1. Ir al portal de Microsoft 365 Defender
1. Ir a: https://security.microsoft.com/safelinksv2  
2. Haz clic en: **+ Create**  
3. Asigna un nombre claro, por ejemplo:  
   **Safe Links** o **Safe Links – BEC Protection** (En caso de que la política solo sea para esta función)  
4. Descripción recomendada:  
   *“Protección reforzada de URLs para prevenir fraude tipo BEC, vendor compromise y secuestro de hilos.”*

---

## 2. Name your policy
1. Asigna un nombre claro, por ejemplo:  
   **Safe Links** o **Safe Links – BEC Protection** (En caso de que la política solo sea para esta función)
2. Descripción recomendada:  
   *“Protección reforzada de URLs para prevenir fraude tipo BEC, vendor compromise y secuestro de hilos.”*
3. Click **Next**

---

## 3. Users and domains
1. En **Users, Groups and domains**, selecciona:

Si todos los usuarios tienen una licencia E5 o bien si la organización cuenta con un Plan de MDO, se pueden incluir todos los dominios de la organización.

O usuarios prioritarios (recomendado para BEC):
- Ejecutivos (CEO, CFO, COO)
- Finanzas / Cuentas por pagar
- Legal
- Compras
- Operaciones críticas

Opcional: luego puedes ampliar a **All users**.

---

## 4. URL &amp; click protection settings  
Esta es la parte más importante para BEC.

### Email
1. Marca:
   - **On – Enable Safe Links for email messages**
     - Apply Safe Links to email messages sent within the organization  
     - Apply real-time URL scanning for suspicious links and links that point to files  
       - Wait for URLs scanning to complete before delivering the message  
     - Do not rewrite URLs, do checks via Safe Links API only

---

### Teams
1. Activar:
   - **On:** Safe Links checks a list of known, malicious links when users click links in Microsoft Teams.  
     *URLs are not rewritten.*

---

### Office 365 Apps
1. Activar:
   - **On:** Safe Links checks a list of known, malicious links when users click links in Microsoft Office.  
     *URLs are not rewritten.*

---

### Click protection settings
1. Activar:
   - Track user clicks  
   - Display the organization branding on notification and warning pages

---

## 6. Notification  
**How would you like to notify users?**

1. Activar:
   - Use the default notification text

---

## Finalizar
Hacer clic en **Next** y luego **Submit**.