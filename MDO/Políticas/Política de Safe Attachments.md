# Paso a paso para crear una política de Safe Attachments
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*
**Safe Attachments** forma parte de **Microsoft Defender for Office 365 Plan 1 o Plan 2** y proporciona protección avanzada contra malware mediante análisis en sandbox (“detonación”) antes de entregar los archivos a los usuarios.

---

## 1. Verifica que tienes permisos adecuados

Debes contar con alguno de estos roles:

- **Security Administrator**
- **Global Administrator**
- **Security Operator**

> Si ya administras Defender en tu tenant, es muy probable que ya cuentes con alguno de estos permisos.

---

## 2. Creación de la política Safe Attachments

### 2.1 Acceso al portal

1. Ir a:  
    https://security.microsoft.com/safeattachmentv2

2. Antes de crear la política, valida que estén habilitadas las siguientes opciones:
   - **Defender for Office 365 for SharePoint, OneDrive, and Microsoft Teams**
   - **Turn on Safe Documents for Office clients**

3. Haz clic en **Global settings**.

4. Valida que:
   -  Defender for Office 365 for SharePoint, OneDrive, and Microsoft Teams esté **encendido**
   -  Turn on Safe Documents for Office clients esté **encendido**

---

### 2.2 Creación de la política

5. Haz clic en **+ Create**.

6. En **Name your policy**:
   - Asigna un nombre claro, por ejemplo:
     - `Safe Attachments - Protección Estándar`
     - `Safe Attachments - Ejecutivos Críticos (VIP)`
   - En **Description**, agrega un breve resumen de la política.

7. Haz clic en **Next**.

---

### 2.3 Selección de usuarios y dominios

8. En **Users and domains**, selecciona según el caso:

- **Users**
  - Si la política va dirigida a uno o varios usuarios específicos.
- **Groups**
  - Si va dirigida a un grupo de usuarios, por ejemplo **Ejecutivos Críticos (VIP)**.
- **Domains**
  - Puedes agregar todos los **accepted domains** del tenant.

9. Haz clic en **Next**.

---

### 2.4 Configuración de acciones (Settings)

10. En **Settings**, define las acciones de la política.  
   >  Esta sección es crítica y debe revisarse cuidadosamente.

11. Selecciona **Dynamic Delivery** o **Block**.

12. Modos disponibles:

| Modo              | Recomendado | Motivo |
|-------------------|-------------|--------|
| Monitor           |  No        | No bloquea, solo reporta. |
| Block             |  Bueno     | Bloquea archivos maliciosos. |
| Replace           |  Bueno     | Reemplaza el adjunto malicioso por un mensaje seguro. |
| Dynamic Delivery  |  Recomendado | Entrega el correo inmediatamente y agrega el adjunto solo si es seguro. |

**Selecciona: `Dynamic Delivery` (best practice Zero Trust)**

13. Haz clic en **Next**.

---

### 2.5 Revisión y creación

14. Microsoft Defender mostrará un resumen de la configuración.

15. Valida cuidadosamente las opciones y presiona **Submit**.

16. **¡Listo!** La política entra en vigor de inmediato.

