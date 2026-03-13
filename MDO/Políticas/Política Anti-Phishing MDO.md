# Paso a paso para crear una política Anti-Phishing en MDO 🛡️
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

Una **política Anti‑phishing en Microsoft Defender for Office 365 detecta y bloquea correos diseñados para engañar al usuario**, incluso cuando el mensaje **parece legítimo** y no contiene malware evidente

---
1. Ir a: https://security.microsoft.com/antiphishing
2. Haz clic en **Create**
3. En la sección **Policy name**:
   - **Name**: Anti‑Phishing – BEC Protection
   - **Description**: Protección contra BEC con impersonation para Ejecutivos, Finanzas y Legal
4. Haz clic en **Next**
5. En la sección **Users, groups, and domains**:
   - Aplica la política a:
     - **Dominios**
       - Agrega todos tus dominios
   - Evita exclusiones salvo casos muy justificados
6. Haz clic en **Next**
7. En la sección **Phishing threshold & protection**:
   - En **Phishing email threshold**, configura el slider en:
     - **3 – More aggressive**
       - Incrementa la sensibilidad para detectar phishing dirigido y BEC
8. Configura **Impersonation**:
   - Habilita **Enable users to protect**
   - Haz clic en **Manage sender(s)**
     - Agrega usuarios (Nombre + correo):
       - Ejecutivos (CEO, CFO, COO, etc.)
       - Usuarios de Finanzas
       - Usuarios de Legal
     - Máximo: **350 usuarios por política**
   - Finaliza con **Done**
9. Habilita **protección de dominios**:
   - Marca **Include the domains I own**
   - Marca **Include custom domains**
     - En **Manage custom domains**, agrega:
       - Bancos
       - Proveedores clave
       - Partners estratégicos
10. **Mailbox Intelligence (Obligatorio)**:
    - Enable mailbox intelligence
    - Enable intelligence for impersonation protection

    > Detecta secuestro de hilos y comportamiento anómalo incluso sin spoofing clásico

11. En **Spoof Intelligence**:
    - Verifica que esté habilitado **Enable spoof intelligence**
12. Haz clic en **Next**
13. En la sección **Acciones**
14. Configura **Message action**:
    - User impersonation → **Quarantine the message**
      - Quarantine policy: `DefaultFullAccessPolicy` (o política SOC dedicada)
    - Domain impersonation → **Quarantine the message**
      - Quarantine policy: `DefaultFullAccessPolicy` (o política SOC dedicada)
    - Selecciona **Honor DMARC record policy**
    - Spoof + DMARC `p=quarantine` → **Quarantine the message**
    - Spoof + DMARC `p=reject` → **Reject the message**
    - Spoof by spoof intelligence → **Quarantine the message**
15. En **Safety Tips & Indicators**, habilita:
    - Show first contact safety tip
    - Show user impersonation safety tip
    - Show domain impersonation safety tip
    - Show user impersonation unusual characters safety tip
    - Show ? for unauthenticated sender for spoof
    - Show "via" tag
16. Haz clic en **Next** y **Submit**