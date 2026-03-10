# Protección contra Business Email Compromise (BEC)

## ¿Qué es BEC?
Business Email Compromise (BEC) es un ataque de fraude dirigido que utiliza correo electrónico y técnicas avanzadas de ingeniería social para engañar a empleados y provocar acciones de negocio con impacto financiero u operativo.

---

# Estrategia de Protección por Capas

## 1. Autenticación del correo
- SPF correctamente configurado
- DKIM habilitado para todos los dominios
- DMARC en modo `reject` o `quarantine`

Objetivo: prevenir suplantación de identidad y spoofing.

---

## 2. Microsoft Defender for Office 365
- Protección contra impersonación (usuarios y dominios)
- Spoof intelligence
- Mailbox intelligence
- Zero-Hour Auto Purge (ZAP)
- Correlación de campañas BEC

Objetivo: detectar BEC incluso sin malware o URLs.



## Anti‑Phishing (BEC‑ready) en Microsoft Defender for Office 365

### Prerrequisitos

- Defender for Office 365 Plan 1 o Plan 2
- Rol: **Security Administrator**, **Exchange Organization Management** o equivalente

---

### Crear política Anti‑Phishing


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



---

### 3. Protección de identidad (Zero Trust)
- MFA obligatorio para todos los usuarios
- MFA resistente a phishing para cuentas críticas
- Conditional Access basado en riesgo
- Revisión periódica de reglas de inbox

Objetivo: prevenir account takeover.

---

### 4. Controles de proceso de negocio
- Doble validación fuera de banda para pagos y cambios bancarios
- Separación de funciones
- Identificación de cuentas prioritarias (Finance, Executives)

Objetivo: reducir el impacto incluso si el correo llega.

---

### 5. Detección y respuesta SOC
- Monitoreo de alertas de impersonación
- Investigación de inbox rules sospechosas
- Uso de Threat Explorer y Advanced Hunting
- Correlación en Defender XDR

Objetivo: detección temprana y contención rápida.

---

### 6. Concientización del usuario
- Attack Simulation Training
- Simulaciones de CEO Fraud y Vendor Fraud
- Métricas de usuarios vulnerables

Objetivo: reducir efectividad de la ingeniería social.

---

## Resumen Ejecutivo

BEC no se detiene con una sola herramienta. Se mitiga combinando identidad fuerte, autenticación de correo, detección avanzada y disciplina operativa.
