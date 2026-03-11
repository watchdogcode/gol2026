# Protección contra Business Email Compromise (BEC)

## ¿Qué es BEC?
Business Email Compromise (BEC) es un ataque de fraude dirigido que utiliza correo electrónico y técnicas avanzadas de ingeniería social para engañar a empleados y provocar acciones de negocio con impacto financiero u operativo.

---

## Estrategia de Protección por Capas

### [1. Autenticación del correo](https://github.com/watchdogcode/gol2026/blob/3.0/MDO/Linea%20base%20proteccion%20contra%20BEC.md#crear-pol%C3%ADtica-antiphishing)
- SPF correctamente configurado
- DKIM habilitado para todos los dominios
- DMARC en modo `reject` o `quarantine`

Objetivo: prevenir suplantación de identidad y spoofing.

---

### [2. Política Anti-Phishing Microsoft Defender for Office 365](https://github.com/watchdogcode/gol2026/blob/3.0/MDO/Linea%20base%20proteccion%20contra%20BEC.md#crear-pol%C3%ADtica-antiphishing)
- Protección contra impersonación (usuarios y dominios)
- Spoof intelligence
- Mailbox intelligence
- Zero-Hour Auto Purge (ZAP)
- Correlación de campañas BEC

Objetivo: detectar BEC incluso sin malware o URLs.


---

### [3. Protección de identidad (Zero Trust)](https://github.com/watchdogcode/gol2026/blob/3.0/MDO/Linea%20base%20proteccion%20contra%20BEC.md#3-protecci%C3%B3n-de-identidad-zero-trust)
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
---
---

# Paso a paso

## Autenticación del correo
### Sender Policy Framework (SPF) 
Autorizar solo a Microsoft 365 (y fuentes explícitas) a enviar correo y rechazar todo lo demás.

**Dónde se configura**
1. En DNS del dominio (registro TXT).
2. Valor recomendado para Microsoft 365
 
 | v=spf1 include:spf.protection.outlook.com -all |

### DKIM
Garantizar integridad del mensaje y alineación DMARC mediante firma digital.

**Dónde se habilita**
1. Ir a https://security.microsoft.com/authentication?viewid=DKIM
2. Selecciona tu dominio personalizado
3. Clic en Create DKIM keys
4. Microsoft generará 2 registros CNAME
5. Publícalos en tu DNS

**Ejemplo de registros DKIM**

| Selector | CNAME |
|---------|------|
| selector1._domainkey.tudominio.com | selector1-tudominio-com._domainkey.tutenant.onmicrosoft.com |
| selector2._domainkey.tudominio.com | selector2-tudominio-com._domainkey.tutenant.onmicrosoft.com |


6. Espera propagación DNS

7. Regresa al portal y habilita: Sign messages for this domain with DKIM signatures



## Crear política Anti‑Phishing

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

## MFA obligatorio para todos – Template oficial

### Paso a paso
1. Ir a: https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies/menuId//fromNav/Identity  
   Selecciona **+ New policy from template**
2. **Categoría:** Secure foundation
3. **Template:** Require multifactor authentication for all users
4. Selecciona **Review + Create**
5. Clic en **Create**
6. Una vez creada, selecciona **Require multifactor authentication for all users**
7. **Users or agents**
   - Include → Grupo piloto (hacer pruebas de validación necesarias)
   - Include → All users (una vez concluida la fase de pruebas se puede agregar a todos o por olas)
   - Exclude →
     - Cuentas de emergencia (break-glass)
     - Cuenta del administrador que está creando la política (temporal, después se remueve)
8. **Targeted resources** (antes *Cloud apps*)
   - All resources (antes *All cloud apps*) – preconfigurado
9. **Grant**
   - Require multifactor authentication – preconfigurado
10. **Enable policy**
   - Report-only → Validar en **Sign-in logs**
   - Después de una semana de análisis → Cambiar a **On**

---

## Phishing-resistant MFA para administradores – Template dedicado

### Paso a paso (Template)
1. Ir a: https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies/menuId//fromNav/Identity
2. **+ New policy from template**
3. **Categoría:** Protect administrators
4. Selecciona: **Require phishing-resistant multifactor authentication for administrators**
5. **Review settings**
   - Target → Directory roles
   - Roles incluidos (predefinidos):
     - Global Administrator
     - Exchange Administrator
     - Security Administrator
     - Conditional Access Administrator
     - Privileged Role Administrator
6. **Grant**
   - Require authentication strength
   - Phishing-resistant MFA – preconfigurado
7. **Exclude**
   - Emergency access accounts
8. **Enable**
   - Report-only → On

> ⚠️ **Advertencia crítica del template**  
> Los administradores deben registrar previamente **FIDO2 / Windows Hello for Business (WHfB)** para evitar *lockout*.

---

## Evaluación de riesgo de inicio de sesión – Template Identity Protection

### Paso a paso
1. Ir a: https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies/menuId//fromNav/Identity
2. **+ New policy from template**
3. **Categoría:** Emerging threats
4. Selecciona: **Require multifactor authentication for risky sign-ins**
5. **Configuración incluida por el template:**
   - Condition → Sign-in risk
     - Medium
     - High
   - Grant → Require MFA
6. **Exclude**
   - Break-glass accounts
7. **Enable**
   - Report-only → On

✅ **Resultado:** Protección adaptativa basada en señales de riesgo de Microsoft.