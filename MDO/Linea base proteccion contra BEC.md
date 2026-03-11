# Protección contra Business Email Compromise (BEC)

## ¿Qué es BEC?
Business Email Compromise (BEC) es un ataque de fraude dirigido que utiliza correo electrónico y técnicas avanzadas de ingeniería social para engañar a empleados y provocar acciones de negocio con impacto financiero u operativo.

---

## Estrategia de Protección por Capas

### [1. Autenticación del correo](https://github.com/watchdogcode/gol2026/blob/3.0/MDO/Linea%20base%20proteccion%20contra%20BEC.md#1-autenticaci%C3%B3n-del-correo-1)
- SPF correctamente configurado
- DKIM habilitado para todos los dominios
- DMARC en modo `reject` o `quarantine`

Objetivo: prevenir suplantación de identidad y spoofing.

---

### [2. Política Anti-Phishing Microsoft Defender for Office 365](https://github.com/watchdogcode/gol2026/blob/3.0/MDO/Linea%20base%20proteccion%20contra%20BEC.md#2-pol%C3%ADtica-anti-phishing-microsoft-defender-for-office-365-1)
- Protección contra impersonación (usuarios y dominios)
- Spoof intelligence
- Mailbox intelligence
- Zero-Hour Auto Purge (ZAP)
- Correlación de campañas BEC

Objetivo: detectar BEC incluso sin malware o URLs.


---

### [3. Protección de identidad (Zero Trust)](https://github.com/watchdogcode/gol2026/blob/3.0/MDO/Linea%20base%20proteccion%20contra%20BEC.md#3-protecci%C3%B3n-de-identidad-zero-trust-1)
- MFA obligatorio para todos los usuarios
- MFA resistente a phishing para cuentas críticas
- Conditional Access basado en riesgo
- Revisión periódica de reglas de inbox

Objetivo: prevenir account takeover.

---

### [4. Controles de proceso de negocio](https://github.com/watchdogcode/gol2026/blob/3.0/MDO/Linea%20base%20proteccion%20contra%20BEC.md#4-controles-de-proceso-de-negocio-1)
- Doble validación fuera de banda para pagos y cambios bancarios
- Separación de funciones
- Identificación de cuentas prioritarias (Finance, Executives)

Objetivo: reducir el impacto incluso si el correo llega.

---

### [5. Detección y respuesta SOC](https://github.com/watchdogcode/gol2026/blob/3.0/MDO/Linea%20base%20proteccion%20contra%20BEC.md#5-detecci%C3%B3n-y-respuesta-soc-1)
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

## 1. Autenticación del correo
### 1.1 SPF (Sender Policy Framework) 
Autorizar solo a Microsoft 365 (y fuentes explícitas) a enviar correo y rechazar todo lo demás.

**Dónde se configura**
1. En DNS del dominio (registro TXT).
2. Valor recomendado para Microsoft 365

| Tipo | Registro | TTL |
|---------|------|------|
| TXT | v=spf1 include:spf.protection.outlook.com -all | 3600 |


### 1.2 DKIM (DomainKeys Identified Mail)
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

### 1.3 DMARC (Domain-based Message Authentication, Reporting & Conformance)

Indicar a los receptores que pongan en cuarentena los correos que fallen SPF y DKIM.

**Dónde se configura**
1. En DNS del dominio (registro TXT _dmarc)
2. Registro DMARC recomendado (Quarantine)

| Tipo | Registro |
|---------|------|
| TXT | v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@tudominio.com; ruf=mailto:dmarc-forensic@tudominio.com; fo=1; aspf=s; adkim=s  |

**Para mayor detalle consultar** [Configuraciones base para Exchange Online](https://github.com/watchdogcode/gol2026/blob/3.0/MDO/L%C3%ADnea%20base%20para%20mejorar%20la%20postura%20de%20seguridad%20en%20Exchange%20online.md#%EF%B8%8F-seguridad-integral-de-correo-electr%C3%B3nico-en-microsoft-365)

---
## 2. Política Anti-Phishing Microsoft Defender for Office 365

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

## 3. Protección de identidad (Zero Trust)

### 3.1 MFA obligatorio para todos – Template oficial

**Paso a paso**
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

### 3.2 Phishing-resistant MFA para administradores – Template dedicado

**Paso a paso (Template)**
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

### 3.3 Evaluación de riesgo de inicio de sesión – Template Identity Protection

**Paso a paso**
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

**Resultado:** Protección adaptativa basada en señales de riesgo de Microsoft.

---

## 4. Controles de proceso de negocio

**Objetivo:** reducir el impacto incluso si el correo malicioso llega al usuario.

**Principio clave:** asumir que el correo puede estar comprometido y diseñar procesos que no dependan del email como mecanismo de autorización.

---

### 4.1 Doble validación fuera de banda (Out-of-Band Verification)

Es un control que obliga a verificar pagos o cambios bancarios usando un canal distinto al correo electrónico, incluso si el mensaje parece legítimo o proviene de una cuenta real.

**¿Por qué es crítico en BEC?**

En muchos ataques BEC:
- El correo es legítimo (cuenta comprometida)
- El mensaje continúa un hilo real
- El tono y firma coinciden

Por diseño, el **email NO puede ser usado como prueba de autenticidad**.

**¿Cuándo se debe aplicar?**

Debe ser **MANDATORIO** para:
- Cambios de cuenta bancaria de proveedores
- Pagos urgentes o fuera de patrón
- Primer pago a un nuevo proveedor
- Pagos solicitados por ejecutivos

**¿Cómo se implementa correctamente?**

**Buenas prácticas:**
- Llamar a un **número previamente registrado** (no el del correo)
- No usar **Teams/Email** como canal de validación
- Documentar la verificación
- Requerir **segunda aprobación** posterior

**Error común:**
- “Confirmar” respondiendo el mismo email  (inútil)

> Este control por sí solo ha prevenido innumerables fraudes financieros documentados.

---

### 4.2 Separación de funciones (Segregation of Duties – SoD)


Es el principio de que **ninguna persona debe poder iniciar, aprobar y ejecutar una transacción crítica por sí sola**.

***¿Por qué es clave contra BEC?***
BEC busca un **único punto de decisión**. Si el proceso permite que una sola persona:
- Reciba el correo
- Cambie datos
- Autorice el pago

El fraude es inmediato.

Separar funciones **obliga a colusión**, lo cual reduce drásticamente el riesgo.

**Modelo mínimo recomendado (pagos)**

| Rol | Responsable |
|---|---|
| Solicita / recibe instrucción | Finanzas / AP |
| Aprueba | Manager / Finance Lead |
| Ejecuta pago | Tesorería |
| Revisa / reconcilia | Control financiero |

**Ejemplos de separación efectiva**
- Quien actualiza datos bancarios **no puede** autorizar pagos
- Quien aprueba pagos **no puede** liberarlos
- Quien libera pagos **no puede** modificar proveedores

> Este modelo está alineado con marcos de control financiero y prevención de fraude.

---

### 4.3 Identificación de cuentas prioritarias (Finance, Executives, Legal)

**¿Qué significa?**
Reconocer formalmente que algunos usuarios tienen un **impacto de riesgo desproporcionado**, y requieren controles reforzados.

**¿Por qué es esencial en BEC?**
Los atacantes:
- Apuntan a **ejecutivos** (autoridad)
- Apuntan a **finanzas** (capacidad de pago)
- Apuntan a **legal** (acceso a información sensible)

Esto es consistente en casi todos los incidentes BEC documentados.

**¿Qué implica ser “cuenta prioritaria”?**

**Procesos especiales:**
- Doble validación obligatoria
- Prohibición de aprobaciones solo por email
- Verificación reforzada en cambios críticos

**Gobierno:**
- Lista oficial mantenida por **Seguridad + Finanzas**
- Revisión periódica (los roles cambian)

**Alineación técnica:**
Estas cuentas deben coincidir con:
- Anti‑phishing impersonation
- Alertas de alta severidad
- MFA fuerte

---

### 4.4 Objetivo global del control

**¿Qué problema resuelven estos controles?**
Reducen el impacto cuando **TODA la capa técnica falla**:
- El correo llega 
- El usuario lo lee 
- Parece legítimo 

**El proceso bloquea la acción fraudulenta**.

> **BEC no se detiene solo con tecnología; se detiene cuando los procesos asumen que el correo puede mentir y hacen el fraude operativamente imposible.**

---

## 5. Detección y respuesta SOC

**Objetivo:** detección temprana y contención rápida antes de que el fraude se materialice.

---

### 5.1 Monitoreo de alertas de impersonación

**¿Qué debe monitorear el SOC?**
El SOC no debe esperar a que exista un fraude confirmado. En ataques BEC, la señal temprana más confiable es la **impersonación**.

Alertas críticas a monitorear de forma continua:
- User impersonation detected
- Domain impersonation detected
- Mailbox Intelligence detects impersonation
- Suspicious sequence of events possibly related to BEC

Estas alertas se generan en Microsoft Defender for Office 365 y se correlacionan automáticamente en Defender XDR cuando existe alta confianza de ataque.

**¿Por qué es crítico?**
BEC rara vez contiene malware o URLs. Si el SOC espera señales tradicionales, el pago fraudulento ya ocurrió. La velocidad es el factor decisivo.

---

### 5.2 Investigación de inbox rules sospechosas

**¿Por qué las inbox rules son clave en BEC?**
En ataques BEC reales, los atacantes utilizan reglas de buzón para ocultar su actividad y manipular conversaciones sensibles.

Patrones comunes:
- Mover correos a carpetas no visibles
- Marcar correos como leídos automáticamente
- Reenviar mensajes a cuentas externas
- Filtrar por palabras clave financieras (invoice, payment, wire)
- Eliminar correos enviados para borrar evidencia

Una sola regla sospechosa es suficiente para escalar el incidente.

---

### 5.3 Uso de Threat Explorer y Advanced Hunting

**Threat Explorer (análisis inmediato)**
Threat Explorer permite al SOC:
- Identificar todos los correos relacionados con un incidente
- Determinar quién recibió, respondió o reenvi el mensaje
- Evaluar el blast radius
- Confirmar impacto operativo

Es la herramienta principal para análisis rápido y toma de decisiones.

**Advanced Hunting (detección proactiva)**
Advanced Hunting se utiliza para:
- Detectar actividad BEC sin alerta explícita
- Analizar comportamiento histórico
- Correlacionar señales de identidad y correo

Hunting reduce significativamente el Mean Time To Detect (MTTD).

---

### 5.4 Correlación en Defender XDR

**¿Por qué XDR es crítico para BEC?**
Un ataque BEC no es un solo evento, sino una cadena:
- Inicio de sesión sospechoso
- Lectura de correos
- Creación de inbox rules
- Envío y eliminación de mensajes
- Comunicación con finanzas

Defender XDR correlaciona automáticamente estas señales y genera un único incidente de alta confianza.

**Beneficios operativos para el SOC**
- Reducción de ruido
- Mayor precisión
- Respuesta acelerada
- Capacidad de disrupción automática manteniendo control humano

---

### 5.5 Flujo operativo SOC resumido

**Detección**
1. Alerta de impersonación
2. Correlación automática en XDR

**Investigación**
3. Revisión de inbox rules
4. Análisis en Threat Explorer
5. Hunting avanzado si es necesario

**Contención**
6. Reset de credenciales
7. Eliminación de reglas maliciosas
8. Bloqueo de la conversación fraudulenta

Antes de que el equipo financiero ejecute cualquier pago.

---

### 5.6 Resultado esperado

Estos controles permiten:
- Detectar BEC en minutos
- Contener antes del impacto financiero
- Operar con señales reales y correlacionadas

> **BEC se gana o se pierde en la velocidad del SOC. Defender XDR existe para comprimir ese tiempo.**
