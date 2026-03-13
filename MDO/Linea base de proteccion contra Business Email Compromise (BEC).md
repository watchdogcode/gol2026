# Protección contra Business Email Compromise (BEC) 🛡️

## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

Business Email Compromise (BEC) es un ataque de fraude altamente dirigido basado en ingeniería social, suplantación y compromiso de identidad. Su objetivo es manipular decisiones financieras u operativas mediante correos que parecen auténticos, frecuentemente enviados desde cuentas legítimas comprometidas.

---

### Los ataques BEC modernos combinan:
- Compromiso de identidad
- Impersonación de usuarios y dominios
- Suplantación avanzada sin spoofing técnico
- Conocimiento real de procesos internos
- Manipulación de hilos de correo

Ninguna capa por sí sola detiene BEC.
La mitigación requiere **disciplina + tecnología + procesos**.

---

# Modelo de Protección Multicapa (Zero Trust + NIST + Microsoft Defender 2026)

1. Autenticación del correo (SPF, DKIM, DMARC)
2. Anti‑phishing avanzado (DfO)
3. Safe Links / Safe Attachments / ZAP
4. Protección de identidad (Zero Trust / Entra ID Protection)
5. Controles de proceso de negocio
6. Detección y respuesta SOC (DfO + XDR)
7. Concientización continua

---

# 1. Autenticación del correo  
### En conjunto, estos mecanismos protegen la marca, reducen el riesgo de fraude y garantizan que el correo crítico del negocio llegue de forma segura a su destino

## SPF
SPF (Sender Policy Framework) define qué servidores están autorizados a enviar correo en nombre de tu dominio.

Configuración básica, donde se destaca -all:
```
v=spf1 include:spf.protection.outlook.com -all
```

## DKIM
DKIM (DomainKeys Identified Mail) agrega una firma digital a cada correo saliente.

Habilitado obligatoriamente en todos los dominios.
```
selector1._domainkey.tudominio.com  | selector1-tudominio-com._domainkey.tutenant.onmicrosoft.com
selector2._domainkey.tudominio.com  | selector2-tudominio-com._domainkey.tutenant.onmicrosoft.com
```

## DMARC
DMARC (Domain-based Message Authentication, Reporting & Conformance) define qué hacer cuando SPF o DKIM fallan y exige alineación con el dominio visible del correo.

Mínimo aceptable:
```
v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@tudominio.com; ruf=mailto:dmarc-forensic@tudominio.com; fo=1; aspf=s; adkim=s
```
Ideal:
```
v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@tudominio.com; ruf=mailto:dmarc-forensic@tudominio.com; fo=1; aspf=s; adkim=s
```

> Para mayor detalle consultar [**Estándares SPF, DKIM, DMARC y MTA-STS**](https://github.com/watchdogcode/gol2026/blob/main/MDO/L%C3%ADnea%20base%20para%20mejorar%20la%20postura%20de%20seguridad%20en%20Exchange%20online.md#4-est%C3%A1ndares-spf-dkim-dmarc-y-mta-sts)

---

# 2. Anti‑Phishing – Microsoft Defender for Office 365
**Esta medida es esencial para bloquear intentos de suplantación altamente específicos y sofisticados, donde el atacante imita a ejecutivos, proveedores o áreas clave para inducir acciones fraudulentas**

---

## Phishing threshold
Este umbral controla la sensibilidad para aplicar modelos de aprendizaje automático a los mensajes para determinar un veredicto de phishing.
1 - Standard

2 - Aggressive

**3 – More aggressive** (Recomendado)

4 - Most aggressive

### Impersonation Protection
La protección contra suplantación recibió fuertes señales de que los siguientes mensajes son sospechosos
- Ejecutivos
- Finanzas
- Legal
- Proveedores críticos
- Socios estratégicos

## Mailbox Intelligence
La inteligencia del buzón utiliza inteligencia artificial (IA) para determinar los patrones de correo electrónico del usuario con sus contactos frecuentes.

**Habilitado + Protección de suplantación**

## Spoof Intelligence
Elija cómo desea filtrar los correos electrónicos de remitentes que están suplantando dominios.

**Activado y respetando DMARC**

> 

Cómo crear [**Política Anti-Phishing**](Políticas/Política%20Anti-Phishing%20MDO.md)

---

# 3. Safe Links, Safe Attachments y ZAP
**Safe Links, Safe Attachments y ZAP ofrecen protección en tiempo real contra URL maliciosas, archivos peligrosos y correos que se vuelven sospechosos después de ser entregados**

## Safe Links
Protege a tus usuarios de abrir y compartir enlaces maliciosos en mensajes de correo electrónico y aplicaciones de Office

**Protección en tiempo real:**
- Outlook, Teams, SharePoint, OneDrive
- Click‑time scanning
- Bloquear URL original
- Registrar clics

> Referencia: [**Politica Safe links**](Políticas/Politica%20Safe%20links.md)

## Safe Attachments
Proteja su organización de contenido malicioso en archivos adjuntos de correo electrónico y archivos en SharePoint, OneDrive y Teams

**Recomendación:**
- **Dynamic Delivery**
- Modo **Block**
- Activar para SharePoint / OneDrive / Teams

> Referencia: [**Politica Safe Attachments**](Políticas/Política%20de%20Safe%20Attachments.md)

## Zero‑Hour Auto Purge (ZAP)
**Zero‑Hour Auto Purge (ZAP)** es una protección post‑entrega de Microsoft Defender for Office 365 que **detecta y elimina automáticamente** correos maliciosos que ya fueron entregados al **buzón del usuario**
- Activado globalmente
- Elimina correos entregados que luego se clasifican como maliciosos

> Para validar ZAP ejecute este escript [**Validate-ZAPConfiguration**](Scripts/Validate-ZAPConfiguration.ps1)

---
# 4. Protección de identidad (Zero Trust)
## MFA obligatorio todos los usuarios

Requiere que **todos los usuarios** completen **autenticación multifactor (MFA)** al acceder a los recursos de la organización, como una medida base para reducir el riesgo de compromiso de credenciales

> Recomendado usar template: **Require multifactor authentication for all users**

## MFA resistente a phishing (administradores)

Requiere que las **cuentas administrativas** utilicen **métodos de MFA resistentes al phishing** para proteger los roles con mayor impacto sobre la seguridad del tenant.

> Recomendado usar template: **Require phishing-resistant multifactor authentication for administrators**

## Detecta inicios de sesión riesgosos

Requiere MFA cuando Microsoft Entra ID detecta un **riesgo medio o alto en el inicio de sesión**, utilizando señales de riesgo para aplicar protección adaptativa.

> Recomendado usar template: **Require multifactor authentication for risky sign-ins**

## Bloqueo de Autenticación Heredada (Legacy Authentication)

Bloquea los intentos de inicio de sesión que usan **protocolos de autenticación heredados**, los cuales no admiten MFA y son comúnmente utilizados en ataques de fuerza bruta y password spray

> Recomendado usar template: **Block legacy authentication**


> Guía para [**Conditional Access Policies**](../EntraID/Políticas/Linea%20base%20Conditional%20Access%20Policies.md)

---

# 5. Controles de proceso de negocio

## Doble validación fuera de banda

### Es un control que obliga a verificar transacciones críticas usando un canal distinto al correo electrónico, aunque el mensaje:
- Parezca legítimo
- Continúe un hilo real
- Use firmas, tono y lenguaje correctos

**Esto es crítico porque en ataques BEC modernos:**
- El atacante sí controla la cuenta
- El correo sí es real
- Las herramientas técnicas pueden no bloquearlo 

**Debe de ser obligatorio para:**
- Cambios bancarios de proveedores
- Pagos urgentes o fuera de patrón
- Nuevos proveedores
- Instrucciones de ejecutivos (CEO Fraud)

**Buenaspracticas recomendads**
- Llamar a un número previamente registrado
- Usar un canal independiente (teléfono corporativo, sistema financiero)
- Documentar la verificación
- Requerir segunda aprobación posterior

## Separación de funciones (SoD)
### La separación de funciones (SoD) es un principio de control que establece que una sola persona NO debe poder ejecutar por sí sola todo un proceso crítico de negocio.

> En términos simples:
>
> Nadie debería poder iniciar, aprobar y ejecutar una transacción sensible sin que otra persona intervenga.
---

**Evita que:**
- Una sola persona ejecute todo el proceso.
- Un atacante (o un error humano)
- Pueda completar un fraude de principio a fin
- Que compromete una sola cuenta

> En ataques BEC, el objetivo del atacante es **un único punto de decisión.**
> 
> Si ese punto existe, el fraude ocurre inmediatamente

**Ejemplo SIN separación de funciones (Riesgoso)**
- La persona recibe el correo (“pago urgente”)
- Cambia los datos bancarios
- Autoriza el pago
- Ejecuta la transferencia

> El atacante gana con una sola cuenta comprometida.

**Ejemplo CON separación de funciones (SoD)**

| Paso                    | Rol distinto |
|-------------------------|--------------|
| Recibir la solicitud    | Usuario A    |
| Validar fuera de banda  | Usuario B    |
| Autorizar el pago       | Usuario C    |
| Ejecutar el pago        | Usuario D    |

 En este modelo, **el atacante necesitaría comprometer a varias personas al mismo tiempo**, lo cual **reduce drásticamente el riesgo de fraude** y eleva significativamente la barrera de ataque.

> **Idea clave**
>
> SoD no es burocracia.
>
> Es una barrera estructural contra el fraude.
>
> Por eso aparece en estándares como ISO 27001, SOX, PCI-DSS y NIST

## Cuentas prioritarias

### Son cuentas cuyo compromiso tiene impacto directo y grave en el negocio, no solo en IT.
**Incluyen típicamente:**
- Ejecutivos (CEO, CFO, COO)
- Finanzas / Tesorería / Compras
- Legal / Compliance

**¿Por qué son tan críticas?**
- Tienen autoridad para pagos, contratos y decisiones
- Sus correos se confían automáticamente
- Son el objetivo principal en ataques BEC

> Un atacante **no necesita malware** si logra convencer a Finanzas o a un Ejecutivo

### Controles diferenciados por tipo de usuario

| Control                     | Usuarios normales | Cuentas prioritarias |
|-----------------------------|------------------|----------------------|
| MFA                         | Si               | Si (phishing‑resistant) |
| Anti‑phishing               | Si               | Si (impersonation dedicado) |
| Safe Attachments / Links    | Si               | Si (modo estricto) |
| SoD obligatorio             | No               | Si |
| Validación fuera de banda   | No               | Si |
| Monitoreo SOC               | Básico           | Continuo |

> **Idea clave**
>
> No todos los usuarios representan el mismo riesgo para el negocio.
> Las cuentas prioritarias requieren controles prioritarios.

---

# 6. Detección y respuesta SOC

##  Señales prioritarias
- Impersonation detected
- Mailbox Intelligence anomalies
- Reglas sospechosas
- Nuevos ASNs o IPs riesgosas

##  Reglas sospechosas comunes
- Auto‑forward externo
- Mover a RSS/Archive
- Marcar como leído
- Eliminar enviados

##  Threat Explorer
- Blast radius
- Lookalike domains
- Quién respondió / reenvío

##  Advanced Hunting
- Secuestro de hilos
- Reglas maliciosas
- Login anómalo

##  XDR
Correlación automática de identidad + correo + endpoint.

---

[Referencia Guías de Seguridad Operacional MDO](https://github.com/watchdogcode/gol2026/tree/main/MDO)

---

# 7. Concientización y entrenamiento

## Simulaciones recomendadas
- CEO Fraud
- Vendor Fraud
- Payment Diversion
- Invoice Scam

## Métricas clave
- Usuarios vulnerables
- Tasa de reporte
- Riesgo acumulado

---

# Resumen Ejecutivo

**La mitigación efectiva de BEC requiere:**
- Identidad fuerte
- Anti‑phishing agresivo
- Safe Links / Safe Attachments / ZAP
- Procesos robustos
- Usuarios entrenados
- SOC rápido y disciplinado
- Correlación XDR

> **BEC falla cuando cada capa asume que la anterior puede ser comprometida.**


---

