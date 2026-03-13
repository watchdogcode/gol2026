# Protección contra Business Email Compromise (BEC) 🛡️

## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

Business Email Compromise (BEC) es un ataque de fraude altamente dirigido basado en ingeniería social, suplantación y compromiso de identidad. Su objetivo es manipular decisiones financieras u operativas mediante correos que parecen auténticos, frecuentemente enviados desde cuentas legítimas comprometidas.

Los ataques BEC modernos combinan:
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

## 1.1 SPF
Configuración básica donde se destaca -all:
```
v=spf1 include:spf.protection.outlook.com -all
```

## 1.2 DKIM
Habilitado obligatoriamente en todos los dominios.
```
selector1._domainkey.tudominio.com  | selector1-tudominio-com._domainkey.tutenant.onmicrosoft.com
selector2._domainkey.tudominio.com  | selector2-tudominio-com._domainkey.tutenant.onmicrosoft.com
```

## 1.3 DMARC
Mínimo aceptable:
```
v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@tudominio.com; ruf=mailto:dmarc-forensic@tudominio.com; fo=1; aspf=s; adkim=s
```
Ideal:
```
v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@tudominio.com; ruf=mailto:dmarc-forensic@tudominio.com; fo=1; aspf=s; adkim=s
```

Para mayor detalle consultar [**Estándares SPF, DKIM, DMARC y MTA-STS**](https://github.com/watchdogcode/gol2026/blob/main/MDO/L%C3%ADnea%20base%20para%20mejorar%20la%20postura%20de%20seguridad%20en%20Exchange%20online.md#4-est%C3%A1ndares-spf-dkim-dmarc-y-mta-sts)

---

# 2. Anti‑Phishing – Microsoft Defender for Office 365
### Esta medida es esencial para bloquear intentos de suplantación altamente específicos y sofisticados, donde el atacante imita a ejecutivos, proveedores o áreas clave para inducir acciones fraudulentas

## Phishing threshold
**3 – More aggressive**

### Impersonation Protection
- Ejecutivos
- Finanzas
- Legal
- Proveedores críticos
- Socios estratégicos

## Mailbox Intelligence
➡ **Habilitado + Protección de suplantación**

## Spoof Intelligence
➡ Activado y respetando DMARC

[Paso a paso para crear Política Anti-Phishing](#política-anti-Phishing-microsoft-defender-for-office-365)

---

# 3. Safe Links, Safe Attachments y ZAP
### Safe Links, Safe Attachments y ZAP ofrecen protección en tiempo real contra URL maliciosas, archivos peligrosos y correos que se vuelven sospechosos después de ser entregados

## 3.1 Safe Links
Protección en tiempo real:
- Outlook, Teams, SharePoint, OneDrive
- Click‑time scanning
- Bloquear URL original
- Registrar clics

Referencia: [Politica Safe links]

## 3.2 Safe Attachments
Recomendación:
- **Dynamic Delivery**
- Modo **Block**
- Activar para SharePoint / OneDrive / Teams

Referencia: [Politica Safe links]

## 3.3 Zero‑Hour Auto Purge (ZAP)
- Activado globalmente
- Elimina correos entregados que luego se clasifican como maliciosos

Para validar que ZAP este bien configurado se puede consultar a través de esre escript [Validate-ZAPConfiguration]

---
# 4. Protección de identidad (Zero Trust)
## 4.1 MFA obligatorio
Recomendado usar template: **Require multifactor authentication for all users**
## 4.2 MFA resistente a phishing (administradores)
Recomendado usar template: **Require phishing-resistant multifactor authentication for administrators**
## 4.3 Identity Protection
Detecta inicios de sesión riesgosos
Recomendado usar template: **Require multifactor authentication for risky sign-ins**
## 4.4 Bloqueo de Autenticación Heredada (Legacy Authentication)
La autenticación heredada no soporta MFA y es un vector común de ataques de fuerza bruta y password spraying.
Recomendado usar template: xxx
Recomendación:
- Deshabilitar POP, IMAP, SMTP AUTH, MAPI, EWS sin OAuth.
- Política de Acceso Condicional: **Block legacy authentication**.
- Excluir únicamente cuentas break-glass.


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

En ataques BEC, el objetivo del atacante es **un único punto de decisión.**
Si ese punto existe, el fraude ocurre inmediatamente

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
> SoD no es burocracia.
> Es una barrera estructural contra el fraude.
> Por eso aparece en estándares como ISO 27001, SOX, PCI-DSS y NIST
































## ✔ Cuentas prioritarias
Ejecutivos, Finanzas, Legal.

---

# 6. Detección y respuesta SOC

## ✔ Señales prioritarias
- Impersonation detected
- Mailbox Intelligence anomalies
- Reglas sospechosas
- Nuevos ASNs o IPs riesgosas

## ✔ Reglas sospechosas comunes
- Auto‑forward externo
- Mover a RSS/Archive
- Marcar como leído
- Eliminar enviados

## ✔ Threat Explorer
- Blast radius
- Lookalike domains
- Quién respondió / reenvi3

## ✔ Advanced Hunting
- Secuestro de hilos
- Reglas maliciosas
- Login anómalo

## ✔ XDR
Correlación automática de identidad + correo + endpoint.

---

# 7. Concientización y entrenamiento

## ✔ Simulaciones recomendadas
- CEO Fraud
- Vendor Fraud
- Payment Diversion
- Invoice Scam

## ✔ Métricas clave
- Usuarios vulnerables
- Tasa de reporte
- Riesgo acumulado

---

# 📌 Resumen Ejecutivo

La mitigación efectiva de BEC requiere:
- Identidad fuerte
- Anti‑phishing agresivo
- Safe Links / Safe Attachments / ZAP
- Procesos robustos
- Usuarios entrenados
- SOC rápido y disciplinado
- Correlación XDR

> **BEC falla cuando cada capa asume que la anterior puede ser comprometida.**


---

