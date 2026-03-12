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

### 1.1 SPF
```
v=spf1 include:spf.protection.outlook.com -all
```

### 1.2 DKIM
Habilitado obligatoriamente en todos los dominios.
```
selector1._domainkey.tudominio.com  | selector1-tudominio-com._domainkey.tutenant.onmicrosoft.com
selector2._domainkey.tudominio.com  | selector2-tudominio-com._domainkey.tutenant.onmicrosoft.com
```

### 1.3 DMARC
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

### Phishing threshold
**3 – More aggressive**

### Impersonation Protection
- Ejecutivos
- Finanzas
- Legal
- Proveedores críticos
- Socios estratégicos

### Mailbox Intelligence
➡ **Habilitado + Protección de suplantación**

### Spoof Intelligence
➡ Activado y respetando DMARC

[Paso a paso para crear Política Anti-Phishing](#política-anti-Phishing-microsoft-defender-for-office-365)

---

# 3. Safe Links, Safe Attachments y ZAP

## 3.1 Safe Links
Protección en tiempo real:
- Outlook, Teams, SharePoint, OneDrive
- Click‑time scanning
- Bloquear URL original
- Registrar clics

## 3.2 Safe Attachments
Recomendación:
- **Dynamic Delivery**
- Modo **Block**
- Activar para SharePoint / OneDrive / Teams

## 3.3 Zero‑Hour Auto Purge (ZAP)
- Activado globalmente
- Elimina correos entregados que luego se clasifican como maliciosos

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

## ✔ Doble validación fuera de banda
Obligatorio en:
- Cambios bancarios
- Pagos urgentes
- Nuevos proveedores
- Instrucciones de ejecutivos

## ✔ Separación de funciones (SoD)
Evita que una sola persona ejecute todo el proceso.

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

