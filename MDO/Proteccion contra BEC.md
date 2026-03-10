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
