# Importancia de SPF, DKIM, DMARC y MTA-STS

SPF, DKIM, DMARC y MTA-STS son controles fundamentales de seguridad de correo electrónico que protegen a las organizaciones contra suplantación de identidad (spoofing), phishing, fraude y ataques en tránsito, además de asegurar la entregabilidad del correo legítimo.

**En conjunto, estos mecanismos protegen la marca, reducen el riesgo de fraude y garantizan que el correo crítico del negocio llegue de forma segura a su destino.**

---

## SPF (Sender Policy Framework)

### ¿Qué es SPF?
SPF define qué servidores están autorizados a enviar correos en nombre de un dominio.

### ¿Qué problemas previene?
- Envío de correos falsificados usando tu dominio
- Spoofing básico basado en IP

### ¿Cómo funciona SPF?

#### 1. Registro SPF en DNS (TXT)
El dominio publica un registro TXT que especifica los hosts/IPs autorizados.

Ejemplo:
```
v=spf1 ip4:203.0.113.0/24 include:mail.example.com -all
```

Estructura:
- `v=spf1` → versión
- Mecanismos: `ip4`, `ip6`, `a`, `mx`, `include`, `exists`
- Qualifier final: `-all`, `~all`, `?all`, `+all`

#### 2. Evaluación en el servidor receptor
- El MTA receptor consulta el dominio del **MAIL FROM**
- Compara la IP remitente contra los mecanismos definidos

Resultados posibles:
- `pass`
- `fail`
- `softfail`
- `neutral`
- `permerror`
- `temperror`

#### 3. Acción según resultado
- **pass** → correo aceptado
- **fail (-all)** → posible rechazo
- **softfail (~all)** → marcado como sospechoso

### Mecanismos principales SPF

- **ip4 / ip6** → autoriza IPs específicas
- **a / mx** → autoriza IPs resueltas por DNS
- **include** → hereda reglas de otro dominio
- **exists** → validación condicional avanzada

### Qualifiers SPF

- `-all` → rechazo duro
- `~all` → rechazo suave
- `?all` → neutral
- `+all` → permitir todo (no recomendado)

> Nota: El qualifier `/all` **no existe** en el estándar SPF.

---

## DKIM (DomainKeys Identified Mail)

### ¿Qué es DKIM?
DKIM es un mecanismo de autenticación criptográfica a nivel de dominio que permite verificar que:
1. El mensaje fue autorizado por el dominio emisor
2. El contenido no fue alterado en tránsito

DKIM valida **el dominio**, no al usuario.

### Componentes clave

#### Par de claves criptográficas
- **Clave privada**: reside en el servidor de envío y firma el mensaje
- **Clave pública**: se publica en DNS como registro TXT

> Recomendación actual: **RSA 2048 bits**

#### Selector DKIM
Permite múltiples claves activas por dominio.

Ejemplo:
```
selector1._domainkey.ejemplo.com
```

Ventajas:
- Rotación sin downtime
- Múltiples proveedores
- Delegación segura

#### Header DKIM-Signature

Ejemplo:
```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=ejemplo.com; s=selector1;
 h=from:to:subject:date:message-id;
 bh=Base64HashBody;
 b=FirmaDigitalBase64
```

Campos importantes:
- `d` → dominio firmante
- `s` → selector
- `h` → headers firmados
- `bh` → hash del cuerpo
- `b` → firma digital

---

## DMARC (Domain-based Message Authentication, Reporting & Conformance)

### ¿Qué es DMARC?
DMARC es un protocolo que opera sobre SPF y DKIM, añadiendo:
- Alineación con el campo **From:**
- Políticas de acción
- Reportes de visibilidad

### ¿Cómo funciona?
1. El receptor evalúa SPF y DKIM
2. Verifica alineación con From:
3. Aplica la política definida (`none`, `quarantine`, `reject`)

### Componentes de un registro DMARC

Publicado en:
```
_dmarc.tudominio.com
```

Tags principales:
- `p` → política
- `rua` → reportes agregados
- `ruf` → reportes forenses
- `adkim` / `aspf` → alineación
- `pct` → porcentaje de aplicación

### Implementación recomendada

1. Preparar SPF y DKIM
2. Empezar con `p=none`
3. Analizar reportes
4. Migrar a `quarantine`
5. Endurecer a `reject`

Ejemplo estricto:
```
v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100
```

Buenas prácticas:
- Monitoreo continuo
- Alineación estricta
- Protección de subdominios

---

## MTA-STS (Mail Transfer Agent – Strict Transport Security)

### ¿Qué es MTA-STS?
MTA-STS es un estándar (RFC 8461) que protege el correo **en tránsito entre servidores SMTP**, forzando el uso de TLS validado.

### Amenazas mitigadas
- Man-in-the-Middle (MITM)
- TLS downgrade
- Intercepción del tráfico SMTP

### Problema histórico de SMTP
- STARTTLS oportunista
- Fallback a texto plano

MTA-STS convierte TLS en **obligatorio**.

### Componentes clave

#### 1. Registro DNS `_mta-sts`
```
_mta-sts.ejemplo.com IN TXT "v=STSv1; id=2024022501"
```

#### 2. Política HTTPS

Ubicación:
```
https://mta-sts.ejemplo.com/.well-known/mta-sts.txt
```

Ejemplo:
```
version: STSv1
mode: enforce
mx: mail.ejemplo.com
max_age: 604800
```

#### 3. TLS Reporting (TLS-RPT)

```
_smtp._tls.ejemplo.com IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@ejemplo.com"
```

Permite visibilidad operativa.

---

## Script de validación

Puedes validar SPF, DKIM, DMARC y MTA-STS con el siguiente script:

[Domain-Health-Check.ps1](https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/Scripts/Domain-Health-Check.ps1)

# Reglas básicas de flujo de correo – Microsoft 365

A continuación encontrará reglas básicas de flujo de correo que son **altamente recomendadas** agregar para mejorar la postura de seguridad de Microsoft 365.

## Objetivos

- Bloqueo de correos enviados a `mydominio.onmicrosoft.com` y `mydominio.mail.onmicrosoft.com`
- Bloqueo de correos que no pueden ser analizados (enviados a cuarentena)

---

## Regla de flujo de correo para bloquear correos enviados a mydominio.onmicrosoft.com y mydominio.mail.onmicrosoft.com

### Opción 1: Script automatizado descargue el script que ejecuta esta tarea: [Block-onmicrosoftEmails](https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/Scripts/Block-OnMicrosoftEmails.ps1)

### Opción 2: Creación manual

**Nota:** Reemplace `mydomain` con el dominio base del tenant.

#### Pasos

1. Ir a https://admin.exchange.microsoft.com/#/transportrules
2. Hacer clic en **+ Add a rule**
3. Seleccionar **Create a new rule**
4. Nombre: **Block emails sent to mydomain.onmicrosoft.com**
5. Apply this rule if: **The message headers** → **matches these text patterns**
6. En **Enter text**, especificar el header **To** y guardar
7. En **Enter words**, agregar:
   - `@mydomain\.onmicrosoft.com`
   - `@mydomain\.mail\.onmicrosoft.com`
8. Do the following: **Block the message** → **Delete the message without notifying anyone**
9. Next
10. Rule mode: **Enforce**
11. Severity: **High**
12. Marcar **Defer the message if rule processing doesn't complete**
13. Next
14. Finish

#### Referencias

- Mail flow rules (transport rules) in Exchange Online  
  https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules
- New-TransportRule (Exchange PowerShell)  
  https://learn.microsoft.com/en-us/powershell/module/exchange/new-transportrule

---

## Regla de flujo de correo para bloquear correos que no pueden ser inspeccionados

### Opción 1: Script automatizado descargue el script que ejecuta esta tarea [Quarantine Attachments Can’t be inspected](https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/Scripts/Quarantine%20Attachments%20Can%C2%B4t%20be%20inspected.ps1)

### Opción 2: Creación manual

#### Pasos

1. Ir a https://admin.exchange.microsoft.com/#/transportrules
2. Hacer clic en **+ Add a rule**
3. Seleccionar **Create a new rule**
4. Nombre: **Quarantine Attachments Can’t be inspected**
5. Apply this rule if: **Any attachment** → **content can’t be inspected**
6. Do the following: **Redirect the message to** → **Hosted quarantine**
7. Next
8. Rule mode: **Enforce**
9. Severity: **High**
10. Next
11. Finish

#### Referencia

- Inspect message attachments – Microsoft Learn  
  https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/inspect-message-attachments
