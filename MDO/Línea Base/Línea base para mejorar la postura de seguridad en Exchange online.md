# Seguridad Básica Integral de Correo Electrónico en Microsoft 365 🛡️
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*
---

# Configuraciones base para Exchange Online

**Audiencia:** Arquitectura, Messaging, SOC, SecOps, CISO  
**Nivel:** Técnico / Operativo (Enterprise)  
**Marco:** Zero Trust – Mail Flow Security

**Autores:** [Ernesto Cobos Roqueñí](https://www.linkedin.com/in/ernesto-cobos/) & [Arturo Mandujano](https://www.linkedin.com/in/jose-arturo-mandujano-avila-621b00b9/)

---

## Índice
1. [Introducción](#1-introducción)
2. [Reglas básicas de flujo de correo – Microsoft 365](#2-reglas-básicas-de-flujo-de-correo--microsoft-365)
3. [RejectDirectSend en Exchange Online](#3-rejectdirectsend-en-exchange-online)
4. [Estándares SPF, DKIM, DMARC y MTA-STS](#4-estándares-spf-dkim-dmarc-y-mta-sts)
5. [Dominios estacionados (Parked Domains)](#5--dominios-estacionados-parked-domains)
6. [Autenticación Legacy (Basic Autentication)](#6-autenticación-legacy-basic-autentication)
7. [Bloquear auto-forward externo](#7-bloquear-auto-forward-externo)
8. [Validación Línea base para mejorar la postura de seguridad en Exchange online](#validación-línea-base-para-mejorar-la-postura-de-seguridad-en-exchange-online)


---
# 1. Introducción

Un setup correcto de **reglas de flujo de correo en Microsoft 365** , **Bloqueo de Direct Send** y las correctas configuraciones de **SPF, DKIM, DMARC y MTA‑STS**, permiten:

- Proteger la **marca** y el **dominio**
- Reducir **phishing** y **spoofing**
- Asegurar la **entregabilidad** del correo legítimo
- Evitar el **abuso de dominios técnicos** (por ejemplo: `*.onmicrosoft.com`)
- Forzar el **cifrado SMTP en tránsito** entre servidores
- Proteger **dominios sin uso**
- Línea base para mejorar la postura de seguridad en Exchange online

---
> Este setup básico establece los controles mínimos necesarios para proteger la identidad del dominio y garantizar una comunicación de correo electrónico segura y confiable.
---

# 2. Reglas básicas de flujo de correo – Microsoft 365

A continuación encontrará reglas básicas de flujo de correo que son **altamente recomendadas** agregar para mejorar la postura de seguridad de Microsoft 365.

## Objetivos

- Bloqueo de correos enviados a `mydominio.onmicrosoft.com` y `mydominio.mail.onmicrosoft.com`
- Bloqueo de correos que no pueden ser analizados (enviados a cuarentena)

---

## Regla de flujo de correo para bloquear correos enviados a mydominio.onmicrosoft.com y mydominio.mail.onmicrosoft.com

### Opción 1: Script automatizado descargue el script que ejecuta esta tarea: [Block-onmicrosoftEmails](../Scripts/Block-OnMicrosoftEmails.ps1)

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
12. Marcamos **Stop processing more rules**
13. Marcar **Defer the message if rule processing doesn't complete**
14. Next y **Finish**
15. Una vez creada la regla, la editamos y en Prioridad la cambiaos a 0
16. Clic en Save

#### Referencias
> [Mail flow rules (transport rules) in Exchange Online](https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules)
> 
> [New-TransportRule (Exchange PowerShell](https://learn.microsoft.com/en-us/powershell/module/exchange/new-transportrule)
  

---

## Regla de flujo de correo para bloquear correos que no pueden ser inspeccionados

### Opción 1: Script automatizado descargue el script que ejecuta esta tarea: [Attachments Can't be inspected](../Scripts/Attachmentscannotbeinspected.ps1)

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
10. Marcamos **Stop processing more rules**
11. Next y **Finish**
12. Una vez creada la regla, la editamos y en Prioridad la cambiaos a 1
13. Clic en Save


#### Referencia
> [Inspect message attachments – Microsoft Learn](https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/inspect-message-attachments)
  


---
# 3. RejectDirectSend en Exchange Online
---
## ¿Qué es Direct Send?

**Direct Send** permite enviar correos a buzones internos del tenant usando:

- SMTP puerto **25**  
- Destino: `tenant.mail.protection.outlook.com`  
- **Sin autenticación** (anónimo)  
- Dominio del remitente (**P1 MAIL FROM**) pertenece a un *accepted domain*

Diseñado para:

- Impresoras  
- Scanners  
- Aplicaciones legacy on‑prem

### Riesgo inherente

- No requiere compromiso de cuenta  
- Permite suplantación interna creíble (CEO, Finanzas, RRHH)  
- Depende de SPF / DKIM / DMARC (controles posteriores, no preventivos)

---

### ¿Qué hace RejectDirectSend?

```powershell
Set-OrganizationConfig -RejectDirectSend $true
```

### Lógica de evaluación

Exchange Online **rechaza el mensaje** cuando:

1. El correo llega de forma **anónima**  
2. No está asociado a un **Mail Flow Connector autenticado**  
3. El **P1 MAIL FROM** pertenece a un dominio aceptado del tenant  
4. El destinatario es un buzón interno

### Resultado

- ❌ No entra al pipeline antispam  
- ❌ No se evalúa SPF / DKIM / DMARC  
- ✅ Rechazo inmediato en SMTP

**Error típico:**

```
550 5.7.68 TenantInboundAttribution; Direct Send not allowed for this organization
```

---

### Qué NO hace este control

- No valida el **P2 From header**  
- No analiza reputación  
- No depende de DMARC  
- No aplica heurística

Es un **control determinístico**, no probabilístico.

---

### Impacto en seguridad (SOC view)

**Sin RejectDirectSend**

- Phishing interno sin compromiso de identidad  
- Correos spoofeados pueden llegar a Inbox / Junk  
- Alto riesgo de fraude financiero

**Con RejectDirectSend**

- Bloqueo total de spoofing interno por SMTP  
- Reducción inmediata de superficie de ataque  
- Control alineado a Zero Trust

---

### Impacto operativo en aplicaciones

**Flujos que se rompen**

- Impresoras / scanners  
- ERPs / HR legacy  
- Scripts SMTP antiguos  
- SaaS mal configurados

**Alternativas soportadas**

- ✅ Mail Flow Connector autenticado por **certificado** (recomendado)  
- ✅ Mail Flow Connector por **IP fija**  
- ✅ SMTP AUTH con cuenta dedicada (último recurso)

---

### Estado del control

| Propiedad | Valor |
|---------|------|
| Default | false |
| $false | Direct Send isn't blocked |
| $true | Direct Send is blocked |
| Propagación | ~30 minutos |

**Verificación:**

```powershell
Get-OrganizationConfig | Select RejectDirectSend
```

#### Referencia
> [Envío directo: envíe correo directamente desde el dispositivo o la aplicación a Microsoft 365 o Office 365](https://learn.microsoft.com/es-mx/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365#direct-send-send-mail-directly-from-your-device-or-application-to-microsoft-365-or-office-365)
> 
> [RejectDirectSend](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig?view=exchange-ps#-rejectdirectsend)

---

# 4. Estándares SPF, DKIM, DMARC y MTA-STS

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

#### Acción según resultado
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

#### Referencia
> [Sender Policy Framework (SPF)](https://www.rfc-editor.org/rfc/rfc7208)

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


#### Referencia
> [DomainKeys Identified Mail (DKIM)](https://dkim.org/)
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

#### Referencia
> [Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://www.rfc-editor.org/rfc/rfc7489.html)

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

####  TLS Reporting (TLS-RPT)

```
_smtp._tls.ejemplo.com IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@ejemplo.com"
```

Permite visibilidad operativa.

---

## Script de validación

Puedes validar SPF, DKIM, DMARC y MTA-STS con el siguiente script: [Domain-Health-Check.ps1](../Scripts/Domain-Health-Check.ps1)

#### Referencia
> [SMTP MTA Strict Transport Security (MTA-STS)](https://www.rfc-editor.org/rfc/rfc8461)

---

# 5.  Dominios estacionados (Parked Domains)

##**¿Qué es un “parked domain”?**

Un **dominio estacionado** es un dominio que:
- No tiene servicios activos (web, correo, aplicaciones).
- Apunta a una página genérica del proveedor (hosting o registrador).
- No tiene configuraciones explícitas de **DNS**, **seguridad** o **correo**.

> En la práctica: el dominio existe, pero **no se controla realmente a nivel operativo**.

---

## ¿Qué hacer en lugar de usar un “parked domain”?

Aunque **no vayas a usar activamente el dominio**, se recomienda configurarlo de forma mínima y defensiva.

### Configuración mínima recomendada

#### SPF (dominio no usado para correo)
```dns
v=spf1 -all
```

#### DMARC (configuración más segura)
```dns
v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:dmarc@tudominio.com
```

### ¿Qué logra esta configuración?
- Rechaza todo correo que falle **SPF** o **DKIM**.
- Protege completamente contra **spoofing**.
- Envía **reportes agregados** de autenticación (rua).

---

## Riesgo de abuso para phishing y suplantación

Un dominio aparcado normalmente:
- No tiene **SPF**, **DKIM** ni **DMARC** configurados.
- No rechaza correo por diseño.
- Puede ser usado por atacantes para **suplantar tu marca**.

### Impacto real
- Phishing usando tu dominio.
- Fraude a clientes y proveedores.
- Daño reputacional inmediato.

> Muchos ataques utilizan dominios "olvidados" porque **nadie monitorea su uso**.

---

## Reputación de dominio y problemas futuros de correo

Si un dominio aparcado:
- Aparece en campañas de spam.
- No tiene políticas DMARC restrictivas.
- No mantiene un historial de envío limpio.

Cuando después quieras usarlo:
- Los correos irán a **SPAM**.
- Habrá bloqueos en Microsoft, Google, Proofpoint, entre otros.
- Será necesario **reconstruir la reputación desde cero**.

> Es mucho más barato prevenir que recuperar la reputación de un dominio.

---

## Falta total de control de seguridad (DNS y ownership)

Un dominio aparcado suele:
- Usar DNS del registrador.
- No tener registros explícitos (**CAA**, **DNSSEC**, **MX controlado**).
- Depender de configuraciones genéricas compartidas.

### Riesgos asociados
- Cambios no auditados.
- Mayor facilidad para **DNS hijacking**.
- Falta de trazabilidad durante incidentes.

---

## Riesgo de “Domain Shadow IT”

En organizaciones grandes es común:
- Comprar dominios “por si acaso”.
- Olvidarlos.
- No asignar un **owner** responsable.

### Resultado
- Nadie monitorea el dominio.
- Nadie recibe alertas.
- Nadie revisa logs.

> Esto es **Shadow IT de identidad y marca**, uno de los riesgos más ignorados en seguridad.
 ---
---
#### Referencia
> [Parked and Inactive Domain Setup for MX, SPF and DMARC](https://support.dmarcreport.com/support/solutions/articles/5000882467-parked-and-inactive-domain-setup-for-mx-spf-and-dmarc)

---

# 6. Autenticación Legacy (Basic Autentication)

## La autenticación legacy (también conocida como autenticación básica) no admite una autenticación fuerte ni restricciones basadas en dispositivos y es un vector de ataque común.

Para una protección redundante, bloquea explícitamente la autenticación legacy usando todo lo siguiente:
- Políticas de acceso condicional
- Proveedor de federación (si aplica)
- Políticas de autenticación de Exchange

### Políticas de acceso condicional

Una política que bloquea explícitamente el acceso para todos los usuarios que usan clientes de autenticación antiguos asegura que no haya excepciones no intencionales al usar el bloqueo implícito

**Pasos**
1. Create new policy from template
2. Categoría: **Secure foundation**
3. Template: **Block legacy authentication**
4. Review + Create

**Configuración**
- Users: Include **All users**
- Exclude: Break-glass (y cuentas legacy justificadas)
- Conditions → Client apps: **Exchange ActiveSync** y **Other clients**
- Grant: **Block access**
- Enable policy: **Report-only** (Despues de un periodo de evaluación no mayor a 30 días cambiar a On)

### Proveedor de federación (si aplica)

Los endpoints usados para la autenticación legacy deberían desactivarse en el Proxy de Aplicación Web (o en el proxy soportado).

Todavía se pueden usar internamente, pero no están disponibles externamente.

> ¡Aunque los Endpoints deberían estar bloqueados, verifica que ningún tercero que dependa de Microsoft 365 los necesite antes de desactivarlos!

Los Endpoint de AD FS se pueden desactivar en el proxy usando el siguiente cmdlet de PowerShell:
```powershell
Set-AdfsEndpoint -TargetAddressPath /adfs/services/trust/13/certificatemixed -Proxy $false
```

**Desactiva los endpoints de WS-Trust de Windows en el proxy desde el extranet.**

Los endpoints de WS-Trust de Windows (/adfs/services/trust/2005/windowstransport y /adfs/services/trust/13/windowstransport) están pensados solo para ser accesibles desde la intranet y usan el enlace WIA sobre HTTPS. Exponerlos al extranet podría permitir que las solicitudes a estos endpoints eviten las protecciones de bloqueo. Por eso, estos endpoints deberían desactivarse en el proxy (es decir, desactivarse desde el extranet) para proteger el bloqueo de cuentas de AD usando los siguientes comandos de PowerShell. No se espera que esto afecte a los usuarios finales al desactivar estos endpoints en el proxy.
```powershell
Set-AdfsEndpoint -TargetAddressPath /adfs/services/trust/2005/windowstransport -Proxy $false

Set-AdfsEndpoint -TargetAddressPath /adfs/services/trust/13/windowstransport -Proxy $false
```

### Exchange Online authentication policies

La autenticación básica está bloqueada a nivel de servicio para todos los protocolos excepto SMTP, así que todavía se usa una política de autenticación de Exchange para bloquear ese protocolo.  

Configura una política como predeterminada a nivel de la organización que bloquee SMTP; se puede aplicar una política separada que permita SMTP a individuos como una excepción.

Con la autenticación básica bloqueada a nivel de servicio, el valor Verdadero/Falso de cualquier protocolo que no sea SMTP es irrelevante porque no tiene ningún impacto.  

Una política se asigna explícitamente a uno o más usuarios (o implícitamente al configurarla como la política predeterminada usando Set-OrganizationConfig -DefaultAuthenticationPolicy) para bloquear (o permitir) la autenticación básica para SMTP.  

En el centro de administración de M365, se puede gestionar la política predeterminada en Configuración / Configuración de la organización / Autenticación moderna.

**Paso 1: Crea la política de autenticación**

Para crear una política que bloquee la autenticación básica para todos los protocolos de cliente disponibles en Exchange Online (la configuración recomendada), usa la siguiente sintaxis:
```powershell
New-AuthenticationPolicy -Name "Block Basic Auth"
```
Para habilitar la autenticación básica para protocolos específicos en la política, utilice Set-AuthenticationPolicy
 
---
# 7. Bloquear auto-forward externo

## Los usuarios pueden configurar el reenvío automático de sus correos electrónicos a un destinatario externo, pero también puede ser usado por un actor malicioso  para lograr persistencia.

**Métodos automáticos de reenvío de correo electrónico**

Los usuarios pueden configurar el reenvío automático de correos electrónicos mediante reglas de la bandeja de entrada, reenvío SMTP (en Outlook en la web) y Power Automate.

Se pueden implementar múltiples controles para regular el reenvío automático de correos electrónicos a destinatarios externos. Aunque el reenvío mediante reglas de la bandeja de entrada y el reenvío SMTP está bloqueado de forma predeterminada, el reenvío mediante Power Automate no lo está. Por lo tanto, tanto en una configuración de forma predeterminada como en una no de forma predeterminada, la información puede enviarse automáticamente a ubicaciones menos seguras y sin control.

También es común que se configure el reenvío automático en caso de un compromiso de la cuenta por parte de un actor malicioso, para mantener acceso indirecto a los nuevos correos enviados a la cuenta comprometida incluso después de que la cuenta misma haya sido remediada.

Hay varias formas de controlar el reenvío automático de correos electrónicos:
- Outbound spam filter policy
- Remote domain
- Mail flow rule
- Exchange role assignment policy (para ocultar a los usuarios la capacidad de configurar el reenvío SMTP en Outlook en la Web)

## Política de filtro de correo no deseado saliente (Outbound spam filter policy)

Para bloquear correos electrónicos reenviados mediante el reenvío SMTP y las reglas de la bandeja de entrada (y enviar un NDR al usuario), establece la opción de Reenvío automático en la política correspondiente a Automático o Desactivado. (Automático y Desactivado son equivalentes.)

Para validar ir a https://security.microsoft.com/antispam

Clic en Anti-spam outbound policy (Default)
Validar en **Forwarding rules** que **Automatic forwarding rules** este seleccionado **Automatic System-controlled** este seleccionado

## Remote domain

Para eliminar silenciosamente los correos electrónicos reenviados automáticamente enviados por reglas de la Bandeja de entrada y el reenvío SMTP a cualquier dominio externo que no esté cubierto por una política de dominio remoto más específica, ejecuta el siguiente comando:

```powershell
Set-RemoteDomain -Name Default -AutoForwardEnabled $false
```
> Esta configuración no envia notificaciones del bloqueo de reenvio automatico

## Mail flow rule

Para actuar sobre los correos electrónicos reenviados desde Power Automate, crea una regla de flujo de correo que busque los encabezados que Power Automate añade a cada correo que envía. 

Para actuar sobre los correos electrónicos reenviados por las reglas de la bandeja de entrada, crea una regla de flujo de correo basada en el tipo de mensaje "Reenvío automático" (condición) que va a "Fuera de la organización" (condición), con la acción deseada, como Rechazar o Eliminar (acción).

Los administradores de Exchange pueden usar estos encabezados para configurar reglas de bloqueo de exfiltración en el centro de administración de Exchange, como se muestra en el ejemplo aquí. Aquí, la regla de 'flujo de correo' rechaza los mensajes de correo salientes con:

- ‘x-ms-mail-application’ header set as ‘Microsoft Power Automate’ y
- ‘x-ms-mail-operation-type’ header set as ‘Send’ or ‘Forward’

Esto es equivalente a la regla de 'flujo de correo' de Exchange configurada para el tipo de mensaje igual a 'reenviar automáticamente'. Esta regla utiliza Outlook y los clientes de Outlook en la web.

Ejemplo de creacion de regla de flujo de correo

Name: **Bloquear la exfiltración de correos de Power Platform**
Apply this rule if... **The recipient es located...** y seleccioanr **Outside the organization**

and

**A message header includes...** agregar **‘x-ms-mail-application’** header includes **‘Microsoft Power Automate’**

and

**A message header matches...** agregar **‘x-ms-mail-operation-type’** header matches ‘Send’ or ‘Forward’**


Do the following... **Delete the message without notifying anymore**

y guardar

---

# 8. Validación Línea base para mejorar la postura de seguridad en Exchange online

**Se puede hacer una validación rapida ejecutando el siguiente escript: [Validate-EXOSecurityBaseline](../Scripts/Validate-EXOSecurityBaseline.ps1)**

  > Internal Tools 2026