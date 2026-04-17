# Paquete de Consultas KQL (Advanced Hunting) 🛡️
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

## Recomendaciones rápidas (antes de ejecutar)

- Ajusta `TimeRange` y/o filtros (`AccountName`, `DeviceName`, `DomainName`) para reducir ruido.
- Si una tabla no existe en tu tenant (depende de licenciamiento/ingesta), usa la alternativa indicada en cada query.
- Para convertir una query en **Custom Detection**, Microsoft recomienda basarla en **Advanced Hunting** y ejecutarla regularmente.

Este documento recopila una serie de consultas KQL (Kusto Query Language) diseñadas para la detección, triaje e investigación de amenazas en Microsoft Defender XDR.

**Autores:** Ernesto Cobos Roqueñí, Arturo Mandujano

---
## Índice
- [Requisitos y Notas](#-requisitos-y-notas)
- [Spoofing y Autenticación](#-spoofing-y-autenticación)
  - [1. Spoofing: From (Header) ≠ MailFrom (Envelope)](#1-spoofing-from-header--mailfrom-envelope)
  - [2. Spoofing: Header From interno vs MailFrom externo](#2-spoofing-header-from-interno-vs-mailfrom-externo)
  - [3. Spoofing: Fallos de Autenticación (SPF/DKIM/DMARC)](#3-spoofing-fallos-de-autenticación-spfdkimdmarc)
  - [4. Spoofing: Análisis de Campañas](#4-spoofing-análisis-de-campañas)
- [Impersonation & Brand Protection](#️-impersonation--brand-protection)
  - [5. Impersonation: Dominios Typosquat (Levenshtein)](#5-impersonation-dominios-typosquat-levenshtein)
  - [6. Impersonation: Homoglyph / Punycode](#6-impersonation-homoglyph--punycode)
  - [7. Impersonation: Usuario VIP](#7-impersonation-usuario-vip)
  - [8. Impersonation: Dominios Look-alike (Heurística Simple)](#8-impersonation-dominios-look-alike-heurística-simple)
- [Phishing, BEC & Ingeniería Social](#-phishing-bec--ingeniería-social)
  - [9. BEC: Señales de Urgencia y Pagos](#9-bec-señales-de-urgencia-y-pagos)
  - [10. Spear-phishing a VIPs](#10-spear-phishing-a-vips)
  - [11. BEC Ligero: Reply-To Mismatch](#11-bec-ligero-reply-to-mismatch)
  - [12. Técnica "Quasi-QRCode" / Image Only](#12-técnica-quasi-qrcode--image-only)
  - [13. Kits de Phishing (Formularios)](#13-kits-de-phishing-formularios)
- [Análisis de URLs & Adjuntos](#-análisis-de-urls--adjuntos)
  - [14. Pivot por URLs Sospechosas](#14-pivot-por-urls-sospechosas)
  - [15. URLs de Bajo Rédito / TLDs de Riesgo](#15-urls-de-bajo-rédito--tlds-de-riesgo)
  - [16. Campaña Activa: Múltiples Clics en misma URL](#16-campaña-activa-múltiples-clics-en-misma-url)
  - [17. Bloqueos de Safe Links](#17-bloqueos-de-safe-links)
  - [18. Adjuntos de Riesgo (Ejecutables/Scripts)](#18-adjuntos-de-riesgo-ejecutablesscripts)
  - [19. Adjuntos HTML/HTA con Data URI](#19-adjuntos-htmlhta-con-data-uri)
- [Detección de Anomalías & Comportamiento](#-detección-de-anomalías--comportamiento)
  - [20. Dominio del Remitente "Recién Visto"](#20-dominio-del-remitente-recién-visto)
  - [21. Usuarios con Alto Volumen de Reportes](#21-usuarios-con-alto-volumen-de-reportes)
  - [22. Top Targets (Pareto de Riesgo)](#22-top-targets-pareto-de-riesgo)
  - [23. Reglas de Bandeja de Entrada "Post-Compromiso"](#23-reglas-de-bandeja-de-entrada-post-compromiso)
  - [24. Clics desde Ubicaciones Atípicas](#24-clics-desde-ubicaciones-atípicas)
  - [25. Top Campañas Activas](#25-top-campañas-activas)
- [Efectividad de Defensa & Post-Delivery](#️-efectividad-de-defensa--post-delivery)
  - [26. Mensajes Remediados Post-Entrega (ZAP)](#26-mensajes-remediados-post-entrega-zap)
  - [27. Evasión Inicial + ZAP Posterior](#27-evasión-inicial--zap-posterior)
  - [28. Bypass por Allow/Override](#28-bypass-por-allowoverride)
- [Validación de Correos Entregados con Amenazas](#-validación-de-correos-entregados-con-amenazas)
  - [29. Correos entregados con algún tipo de amenaza (Query base)](#29-correos-entregados-con-algún-tipo-de-amenaza-query-base)
  - [30. Confirmar si fue Safe Attachments o Safe Links](#30-confirmar-si-fue-safe-attachments-o-safe-links)
  
---

## 📋 Requisitos y Notas

*   **Tablas requeridas:** Estas consultas utilizan tablas estándar como `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `EmailPostDeliveryEvents`, `UrlClickEvents`, `CloudAppEvents`.
*   **Personalización:** Algunos campos pueden variar según la configuración del tenant. Busca los comentarios en el código (ej. `// <-- Cambia por tus dominios`) para ajustar las variables.
*   **Uso sugerido:** Utiliza estas queries para detección proactiva y triaje. Pivota los resultados por `NetworkMessageId`, `SenderFromAddress` o `RecipientEmailAddress` para profundizar.

---

## 🎭 Spoofing y Autenticación

### 1. Spoofing: From (Header) ≠ MailFrom (Envelope)
Detecta mensajes donde el dominio visible ("From") no coincide con el dominio real del sobre SMTP ("MailFrom"). Útil para spoofing clásico y configuraciones erróneas de "send on behalf".

```kql

EmailEvents
| where Timestamp >= ago(7d)
| where isempty(SenderFromDomain) == false and isempty(SenderMailFromDomain) == false
| where SenderFromDomain != SenderMailFromDomain
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
```

### 2. Spoofing: Header From interno vs MailFrom externo
Muy efectivo para detectar intentos de suplantación de identidad corporativa ("me hago pasar por tu org").

```kql

EmailEvents
| where Timestamp >= ago(7d)
| where SenderFromDomain in ("contoso.com","contoso.mx")
| where SenderMailFromDomain !in ("contoso.com","contoso.mx")
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
```

### 3. Spoofing: Fallos de Autenticación (SPF/DKIM/DMARC)
Analiza los detalles de autenticación cuando están disponibles en `AuthenticationDetails`.

```kql

EmailEvents
| where Timestamp >= ago(7d)
| extend Auth = parse_json(AuthenticationDetails)
| extend SPF = tostring(Auth.SPF), DKIM = tostring(Auth.DKIM), DMARC = tostring(Auth.DMARC)
| where SPF has_any ("fail","softfail","temperror","permerror") or DKIM has_any ("fail","none","temperror","permerror") or DMARC has_any ("fail","none","temperror","permerror")
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, SPF, DKIM, DMARC, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
```

### 4. Spoofing: Análisis de Campañas
Agrupa por remitente y dominio para determinar si es un evento aislado o una campaña masiva.

```kql

EmailEvents
| where Timestamp >= ago(7d)
| where SenderFromDomain != SenderMailFromDomain
| summarize Msgs = count(), Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by SenderFromDomain, SenderMailFromDomain, SenderFromAddress
| order by Msgs desc, Recipients desc
```

---

## 🕵️ Impersonation & Brand Protection

### 5. Impersonation: Dominios Typosquat (Levenshtein)
Detecta dominios "parecidos" a un dominio VIP o partner usando distancia de edición (ej. `contoso.com` -> `cont0so.com`).

```kql
let protectedDomains = dynamic(["contoso.com","fabrikam.com"]);
EmailEvents
| where Timestamp >= ago(7d)
| where isnotempty(SenderFromDomain)
| where SenderFromDomain !in (protectedDomains)
| mv-expand ProtectedDomain = protectedDomains
| extend ProtectedDomain = tostring(ProtectedDomain)
//
// Root aproximado: penúltimo label (mejor que [0] si hay subdominios)
//
| extend SenderParts = split(SenderFromDomain, ".")
| extend ProtectedParts = split(ProtectedDomain, ".")
| extend SenderRoot = tostring(SenderParts[array_length(SenderParts)-2])
| extend ProtectedRoot = tostring(ProtectedParts[array_length(ProtectedParts)-2])
| where isnotempty(SenderRoot) and isnotempty(ProtectedRoot)
//
// Normalización básica
//
| extend LenDiff = abs(strlen(SenderRoot) - strlen(ProtectedRoot))
| extend NormalizedSenderRoot = SenderRoot
| extend NormalizedSenderRoot = replace(@"0","o", NormalizedSenderRoot)
| extend NormalizedSenderRoot = replace(@"1","l", NormalizedSenderRoot)
| extend NormalizedSenderRoot = replace(@"3","e", NormalizedSenderRoot)
| extend NormalizedSenderRoot = replace(@"5","s", NormalizedSenderRoot)
//
// Score
//
| extend Score = 0
| extend Score = Score + iif(LenDiff <= 1, 2, iif(LenDiff <= 2, 1, 0))
| extend Score = Score + iif(strlen(ProtectedRoot) >= 6 and (SenderRoot contains ProtectedRoot or ProtectedRoot contains SenderRoot), 1, 0)
| extend Score = Score + iif(strlen(ProtectedRoot) >= 6 and (NormalizedSenderRoot contains ProtectedRoot or ProtectedRoot contains NormalizedSenderRoot), 1, 0)
| where Score >= 2
| summarize
    Msgs        = count(),
    Recipients  = dcount(RecipientEmailAddress),
    FirstSeen   = min(Timestamp),
    LastSeen    = max(Timestamp),
    ExampleFrom = any(SenderFromAddress)
  by 
    SenderFromDomain, 
    ProtectedDomain,
    SenderRoot, 
    ProtectedRoot, 
    LenDiff, 
    NormalizedSenderRoot,
    Score
| order by Score desc, Msgs desc
```

### 6. Impersonation: Homoglyph / Punycode
Busca dominios que incluyen `xn--` o caracteres no ASCII.

```kql

EmailEvents
| where Timestamp >= ago(7d)
| where SenderFromDomain has "xn--" or SenderFromDomain matches regex @"[^\u0000-\u007F]" // no ASCII
| summarize Msgs=count(), Recipients=dcount(RecipientEmailAddress), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), ExampleFrom=any(SenderFromAddress), Subjects=make_set(Subject, 5) by SenderFromDomain
| order by Msgs desc
```

### 7. Impersonation: Usuario VIP
Compara la parte izquierda del email (alias) contra una lista de VIPs para detectar variaciones sutiles (ej. `michelle` vs `rnichell`).

```kql
// Definir la lista de nombres de visualización de tus VIPs
let VIPNames = dynamic(["Satya Nadella", "Nombre Apellido1", "Director General"]);
EmailEvents
| where Timestamp > ago(7d)
// 1. Filtrar solo correos que vienen de fuera de la organización
| where EmailDirection == "Inbound"
// 2. Buscar coincidencias exactas o parciales en el Display Name
| where SenderDisplayName has_any (VIPNames)
// 3. Excluir si el dominio del remitente es el tuyo (evitar falsos positivos de correos legítimos)
// Reemplaza 'tu-dominio.com' por tu dominio real
| where SenderFromDomain !endswith "tu-dominio.com"
| project Timestamp, Subject, SenderFromAddress, SenderDisplayName, RecipientEmailAddress, NetworkMessageId
| join kind=inner (
    EmailUrlInfo // Unimos para ver si además traen URLs sospechosas
    | project NetworkMessageId, Url
) on NetworkMessageId
| summarize ScanCount = count(), UniqueUrls = make_set(Url) by Timestamp, SenderDisplayName, SenderFromAddress, RecipientEmailAddress, Subject
| order by Timestamp desc
```

### 8. Impersonation: Dominios Look-alike (Heurística Simple)
Busca variaciones específicas de marca en el dominio del remitente.

```kql

let brand = "contoso.com";
EmailEvents
| where Timestamp > ago(7d)
| extend FromDomain = tostring(split(SenderFromAddress,"@")[1])
| where FromDomain != brand
| extend Dist = abs(strlen(FromDomain) - strlen(brand))
| where Dist <= 3
| where FromDomain contains "cont0so" or FromDomain contains "c0ntoso" or FromDomain contains "contoso-sec" or FromDomain contains "contoso-support"
| summarize count(), Victims=dcount(RecipientEmailAddress) by FromDomain
| order by count_ desc
```

---

## 🎣 Phishing, BEC & Ingeniería Social

### 9. BEC: Señales de Urgencia y Pagos
Busca palabras clave de presión financiera en correos con indicadores de spoofing.

```kql

let becKeywords = dynamic(["urgent","wire","payment","invoice","transfer","bank","remittance","pago","transferencia","factura","urgente"]);
EmailEvents
| where Timestamp >= ago(7d)
| where SenderFromDomain != SenderMailFromDomain or SenderFromDomain has "xn--"
| where Subject has_any (becKeywords)
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
```

### 10. Spear-phishing a VIPs
Detecta correos entregados a VIPs que tienen fallos de autenticación o fueron detectados posteriormente como Phishing.

```kql

let vip_list = dynamic(["ceo@contoso.com","cfo@contoso.com","board.alias@contoso.com"]);
EmailEvents
| where Timestamp > ago(7d)
| where RecipientEmailAddress in (vip_list)
| where DeliveryLocation in ("Inbox","Folder","JunkFolder")
| extend AuthFail = not( AuthenticationDetails has "dmarc=pass" and AuthenticationDetails has "spf=pass" )
| summarize Total=count(), DistinctSenders=dcount(SenderFromAddress), WithAuthIssues=countif(AuthFail), HighConfidencePhish=countif(ThreatTypes has "Phish" and DetectionMethods has "ZAP" or DetectionMethods has "PhishFilter") by RecipientEmailAddress
| order by HighConfidencePhish desc, WithAuthIssues desc
```

### 11. BEC Ligero: Reply-To Mismatch
Detecta correos donde la dirección de respuesta (`Reply-To`) es diferente al dominio del remitente, una táctica común en BEC.

```kql

EmailEvents
| where Timestamp > ago(7d)
| where DeliveryLocation in ("Inbox","Folder")
| extend ReplyToDomain = tostring(parse_json(AdditionalFields).ReplyToDomain)
| extend FromDomain = tostring(split(SenderFromAddress,"@")[1])
| where isnotempty(ReplyToDomain) and ReplyToDomain != FromDomain
| summarize count(), DistinctSenders=dcount(SenderFromAddress) by ReplyToDomain, FromDomain
| order by count_ desc
```

### 12. Técnica "Quasi-QRCode" / Image Only
Identifica correos con imágenes pesadas, sin texto/URLs explícitas, que derivan en clics externos (posible escaneo de QR o enlace en imagen).

```kql

let delivered_images = EmailEvents
    | where Timestamp > ago(7d)
    | where DeliveryLocation in ("Inbox", "Folder")
    // Anti-join para excluir correos que tengan URLs (según tu lógica original)
    | join kind=leftanti (
        EmailUrlInfo 
        | where Timestamp > ago(7d) 
        | project NetworkMessageId
    ) on NetworkMessageId
    // Join para filtrar correos que SOLO tengan imágenes adjuntas
    | join kind=inner (
        EmailAttachmentInfo 
        | where Timestamp > ago(7d)
        | where FileType has "image" or FileName matches regex @".*\.(png|jpg|jpeg|gif)$"
        | project NetworkMessageId
    ) on NetworkMessageId
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject, EmailTimestamp = Timestamp;
// Cruce con clics en URLs (Nota: si el correo no tiene URLs por el leftanti, este join podría devolver cero resultados)
delivered_images
| join kind=inner (
    UrlClickEvents 
    | where Timestamp > ago(7d)
    // En UrlClickEvents, el campo suele ser AccountUpn
    | project ClickTimestamp = Timestamp, RecipientEmailAddress = AccountUpn 
) on RecipientEmailAddress
// Filtramos para que el clic haya sido DESPUÉS de recibir el correo
| where ClickTimestamp > EmailTimestamp
| summarize MensajesImagenes = count(), DistinctRecipients = dcount(RecipientEmailAddress)
```

### 13. Kits de Phishing (Formularios)
Detecta enlaces a servicios de formularios legítimos abusados para robo de credenciales.

```kql

let form_kits = dynamic(["forms.office.com", "forms.gle", "formcrafts.com", "typeform.com", "smartsheet.com", "airtable.com", "notion.site", "forms.google.com", "formulario.link"]);
EmailUrlInfo
| where Timestamp > ago(7d)
// 1. Filtramos las URLs que coincidan con los dominios de formularios
| where UrlDomain has_any (form_kits) or Url has_any (form_kits)
// 2. Unimos con EmailEvents para obtener quién recibió el correo
| join kind=inner (
    EmailEvents 
    | where Timestamp > ago(7d)
    | project NetworkMessageId, RecipientEmailAddress
) on NetworkMessageId
// 3. Ahora sí podemos usar RecipientEmailAddress para el conteo
| summarize 
    EmailCount = count(), 
    Victims = dcount(RecipientEmailAddress) 
    by UrlDomain
| order by EmailCount desc
```

---

## 🔗 Análisis de URLs & Adjuntos

### 14. Pivot por URLs Sospechosas
Correlaciona eventos de spoofing con las URLs contenidas en ellos.

```kql

let suspicious = EmailEvents
| where Timestamp >= ago(7d)
| where SenderFromDomain != SenderMailFromDomain
| project NetworkMessageId, Timestamp, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject;
suspicious
| join kind=inner (
    EmailUrlInfo
    | where Timestamp >= ago(7d)
    | project NetworkMessageId, Url, UrlDomain
) on NetworkMessageId
| summarize UrlCount=count(), Recipients=dcount(RecipientEmailAddress), Examples=make_set(Url, 10) by SenderFromDomain, SenderFromAddress, Subject
| order by UrlCount desc
```

### 15. URLs de Bajo Rédito / TLDs de Riesgo
Identifica dominios con TLDs inusuales (ej. `.xyz`, `.top`) que han sido entregados y clicados.

```kql

let risky_tlds = dynamic([".top",".xyz",".click",".monster",".fit",".rest",".lol",".casa"]);
let delivered_urls = EmailEvents
    | where Timestamp > ago(7d)
    | where DeliveryLocation in ("Inbox","Folder","JunkFolder")
    | join kind=inner (EmailUrlInfo | where Timestamp > ago(7d)) on NetworkMessageId
    | extend Tld = tostring(extract(@"(\.[A-Za-z0-9\-]{2,})$", 1, UrlDomain))
    | where Tld in (risky_tlds)
    | project Timestamp, RecipientEmailAddress, SenderFromAddress, Url, UrlDomain, NetworkMessageId;
delivered_urls
| join kind=leftsemi (UrlClickEvents | where Timestamp > ago(7d) | project NetworkMessageId) on NetworkMessageId
| summarize Clics=count() by UrlDomain
| order by Clics desc
```

### 16. Campaña Activa: Múltiples Clics en misma URL

```kql

UrlClickEvents
| where Timestamp > ago(7d)
// En UrlClickEvents el usuario es 'AccountUpn'
| summarize DistinctVictims=dcount(AccountUpn), FirstClick=min(Timestamp), LastClick=max(Timestamp) by Url
| where DistinctVictims >= 3
| order by DistinctVictims desc, LastClick desc
```

### 17. Bloqueos de Safe Links

```kql

UrlClickEvents
| where Timestamp > ago(7d)
// 1. Usamos ActionType para filtrar bloqueos (como en el paso anterior)
| where ActionType has "Block" 
// 2. Extraemos el dominio de la columna 'Url'
| extend ParsedUrl = parse_url(Url)
| extend Domain = tostring(ParsedUrl.Host)
// 3. Ahora resumimos usando la nueva columna 'Domain' y 'AccountUpn'
| summarize 
    BlockedClicks = count(), 
    Victims = dcount(AccountUpn) 
    by Domain
| where isnotempty(Domain)
| order by BlockedClicks desc
```

### 18. Adjuntos de Riesgo (Ejecutables/Scripts)

```kql

let risky_ext = dynamic([".html",".htm",".hta",".js",".vbs",".wsf",".lnk",".iso",".img",".dll",".exe",".ps1",".bat",".cmd",".jar"]);
EmailAttachmentInfo
| where Timestamp > ago(7d)
| extend Ext = tolower(tostring(extract(@"\.[^.]+$", 0, FileName)))
| where Ext in (risky_ext)
| join kind=inner (EmailEvents | where DeliveryLocation in ("Inbox","Folder","JunkFolder")) on NetworkMessageId
| summarize count(), DistinctRecipients=dcount(RecipientEmailAddress) by Ext, SenderFromAddress
| order by count_ desc
```

### 19. Adjuntos HTML/HTA con Data URI
Detecta adjuntos HTML que usan `data:text/html` para ofuscar contenido malicioso.

```kql

EmailAttachmentInfo
| where Timestamp > ago(7d)
| where tolower(FileName) matches regex @"\.(html|htm|hta)$"
| join kind=inner (EmailEvents) on NetworkMessageId
| join kind=leftouter (EmailUrlInfo) on NetworkMessageId
| extend IsDataUri = iif(isnotempty(Url) and Url startswith "data:text/html", true, false)
| summarize Total=count(), DataUri=countif(IsDataUri) by SenderFromAddress
| order by DataUri desc, Total desc
```

---

## 📊 Detección de Anomalías & Comportamiento

### 20. Dominio del Remitente "Recién Visto"
Compara el tráfico reciente contra un histórico de 45 días para detectar dominios nuevos.

```kql

let Baseline = 45d;
let recent = EmailEvents
  | where Timestamp > ago(7d)
  | extend SenderDomain = tostring(split(SenderFromAddress, "@")[1])
  | summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Cnt=count() by SenderDomain;
let historical = EmailEvents
  | where Timestamp between (ago(Baseline) .. ago(7d))
  | extend SenderDomain = tostring(split(SenderFromAddress, "@")[1])
  | summarize PrevCnt=count() by SenderDomain;
recent
| join kind=leftouter (historical) on SenderDomain
| where isnull(PrevCnt) or PrevCnt == 0
| order by Cnt desc, LastSeen desc
```

### 21. Usuarios con Alto Volumen de Reportes
Identifica usuarios que están reportando mucho phishing (posiblemente bajo ataque sostenido).

```kql

AlertInfo
| where Timestamp > ago(7d)
// 1. Filtramos por el título de la alerta que genera Microsoft cuando un usuario reporta
| where Title has "User reported" or ServiceSource == "Microsoft Defender for Office 365"
| join kind=inner (
    AlertEvidence
    | where EntityType == "User"
    // 2. En AlertEvidence, la columna suele ser AccountUpn o UserPrincipalName
    | project AlertId, ReportingUser = AccountUpn
) on AlertId
| summarize Reports = count() by ReportingUser
| where isnotempty(ReportingUser)
| order by Reports desc
```

### 22. Top Targets (Pareto de Riesgo)
Usuarios que más reciben amenazas vs. usuarios que más hacen clic.

```kql

// 1. Identificamos correos con amenazas detectadas
let delivered_threats = EmailEvents
    | where Timestamp > ago(7d)
    | where ThreatTypes has_any ("Phish", "Malware", "CredentialPhish")
    | summarize Delivered = count(), DistinctSenders = dcount(SenderFromAddress) by RecipientEmailAddress;
// 2. Identificamos clics (usando AccountUpn y renombrándolo para el join)
let clicked = UrlClickEvents
    | where Timestamp > ago(7d)
    | summarize Clicks = count() by RecipientEmailAddress = AccountUpn; 
// 3. Unimos ambas tablas por la dirección de correo
delivered_threats
| join kind=leftouter clicked on RecipientEmailAddress
| extend Clicks = coalesce(Clicks, 0)
| project RecipientEmailAddress, Delivered, DistinctSenders, Clicks
| order by Delivered desc, Clicks desc
```

### 23. Reglas de Bandeja de Entrada "Post-Compromiso"
Detecta reglas de reenvío a direcciones externas creadas recientemente.

```kql

CloudAppEvents
| where Timestamp > ago(7d)
// 1. Buscamos las operaciones específicas de reglas en Exchange Online
| where ActionType in ("New-InboxRule", "Set-InboxRule")
// 2. Extraemos los detalles de la regla desde la columna RawEventData
| extend RuleDetails = parse_json(RawEventData).Parameters
| extend RuleName = tostring(parse_json(RawEventData).ObjectId)
// 3. Buscamos parámetros de reenvío (ForwardTo o ForwardAsAttachmentTo)
| mv-expand RuleDetails // Expandimos los parámetros para buscar el de reenvío
| where RuleDetails.Name in ("ForwardTo", "ForwardAsAttachmentTo")
| extend FwdTo = tostring(RuleDetails.Value)
// 4. Filtramos reenvíos que NO sean a tu dominio (cambia @tu-dominio.com)
| where isnotempty(FwdTo) and not(FwdTo endswith "@tu-dominio.com")
| project Timestamp, AccountUpn, ActionType, RuleName, FwdTo, IPAddress, CountryCode
| order by Timestamp desc
```

### 24. Clics desde Ubicaciones Atípicas
Compara el país del clic actual contra el histórico del usuario.

```kql

// 1. Creamos el mapa de ubicación usando la tabla Beta de Sign-ins (más rica en datos geo)
let ip_location_map = AADSignInEventsBeta
    | where Timestamp > ago(60d)
    | where isnotempty(IPAddress) and isnotempty(Country)
    | summarize LastKnownCountry = take_any(Country) by IPAddress;
// 2. Línea base de países habituales por usuario
let user_baseline = AADSignInEventsBeta
    | where Timestamp between (ago(60d) .. ago(7d))
    | summarize BaselineCountries = make_set(Country) by AccountUpn;
// 3. Cruce con los Clics
UrlClickEvents
| where Timestamp > ago(7d)
| join kind=inner ip_location_map on IPAddress
| join kind=leftouter user_baseline on AccountUpn
// 4. Lógica de detección de anomalía
| extend IsNewCountry = not(set_has_element(BaselineCountries, LastKnownCountry))
| where IsNewCountry == true
| summarize 
    TotalClicks = count(), 
    NewCountryFound = any(LastKnownCountry), 
    EvidenceIP = any(IPAddress),
    ClickedUrl = take_any(Url)
    by AccountUpn
| order by TotalClicks desc
```

### 25. Top Campañas Activas
Vista resumen tipo "Threat Explorer" agrupada por asunto y dominio.

```kql

EmailEvents
| where Timestamp > ago(7d)
| where DeliveryLocation in ("Inbox","Folder","JunkFolder")
| summarize Msgs=count(), Victims=dcount(RecipientEmailAddress), Senders=dcount(SenderFromAddress) by SenderFromDomain, Subject
| order by Msgs desc
```

---

## 🛡️ Efectividad de Defensa & Post-Delivery

### 26. Mensajes Remediados Post-Entrega (ZAP)

```kql

EmailPostDeliveryEvents
| where Timestamp >= ago(7d)
| where ActionType in ("ZAP","Quarantine","SoftDelete","HardDelete")
| project Timestamp, NetworkMessageId, ActionType, ActionResult, RecipientEmailAddress
| order by Timestamp desc
```

### 27. Evasión Inicial + ZAP Posterior
Detecta mensajes que entraron limpios (sin detección inicial) pero fueron remediados después.

```kql

EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionType in ("SoftDelete","MoveToQuarantine","ZAP")
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(7d)
    | where DetectionMethods !has "PhishFilter" and ThreatTypes == ""
) on NetworkMessageId
| project Timestamp, ActionType, RecipientEmailAddress, SenderFromAddress, Subject, NetworkMessageId
| order by Timestamp desc
```

### 28. Bypass por Allow/Override
Revisa correos permitidos por políticas de organización o overrides de usuario/admin.

```kql

EmailEvents
| where Timestamp > ago(7d)
| where OrgLevelAction in ("Allow","DeliverToInbox") or (DetectionMethods has "UserOverride" or DetectionMethods has "AdminOverride")
| summarize Total=count(), DistinctSenders=dcount(SenderFromAddress) by OrgLevelAction, DetectionMethods
| order by Total desc
```

---

## 📧 Validación de Correos Entregados con Amenazas

### 29. Correos entregados con algún tipo de amenaza (Query base)
Query imprescindible para identificar todos los correos que llegaron al buzón con algún tipo de amenaza detectada. Punto de partida para cualquier investigación de correos maliciosos entregados.

```kql
EmailEvents
| where Timestamp >= ago(7d)
| where DeliveryAction == "Delivered"
| where ThreatTypes has_any ("Malware", "Phish", "Spam")
| project
    EventTimestamp = Timestamp,
    NetworkMessageId,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    ThreatTypes,
    DetectionMethods,
    AuthenticationDetails,
    ConfidenceLevel,
    DeliveryLocation,
    EmailClusterId,
    ReportId
| join kind=leftouter (
    EmailPostDeliveryEvents
    | where Timestamp >= ago(7d)
    | project
        NetworkMessageId,
        PostDeliveryTimestamp = Timestamp,
        ActionType,
        ActionResult
) on NetworkMessageId
```

**Validar por tipo de amenaza específicamente:**

Agrega cualquiera de los siguientes filtros a la query base para segmentar por categoría de amenaza:

#### Malware
```kql
| where ThreatTypes has "Malware"
```

#### Phishing
```kql
| where ThreatTypes has "Phish"
```

#### Spam de alto riesgo
```kql
| where ThreatTypes has "Spam"
```

### 30. Confirmar si fue Safe Attachments o Safe Links
Verifica si los adjuntos detectados fueron procesados por Safe Attachments y cuál fue el veredicto del filtro de malware.

```kql
EmailEvents
| where Timestamp > ago(14d)
| project NetworkMessageId,
          SenderFromAddress,
          SenderDisplayName,
          RecipientEmailAddress,
          Subject,
          EmailTimestamp = Timestamp
// ---- SAFE ATTACHMENTS ----
| join kind=leftouter (
    EmailAttachmentInfo
    | where Timestamp > ago(14d)
    | where isnotempty(MalwareFilterVerdict) and MalwareFilterVerdict != "Clean"
    | project NetworkMessageId,
              FileName,
              SHA256,
              MalwareFilterVerdict,
              AttachmentTimestamp = Timestamp
) on NetworkMessageId
// ---- SAFE LINKS ----
| join kind=leftouter (
    EmailUrlInfo
    | where Timestamp > ago(14d)
    | where ActionType in ("ClickBlocked", "ClickAllowedBlocked")
    | project NetworkMessageId,
              Url,
              UrlDomain,
              SafeLinksAction = ActionType,
              UrlTimestamp = Timestamp
) on NetworkMessageId
// ---- SOLO MENSAJES QUE TIENEN ALGUNA PROTECCIÓN ACTIVADA ----
| where isnotempty(MalwareFilterVerdict) or isnotempty(SafeLinksAction)
| project
      EmailTimestamp,
      SenderFromAddress,
      SenderDisplayName,
      RecipientEmailAddress,
      Subject,
      FileName,
      MalwareFilterVerdict,
      Url,
      UrlDomain,
      SafeLinksAction
| order by EmailTimestamp desc
```


  > Internal Tools 2026
