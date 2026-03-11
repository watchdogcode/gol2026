# 🛡️ Paquete de Consultas KQL (Advanced Hunting)
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*
---
## Recomendaciones rápidas (antes de ejecutar)

- Ajusta `TimeRange` y/o filtros (`AccountName`, `DeviceName`, `DomainName`) para reducir ruido.
- Si una tabla no existe en tu tenant (depende de licenciamiento/ingesta), usa la alternativa indicada en cada query.
- Para convertir una query en **Custom Detection**, Microsoft recomienda basarla en **Advanced Hunting** y ejecutarla regularmente.

Este documento recopila una serie de consultas KQL (Kusto Query Language) diseñadas para la detección, triaje e investigación de amenazas en Microsoft Defender XDR.

**Autores:** Ernesto Cobos Roqueñí, Arturo Mandujano

---
## Índice
- [Requisitos y Notas](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#-requisitos-y-notas)
- [Spoofing y Autenticación](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#-spoofing-y-autenticaci%C3%B3n)
  - [1. Spoofing: From (Header) ≠ MailFrom (Envelope)](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#1-spoofing-from-header--mailfrom-envelope)
  - [2. Spoofing: Header From interno vs MailFrom externo](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#2-spoofing-header-from-interno-vs-mailfrom-externo)
  - [3. Spoofing: Fallos de Autenticación (SPF/DKIM/DMARC)](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#3-spoofing-fallos-de-autenticaci%C3%B3n-spfdkimdmarc)
  - [4. Spoofing: Análisis de Campañas](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#4-spoofing-an%C3%A1lisis-de-campa%C3%B1as)
- [Impersonation & Brand Protection](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#%EF%B8%8F-impersonation--brand-protection)
  - [5. Impersonation: Dominios Typosquat (Levenshtein)](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#5-impersonation-dominios-typosquat-levenshtein)
  - [6. Impersonation: Homoglyph / Punycode](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#6-impersonation-homoglyph--punycode)
  - [7. Impersonation: Usuario VIP](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#7-impersonation-usuario-vip)
  - [8. Impersonation: Dominios Look-alike (Heurística Simple)](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#8-impersonation-dominios-look-alike-heur%C3%ADstica-simple)
- [Phishing, BEC & Ingeniería Social](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#-phishing-bec--ingenier%C3%ADa-social)
  - [9. BEC: Señales de Urgencia y Pagos](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#9-bec-se%C3%B1ales-de-urgencia-y-pagos)
  - [10. Spear-phishing a VIPs](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#10-spear-phishing-a-vips)
  - [11. BEC Ligero: Reply-To Mismatch](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#11-bec-ligero-reply-to-mismatch)
  - [12. Técnica "Quasi-QRCode" / Image Only](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#12-t%C3%A9cnica-quasi-qrcode--image-only)
  - [13. Kits de Phishing (Formularios)](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#13-kits-de-phishing-formularios)
- [Análisis de URLs & Adjuntos](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#-an%C3%A1lisis-de-urls--adjuntos)
  - [14. Pivot por URLs Sospechosas](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#14-pivot-por-urls-sospechosas)
  - [15. URLs de Bajo Rédito / TLDs de Riesgo](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#15-urls-de-bajo-r%C3%A9dito--tlds-de-riesgo)
  - [16. Campaña Activa: Múltiples Clics en misma URL](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#16-campa%C3%B1a-activa-m%C3%BAltiples-clics-en-misma-url)
  - [17. Bloqueos de Safe Links](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#17-bloqueos-de-safe-links)
  - [18. Adjuntos de Riesgo (Ejecutables/Scripts)](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#18-adjuntos-de-riesgo-ejecutablesscripts)
  - [19. Adjuntos HTML/HTA con Data URI](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#19-adjuntos-htmlhta-con-data-uri)
- [Detección de Anomalías & Comportamiento](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#-detecci%C3%B3n-de-anomal%C3%ADas--comportamiento)
  - [20. Dominio del Remitente "Recién Visto"](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#20-dominio-del-remitente-reci%C3%A9n-visto)
  - [21. Usuarios con Alto Volumen de Reportes](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#21-usuarios-con-alto-volumen-de-reportes)
  - [22. Top Targets (Pareto de Riesgo)](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#22-top-targets-pareto-de-riesgo)
  - [23. Reglas de Bandeja de Entrada "Post-Compromiso"](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#23-reglas-de-bandeja-de-entrada-post-compromiso)
  - [24. Clics desde Ubicaciones Atípicas](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#24-clics-desde-ubicaciones-at%C3%ADpicas)
  - [25. Top Campañas Activas](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#25-top-campa%C3%B1as-activas)
- [Efectividad de Defensa & Post-Delivery](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#%EF%B8%8F-efectividad-de-defensa--post-delivery)
  - [26. Mensajes Remediados Post-Entrega (ZAP)](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#26-mensajes-remediados-post-entrega-zap)
  - [27. Evasión Inicial + ZAP Posterior](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#27-evasi%C3%B3n-inicial--zap-posterior)
  - [28. Bypass por Allow/Override](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#28-bypass-por-allowoverride)
- [Validación de Correos Entregados con Amenazas](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#-validaci%C3%B3n-de-correos-entregados-con-amenazas)
  - [29. Correos entregados con algún tipo de amenaza (Query base)](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#29-correos-entregados-con-alg%C3%BAn-tipo-de-amenaza-query-base)
  - [30. Confirmar si fue Safe Attachments o Safe Links](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#30-confirmar-si-fue-safe-attachments-o-safe-links)
  - [31. Enlaces maliciosos entregados](https://github.com/watchdogcode/gol2026/blob/main/MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md#31-enlaces-maliciosos-entregados)

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
let lookback = 7d;
EmailEvents
| where Timestamp >= ago(lookback)
| where isempty(SenderFromDomain) == false and isempty(SenderMailFromDomain) == false
| where SenderFromDomain != SenderMailFromDomain
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
```

### 2. Spoofing: Header From interno vs MailFrom externo
Muy efectivo para detectar intentos de suplantación de identidad corporativa ("me hago pasar por tu org").

```kql
let lookback = 7d;
let orgDomains = dynamic(["contoso.com","contoso.mx"]); // <-- Cambia por tus dominios
EmailEvents
| where Timestamp >= ago(lookback)
| where SenderFromDomain in (orgDomains)
| where SenderMailFromDomain !in (orgDomains)
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
```

### 3. Spoofing: Fallos de Autenticación (SPF/DKIM/DMARC)
Analiza los detalles de autenticación cuando están disponibles en `AuthenticationDetails`.

```kql
let lookback = 7d;
EmailEvents
| where Timestamp >= ago(lookback)
| extend Auth = parse_json(AuthenticationDetails)
| extend SPF = tostring(Auth.SPF), DKIM = tostring(Auth.DKIM), DMARC = tostring(Auth.DMARC)
| where SPF has_any ("fail","softfail","temperror","permerror") or DKIM has_any ("fail","none","temperror","permerror") or DMARC has_any ("fail","none","temperror","permerror")
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, SPF, DKIM, DMARC, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
```

### 4. Spoofing: Análisis de Campañas
Agrupa por remitente y dominio para determinar si es un evento aislado o una campaña masiva.

```kql
let lookback = 7d;
EmailEvents
| where Timestamp >= ago(lookback)
| where SenderFromDomain != SenderMailFromDomain
| summarize Msgs = count(), Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by SenderFromDomain, SenderMailFromDomain, SenderFromAddress
| order by Msgs desc, Recipients desc
```

---

## 🕵️ Impersonation & Brand Protection

### 5. Impersonation: Dominios Typosquat (Levenshtein)
Detecta dominios "parecidos" a un dominio VIP o partner usando distancia de edición (ej. `contoso.com` -> `cont0so.com`).

```kql
let lookback = 14d;
let protectedDomains = dynamic(["contoso.com","fabrikam.com"]); // <-- dominios a proteger
EmailEvents
| where Timestamp >= ago(lookback)
| where SenderFromDomain !in (protectedDomains)
| extend Closest = tostring(protectedDomains[0])
| mv-expand pd = protectedDomains
| extend Distance = levenshtein_distance(SenderFromDomain, tostring(pd))
| where Distance between (1 .. 2) // 1-2 cambios típicos
| summarize Msgs = count(), Recipients = dcount(RecipientEmailAddress), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), ExampleFrom = any(SenderFromAddress) by SenderFromDomain, ProtectedDomain=tostring(pd), Distance
| order by Distance asc, Msgs desc
```

### 6. Impersonation: Homoglyph / Punycode
Busca dominios que incluyen `xn--` o caracteres no ASCII.

```kql
let lookback = 30d;
EmailEvents
| where Timestamp >= ago(lookback)
| where SenderFromDomain has "xn--" or SenderFromDomain matches regex @"[^\u0000-\u007F]" // no ASCII
| summarize Msgs=count(), Recipients=dcount(RecipientEmailAddress), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), ExampleFrom=any(SenderFromAddress), Subjects=make_set(Subject, 5) by SenderFromDomain
| order by Msgs desc
```

### 7. Impersonation: Usuario VIP
Compara la parte izquierda del email (alias) contra una lista de VIPs para detectar variaciones sutiles (ej. `michelle` vs `rnichell`).

```kql
let lookback = 14d;
let vipUsers = dynamic(["ceo@contoso.com","cfo@contoso.com","payments@contoso.com"]);
let vipAliases = vipUsers
| extend a = tostring(split(tolower(vipUsers[0]), "@")[0]); // placeholder
EmailEvents
| where Timestamp >= ago(lookback)
| extend FromAddr = tolower(SenderFromAddress)
| extend FromAlias = tostring(split(FromAddr,"@")[0])
| mv-expand vip = vipUsers
| extend VipAlias = tostring(split(tolower(tostring(vip)),"@")[0])
| extend Dist = levenshtein_distance(FromAlias, VipAlias)
| where Dist between (1 .. 2)
| where FromAddr != tolower(tostring(vip)) // excluye el real
| summarize Msgs=count(), Recipients=dcount(RecipientEmailAddress), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), ExampleFrom=any(SenderFromAddress), Subjects=make_set(Subject, 5) by ImpersonatingAlias=FromAlias, VipImpersonated=tostring(vip), Dist, SenderFromDomain
| order by Dist asc, Msgs desc
```

### 8. Impersonation: Dominios Look-alike (Heurística Simple)
Busca variaciones específicas de marca en el dominio del remitente.

```kql
let Lookback = 30d;
let brand = "contoso.com";
EmailEvents
| where Timestamp > ago(Lookback)
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
let lookback = 7d;
let becKeywords = dynamic(["urgent","wire","payment","invoice","transfer","bank","remittance","pago","transferencia","factura","urgente"]);
EmailEvents
| where Timestamp >= ago(lookback)
| where SenderFromDomain != SenderMailFromDomain or SenderFromDomain has "xn--"
| where Subject has_any (becKeywords)
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
```

### 10. Spear-phishing a VIPs
Detecta correos entregados a VIPs que tienen fallos de autenticación o fueron detectados posteriormente como Phishing.

```kql
let Lookback = 14d;
let vip_list = dynamic(["ceo@contoso.com","cfo@contoso.com","board.alias@contoso.com"]);
EmailEvents
| where Timestamp > ago(Lookback)
| where RecipientEmailAddress in (vip_list)
| where DeliveryLocation in ("Inbox","Folder","JunkFolder")
| extend AuthFail = not( AuthenticationDetails has "dmarc=pass" and AuthenticationDetails has "spf=pass" )
| summarize Total=count(), DistinctSenders=dcount(SenderFromAddress), WithAuthIssues=countif(AuthFail), HighConfidencePhish=countif(ThreatTypes has "Phish" and DetectionMethods has "ZAP" or DetectionMethods has "PhishFilter") by RecipientEmailAddress
| order by HighConfidencePhish desc, WithAuthIssues desc
```

### 11. BEC Ligero: Reply-To Mismatch
Detecta correos donde la dirección de respuesta (`Reply-To`) es diferente al dominio del remitente, una táctica común en BEC.

```kql
let Lookback = 14d;
EmailEvents
| where Timestamp > ago(Lookback)
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
let Lookback = 14d;
let delivered_images = EmailEvents
    | where Timestamp > ago(Lookback)
    | where DeliveryLocation in ("Inbox","Folder")
    | join kind=leftanti (EmailUrlInfo | where Timestamp > ago(Lookback) | project NetworkMessageId) on NetworkMessageId
    | join kind=inner (EmailAttachmentInfo | where Timestamp > ago(Lookback)
        | where tolower(FileType) has "image" or FileName matches regex @"\.(png|jpg|jpeg|gif)$") on NetworkMessageId
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject, Timestamp;
delivered_images
| join kind=leftsemi (UrlClickEvents | where Timestamp > ago(Lookback) | project RecipientEmailAddress, Timestamp) on RecipientEmailAddress
| summarize MensajesImagenes=count(), DistinctRecipients=dcount(RecipientEmailAddress)
```

### 13. Kits de Phishing (Formularios)
Detecta enlaces a servicios de formularios legítimos abusados para robo de credenciales.

```kql
let Lookback = 14d;
let form_kits = dynamic(["forms.co","formcrafts.com","typeform.com","smartsheet.com","airtable.com","notion.site","google.com/forms","formulario.link"]);
EmailUrlInfo
| where Timestamp > ago(Lookback)
| where UrlDomain has_any (form_kits)
| summarize count(), Victims=dcount(RecipientEmailAddress) by UrlDomain
| order by count_ desc
```

---

## 🔗 Análisis de URLs & Adjuntos

### 14. Pivot por URLs Sospechosas
Correlaciona eventos de spoofing con las URLs contenidas en ellos.

```kql
let lookback = 7d;
let suspicious = EmailEvents
| where Timestamp >= ago(lookback)
| where SenderFromDomain != SenderMailFromDomain
| project NetworkMessageId, Timestamp, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject;
suspicious
| join kind=inner (
    EmailUrlInfo
    | where Timestamp >= ago(lookback)
    | project NetworkMessageId, Url, UrlDomain
) on NetworkMessageId
| summarize UrlCount=count(), Recipients=dcount(RecipientEmailAddress), Examples=make_set(Url, 10) by SenderFromDomain, SenderFromAddress, Subject
| order by UrlCount desc
```

### 15. URLs de Bajo Rédito / TLDs de Riesgo
Identifica dominios con TLDs inusuales (ej. `.xyz`, `.top`) que han sido entregados y clicados.

```kql
let Lookback = 14d;
let risky_tlds = dynamic([".top",".xyz",".click",".monster",".fit",".rest",".lol",".casa"]);
let delivered_urls = EmailEvents
    | where Timestamp > ago(Lookback)
    | where DeliveryLocation in ("Inbox","Folder","JunkFolder")
    | join kind=inner (EmailUrlInfo | where Timestamp > ago(Lookback)) on NetworkMessageId
    | extend Tld = tostring(extract(@"(\.[A-Za-z0-9\-]{2,})$", 1, UrlDomain))
    | where Tld in (risky_tlds)
    | project Timestamp, RecipientEmailAddress, SenderFromAddress, Url, UrlDomain, NetworkMessageId;
delivered_urls
| join kind=leftsemi (UrlClickEvents | where Timestamp > ago(Lookback) | project NetworkMessageId) on NetworkMessageId
| summarize Clics=count() by UrlDomain
| order by Clics desc
```

### 16. Campaña Activa: Múltiples Clics en misma URL

```kql
let Lookback = 7d;
UrlClickEvents
| where Timestamp > ago(Lookback)
| summarize DistinctVictims=dcount(RecipientEmailAddress), FirstClick=min(Timestamp), LastClick=max(Timestamp) by Url
| where DistinctVictims >= 3
| order by DistinctVictims desc, LastClick desc
```

### 17. Bloqueos de Safe Links

```kql
let Lookback = 14d;
UrlClickEvents
| where Timestamp > ago(Lookback)
| where ClickVerdict in ("Blocked","BlockedBySafeLinks")
| summarize BlockedClicks=count(), Victims=dcount(RecipientEmailAddress) by UrlDomain
| order by BlockedClicks desc
```

### 18. Adjuntos de Riesgo (Ejecutables/Scripts)

```kql
let Lookback = 14d;
let risky_ext = dynamic([".html",".htm",".hta",".js",".vbs",".wsf",".lnk",".iso",".img",".dll",".exe",".ps1",".bat",".cmd",".jar"]);
EmailAttachmentInfo
| where Timestamp > ago(Lookback)
| extend Ext = tolower(tostring(extract(@"\.[^.]+$", 0, FileName)))
| where Ext in (risky_ext)
| join kind=inner (EmailEvents | where DeliveryLocation in ("Inbox","Folder","JunkFolder")) on NetworkMessageId
| summarize count(), DistinctRecipients=dcount(RecipientEmailAddress) by Ext, SenderFromAddress
| order by count_ desc
```

### 19. Adjuntos HTML/HTA con Data URI
Detecta adjuntos HTML que usan `data:text/html` para ofuscar contenido malicioso.

```kql
let Lookback = 14d;
EmailAttachmentInfo
| where Timestamp > ago(Lookback)
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
let Lookback = 14d;
let Baseline = 45d;
let recent = EmailEvents
  | where Timestamp > ago(Lookback)
  | extend SenderDomain = tostring(split(SenderFromAddress, "@")[1])
  | summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Cnt=count() by SenderDomain;
let historical = EmailEvents
  | where Timestamp between (ago(Baseline) .. ago(Lookback))
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
let Lookback = 30d;
CloudAppEvents
| where Timestamp > ago(Lookback)
| where ActionType == "UserSubmission"
| summarize Reports=count() by UserId
| order by Reports desc
```

### 22. Top Targets (Pareto de Riesgo)
Usuarios que más reciben amenazas vs. usuarios que más hacen clic.

```kql
let Lookback = 30d;
let delivered_threats = EmailEvents
  | where Timestamp > ago(Lookback)
  | where ThreatTypes has_any ("Phish","Malware","CredentialPhish");
let clicked = UrlClickEvents
  | where Timestamp > ago(Lookback)
  | summarize Clicks=count() by RecipientEmailAddress;
delivered_threats
| summarize Delivered=count(), DistinctSenders=dcount(SenderFromAddress) by RecipientEmailAddress
| join kind=leftouter clicked on RecipientEmailAddress
| extend Clicks = coalesce(Clicks, 0)
| order by Delivered desc, Clicks desc
```

### 23. Reglas de Bandeja de Entrada "Post-Compromiso"
Detecta reglas de reenvío a direcciones externas creadas recientemente.

```kql
let Lookback = 7d;
EmailEvents
| where Timestamp > ago(Lookback)
| where ActionType == "InboxRuleCreated" or ActionType == "InboxRuleUpdated"
| extend Rule = parse_json(AdditionalDetails)
| extend FwdTo = tostring(Rule.ForwardTo)
| where isnotempty(FwdTo) and not(FwdTo endswith "@contoso.com")
| project Timestamp, AccountUpn, FwdTo, SenderFromAddress, IPAddress, Subject
| order by Timestamp desc
```

### 24. Clics desde Ubicaciones Atípicas
Compara el país del clic actual contra el histórico del usuario.

```kql
let Lookback = 14d;
let baseline = UrlClickEvents
  | where Timestamp between (ago(60d) .. ago(Lookback))
  | summarize BaselineCountries=make_set(RecipientCountry) by RecipientEmailAddress;
UrlClickEvents
| where Timestamp > ago(Lookback)
| join kind=leftouter baseline on RecipientEmailAddress
| extend Known=set_has_element(BaselineCountries, RecipientCountry)
| where Known == false
| summarize Clicks=count() by RecipientEmailAddress, RecipientCountry
| order by Clicks desc
```

### 25. Top Campañas Activas
Vista resumen tipo "Threat Explorer" agrupada por asunto y dominio.

```kql
let Lookback = 7d;
EmailEvents
| where Timestamp > ago(Lookback)
| where DeliveryLocation in ("Inbox","Folder","JunkFolder")
| summarize Msgs=count(), Victims=dcount(RecipientEmailAddress), Senders=dcount(SenderFromAddress) by SenderFromDomain, Subject
| order by Msgs desc
```

---

## 🛡️ Efectividad de Defensa & Post-Delivery

### 26. Mensajes Remediados Post-Entrega (ZAP)

```kql
let lookback = 7d;
EmailPostDeliveryEvents
| where Timestamp >= ago(lookback)
| where ActionType in ("ZAP","Quarantine","SoftDelete","HardDelete")
| project Timestamp, NetworkMessageId, ActionType, ActionResult, RecipientEmailAddress
| order by Timestamp desc
```

### 27. Evasión Inicial + ZAP Posterior
Detecta mensajes que entraron limpios (sin detección inicial) pero fueron remediados después.

```kql
let Lookback = 14d;
EmailPostDeliveryEvents
| where Timestamp > ago(Lookback)
| where ActionType in ("SoftDelete","MoveToQuarantine","ZAP")
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(Lookback)
    | where DetectionMethods !has "PhishFilter" and ThreatTypes == ""
) on NetworkMessageId
| project Timestamp, ActionType, RecipientEmailAddress, SenderFromAddress, Subject, NetworkMessageId
| order by Timestamp desc
```

### 28. Bypass por Allow/Override
Revisa correos permitidos por políticas de organización o overrides de usuario/admin.

```kql
let Lookback = 30d;
EmailEvents
| where Timestamp > ago(Lookback)
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
| where DeliveryAction == "Delivered"
| where ThreatTypes != ""
| project
    Timestamp,
    NetworkMessageId,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    ThreatTypes,
    DetectionMethods,
    ConfidenceLevel,
    DeliveryLocation
| order by Timestamp desc
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
EmailAttachmentInfo
| where MalwareFilterVerdict != "Clean"
| project
    Timestamp,
    NetworkMessageId,
    FileName,
    MalwareFilterVerdict,
    DetectionMethods
```

### 31. Enlaces maliciosos entregados
Identifica URLs con algún tipo de amenaza detectada que fueron incluidas en correos entregados.

```kql
EmailUrlInfo
| where UrlThreatType != "None"
| project
    Timestamp,
    NetworkMessageId,
    Url,
    UrlThreatType,
    DetectionMethods
```

  > Internal Tools 2026