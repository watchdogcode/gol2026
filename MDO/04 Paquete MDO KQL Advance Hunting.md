# 🛡️ Paquete de Consultas KQL (Advanced Hunting)

Este documento recopila una serie de consultas KQL (Kusto Query Language) diseñadas para la detección, triaje e investigación de amenazas en Microsoft Defender XDR.

**Autores:** Ernesto Cobos Roqueñí, Arturo Mandujano

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