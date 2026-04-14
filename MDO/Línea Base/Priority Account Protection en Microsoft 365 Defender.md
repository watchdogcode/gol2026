# Priority Account Protection en Microsoft 365 Defender 🛡️

## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

**Autores:** Ernesto Cobos Roqueñí, Arturo Mandujano

---

## 1. Priority Account Protection 

Es un mecanismo de clasificación de identidades de alto valor (High Value Targets – HVT) dentro de Microsoft 365 Defender.

No es solo una “etiqueta visual” al marcar un usuario como Priority account, el motor de detección modifica el modelo de riesgo, aumenta la sensibilidad de detecciones y eleva automáticamente la severidad de alertas e incidentes relacionados con correo, identidad y colaboración.

El objetivo es reducir el dwell time y el impacto de ataques dirigidos (phishing, BEC, account takeover) contra usuarios críticos para el negocio.

Todas las organizaciones tienen cuentas de alto valor, como ejecutivos y la alta dirección que, debido a su acceso a información sensible o de alta prioridad, tienen una mayor tasa de ataque. Algunas de estas cuentas pueden ser muy visibles (por ejemplo, listadas en un sitio web público) y, por lo tanto, ser más fáciles de investigar y atacar para un atacante mediante técnicas cada vez más sofisticadas. 

Aplicar una etiqueta de "Cuenta prioritaria" en estas cuentas permitirá a Defender para Office 365 escanear los correos electrónicos enviados a estas cuentas con heurísticas adicionales que están específicamente diseñadas para ejecutivos de la empresa con el fin de detectar estas amenazas, al mismo tiempo que se minimizan los falsos positivos.

Aplicar una etiqueta de usuario como "Cuenta prioritaria" también permite a los equipos de seguridad priorizar su enfoque al tratar con investigaciones y alertas.

---

## 2. Mejor práctica recomendada

- Las organizaciones NO deben tratar todas las identidades igual
- Los atacantes priorizan ejecutivos y roles con poder de decisión

El control recomendado es:

- Identificar HVT
- Clasificarlos explícitamente
- Aplicar lógica de detección diferenciada

Microsoft implementa esta práctica mediante:

- Priority Account Protection
- Integración con:
  - Defender for Office 365
  - Microsoft 365 Defender Incidents
  - Señales de Identity, Email y Collaboration

> Este control soporta:
>
> - Zero Trust → Assume Breach
> - NIST SP 800‑53 → IA‑2, IR‑4, IR‑5
> - MITRE ATT&CK → TA0001 (Initial Access), TA0006 (Credential Access)

## 3. Paso a paso completo para implementación (con profundidad técnica)

### Fase 1 – Habilitar el feature a nivel organización
**Ruta:**
Microsoft 365 Defender → Settings → Email & collaboration → Priority account protection

**Qué ocurre internamente:**

- Se habilita un flag organizacional
- Defender empieza a evaluar userTags en el pipeline de detección

Sin este flag:

- Los tags existen
- Pero NO afectan detecciones ni severidad

Este paso es obligatorio y frecuentemente olvidado

### Fase 2 – Definir formalmente qué es un Priority Account
**Buenas prácticas reales (no teóricas):**

| Categoría | Ejemplo | Motivo |
|---------|--------|--------|
| Ejecutivos | CEO, CFO, CIO | Objetivo clásico de BEC |
| Dirección | Managers, Heads | Autoridad operacional |
| Finanzas | AP, AR, Payroll | Capacidad de pago |
| Legal / HR | Legal Counsel, HR BP | Datos sensibles |
| Asistentes | Executive Assistants | Puente hacia ejecutivos |

No confundir con cuentas privilegiadas

Un Priority Account:

- Puede no ser admin
- Pero su impacto de compromiso es alto

### Fase 3 – Asignación del tag “Priority account”

**Opción A – Microsoft 365 Defender Portal**
Settings → Email & collaboration → User tags

https://security.microsoft.com/securitysettings/userTags

**Opción B – Microsoft 365 Admin Center**
Users → Active users → Manage priority accounts

https://admin.microsoft.com/Adminportal/#/priorityaccounts

**Qué ocurre técnicamente:**

- El usuario recibe un tag lógico interno
- Ese tag es consumido por:
  - Anti‑Phishing engine
  - Incident correlation engine
  - Alert prioritization logic

**Nota. No es un atributo visible en Entra ID ni Graph estándar**

### Fase 4 – Qué cambia realmente cuando un usuario es Priority Account

#### 1 Detecciones más sensibles

- **Phishing dirigido:**
  - Umbral más bajo para generar alerta
- **BEC:**
  - Mayor peso a anomalías de remitente/contenido
- **Spoofing:**
  - Incrementa score de riesgo

#### 2 Elevación automática de severidad

Ejemplo:

- Usuario normal → Alert = Medium
- Priority Account → Alert = High

Esto afecta:

- Alertas
- Incidentes
- Playbooks automáticos

#### 3 Correlación preferente en Incidents

- Defender correlaciona primero eventos de Priority Accounts
- Se reduce el riesgo de que un ataque pase desapercibido entre ruido

#### 4️ Visibilidad SOC

- Incidentes resaltados
- Mayor probabilidad de:
  - Auto‑investigation
  - Auto‑remediation
  - Escalamiento automático

## 4. Ejemplos de scripts, queries y automatizaciones

**Nota importante:** Microsoft no expone aún el tag Priority Account vía Graph, por lo que el monitoreo es indirecto, vía incidentes y señales.

### a) PowerShell – Listar usuarios con Priority Account

```powershell
# Requiere Microsoft Graph
Connect-MgGraph -Scopes User.Read.All

Get-MgUser -All |
Where-Object {
    $_.SecurityIdentifier -ne $null
} |
Select DisplayName, UserPrincipalName, UserType
```

**Nota:** El tag Priority Account no es visible aún vía Graph estándar; se valida vía portal y señales Defender.


### b) KQL – Incidentes que involucran Priority Accounts
```kql
SecurityIncident
| where Entities has "Priority"
| project TimeGenerated, IncidentNumber, Title, Severity, Status, Classification
```

Uso:

- Dashboard SOC
- Evidencia SOA
- Seguimiento HVT

### C) KQL – Phishing dirigido a ejecutivos
```kql
EmailEvents
| where ThreatTypes has "Phish"
| where RecipientEmailAddress in (
    "ceo@contoso.com",
    "cfo@contoso.com"
)
| project TimeGenerated, SenderFromAddress, Subject, ThreatTypes
```

### d) KQL – Detectar alertas relacionadas con Priority Accounts

```kql
SecurityIncident
| where Title has_any ("Phish", "BEC", "Email", "Compromise")
| where Entities has "Priority"
| project TimeGenerated, Title, Severity, Status, IncidentNumber
```



### e) KQL – Sign‑ins de alto riesgo en Priority Accounts
```kql
SigninLogs
| where UserPrincipalName in (
    "ceo@contoso.com",
    "cfo@contoso.com"
)
| where RiskLevelDuringSignIn in ("medium","high")
| project TimeGenerated, UserPrincipalName, IPAddress, RiskLevelDuringSignIn
```

### f) Ejemplo de alerta automatizada (Sentinel)

**Nombre:** Priority Account – High Risk Activity

**Condición:**

- Usuario HVT
- Riesgo Medium/High
- Phishing o sign‑in anómalo

**Acciones:**

- Crear incidente
- Notificar SOC
- Forzar password reset
- Requerir MFA
- Bloquear sesión (Conditional Access)

**Útil para:**

- Dashboards SOC
- Auditorías SOA
- Evidencia de control


## 5. Notas y advertencias críticas

- No reemplaza MFA ni Conditional Access
- No protege cuentas de servicio
- No sobre‑etiquetar (fatiga SOC)
- Revisar lista cada trimestre
- Documentar criterio HVT (auditoría)

**Errores comunes:**

- Pensar que es solo “visual”
- No habilitar el feature
- No correlacionarlo con procesos SOC

## 6. Referencias oficiales

- https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/introducing-differentiated-protection-for-priority-accounts-in-microsoft-defende/3283838
- https://learn.microsoft.com/microsoft-365/security/defender/priority-account-protection
- https://learn.microsoft.com/microsoft-365/security/office-365-security/anti-phishing-policies
- https://learn.microsoft.com/microsoft-365/security/defender/incidents-overview
- https://learn.microsoft.com/security/zero-trust/
- https://learn.microsoft.com/en-us/defender-office-365/priority-accounts-turn-on-priority-account-protection?view=o365-worldwide

---

