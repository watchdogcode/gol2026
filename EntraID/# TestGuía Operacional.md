# Guía Operacional
## Revisión de Usuarios e Inicios de Sesión con Riesgo  
### Microsoft Entra ID Protection (P2)

**Branding:**  
Microsoft Security | Zero Trust | Identity First  
SOC / IAM Operations Runbook  

---

## Objetivo
Identificar, analizar y responder a **usuarios e inicios de sesión con riesgo Alto o Medio** utilizando Microsoft Entra ID Protection (P2), reduciendo el riesgo de compromiso de identidad, abuso de credenciales y movimiento lateral.

---

## Alcance
- SOC
- IAM Operations
- Blue Team
- Auditoría de Seguridad (ISO 27001 / Zero Trust)

---

## Prerrequisitos
- Licenciamiento **Microsoft Entra ID P2**
- Rol: Security Administrator / Global Reader / Security Reader
- Acceso al portal Microsoft Entra

---

## 1. Revisión de Usuarios con Riesgo (Alto / Medio)

### Paso 1 – Acceso
Portal Microsoft Entra  
`Protección > Identity Protection`

### Paso 2 – Usuarios en Riesgo
URL directa:  
https://entra.microsoft.com/#view/Microsoft_AAD_IAM/IdentityProtectionUsersBlade

### Paso 3 – Filtros recomendados
- Nivel de riesgo: **Alto, Medio**
- Estado del riesgo: **Activo**
- (Opcional) Tipo de riesgo, ubicación, fecha

### Paso 4 – Análisis por usuario
Revisar:
- Nivel de riesgo actual
- Tipo de riesgo:
  - Password Spray
  - Anonymous IP
  - Impossible Travel
  - Leaked Credentials
- Última actividad riesgosa
- Estado: Active / Remediated / Dismissed

### Paso 5 – Acciones operativas
- Forzar cambio de contraseña
- Requerir MFA
- Confirmar actividad con el usuario
- Marcar como **Remediated** si fue mitigado

Referencia:  
https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks

---

## 2. Revisión de Inicios de Sesión con Riesgo

### Paso 6 – Inicios con Riesgo
URL directa:  
https://entra.microsoft.com/#view/Microsoft_AAD_IAM/IdentityProtectionSignInsBlade

### Paso 7 – Filtros
- Nivel de riesgo: **Alto, Medio**
- Estado: Activo
- Aplicación, IP, Ubicación

### Paso 8 – Análisis del evento
Revisar:
- Usuario afectado
- Aplicación objetivo
- Dirección IP / País
- Tipo de riesgo
- Resultado: Success / Failure / Interrupted

Referencia:  
https://learn.microsoft.com/entra/id-protection/concept-identity-protection-sign-in-risk

---

## 3. Validación de Acceso Condicional basado en Riesgo

### Paso 9 – Verificar políticas
`Protección > Acceso Condicional`

Confirmar:
- User Risk Policy
- Sign-in Risk Policy

Controles esperados:
- Riesgo Alto: **Bloquear acceso**
- Riesgo Medio: **Requerir MFA / Cambio de contraseña**

Referencia:  
https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies

---

## 4. Correlación Avanzada (Defender XDR / Sentinel)

### KQL – Correlación Usuario Riesgoso + Actividad Endpoint
```kql
IdentityInfo
| where RiskLevel in ("High","Medium")
| join kind=inner (
    DeviceLogonEvents
    | where Timestamp > ago(7d)
) on AccountUpn
| project Timestamp, AccountUpn, RiskLevel, DeviceName, LogonType, IPAddress