# Guía paso a paso – Conditional Access Templates (Microsoft Entra)
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*
## Prerrequisitos
- Tener al menos una cuenta **break-glass** excluida de Conditional Access.
- Siempre iniciar políticas en **Report-only**.

---

## Require multifactor authentication for all users

### Objetivo
Requerir MFA para todos los usuarios del tenant.

### Pasos
1. Ir a https://entra.microsoft.com
2. Entra ID → Protection → Conditional Access
3. **Create new policy from template**
4. Categoría: **Secure foundation**
5. Template: **Require multifactor authentication for all users**
6. Review + Create

### Configuración
- Users: Include **All users**
- Exclude: Break-glass y cuenta admin temporal
- Target resources: **All resources**
- Grant: **Require multifactor authentication**
- Enable policy: **Report-only**

---

## Require phishing-resistant multifactor authentication for administrators

### Objetivo
Proteger cuentas administrativas con MFA resistente a phishing.

### Pasos
1. Conditional Access → Create new policy from template
2. Categoría: **Protect administrators**
3. Template: **Require phishing-resistant multifactor authentication for administrators**
4. Review + Create

### Configuración
- Target: **Directory roles** (roles admin críticos)
- Grant: **Require authentication strength → Phishing-resistant MFA**
- Exclude: Break-glass
- Enable policy: **Report-only**

**Registrar previamente FIDO2 o Windows Hello for Business.**

---

## Require multifactor authentication for risky sign-ins

### Objetivo
Solicitar MFA cuando el riesgo de inicio de sesión sea medio o alto.

### Pasos
1. Create new policy from template
2. Categoría: **Emerging threats**
3. Template: **Require multifactor authentication for risky sign-ins**
4. Review + Create

### Configuración
- Condition: Sign-in risk **Medium** y **High**
- Grant: **Require MFA**
- Exclude: Break-glass
- Enable policy: **Report-only**

---

## Block legacy authentication

### Objetivo
Bloquear autenticación heredada que no soporta MFA.

### Pasos
1. Create new policy from template
2. Categoría: **Secure foundation**
3. Template: **Block legacy authentication**
4. Review + Create

### Configuración
- Users: Include **All users**
- Exclude: Break-glass (y cuentas legacy justificadas)
- Conditions → Client apps: **Exchange ActiveSync** y **Other clients**
- Grant: **Block access**
- Enable policy: **Report-only**

---

## Orden recomendado de despliegue
1. MFA for all users
2. Phishing-resistant MFA for admins
3. MFA for risky sign-ins
4. Block legacy authentication

---


