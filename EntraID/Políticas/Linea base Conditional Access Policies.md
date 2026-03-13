# Conditional Access Templates (Microsoft Entra) 🛡️
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*
## Prerrequisitos
- Tener al menos una cuenta **break-glass** excluida de Conditional Access.
- Siempre iniciar políticas en **Report-only**.

---

## Require multifactor authentication for all users

### Objetivo
Requiere que **todos los usuarios** completen **autenticación multifactor (MFA)** al acceder a los recursos de la organización, como una medida base para reducir el riesgo de compromiso de credenciales

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
Requiere que las **cuentas administrativas** utilicen **métodos de MFA resistentes al phishing** para proteger los roles con mayor impacto sobre la seguridad del tenant.

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
Requiere MFA cuando Microsoft Entra ID detecta un **riesgo medio o alto en el inicio de sesión**, utilizando señales de riesgo para aplicar protección adaptativa.

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
Bloquea los intentos de inicio de sesión que usan **protocolos de autenticación heredados**, los cuales no admiten MFA y son comúnmente utilizados en ataques de fuerza bruta y password spray

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


