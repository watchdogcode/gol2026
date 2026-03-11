# 🛡️ Principio de Menor Privilegio
## Líneas base de seguridad para cuentas privilegiadas  
**Microsoft Entra ID / Microsoft 365**

---

## 1. No more than four permanent Global Administrators

### Línea base
La organización debe mantener **un máximo de cuatro (4) cuentas con el rol Global Administrator asignado de forma permanente**.  
Estas cuentas se distribuyen de la siguiente manera:

- **Dos (2) deben ser cuentas de emergencia (Break Glass / Emergency Access Accounts)**  
- **Dos (2) pueden ser cuentas administrativas nominales permanentes**, asignadas a personal altamente confiable

No deben existir más cuentas con Global Administrator permanente fuera de este modelo.  
Cualquier requerimiento adicional de privilegios Global Administrator debe gestionarse **exclusivamente mediante acceso temporal (Just‑In‑Time)** utilizando **Privileged Identity Management (PIM)**.

---

###  Break Glass Accounts (2 cuentas)

Cuentas dedicadas exclusivamente a escenarios de emergencia, tales como:
- Bloqueos por Conditional Access
- Fallas de MFA
- Caídas de federación o identidad
- Errores de configuración que impidan acceso administrativo

**Requisitos obligatorios:**
- Cloud‑only (no sincronizadas desde Active Directory on‑premises)
- Rol **Global Administrator** asignado de forma permanente
- Excluidas de todas las políticas de Conditional Access
- Uso estrictamente limitado a emergencias
- Monitoreo y alertas ante cualquier inicio de sesión

---

###  Global Administrators nominales (2 cuentas)

Cuentas administrativas asociadas a personas específicas, responsables de la operación crítica del tenant.

**Características:**
- Pueden ser **permanentes**
- Uso **controlado y excepcional**
- Preferentemente gestionadas mediante **Privileged Identity Management (PIM)**
- Actividad sujeta a auditoría y revisión periódica

---

## 2. Separate user and administrative accounts

### Línea base
Todo personal con responsabilidades administrativas debe contar con:
- **Una cuenta de usuario estándar** para actividades diarias (correo, Teams, navegación)
- **Una cuenta administrativa separada**, utilizada únicamente para tareas privilegiadas

Las cuentas de usuario **no deben tener roles administrativos asignados**.

### Justificación
Las cuentas de uso diario están expuestas a phishing, malware e ingeniería social.  
Separar identidades evita que un compromiso común derive en acceso administrativo.

---

## 3. Use named accounts, avoiding shared accounts

### Línea base
Todas las cuentas con privilegios administrativos deben ser **cuentas nominales**, asociadas a una persona específica.  
El uso de **cuentas compartidas está prohibido**.

### Justificación
Las cuentas compartidas eliminan trazabilidad, impiden atribución de acciones y dificultan investigaciones forenses y auditorías.

---

## 4. Use cloud-only accounts for any privileged role

### Línea base
Todas las cuentas con roles privilegiados (Global Admin, Privileged Role Admin, Security Admin, etc.) deben ser **cloud‑only**:
- No sincronizadas desde Active Directory on‑premises
- No federadas con infraestructura local

### Justificación
Un compromiso del AD on‑premises puede propagarse al entorno cloud si las cuentas privilegiadas están sincronizadas.  
Las cuentas cloud‑only aíslan el plano de control del tenant.

---

## 5. Require Multi-Factor Authentication (MFA) for all privileged accounts

### Línea base
**Todas las cuentas privilegiadas** deben tener **MFA habilitado obligatoriamente**, incluyendo:
- Global Administrators
- Break Glass Accounts
- Privileged Role Administrators
- Security, Exchange y Compliance Administrators

Siempre que sea posible, se debe utilizar **MFA resistente a phishing (Phishing‑Resistant MFA)** como método preferido.

---

### Métodos de autenticación recomendados

**Orden de preferencia:**
1. Phishing‑resistant MFA  
   - FIDO2 / Passkeys  
   - Certificate‑based authentication  
2. Microsoft Authenticator con number matching  
3. Métodos legacy (SMS, llamadas) **no recomendados**

---

### Consideraciones para Break Glass Accounts
- Al menos una cuenta debe garantizar acceso incluso ante fallas de Conditional Access
- MFA no debe depender de dispositivos personales
- Las credenciales deben almacenarse de forma segura
- Todo uso debe generar alertas de alta criticidad

---

##  Resumen Ejecutivo

| Control | Objetivo | Beneficio |
|------|--------|---------|
| ≤ 4 Global Admin permanentes | Reducir superficie de ataque | Menor riesgo de control total |
| 2 Break Glass Accounts | Resiliencia operativa | Evitar tenant lockout |
| Separación de cuentas | Contención | Protección ante phishing |
| Cuentas nominales | Trazabilidad | Auditoría e investigación |
| Cuentas cloud‑only | Aislamiento | Protección híbrida |
| MFA obligatorio (phishing‑resistant) | Prevención de ATO | Protección de identidades críticas |

---