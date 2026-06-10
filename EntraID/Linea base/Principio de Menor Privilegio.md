# Principio de Menor Privilegio 🛡️
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

**Microsoft Entra ID / Microsoft 365**

**Autores:** [Ernesto Cobos Roqueñí](https://www.linkedin.com/in/ernesto-cobos/) & [Arturo Mandujano](https://www.linkedin.com/in/jose-arturo-mandujano-avila-621b00b9/)

---

## Índice
1. [No mas de cuatro Global Administrators permanentes](#1-no-mas-de-cuatro-global-administrators-permanentes)
2. [Separar las cuentas de usuario y administrativas](#2-separar-las-cuentas-de-usuario-y-administrativas)
3. [Usa cuentas nombradas, evitando cuentas compartidas](#3-usa-cuentas-nombradas-evitando-cuentas-compartidas)
4. [Utilice cuentas solo en la nube para cualquier rol privilegiado](#4-utilice-cuentas-solo-en-la-nube-para-cualquier-rol-privilegiado)
5. [Utilizar Privileged Identity Management (PIM)](#5-utilizar-privileged-identity-management-pim)
6. [Requerir autenticación multifactor (MFA) para todas las cuentas privilegiadas](#5-requerir-autenticación-multifactor-mfa-para-todas-las-cuentas-privilegiadas)
7. [Validación semestral de cuentas privilegiadas](#6-validación-semestral-de-cuentas-privilegiadas)
8. [Resumen Ejecutivo](#resumen-ejecutivo)

---

## 1. No mas de cuatro Global Administrators permanentes

La organización debe mantener **un máximo de cuatro (4) cuentas con el rol Global Administrator asignado de forma permanente**.  
Estas cuentas se distribuyen de la siguiente manera:

- **Dos deben ser cuentas de emergencia (Break Glass / Emergency Access Accounts)**  
- **Dos pueden ser cuentas administrativas nominales permanentes**, asignadas a personal altamente confiable

No deben existir más cuentas con Global Administrator permanente fuera de este modelo.  
Cualquier requerimiento adicional de privilegios Global Administrator debe gestionarse **exclusivamente mediante acceso temporal (Just‑In‑Time)** utilizando **Privileged Identity Management (PIM)**.

---

###  Cuentas de emergecia (Break Glass Accounts)

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

###  Global Administrators

Cuentas administrativas asociadas a personas específicas, responsables de la operación crítica del tenant.

**Características:**
- Pueden ser **permanentes**
- Uso **controlado y excepcional**
- Preferentemente gestionadas mediante **Privileged Identity Management (PIM)**
- Actividad sujeta a auditoría y revisión periódica

---

## 2. Separar las cuentas de usuario y administrativas

Todo personal con responsabilidades administrativas debe contar con:
- **Una cuenta de usuario estándar** para actividades diarias (correo, Teams, navegación)
- **Una cuenta administrativa separada**, utilizada únicamente para tareas privilegiadas

Las cuentas de usuario **no deben tener roles administrativos asignados**.

### Justificación
Las cuentas de uso diario están expuestas a phishing, malware e ingeniería social.  
Separar identidades evita que un compromiso común derive en acceso administrativo.

---

## 3. Usa cuentas nombradas, evitando cuentas compartidas

Todas las cuentas con privilegios administrativos deben ser **cuentas nominales**, asociadas a una persona específica.  
El uso de **cuentas compartidas está prohibido**.

### Justificación
Las cuentas compartidas eliminan trazabilidad, impiden atribución de acciones y dificultan investigaciones forenses y auditorías.

---

## 4. Utilice cuentas solo en la nube para cualquier rol privilegiado

Todas las cuentas con roles privilegiados (Global Admin, Privileged Role Admin, Security Admin, etc.) deben ser **cloud‑only**:
- No sincronizadas desde Active Directory on‑premises
- No federadas con infraestructura local

### Justificación
Un compromiso del AD on‑premises puede propagarse al entorno cloud si las cuentas privilegiadas están sincronizadas.  
Las cuentas cloud‑only aíslan el plano de control del tenant.

---

## 5. Utilizar Privileged Identity Management (PIM)

Es un servicio de Microsoft Entra ID que permite: Controlar, administrar y monitorear el acceso privilegiado a recursos críticos (Entra ID, Azure, Microsoft 365).

### Su objetivo principal es:
- Reducir el riesgo de accesos excesivos
- Evitar privilegios permanentes innecesarios
- Tener visibilidad total sobre quién usa privilegios

### PIM cambia el modelo tradicional de acceso privilegiado por uno controlado y temporal:
**Asignación de roles**

Un usuario recibe un rol de dos formas:

Eligible → no tiene acceso directo, solo puede activarlo cuando lo necesita

Active → tiene acceso permanente (debe minimizarse)

**Activación (Just-In-Time)**

Si el usuario es eligible:

- Solicita activar el rol
- Debe cumplir condiciones como:

   - MFA
   - Justificación
   - Aprobación (opcional)

El acceso se activa solo por un tiempo limitado

**Uso del privilegio**

- El usuario ejecuta tareas administrativas
- Todo queda:

   - Registrado
   - Monitoreado
   - Auditado

**Expiración automática**

-El acceso se elimina al terminar el tiempo configurado
- Evita privilegios persistentes

**Gobierno continuo**

PIM incluye controles de gobierno:

- Access Reviews → validar que el acceso sigue siendo necesario
- Alertas → cuando se elevan privilegios
- Auditoría → historial completo de uso

> **“Los privilegios no deben existir todo el tiempo, solo cuando se necesitan.”**
> Esto implementa directamente:
>
> Least Privilege
> Zero Trust
> Reducción del blast radius
---

## 6. Requerir autenticación multifactor (MFA) para todas las cuentas privilegiadas

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

## 7. Validación semestral de cuentas privilegiadas

Todas las cuentas con roles administrativos deben ser revisadas **al menos cada seis (6) meses** para verificar que siguen siendo necesarias y apropiadas.

Durante cada revisión se debe confirmar lo siguiente:

| Criterio | Descripción |
|----------|-------------|
| **El administrador aún existe en la organización** | La persona asociada a la cuenta sigue siendo empleado o colaborador activo. Cuentas de personal que ya no pertenece a la organización deben ser revocadas de inmediato. |
| **El rol sigue siendo relevante** | La función laboral del administrador aún justifica el nivel de privilegio asignado. Cambios de puesto o responsabilidades pueden hacer innecesario el rol. |
| **Aún necesitan el acceso (prevenir privilege creep)** | Confirmar que el administrador utiliza activamente los privilegios. Acumulación de roles sin uso genera riesgo innecesario. |
| **No existe un rol de menor privilegio disponible** | Microsoft 365 incorpora nuevos roles con frecuencia. Verificar si existe un rol más acotado que cubra las necesidades actuales y reasignar en consecuencia. |
| **MFA está habilitado y registrado** | Verificar que la autenticación multifactor está activa y que el administrador tiene métodos de autenticación registrados y funcionales. |

### Justificación
Las revisiones periódicas previenen la acumulación de privilegios innecesarios (*privilege creep*), detectan cuentas huérfanas y aseguran que los controles de seguridad se mantienen vigentes a lo largo del tiempo.

Con este script se puede validar: [**Get-M365RoleReport**](../Scripts/Get-M365RoleReport.ps1)

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
| Validación semestral | Higiene de privilegios | Detectar cuentas huérfanas y privilege creep |

---

Gol 2026 | Internal Tools