# Revisar regularmente las asignaciones de roles Privilegiados 🛡️
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*
 
**Autores:** Ernesto Cobos Roqueñí & Arturo Mandujano Avila

---

## Las cuentas privilegiadas tienen un amplio rango de acceso a los datos sensibles de su empresa. Es fundamental que estas cuentas estén protegidas y sean monitoreadas.

**Su organización debe implementar mecanismos para reportar sobre las cuentas administrativas, al menos de forma semestral, considerando lo siguiente:**

- El colaborador sigue en la organización: los empleados se incorporan y abandonan las organizaciones, por lo que es importante llevar un control de las cuentas administrativas asignadas.

- Roles sensibles que no están conectados a Microsoft Entra, por ejemplo (sin limitarse a ello), los roles de **Security and Compliance eDiscovery Manager** y **Administrator**.

- El rol sigue siendo relevante para el usuario: es posible que el usuario ya no requiera ese rol, o que se haya lanzado un nuevo rol en Office 365 que se ajuste mejor.

- Se requiere autenticación multifactor: MFA debe ser obligatoria para todas las cuentas administrativas, considerando su alto nivel de privilegio.

- La autenticación multifactor está registrada: si MFA está habilitada pero no registrada, un atacante podría iniciar sesión solo con la contraseña y configurar su propio segundo factor de autenticación.

- La cuenta está activa.

## Proceso de Revisión

Establezca un proceso que deje claro:

- Con qué frecuencia revisar las asignaciones de roles, al menos una vez cada seis meses (pueden existir diferentes intervalos según el rol).

- Cómo se llevará a cabo la revisión:
  - Manualmente
  - Mediante scripts
  - A través de automatización de flujos de trabajo (por ejemplo, **Access Reviews en Microsoft Entra Privileged Identity Management**)

- Quiénes serán los responsables en la organización de realizar la revisión.

- Quiénes deben ser informados cuando se ejecuten acciones.

## Script de Ejemplo

Existe un script de ejemplo disponible que enumera los usuarios asignados a roles en [Get-M365RoleReport.ps1](../Scripts/Get-M365RoleReport.ps1)


---

## Revisiones de acceso – Privilege Identity Management (PIM)

Use PIM para programar revisiones de acceso únicas o recurrentes para revisar las asignaciones de roles de los administradores inactivos

Se puede configurar a los miembros (ellos mismos) o a su gerente para aprobar/rechazar la renovación