# Alerta de Protección (Monitoreo de cambios de roles) 🛡️
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*
 
**Autores:** Ernesto Cobos Roqueñí & Arturo Mandujano

---

## La asignación de roles sensibles debe ser monitoreada para detectar cambios no autorizados.  

Los roles monitoreados deben incluir, al menos, los siguientes:

- Administrador global  
- Administradores de servicios (Exchange, SharePoint, Teams)  
- Administrador de cumplimiento y Administrador de eDiscovery 
- Administrador de Autenticación

Los roles sensibles y/o privilegiados como Administrador global, administradores de servicios (Exchange, SharePoint, Teams) y Administrador de eDiscovery son objetivos de alto valor.

En un ataque común, un atacante puede utilizar técnicas de movimiento lateral para desplazarse entre diferentes cuentas y elevar permisos.

Asegúrese de que los roles sensibles sean monitoreados para recibir notificaciones en caso de que un atacante haya elevado sus permisos.

---

## Todos los roles sensibles deberían estar siendo monitoreados cuando alguien es asignado a ellos:

---

## Recomendaciones

Implemente el monitoreo de la adición de cuentas a roles sensibles dentro de Microsoft Entra.

### Definición de proceso (RACI)

Defina un proceso y establezca qué usuarios de su empresa deben ser:

- **Responsables (Responsible)**  
- **Aprobadores (Accountable)**  
- **Consultados (Consulted)**  
- **Informados (Informed)**  

Esto debe aplicarse cuando la solución de monitoreo detecte que alguien ha sido asignado a un rol sensible.

### Respuesta ante incidentes

**Defina las acciones que deben tomarse si la elevación de privilegios:**

- No corresponde con el proceso establecido  
- Viola los lineamientos de su organización  

**Considere analizar:**

- Por qué la elevación de privilegios fue posible  
- Qué controles fallaron o no se siguieron  

---

## Implementación de alerta

Puede crear la siguiente política de alerta directamente en PowerShell para generar una alerta cuando una cuenta sea agregada a cualquier rol de Microsoft Entra:

```powershell
New-ProtectionAlert `
  -Category AccessGovernance `
  -Name "Escalación de privilegios - Microsoft Entra" `
  -NotifyUser secops@contoso.com `
  -ThreatType Activity `
  -Operation "Add member to role." `
  -AggregationType None `
  -Severity High
```
**Nota.**

Para crear la Alerta de Protección es necesario el Modulo ExchangeonlineManagement e iniciar sesion con Connect-IPPSSession


#### Referencia
> [New-ProtectionAlert](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-protectionalert?view=exchange-ps)

Internal Tools 2026