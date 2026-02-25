# Reglas básicas de flujo de correo – Microsoft 365

A continuación encontrará reglas básicas de flujo de correo que son **altamente recomendadas** agregar para mejorar la postura de seguridad de Microsoft 365.

## Objetivos

- Bloqueo de correos enviados a `mydominio.onmicrosoft.com` y `mydominio.mail.onmicrosoft.com`
- Bloqueo de correos que no pueden ser analizados (enviados a cuarentena)

---

## Regla de flujo de correo para bloquear correos enviados a mydominio.onmicrosoft.com y mydominio.mail.onmicrosoft.com

### Opción 1: Script automatizado descargue el script que ejecuta esta tarea: [Block-onmicrosoftEmails](https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/Block-OnMicrosoftEmails.ps1)

### Opción 2: Creación manual

**Nota:** Reemplace `mydomain` con el dominio base del tenant.

#### Pasos

1. Ir a https://admin.exchange.microsoft.com/#/transportrules
2. Hacer clic en **+ Add a rule**
3. Seleccionar **Create a new rule**
4. Nombre: **Block emails sent to mydomain.onmicrosoft.com**
5. Apply this rule if: **The message headers** → **matches these text patterns**
6. En **Enter text**, especificar el header **To** y guardar
7. En **Enter words**, agregar:
   - `@mydomain\.onmicrosoft.com`
   - `@mydomain\.mail\.onmicrosoft.com`
8. Do the following: **Block the message** → **Delete the message without notifying anyone**
9. Next
10. Rule mode: **Enforce**
11. Severity: **High**
12. Marcar **Defer the message if rule processing doesn't complete**
13. Next
14. Finish

#### Referencias

- Mail flow rules (transport rules) in Exchange Online  
  https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules
- New-TransportRule (Exchange PowerShell)  
  https://learn.microsoft.com/en-us/powershell/module/exchange/new-transportrule

---

## Regla de flujo de correo para bloquear correos que no pueden ser inspeccionados

### Opción 1: Script automatizado descargue el script que ejecuta esta tarea [Quarantine Attachments Can’t be inspected](https://github.com/watchdogcode/gol2026/blob/V2.1/MDO/Quarantine%20Attachments%20Can%C2%B4t%20be%20inspected.ps1)

### Opción 2: Creación manual

#### Pasos

1. Ir a https://admin.exchange.microsoft.com/#/transportrules
2. Hacer clic en **+ Add a rule**
3. Seleccionar **Create a new rule**
4. Nombre: **Quarantine Attachments Can’t be inspected**
5. Apply this rule if: **Any attachment** → **content can’t be inspected**
6. Do the following: **Redirect the message to** → **Hosted quarantine**
7. Next
8. Rule mode: **Enforce**
9. Severity: **High**
10. Next
11. Finish

#### Referencia

- Inspect message attachments – Microsoft Learn  
  https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/inspect-message-attachments
