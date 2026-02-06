# Monitoreo de Alertas

## Revisar alertas activas 

Ir al portal  [Alerts - Microsoft Defender](https://security.microsoft.com/alerts?tid=0d64d809-2796-406a-af58-54dcf35eca6d)
Seleccione una alerta para abrir el panel de detalles, donde podrá revisar:
* Severidad de la alerta
* Origen de la detección
* Usuarios o activos impactados
* Acciones recomendadas
 
Use la opción **Filter** para filtrar alertas por severidad, servicio o estado.
 
## Investigar alertas 

Desde los detalles de la alerta, seleccione **View full details**.
Revise:
* **Alert Storyline** (línea de tiempo de eventos relacionados)
* Correo o archivo involucrado
* Estado de la investigación automatizada (si está habilitada)
 
Seleccione **Investigate** para iniciar una investigación automática o manual.
 
> Las investigaciones automáticas forman parte del flujo de protección contra amenazas de Microsoft Defender (capacidad general del ecosistema Defender).
 
---

# Monitoreo de Incidentes

Ir al portal **[Incidents - Microsoft Defender](https://nam06.safelinks.protection.outlook.com/?url=https%3A%2F%2Fsecurity.microsoft.com%2Fincidents%3Ftid%3D0d64d809-2796-406a-af58-54dcf35eca6d&data=05%7C02%7Cjomand%40microsoft.com%7C27aab460f2e148e8325808de64defca6%7C72f988bf86f141af91ab2d7cd011db47%7C1%7C0%7C639059106031937678%7CUnknown%7CTWFpbGZsb3d8eyJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiOiJXaW4zMiIsIkFOIjoiTWFpbCIsIldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=07QCGbVk5KYwc%2BTRpq2oNZoBOcMHi6ViShDXN4aZliA%3D&reserved=0)**
En el panel de Incidentes configurar los siguientes filtros:
* **Periodo:** 1 Dia
* **Estado:** Nuevo y En curso
* **Severidad de alerta:** Ordenar descendente (Alta → Media → Baja)
* **Prioridad de marcador:** 15-100
* **Workspaces:** Any

Guardar la vista personalizada para uso futuro

Revisar columnas clave:
* **Severity** (Gravedad)
* **Status** (Estado)
* **Assigned to** (Asignado a)
* **Tags** (Etiquetas)

---

# Triage de Mensajes de Teams Reportados por Usuarios

## Verificar que el reporte esté habilitado

1. Ir a **[Messaging policies - Microsoft Teams admin center](https://nam06.safelinks.protection.outlook.com/?url=https%3A%2F%2Fadmin.teams.microsoft.com%2Fpolicies%2Fmessaging&data=05%7C02%7Cjomand%40microsoft.com%7C27aab460f2e148e8325808de64defca6%7C72f988bf86f141af91ab2d7cd011db47%7C1%7C0%7C639059106031975526%7CUnknown%7CTWFpbGZsb3d8eyJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiOiJXaW4zMiIsIkFOIjoiTWFpbCIsIldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=OEIHk2LdNkPZ%2BtXEzia2gQksvKkwuxKzy3kI%2F5ykQVY%3D&reserved=0)**
2. Abrir la política **Global (Org‑wide default)**.
3. Confirmar que **Report inappropriate content** y **Report a security concern** estén habilitados.
4. Ir a **[Email & collaboration - Microsoft Defender](https://nam06.safelinks.protection.outlook.com/?url=https%3A%2F%2Fsecurity.microsoft.com%2Fsecuritysettings%2FuserSubmission%3Ftid%3D0d64d809-2796-406a-af58-54dcf35eca6d&data=05%7C02%7Cjomand%40microsoft.com%7C27aab460f2e148e8325808de64defca6%7C72f988bf86f141af91ab2d7cd011db47%7C1%7C0%7C639059106031986928%7CUnknown%7CTWFpbGZsb3d8eyJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiOiJXaW4zMiIsIkFOIjoiTWFpbCIsIldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=JU9OCSXIo64smQT4I%2Bx%2FU95tf%2BgZoD0t4FtJ8mddiEI%3D&reserved=0)**
5. Desplazarse a la sección **Microsoft Teams**.
6. Verificar que **Monitor reported messages in Microsoft Teams** esté seleccionado.

> **Nota:** Estos ajustes deben estar activados tanto en Teams Admin Center como en el portal de Defender para que el proceso de triage funcione correctamente.

## Ubicar mensajes de Teams reportados por usuarios

### Opción A: Desde la página de Submissions

1. Ingresar a: [https://security.microsoft.com/reportsubmission?viewid=user](https://security.microsoft.com/reportsubmission?viewid=user)
2. Seleccionar la pestaña **User reported**.
3. Filtrar por **Teams messages** para ver el contenido reportado.

### Opción B: Desde la cola de incidentes de Defender XDR

1. Ir al portal **[Incidents - Microsoft Defender](https://nam06.safelinks.protection.outlook.com/?url=https%3A%2F%2Fsecurity.microsoft.com%2Fincidents%3Ftid%3D0d64d809-2796-406a-af58-54dcf35eca6d&data=05%7C02%7Cjomand%40microsoft.com%7C27aab460f2e148e8325808de64defca6%7C72f988bf86f141af91ab2d7cd011db47%7C1%7C0%7C639059106032019452%7CUnknown%7CTWFpbGZsb3d8eyJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiOiJXaW4zMiIsIkFOIjoiTWFpbCIsIldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=AC527YjWRlDpMHYa0hv0zGqwluPoIxGuVF%2FHkzoBATc%3D&reserved=0)**
2. Buscar alertas con los nombres:
    * `Teams message reported by user as a security risk`
    * `Teams message reported by user as not a security risk`
3. Abrir el incidente correspondiente para iniciar el triage.

## Revisar los detalles del mensaje reportado

Dentro del incidente o submission, seleccionar **View submission**.
Revisar:
* Remitente
* Contenido del mensaje
* URLs
* Archivos adjuntos
* Indicadores de compromiso (IoCs)
* Inteligencia de amenazas y veredictos de Defender

Consultar el panel de entidad del mensaje de Teams para ver metadatos adicionales.

## Ejecutar acciones de Triage

### Clasificar y notificar al usuario que reportó

Los administradores pueden clasificar el mensaje como:
* Phishing
* Spam
* Malware
* No malicioso

Y enviar una notificación al usuario que lo reportó.

### Enviar el mensaje a Microsoft para análisis

1. En la pestaña **User reported**, seleccionar el mensaje.
2. Elegir **Submit to Microsoft for analysis**.

> Esto es necesario porque los mensajes de Teams no pueden enviarse directamente desde la pestaña de Teams messages; solo los mensajes reportados por usuarios son elegibles.

### Agregar bloqueos según sea necesario

Desde la **Tenant Allow/Block List**, se pueden bloquear:
* URLs sospechosas
* Dominios maliciosos
* Direcciones de remitentes peligrosas

### Revisar y manejar mensajes en cuarentena

Si ZAP para Teams está habilitado y el mensaje fue puesto en cuarentena:
> Solo los administradores pueden gestionar estos mensajes.

### Documentar y cerrar el triage

1. Agregar notas al incidente en Defender XDR.
2. Resolver el incidente con la clasificación correspondiente (por ejemplo: true positive, false positive).
3. Confirmar la notificación al usuario (si está configurada).

---

# Revisar y actuar sobre los AIRs (Investigación y Respuesta Automatizada)

1. Ir a **[Action center - Microsoft Defender](https://nam06.safelinks.protection.outlook.com/?url=https%3A%2F%2Fsecurity.microsoft.com%2Faction-center%2Fpending&data=05%7C02%7Cjomand%40microsoft.com%7C27aab460f2e148e8325808de64defca6%7C72f988bf86f141af91ab2d7cd011db47%7C1%7C0%7C639059106032033271%7CUnknown%7CTWFpbGZsb3d8eyJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiOiJXaW4zMiIsIkFOIjoiTWFpbCIsIldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=eGoM3gVbO72Z%2FUSqlFNPrGZyE62B7nWfj%2Bt4WxwAmmg%3D&reserved=0)**
2. Revisar acciones en espera de aprobación:
    * Soft delete email
    * Hard delete email
    * Block URL
    * Block sender
    * Turn off external mail forwarding
3. Para cada acción pendiente:
    * Click en la acción para ver detalles y revisar:
        * **Investigation details:** Razón de la acción
        * **Evidence:** Capturas, análisis de detonación, IOCs
        * **Affected items:** Cantidad de mensajes/usuarios impactados
4. Tomar decisión
    * **Aprobar:** Si la evidencia es concluyente
    * **Rechazar:** Si es falso positivo
5. Verificar pestaña "History" para confirmar ejecución
6. Documentar acciones aprobadas/rechazadas para auditoría

---

# Revisar las Tendencias de Detección de Correo en Microsoft Defender for Office 365

## Mailflow Status Summary Report

Este reporte brinda visibilidad sobre:
* Correo permitido (bueno)
* Detecciones de malware
* Detecciones de phishing
* Detecciones de spam

1. Ir a **[Threat protection status - Microsoft Defender](https://nam06.safelinks.protection.outlook.com/?url=https%3A%2F%2Fsecurity.microsoft.com%2Freports%2FTPSAggregateReportATP&data=05%7C02%7Cjomand%40microsoft.com%7C27aab460f2e148e8325808de64defca6%7C72f988bf86f141af91ab2d7cd011db47%7C1%7C0%7C639059106032045247%7CUnknown%7CTWFpbGZsb3d8eyJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiOiJXaW4zMiIsIkFOIjoiTWFpbCIsIldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=1UB3DJ%2FZkVPKlDdj5f3eJykayMTW3dK2PbEl6K599S0%3D&reserved=0)**
2. Revisar tendencias generales por categoría:
    * Malware
    * Phishing
    * Spam
    * Good email
3. Desplazarse hacia abajo para ver tablas detalladas con volúmenes y capas de filtrado (motor anti‑malware, Safe Attachments, Safe Links, anti‑spam, ZAP, etc.).

## Abrir el Threat Protection Status Report

Este reporte consolida las detecciones de Defender a través de todas las capas de protección.

1. En **Reports**, seleccionar **Threat protection status report**
2. Revisar indicadores como:
    * Tipos de amenazas (malware, phishing, spam)
    * Tecnología de detección (detonación, Safe Links, Safe Attachments, impersonation, filtrado DMARC/SPOOF)
3. Seleccionar cualquier fila para abrir el panel detallado (flyout).
4. Aplicar filtros como:
    * Inbound
    * Outbound
    * Rango de fechas
    * Dirección del correo

Para análisis más específico.

## Comparar Tendencias en el Tiempo

El objetivo es identificar:
* Incrementos en phishing o malware
* Picos repentinos de spam
* Disminución en la eficacia de detección
* Cambios en patrones o técnicas de ataque

> Estos reportes están diseñados para mostrar patrones de largo plazo, no solo eventos diarios.

## Exportar o Programar Reportes (Recomendado)

Esto optimiza la gobernanza y la visibilidad continua.

Desde cualquiera de los reportes, usar las opciones:
* **Create schedule** para generar entregas semanales automáticas
* **Request report** para una exportación completa puntual
* **Export** para descargar en CSV/Excel para análisis offline

> Microsoft recomienda programar reportes TPS para mantener una supervisión consistente.

## Profundizar en Amenazas Específicas (Opcional)

Si observas anomalías o incrementos sospechosos:

1. Abrir **Threat Explorer (Plan 2)**: https://security.microsoft.com/threatexplorerv3
2. O usar **Real‑Time Detections (Plan 1)**: https://security.microsoft.com/realtimereportsv3
3. Filtrar por categoría (Malware, Phish, Campaigns).
4. Investigar remitentes, URLs, resultados de detonación y usuarios afectados.

## Ajustar Políticas de Seguridad Según los Hallazgos

Con los patrones identificados, es posible que debas modificar:
* Políticas anti‑phishing
* Políticas anti‑malware
* Configuraciones de Safe Attachments / Safe Links
* Tenant Allow/Block List
* Reglas de transporte

> La revisión semanal está diseñada para determinar si estos ajustes son necesarios.

---

# Revisar Campañas de Phishing y Malware que Resultaron en Correos Entregados

## Paso 1: Filtrar por Correos Entregados

1. Ir a **Explorer - Microsoft Defender**
2. Aplicar los siguientes filtros:
    * **Delivery action:** Delivered
    * **Campaign Type:** Phish & Malware, o All Threat Types
    * **Time range:** Seleccionar el periodo relevante (predeterminado: 7 días)
3. Seleccionar **Refresh** para actualizar la vista.

## Paso 2: Identificar Campañas de Alto Riesgo

Ordenar las campañas por:
* Número de usuarios impactados
* Severidad del tipo de amenaza
* Nivel de confianza de phishing
* Familia de malware o indicadores asociados a actores de amenaza
* Relación entre mensajes entregados y bloqueados

Priorizar campañas con:
* Alto número de correos entregados
* Alta severidad de amenaza
* Múltiples destinatarios que sean cuentas prioritarias
* Múltiples URLs o dominios asociados

## Paso 3: Abrir el Resumen de una Campaña

1. Seleccionar una campaña de la lista.
2. Revisar el panel de resumen de campaña:
    * Tipo de amenaza (Phishing / Malware)
    * Usuarios impactados
    * Total de mensajes enviados y entregados
    * Detecciones a través de filtros de MDO (ZAP, Safe Links, Safe Attachments)
    * Línea de tiempo de la campaña

> Esto ofrece una visión general del patrón del ataque.

## Paso 4: Revisar “Usuarios Impactados”

1. Ir a la sección **Impacted assets / mailboxes**.
2. Identificar:
    * Usuarios de alto riesgo que fueron objetivo repetidamente
    * Cuentas prioritarias (ejecutivos, finanzas, administradores)
    * Patrones de ataque lateral
3. Puede exportarse con: **Export → CSV**

## Paso 5: Analizar Muestras de Correo

Dentro de la misma campaña:

1. Abrir cualquier correo entregado y revisar:
    * Información del encabezado
    * Dominio del remitente y validación SPF/DKIM/DMARC
    * Reputación de URLs (Malicious, Suspicious, Unknown)
    * Comportamiento de adjuntos
    * Fallos de autenticación
    * Ruta del correo (cómo fue encaminado y entregado)

> Esto revela por qué el mensaje evadió las protecciones.

## Paso 6: Revisar Acciones de ZAP (Zero‑Hour Auto Purge)

Verificar si:
* ZAP eliminó el correo después de su entrega
* ZAP no logró eliminarlo
* Alguna política impidió la acción de ZAP

> Esto ayuda a validar si la remediación post‑entrega funcionó.

## Paso 7: Identificar Brechas en la Configuración

En el resumen de la campaña, revisar:
* Políticas que no se activaron
* Safe Links/Safe Attachments que fueron evadidos
* Anulaciones hechas por usuarios
* Entradas en Tenant Allow/Block List

> Con esto se determina por qué la campaña tuvo éxito.

## Paso 8: Ejecutar Acciones de Respuesta

Desde los detalles de la campaña, están disponibles acciones como:
* Purgar correos de todos los buzones impactados
* Bloquear remitente o dominio
* Bloquear URL desde MDO o Microsoft Defender XDR
* Bloquear hash de archivo / detonar en sandbox
* Enviar muestra para análisis (false positive / false negative)
* Crear o endurecer políticas anti‑phishing o anti‑malware

## Paso 9: Documentar y Rastrear la Amenaza

Para registros SOC y de cumplimiento:

1. Exportar detalles de la campaña (CSV, Excel)
2. Registrar:
    * ID de la campaña
    * Usuarios impactados
    * Vectores de amenaza (URLs, IPs, tipos de adjuntos)
    * Brechas de seguridad identificadas
    * Acciones tomadas

> Opcional: Enviar los hallazgos a Microsoft Sentinel para correlación adicional.

## Paso 10: Ejecutar Remediación con Usuarios

Dependiendo del impacto:
* Notificar a los usuarios afectados
* Restablecer credenciales comprometidas mediante Entra ID
* Activar una Automated Investigation and Response (AIR)
* Educar a los usuarios si interactuaron con contenido malicioso

## Paso 11: Fortalecer Controles Preventivos

Con base en los hallazgos:
* Revisar políticas anti‑phishing
* Habilitar niveles avanzados de protección contra phishing
* Actualizar Safe Links / Safe Attachments
* Eliminar entradas riesgosas en Allow List
* Habilitar MFA y credenciales resistentes al phishing

---

# Revisión de Top Targeted Users

1. Ir a https://security.microsoft.com/threatexplorer
2. Seleccionar **Phishing** o **All email** Tab
3. Configurar los filtros de la siguiente forma:
    * **Período:** Últimas 24 horas
    * **Seleccionar:** `Recipient domian -> Equal ony of -> dominio.com`
4. En la parte inferior del Explorer seleccionar **Top targeted users**
5. Click en el usuario para ver detalles revisar:
    * Tipos de amenazas recibidas
    * Tasa de entrega vs. bloqueo
    * Si hicieron clic en enlaces maliciosos
6. Acciones preventivas:
    * Si el usuario es VIP/Ejecutivo:
        * Agregar a "Priority Accounts"
    * Si hay indicios de compromiso:
        * Forzar cambio de contraseña
        * Revisar actividad en Azure AD Sign-ins
        * Verificar reglas de buzón (forwarding rules)

> Documentar usuarios críticos para monitoreo continuo

Alto número de correos entregados
## Paso 3: Abrir el Resumen de una Campaña

Alta severidad de amenaza
1. Seleccionar una campaña de la lista.
2. Revisar el panel de resumen de campaña:
    * Tipo de amenaza (Phishing / Malware)
    * Usuarios impactados
    * Total de mensajes enviados y entregados
    * Detecciones a través de filtros de MDO (ZAP, Safe Links, Safe Attachments)
    * Línea de tiempo de la campaña

Múltiples destinatarios que sean cuentas prioritarias
> Esto ofrece una visión general del patrón del ataque.

Múltiples URLs o dominios asociados
## Paso 4: Revisar “Usuarios Impactados”

 
1. Ir a la sección **Impacted assets / mailboxes**.
2. Identificar:
    * Usuarios de alto riesgo que fueron objetivo repetidamente
    * Cuentas prioritarias (ejecutivos, finanzas, administradores)
    * Patrones de ataque lateral
3. Puede exportarse con: **Export → CSV**

 
## Paso 5: Analizar Muestras de Correo

Paso 3 Abrir el Resumen de una Campaña

Seleccionar una campaña de la lista.
Revisar el panel de resumen de campaña:
Tipo de amenaza (Phishing / Malware)
Usuarios impactados
Total de mensajes enviados y entregados
Detecciones a través de filtros de MDO (ZAP, Safe Links, Safe Attachments)
Línea de tiempo de la campaña
 

Esto ofrece una visión general del patrón del ataque.

 

 

Paso 4 Revisar “Usuarios Impactados”

Ir a la sección Impacted assets / mailboxes.
Identificar:
Usuarios de alto riesgo que fueron objetivo repetidamente
Cuentas prioritarias (ejecutivos, finanzas, administradores)
Patrones de ataque lateral
Puede exportarse con: Export → CSV

 

Paso 5 Analizar Muestras de Correo

Dentro de la misma campaña:

Abrir cualquier correo entregado y revisar:
Información del encabezado
Dominio del remitente y validación SPF/DKIM/DMARC
Reputación de URLs (Malicious, Suspicious, Unknown)
Comportamiento de adjuntos
Fallos de autenticación
Ruta del correo (cómo fue encaminado y entregado)
Esto revela por qué el mensaje evadió las protecciones.
1. Abrir cualquier correo entregado y revisar:
    * Información del encabezado
    * Dominio del remitente y validación SPF/DKIM/DMARC
    * Reputación de URLs (Malicious, Suspicious, Unknown)
    * Comportamiento de adjuntos
    * Fallos de autenticación
    * Ruta del correo (cómo fue encaminado y entregado)

 
> Esto revela por qué el mensaje evadió las protecciones.

 
## Paso 6: Revisar Acciones de ZAP (Zero‑Hour Auto Purge)

Paso 6 Revisar Acciones de ZAP (Zero‑Hour Auto Purge)

Verificar si:
* ZAP eliminó el correo después de su entrega
* ZAP no logró eliminarlo
* Alguna política impidió la acción de ZAP

ZAP eliminó el correo después de su entrega
ZAP no logró eliminarlo
Alguna política impidió la acción de ZAP
Esto ayuda a validar si la remediación post‑entrega funcionó.
> Esto ayuda a validar si la remediación post‑entrega funcionó.

 
## Paso 7: Identificar Brechas en la Configuración

Paso 7 Identificar Brechas en la Configuración

En el resumen de la campaña, revisar:
* Políticas que no se activaron
* Safe Links/Safe Attachments que fueron evadidos
* Anulaciones hechas por usuarios
* Entradas en Tenant Allow/Block List

Políticas que no se activaron
Safe Links/Safe Attachments que fueron evadidos
Anulaciones hechas por usuarios
Entradas en Tenant Allow/Block List
Con esto se determina por qué la campaña tuvo éxito.
> Con esto se determina por qué la campaña tuvo éxito.

 
## Paso 8: Ejecutar Acciones de Respuesta

 

Paso 8 Ejecutar Acciones de Respuesta

Desde los detalles de la campaña, están disponibles acciones como:
* Purgar correos de todos los buzones impactados
* Bloquear remitente o dominio
* Bloquear URL desde MDO o Microsoft Defender XDR
* Bloquear hash de archivo / detonar en sandbox
* Enviar muestra para análisis (false positive / false negative)
* Crear o endurecer políticas anti‑phishing o anti‑malware

Purgar correos de todos los buzones impactados
Bloquear remitente o dominio
Bloquear URL desde MDO o Microsoft Defender XDR
Bloquear hash de archivo / detonar en sandbox
Enviar muestra para análisis (false positive / false negative)
Crear o endurecer políticas anti‑phishing o anti‑malware
 
## Paso 9: Documentar y Rastrear la Amenaza

 

Paso 9 Documentar y Rastrear la Amenaza

Para registros SOC y de cumplimiento:

 
1. Exportar detalles de la campaña (CSV, Excel)
2. Registrar:
    * ID de la campaña
    * Usuarios impactados
    * Vectores de amenaza (URLs, IPs, tipos de adjuntos)
    * Brechas de seguridad identificadas
    * Acciones tomadas

Exportar detalles de la campaña (CSV, Excel)
Registrar:
ID de la campaña
Usuarios impactados
Vectores de amenaza (URLs, IPs, tipos de adjuntos)
Brechas de seguridad identificadas
Acciones tomadas
 
> Opcional: Enviar los hallazgos a Microsoft Sentinel para correlación adicional.

Opcional: Enviar los hallazgos a Microsoft Sentinel para correlación adicional.
## Paso 10: Ejecutar Remediación con Usuarios

Paso 10 Ejecutar Remediación con Usuarios

Dependiendo del impacto:
* Notificar a los usuarios afectados
* Restablecer credenciales comprometidas mediante Entra ID
* Activar una Automated Investigation and Response (AIR)
* Educar a los usuarios si interactuaron con contenido malicioso

Notificar a los usuarios afectados
Restablecer credenciales comprometidas mediante Entra ID
Activar una Automated Investigation and Response (AIR)
Educar a los usuarios si interactuaron con contenido malicioso
 
## Paso 11: Fortalecer Controles Preventivos

Paso 11 Fortalecer Controles Preventivos

Con base en los hallazgos:
* Revisar políticas anti‑phishing
* Habilitar niveles avanzados de protección contra phishing
* Actualizar Safe Links / Safe Attachments
* Eliminar entradas riesgosas en Allow List
* Habilitar MFA y credenciales resistentes al phishing

Revisar políticas anti‑phishing
Habilitar niveles avanzados de protección contra phishing
Actualizar Safe Links / Safe Attachments
Eliminar entradas riesgosas en Allow List
Habilitar MFA y credenciales resistentes al phishing
 
---

 
# Revisión de Top Targeted Users

----------------------------------------------------------------------
1. Ir a https://security.microsoft.com/threatexplorer
2. Seleccionar **Phishing** o **All email** Tab
3. Configurar los filtros de la siguiente forma:
    * **Período:** Últimas 24 horas
    * **Seleccionar:** `Recipient domian -> Equal ony of -> dominio.com`
4. En la parte inferior del Explorer seleccionar **Top targeted users**
5. Click en el usuario para ver detalles revisar:
    * Tipos de amenazas recibidas
    * Tasa de entrega vs. bloqueo
    * Si hicieron clic en enlaces maliciosos
6. Acciones preventivas:
    * Si el usuario es VIP/Ejecutivo:
        * Agregar a "Priority Accounts"
    * Si hay indicios de compromiso:
        * Forzar cambio de contraseña
        * Revisar actividad en Azure AD Sign-ins
        * Verificar reglas de buzón (forwarding rules)

 

Revisión de Top Targeted Users

 

Ir a https://security.microsoft.com/threatexplorer
Seleccionar Phishing o All email Tab
Configurar los filtros de la siguiente forma:
Período: Últimas 24 horas
Seleccionar: Recipient domian -> Equal ony of -> dominio.com
En la parte inferior del Explorer seleccionar Top targeted users
Click en el usuario para ver detalles revisar:
Tipos de amenazas recibidas
Tasa de entrega vs. bloqueo
Si hicieron clic en enlaces maliciosos
Acciones preventivas:
Si el usuario es VIP/Ejecutivo:
Agregar a "Priority Accounts"
Si hay indicios de compromiso:
Forzar cambio de contraseña
Revisar actividad en Azure AD Sign-ins
Verificar reglas de buzón (forwarding rules)
 

Documentar usuarios críticos para monitoreo continuo
> Documentar usuarios críticos para monitoreo continuo