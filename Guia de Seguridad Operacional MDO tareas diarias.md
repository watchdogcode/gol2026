Monitoreo de Alertas

Revisar alertas activas 

Ir al portal  [Alerts - Microsoft Defender](https://security.microsoft.com/alerts?tid=0d64d809-2796-406a-af58-54dcf35eca6d)
Seleccione una alerta para abrir el panel de detalles, donde podrá revisar:
Severidad de la alerta
Origen de la detección
Usuarios o activos impactados
Acciones recomendadas
 

Use la opción Filter para filtrar alertas por severidad, servicio o estado.
 

Investigar alertas 

Desde los detalles de la alerta, seleccione View full details.
Revise:
Alert Storyline (línea de tiempo de eventos relacionados)
Correo o archivo involucrado
Estado de la investigación automatizada (si está habilitada)
 

Seleccione Investigate para iniciar una investigación automática o manual.
 

Las investigaciones automáticas forman parte del flujo de protección contra amenazas de Microsoft Defender (capacidad general del ecosistema Defender).

 

 ---------------------------------------------------

 

Monitoreo de Incidentes

 

Ir al portal Incidents - Microsoft Defender
En el panel de Incidentes configurar los siguientes filtros:
Periodo: 1 Dia
Estado: Nuevo y En curso
Severidad de alerta: Ordenar descendente (Alta → Media → Baja)
Prioridad de marcador: 15-100
Workspaces: Any
Guardar la vista personalizada para uso futuro
Revisar columnas clave:
Severity (Gravedad)
Status (Estado)
Assigned to (Asignado a)
Tags (Etiquetas)
 

 

-------------------------------------------------------------------------------------

Triage de Mensajes de Teams Reportados por Usuarios

 

Verificar que el reporte esté habilitado

 

Ir a Messaging policies - Microsoft Teams admin center
Abrir la política Global (Org‑wide default).
Confirmar que Report inappropriate content y Report a security concern estén habilitados.
Ir a Email & collaboration - Microsoft Defender
Desplazarse a la sección Microsoft Teams.
Verificar que Monitor reported messages in Microsoft Teams esté seleccionado.
 

Nota: Estos ajustes deben estar activados tanto en Teams Admin Center como en el portal de Defender para que el proceso de triage funcione correctamente.

 

 

Ubicar mensajes de Teams reportados por usuarios

 

Opción A Desde la página de Submissions

Ingresar a: https://security.microsoft.com/reportsubmission?viewid=user
Seleccionar la pestaña User reported.
Filtrar por Teams messages para ver el contenido reportado.
 

Opción B Desde la cola de incidentes de Defender XDR

Ir al portal Incidents - Microsoft Defender
Buscar alertas con los nombres:
Teams message reported by user as a security risk
Teams message reported by user as not a security risk
Abrir el incidente correspondiente para iniciar el triage.
 

 

Revisar los detalles del mensaje reportado

 

Dentro del incidente o submission, seleccionar View submission.
Revisar:
Remitente
Contenido del mensaje
URLs
Archivos adjuntos
Indicadores de compromiso (IoCs)
Inteligencia de amenazas y veredictos de Defender
Consultar el panel de entidad del mensaje de Teams para ver metadatos adicionales.
 

 

Ejecutar acciones de Triage

 

Clasificar y notificar al usuario que reportó

Los administradores pueden clasificar el mensaje como:

Phishing

Spam

Malware

No malicioso

Y enviar una notificación al usuario que lo reportó.

 

Enviar el mensaje a Microsoft para análisis

En la pestaña User reported, seleccionar el mensaje.
Elegir Submit to Microsoft for analysis.
 

Esto es necesario porque los mensajes de Teams no pueden enviarse directamente desde la pestaña de Teams messages; solo los mensajes reportados por usuarios son elegibles.

 

Agregar bloqueos según sea necesario

Desde la Tenant Allow/Block List, se pueden bloquear:

URLs sospechosas

Dominios maliciosos

Direcciones de remitentes peligrosas

 

Revisar y manejar mensajes en cuarentena

Si ZAP para Teams está habilitado y el mensaje fue puesto en cuarentena:

 

Solo los administradores pueden gestionar estos mensajes.

 

 

Documentar y cerrar el triage

Agregar notas al incidente en Defender XDR.
Resolver el incidente con la clasificación correspondiente (por ejemplo: true positive, false positive).
Confirmar la notificación al usuario (si está configurada).
 

 

 

 ---------------------------------------------------------------------------------

 

 

Revisar y actuar sobre los AIRs (Investigación y Respuesta Automatizada)

 

Ir a Action center - Microsoft Defender
Revisar acciones en espera de aprobación:
Soft delete email
Hard delete email
Block URL
Block sender
Turn off external mail forwarding
Para cada acción pendiente:
Click en la acción para ver detalles y revisar:
Investigation details: Razón de la acción
Evidence: Capturas, análisis de detonación, IOCs
Affected items: Cantidad de mensajes/usuarios impactados
Tomar decisión
Aprobar: Si la evidencia es concluyente
Rechazar: Si es falso positivo
Verificar pestaña "History" para confirmar ejecución
Documentar acciones aprobadas/rechazadas para auditoría
 

  --------------------------------------------------------------

 

Revisar las Tendencias de Detección de Correo en Microsoft Defender for Office 365

 

Mailflow Status Summary Report

Este reporte brinda visibilidad sobre:

Correo permitido (bueno)

Detecciones de malware

Detecciones de phishing

Detecciones de spam

 

Ir a Threat protection status - Microsoft Defender
Revisar tendencias generales por categoría:
Malware
Phishing
Spam
Good email
Desplazarse hacia abajo para ver tablas detalladas con volúmenes y capas de filtrado (motor anti‑malware, Safe Attachments, Safe Links, anti‑spam, ZAP, etc.).
 

 

Abrir el Threat Protection Status Report

 

Este reporte consolida las detecciones de Defender a través de todas las capas de protección.

 

En Reports, seleccionar Threat protection status report
Revisar indicadores como:
Tipos de amenazas (malware, phishing, spam)
Tecnología de detección (detonación, Safe Links, Safe Attachments, impersonation, filtrado DMARC/SPOOF)
Seleccionar cualquier fila para abrir el panel detallado (flyout).
Aplicar filtros como
Inbound
Outbound
Rango de fechas
Dirección del correo
Para análisis más específico.

 

 

Comparar Tendencias en el Tiempo

El objetivo es identificar:

Incrementos en phishing o malware

Picos repentinos de spam

Disminución en la eficacia de detección

Cambios en patrones o técnicas de ataque

Estos reportes están diseñados para mostrar patrones de largo plazo, no solo eventos diarios.

 

Exportar o Programar Reportes (Recomendado)

Esto optimiza la gobernanza y la visibilidad continua.

 

Desde cualquiera de los reportes, usar las opciones:
Create schedule para generar entregas semanales automáticas
Request report para una exportación completa puntual
Export para descargar en CSV/Excel para análisis offline
 

Microsoft recomienda programar reportes TPS para mantener una supervisión consistente.

 

 

 

Profundizar en Amenazas Específicas (Opcional)

Si observas anomalías o incrementos sospechosos:

Abrir Threat Explorer (Plan 2):
https://security.microsoft.com/threatexplorerv3

O usar Real‑Time Detections (Plan 1):
https://security.microsoft.com/realtimereportsv3

Filtrar por categoría (Malware, Phish, Campaigns).
Investigar remitentes, URLs, resultados de detonación y usuarios afectados.
 

 

 

Ajustar Políticas de Seguridad Según los Hallazgos

Con los patrones identificados, es posible que debas modificar:

Políticas anti‑phishing

Políticas anti‑malware

Configuraciones de Safe Attachments / Safe Links

Tenant Allow/Block List

Reglas de transporte

 

La revisión semanal está diseñada para determinar si estos ajustes son necesarios.

 

---------------------------------------------------------------------------------------

 

Revisar Campañas de Phishing y Malware que Resultaron en Correos Entregados

 

Paso 1 Filtrar por Correos Entregados

Ir a Explorer - Microsoft Defender
Aplicar los siguientes filtros:
Delivery action: Delivered
Campaign Type: Phish & Malware, o All Threat Types
Time range: Seleccionar el periodo relevante (predeterminado: 7 días)
Seleccionar Refresh para actualizar la vista.
 

Paso 2 Identificar Campañas de Alto Riesgo

Ordenar las campañas por:

Número de usuarios impactados

Severidad del tipo de amenaza

Nivel de confianza de phishing

Familia de malware o indicadores asociados a actores de amenaza

Relación entre mensajes entregados y bloqueados

Priorizar campañas con:

Alto número de correos entregados

Alta severidad de amenaza

Múltiples destinatarios que sean cuentas prioritarias

Múltiples URLs o dominios asociados

 

 

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

 

 

Paso 6 Revisar Acciones de ZAP (Zero‑Hour Auto Purge)

Verificar si:

ZAP eliminó el correo después de su entrega
ZAP no logró eliminarlo
Alguna política impidió la acción de ZAP
Esto ayuda a validar si la remediación post‑entrega funcionó.

 

Paso 7 Identificar Brechas en la Configuración

En el resumen de la campaña, revisar:

Políticas que no se activaron
Safe Links/Safe Attachments que fueron evadidos
Anulaciones hechas por usuarios
Entradas en Tenant Allow/Block List
Con esto se determina por qué la campaña tuvo éxito.

 

 

Paso 8 Ejecutar Acciones de Respuesta

Desde los detalles de la campaña, están disponibles acciones como:

Purgar correos de todos los buzones impactados
Bloquear remitente o dominio
Bloquear URL desde MDO o Microsoft Defender XDR
Bloquear hash de archivo / detonar en sandbox
Enviar muestra para análisis (false positive / false negative)
Crear o endurecer políticas anti‑phishing o anti‑malware
 

 

Paso 9 Documentar y Rastrear la Amenaza

Para registros SOC y de cumplimiento:

 

Exportar detalles de la campaña (CSV, Excel)
Registrar:
ID de la campaña
Usuarios impactados
Vectores de amenaza (URLs, IPs, tipos de adjuntos)
Brechas de seguridad identificadas
Acciones tomadas
 

Opcional: Enviar los hallazgos a Microsoft Sentinel para correlación adicional.

Paso 10 Ejecutar Remediación con Usuarios

Dependiendo del impacto:

Notificar a los usuarios afectados
Restablecer credenciales comprometidas mediante Entra ID
Activar una Automated Investigation and Response (AIR)
Educar a los usuarios si interactuaron con contenido malicioso
 

Paso 11 Fortalecer Controles Preventivos

Con base en los hallazgos:

Revisar políticas anti‑phishing
Habilitar niveles avanzados de protección contra phishing
Actualizar Safe Links / Safe Attachments
Eliminar entradas riesgosas en Allow List
Habilitar MFA y credenciales resistentes al phishing
 

 

----------------------------------------------------------------------

 

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