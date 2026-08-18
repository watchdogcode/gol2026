# Guia Operativa de Microsoft Sentinel para Equipos de Seguridad

Gestion y operacion para equipos SOC que usan Microsoft Sentinel como SIEM/SOAR.

Esta guia esta adaptada para incluirse en un repositorio de GitHub junto con artefactos KQL, funciones de normalizacion, consultas de busqueda, reglas analiticas, workbooks y notebooks.

## Proposito

Establecer un modelo operativo estandar para que cualquier equipo de seguridad pueda operar Microsoft Sentinel de forma consistente, repetible y medible.

La guia busca cubrir:

- Operacion diaria del SIEM.
- Gestion de incidentes.
- Salud de conectores, reglas, agentes y playbooks.
- Gobernanza de costos.
- Uso de fuentes de datos de alto valor.
- Ciclo de vida de contenido KQL.
- Integracion de artefactos versionados en GitHub.

## Audiencia

| Rol | Responsabilidad principal |
| --- | --- |
| Analista SOC Tier 1 | Monitoreo, triaje inicial y clasificacion de incidentes. |
| Analista SOC Tier 2 | Investigacion, correlacion y contencion. |
| Analista SOC Tier 3 / Threat Hunter | Caza proactiva, respuesta avanzada y mejora de detecciones. |
| Ingeniero SOC | Salud de la plataforma, conectores, reglas, funciones KQL y playbooks. |
| Arquitecto / Lider SOC | Gobernanza, costos, permisos, metricas y mejora continua. |

## Principio rector

**Cobertura primero, costo controlado.**

Habilitar primero fuentes de alto valor y bajo costo, estabilizar la operacion con rutinas claras y despues incorporar fuentes adicionales con base en casos de uso concretos.

## Componentes operativos clave

| Componente | Uso operativo |
| --- | --- |
| Log Analytics workspace | Repositorio donde se almacenan e indexan los datos. Define acceso, retencion y costos. |
| Conectores de datos | Integran fuentes Microsoft y de terceros. Su salud debe revisarse de forma recurrente. |
| Funciones KQL | Normalizan datos y permiten reutilizar logica comun. |
| Reglas de analisis | Generan alertas e incidentes a partir de KQL. |
| Incidentes | Unidad principal de trabajo para el SOC. |
| Reglas de automatizacion | Asignan, etiquetan, cambian severidad o disparan playbooks. |
| Playbooks | Automatizan enriquecimiento, notificacion y contencion. |
| Workbooks | Visualizan estado, metricas, cobertura y costos. |
| Consultas de busqueda | Permiten caza proactiva e investigacion. |
| Watchlists | Enriquecen detecciones con listas de activos, VIPs, rangos o excepciones. |

## Fuentes de datos recomendadas

Priorizar fuentes que entregan valor de seguridad sin iniciar con una explosion de costos.

| Fuente | Informacion administrada | Tablas comunes en Sentinel | Prioridad |
| --- | --- | --- | --- |
| Microsoft Defender XDR | Incidentes y alertas correlacionadas de MDE, MDI, MDO y MDA. | `SecurityIncident`, `SecurityAlert` | Critica |
| Microsoft Entra ID | Inicios de sesion, auditoria, aprovisionamiento y riesgo. | `SigninLogs`, `AuditLogs`, `ProvisioningLogs` y tablas AAD segun configuracion | Critica |
| Microsoft 365 / Office 365 | Actividad de Exchange, SharePoint, OneDrive y Teams. | `OfficeActivity` | Alta |
| Azure Activity | Cambios administrativos sobre recursos y suscripciones. | `AzureActivity` | Alta |
| Microsoft Defender for Cloud | Alertas de cargas de trabajo cloud. | `SecurityAlert` | Alta cuando aplique |
| Microsoft Sentinel Health | Salud de reglas, conectores y automatizacion. | `SentinelHealth`, `SentinelAudit` | Critica |
| Windows Server DHCP | Asignaciones IP, MAC, hostname, scope y leases. | `Event`, `WindowsEvent` o tabla personalizada | Segun caso de uso |
| Windows Server DNS | Consultas, respuestas y resolucion de dominios. | `DnsEvents`, `Event`, `WindowsEvent` o tabla personalizada | Segun caso de uso |

> Nota: Las tablas y costos dependen del tipo de conector, licencia y configuracion. Validar siempre la facturacion esperada antes de habilitar telemetria cruda de alto volumen.

## Manejo operativo de fuentes de datos

### Sentinel y Advanced Hunting son planos diferentes

| Plano | Proposito | Ejemplos | Uso operativo |
| --- | --- | --- | --- |
| Microsoft Sentinel / Log Analytics | Centralizar eventos, alertas e incidentes para correlacion, retencion y automatizacion. | `SecurityIncident`, `SecurityAlert`, `SigninLogs`, `AuditLogs`, `OfficeActivity`, `AzureActivity` | Triaje, reglas analiticas, workbooks, playbooks y cumplimiento. |
| Microsoft Defender XDR Advanced Hunting | Consultar telemetria detallada de los productos Defender licenciados y habilitados. | `DeviceProcessEvents`, `EmailEvents`, `IdentityLogonEvents`, `CloudAppEvents`, `EntraIdSignInEvents` | Investigacion profunda, hunting y detecciones personalizadas. |

Las consultas de los paquetes KQL de MDE, MDI, MDO, MDA y Entra ID de este repositorio estan disenadas para Advanced Hunting. No deben copiarse a Sentinel sin comprobar que sus tablas y columnas existan en el area de trabajo.

Flujo de investigacion esperado:

1. Recibir y priorizar el incidente en Sentinel.
2. Identificar usuario, dispositivo, IP, URL, dominio, hash, aplicacion o buzon.
3. Pivotar a Advanced Hunting cuando se requiera telemetria detallada.
4. Registrar en el incidente la consulta, ventana temporal, evidencia y resultado.
5. Ejecutar el playbook correspondiente y verificar la contencion.

### Inventario por tipo de informacion

| Dominio | Informacion administrada | Tablas de Advanced Hunting | Cobertura esperada en Sentinel |
| --- | --- | --- | --- |
| MDE | Procesos, archivos, red, registro, inicios de sesion, dispositivos y vulnerabilidades. | `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceEvents`, tablas `DeviceTvm*` | Alertas e incidentes mediante Microsoft Defender XDR; la telemetria detallada permanece en Advanced Hunting salvo integracion adicional. |
| MDI | Autenticacion on-premises, consultas y cambios de Active Directory. | `IdentityLogonEvents`, `IdentityQueryEvents`, `IdentityDirectoryEvents` | Alertas e incidentes mediante Microsoft Defender XDR. |
| MDO | Flujo de correo, adjuntos, URLs, clics, acciones post-entrega y campanas. | `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `EmailPostDeliveryEvents`, `UrlClickEvents` | Alertas e incidentes mediante Microsoft Defender XDR; auditoria de cargas de trabajo mediante `OfficeActivity`. |
| MDA | Actividad SaaS, aplicaciones OAuth, App Governance y posibles exfiltraciones. | `CloudAppEvents` y tablas relacionadas disponibles en el tenant | Alertas e incidentes mediante Microsoft Defender XDR; otros datos dependen del conector habilitado. |
| Entra ID | Inicios de sesion, aplicaciones, Microsoft Graph, auditoria, aprovisionamiento y riesgo. | `EntraIdSignInEvents`, `EntraIdSpnSignInEvents`, `GraphApiAuditEvents` cuando esten disponibles | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AuditLogs`, `ProvisioningLogs` y tablas de riesgo segun licencia. |
| Defender XDR / IR | Alertas, incidentes, entidades y evidencia correlacionada. | `AlertInfo`, `AlertEvidence` y tablas de cada producto | `SecurityIncident`, `SecurityAlert` como cola central del SOC. |
| Azure y Defender for Cloud | Operaciones sobre recursos, cambios de configuracion y alertas cloud. | No aplica como plano principal para este paquete. | `AzureActivity`, `SecurityAlert` y tablas especificas habilitadas. |
| DHCP y DNS | Identidad de red y resolucion de nombres. | No aplica. | `Event`, `WindowsEvent`, `DnsEvents` o tablas personalizadas. |

La licencia no sustituye el onboarding de activos ni la configuracion del conector. Una fuente solo se considera operativa cuando supera validaciones de cobertura, frescura, esquema y volumen.

### Ciclo de vida de una fuente

#### Alta

Registrar antes de habilitarla:

- Propietario tecnico y operativo.
- Caso de uso, amenazas y entidades cubiertas.
- Conector, licencia, permisos y activos incluidos.
- Tablas y columnas requeridas.
- Volumen estimado, retencion y presupuesto.
- Frecuencia esperada y umbral de frescura.
- Reglas, funciones, workbooks y playbooks dependientes.
- Clasificacion de datos y requisitos de acceso.

#### Criterios de aceptacion

1. El conector aparece conectado y sin errores.
2. Las tablas esperadas reciben datos del alcance aprobado.
3. `TimeGenerated` cumple el umbral de frescura acordado.
4. El esquema contiene las entidades requeridas por las detecciones.
5. El volumen corresponde con la poblacion cubierta y no presenta duplicados evidentes.
6. Una prueba recorre el flujo hasta el incidente sin contencion destructiva.
7. RBAC, retencion y costo estan aprobados.
8. La fuente esta incluida en el workbook y la rutina de salud.

Consulta base de frescura y volumen:

```kql
union withsource=Tabla isfuzzy=true
   SecurityIncident,
   SecurityAlert,
   SigninLogs,
   AuditLogs,
   OfficeActivity,
   AzureActivity,
   SentinelHealth
| where TimeGenerated > ago(24h)
| summarize UltimoEvento=max(TimeGenerated), Eventos=count() by Tabla
| extend MinutosSinDatos=datetime_diff("minute", now(), UltimoEvento)
| order by MinutosSinDatos desc
```

`isfuzzy=true` permite ejecutar la consulta cuando alguna tabla no existe. Una tabla esperada ausente debe investigarse, no ignorarse.

#### Operacion y evidencia

| Cadencia | Control | Evidencia minima |
| --- | --- | --- |
| Diaria | Revisar errores, ultima recepcion, caidas de volumen, activos sin telemetria y sincronizacion de incidentes XDR. | Resultado KQL o workbook y ticket de desviaciones. |
| Semanal | Comparar activos esperados contra observados; revisar reglas sin datos, campos nulos, sensores y conectores degradados. | Porcentaje de cobertura y backlog de correccion. |
| Semanal | Revisar consumo por tabla y cambios de esquema. | Tendencia de ingesta y acciones asignadas. |
| Mensual | Revalidar caso de uso, retencion, RBAC, licencias, dependencias y SLA. | Registro de revision y decision de mantener, ajustar o retirar. |
| Trimestral | Probar continuidad, escalamiento y una deteccion de extremo a extremo. | Resultado del ejercicio y plan de mejora. |

#### Degradacion o ausencia de datos

1. Confirmar tabla, tenant, conector, producto, sensor, activos y ventana afectados.
2. Consultar `SentinelHealth`, `SentinelAudit`, estado del conector y Service Health.
3. Verificar licencias, permisos, credenciales, configuracion y cambios recientes.
4. Comparar el portal de origen con Sentinel para ubicar la falla en generacion o ingesta.
5. Crear ticket con inicio estimado, fuentes, reglas ciegas, riesgo y propietario.
6. Informar al SOC y aplicar monitoreo compensatorio desde el portal de origen.
7. Confirmar recuperacion por frescura, volumen y eventos de muestra; registrar causa raiz.

| Severidad | Condicion | Respuesta |
| --- | --- | --- |
| Critica | Sin incidentes/alertas de Defender XDR o sin identidad para todo el alcance. | Escalamiento inmediato y monitoreo compensatorio. |
| Alta | Un dominio completo o varios activos criticos sin telemetria. | Atender en el turno y notificar al lider SOC. |
| Media | Degradacion parcial, retraso o campos esenciales ausentes. | Crear ticket y corregir segun SLA. |
| Baja | Desviacion menor sin perdida de deteccion. | Mantenimiento planificado. |

#### Cambio y retiro

- Probar cambios de conector, transformacion, retencion o esquema antes de produccion.
- Revisar todos los consumidores: reglas, funciones, workbooks, hunting y playbooks.
- Mantener plan de reversa y ventana de cambio.
- No retirar una fuente mientras existan detecciones o requisitos de cumplimiento dependientes.
- Registrar fecha, aprobador, motivo, impacto de cobertura y destino de datos retenidos.

### Procesos operativos por dominio

| Dominio | Diario | Semanal | Mensual / ad-hoc |
| --- | --- | --- | --- |
| Defender XDR / IR | Validar sincronizacion, priorizar incidentes y asignar propietario. | Revisar volumen por producto, duplicados y automatizaciones fallidas. | Medir cobertura cross-domain, MTTA, MTTC y MTTR. |
| MDE | Revisar alertas, dispositivos en riesgo y salud del sensor; investigar procesos, archivos, red y hashes. | Revisar vulnerabilidades, exposicion, reincidencia y onboarding. | Hunting de persistencia, lineas base y Device Discovery. |
| MDI | Revisar ITDR, incidentes y salud de sensores. | Revisar reconocimiento, ataques de credenciales, movimiento lateral y Secure Score. | Revisar Service Health, alta de sensores y `Test-MDIConfiguration`. |
| MDO | Revisar amenazas entregadas, clics, adjuntos y acciones post-entrega. | Analizar campanas, ZAP, tendencias, latencia y reglas post-compromiso. | Hunting por IoC, BEC, malware y validacion de lineas base. |
| MDA | Revisar alertas, OAuth, actividad anomala y App Governance. | Revisar postura SaaS, conectores, politicas y aplicaciones no sancionadas. | Revisar privilegios OAuth, Shadow IT, retencion y cobertura. |
| Entra ID | Revisar riesgo, fallos de inicio de sesion, cambios sensibles y Entra Connect Health. | Revisar MFA, Conditional Access, privilegios y service principals. | Auditar roles, cuentas de emergencia, metodos de autenticacion y excepciones. |
| Office 365 / Azure | Revisar actividad administrativa y cambios sobre recursos criticos. | Revisar patrones anomalos, cobertura y alertas cloud. | Revalidar auditoria, retencion y casos de uso. |
| DHCP / DNS | Revisar continuidad, hosts nuevos, conflictos, NXDOMAIN y dominios raros. | Comparar cobertura y ajustar normalizacion. | Revisar retencion, volumen y calidad de correlacion. |

Procedimientos detallados del repositorio:

- **MDE:** [diario](../../MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20diarias.md), [semanal](../../MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md), [mensual/ad-hoc](../../MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20mensuales%20ad-hoc.md) y [KQL](../../MDE/Paquete%20MDE%20KQL%20Advance%20Hunting.md).
- **MDI:** [diario](../../MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md), [semanal](../../MDI/Gu%C3%ADa%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md), [mensual/ad-hoc](../../MDI/Gu%C3%ADa%20opertiva%20mensualad-hoc%20de%20Microsoft%20Defender%20for%20Identity.md) y [KQL](../../MDI/Paquete%20MDI%20KQL%20Advance%20Hunting.md).
- **MDO:** [diario](../../MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md), [semanal](../../MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md), [mensual/ad-hoc](../../MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20Mensual%20Ad-Hoc.md) y [KQL](../../MDO/Paquete%20MDO%20KQL%20Advance%20Hunting.md).
- **MDA:** [diario](../../MDA/Gu%C3%ADa%20de%20Seguridad%20Operacional%20MDA%20tareas%20diarias.md), [semanal](../../MDA/Gu%C3%ADa%20de%20Seguridad%20Operacional%20MDA%20tareas%20semanales.md), [mensual](../../MDA/Gu%C3%ADa%20de%20Seguridad%20Operacional%20MDA%20tareas%20mensuales.md) y [KQL](../../MDA/Paquete%20MDA%20KQL%20Advance%20Hunting.md).
- **Entra ID:** [diario](../../EntraID/Gu%C3%ADa%20Operacional%20Microsoft%20EntraID%20Diaria.md), [semanal](../../EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Semanales.md), [mensual/ad-hoc](../../EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Mensuales%20AdHoc.md) y [KQL](../../EntraID/Paquete%20KQL%20Queries%20EntraID%20Advanced%20Hunting.md).
- **IR:** [Plan de Respuesta a Incidentes CSIRT](../../IR/Plan%20de%20Respuesta%20a%20Incidentes%20CSIRT.md) y playbooks por dominio en `IR/Playbooks/`.

### Registro minimo de fuentes

Mantener un inventario versionado o una watchlist con `SourceId`, dominio, propietarios, conector, tablas esperadas, alcance, SLA de frescura, retencion, estado, ultima revision y dependencias.

## Consideraciones para logs DHCP y DNS

Los logs DHCP y DNS son utiles para investigaciones donde la IP por si sola no identifica al activo real.

### DHCP

Casos de uso principales:

- Identificar hosts nuevos.
- Correlacionar IP con MAC address y hostname.
- Detectar cambios frecuentes de IP.
- Detectar multiples MAC asociadas a una misma IP.
- Investigar posibles conflictos, spoofing o dispositivos no autorizados.

Campos recomendados:

- `TimeGenerated`
- `DeviceName`
- `EventId`
- `EventAction`
- `ClientIp`
- `ClientMac`
- `HostName`
- `ScopeId`
- `RawMessage`

### DNS

Casos de uso principales:

- Identificar dominios raros.
- Detectar picos de NXDOMAIN.
- Detectar posibles patrones de DGA.
- Detectar posible tunelizacion DNS.
- Correlacionar actividad DNS con identidad DHCP.

Campos recomendados:

- `TimeGenerated`
- `DeviceName`
- `ClientIp`
- `QueryName`
- `QueryRootDomain`
- `QueryType`
- `ResponseCode`
- `Answers`
- `QueryLength`
- `LabelCount`
- `MaxLabelLength`
- `RawMessage`

## Modelo de repositorio GitHub

Estructura recomendada:

```text
kql/
  functions/
  hunting/
  analytics-rules/
  workbooks/
notebooks/
docs/
  guia_operativa_microsoft_sentinel.md
  source_mapping.md
  next_steps.md
```

### Reglas para contenido reutilizable

- No incluir datos reales de clientes.
- No incluir IPs, dominios, nombres de hosts o usuarios reales.
- Usar placeholders como `REEMPLAZAR_CON_IP`.
- Documentar tablas esperadas y columnas requeridas.
- Mantener comentarios en espanol si la audiencia principal es hispanohablante.
- Separar funciones reutilizables de consultas de busqueda.
- Mantener umbrales como valores ajustables.
- Evitar dependencias no documentadas.

## Ciclo de vida de artefactos KQL

1. **Normalizacion**
   - Crear funciones KQL por fuente.
   - Mantener un esquema comun.
   - Evitar que cada consulta tenga su propio parser.

2. **Busqueda**
   - Crear consultas para investigacion manual.
   - Validar volumen, falsos positivos y utilidad operativa.

3. **Reglas analiticas**
   - Convertir solo consultas con buena senal.
   - Definir severidad, tactica MITRE, entidades y frecuencia.

4. **Automatizacion**
   - Agregar reglas de automatizacion.
   - Usar playbooks para enriquecimiento, notificacion o contencion.

5. **Medicion**
   - Medir ruido, falsos positivos, tiempos de respuesta y cobertura.

## Cadencias operativas

### Tareas diarias

| Tarea | Descripcion | Responsable |
| --- | --- | --- |
| Triaje de incidentes | Revisar nuevos incidentes, priorizar severidad y clasificar. | Tier 1 / Tier 2 |
| Investigacion | Correlacionar entidades, revisar evidencia y determinar alcance. | Tier 2 |
| Busqueda proactiva | Ejecutar consultas de hunting y registrar hallazgos relevantes. | Tier 3 |
| Salud de conectores | Validar que las fuentes clave sigan enviando datos. | Ingeniero SOC |
| Salud de reglas | Revisar reglas fallidas, deshabilitadas o demasiado ruidosas. | Ingeniero SOC |
| Playbooks | Revisar ejecuciones fallidas o acciones pendientes. | Ingeniero SOC |

### Tareas semanales

| Tarea | Descripcion | Responsable |
| --- | --- | --- |
| Revision de contenido | Evaluar nuevas soluciones, reglas, workbooks y playbooks. | Ingeniero SOC |
| Ajuste de reglas ruidosas | Reducir falsos positivos y documentar excepciones. | Ingeniero SOC |
| Revision de metricas | Revisar volumen de incidentes, MTTA, MTTR y cierres por falso positivo. | Lider SOC |
| Revision de busquedas | Promover consultas utiles a reglas analiticas candidatas. | Tier 3 / Ingeniero SOC |
| Revision de costos | Validar ingesta por tabla y crecimiento anomalo. | Arquitecto / Lider |

### Tareas mensuales

| Tarea | Descripcion | Responsable |
| --- | --- | --- |
| Revision de permisos | Validar RBAC, usuarios inactivos y minimo privilegio. | Arquitecto / Lider |
| Revision de retencion | Confirmar que la retencion cumple requisitos operativos y regulatorios. | Ingeniero SOC |
| Cobertura MITRE ATT&CK | Identificar tecnicas cubiertas y brechas de deteccion. | Tier 3 / Ingeniero SOC |
| Revision de backlog | Priorizar nuevas reglas, notebooks, playbooks y mejoras. | Lider SOC |
| Actualizacion del repositorio | Versionar cambios de KQL, documentacion y artefactos. | Ingeniero SOC |

### Tareas trimestrales

- Ejercicio tabletop de respuesta a incidentes.
- Revision de madurez del SOC.
- Revision de arquitectura y costos.
- Revision de convenciones del repositorio.
- Depuracion de contenido obsoleto.
- Actualizacion formal de esta guia.

## Gobernanza de costos

Buenas practicas:

- Empezar por fuentes gratuitas o ya licenciadas.
- Separar alertas de telemetria cruda.
- Habilitar telemetria de alto volumen solo con caso de uso claro.
- Revisar ingesta por tabla de forma recurrente.
- Usar transformaciones de ingesta cuando aplique.
- Ajustar retencion por valor investigativo.
- Documentar supuestos de costo por fuente.

Consultas sugeridas para control:

```kql
Usage
| where TimeGenerated > ago(30d)
| summarize GB = sum(Quantity) / 1024 by DataType, bin(TimeGenerated, 1d)
| order by TimeGenerated desc, GB desc
```

```kql
Heartbeat
| summarize LastSeen = max(TimeGenerated) by Computer, OSType
| order by LastSeen asc
```

## Reglas analiticas

Antes de convertir una busqueda en regla:

1. Validar que la consulta regrese resultados esperados.
2. Revisar falsos positivos.
3. Ajustar umbrales.
4. Agregar entidades.
5. Mapear tacticas y tecnicas MITRE ATT&CK.
6. Definir frecuencia y periodo de busqueda.
7. Documentar la logica de deteccion.
8. Probar en modo de observacion antes de habilitar respuesta automatica.

### Campos minimos recomendados para reglas

| Campo | Recomendacion |
| --- | --- |
| Nombre | Claro, accionable y consistente. |
| Descripcion | Explicar que detecta y por que importa. |
| Severidad | Basada en impacto y confianza. |
| Tacticas MITRE | Mapear segun comportamiento observado. |
| Entidades | IP, cuenta, host, URL, hash, recurso cloud, segun aplique. |
| Frecuencia | Evitar solapamientos innecesarios. |
| Supresion | Usar solo si el ruido esta entendido. |
| Automatizacion | Empezar con enriquecimiento y notificacion antes de contencion. |

## Playbooks y automatizacion

Tipos recomendados:

- Notificacion a Teams o correo.
- Enriquecimiento de IP, usuario, host o recurso.
- Etiquetado automatico de incidentes.
- Cambio de severidad por contexto.
- Creacion de tickets.
- Contencion con aprobacion.

Buenas practicas:

- No automatizar contencion destructiva sin aprobacion inicial.
- Registrar acciones ejecutadas en comentarios del incidente.
- Medir ejecuciones fallidas.
- Revisar costos de Logic Apps.
- Versionar playbooks o documentar cambios relevantes.

## KPIs operativos

| KPI | Que mide |
| --- | --- |
| MTTD | Tiempo medio de deteccion. |
| MTTA | Tiempo medio de reconocimiento. |
| MTTR | Tiempo medio de respuesta o resolucion. |
| Volumen de incidentes | Tendencia diaria, semanal y mensual. |
| Tasa de falsos positivos | Porcentaje de incidentes cerrados como falso positivo. |
| Reglas ruidosas | Reglas con mayor volumen o menor precision. |
| Cobertura MITRE | Tecnicas cubiertas por detecciones activas. |
| Salud de conectores | Fuentes sin datos o con errores. |
| Automatizacion | Porcentaje de incidentes enriquecidos o respondidos por playbooks. |
| Ingesta por tabla | Control de costo y crecimiento. |

## Checklist inicial de implementacion

| # | Actividad | Responsable |
| --- | --- | --- |
| 1 | Habilitar Microsoft Sentinel sobre el area de trabajo. | Ingeniero SOC |
| 2 | Activar salud y auditoria de Sentinel. | Ingeniero SOC |
| 3 | Conectar fuentes base de alto valor. | Ingeniero SOC |
| 4 | Validar ingesta por tabla. | Ingeniero SOC |
| 5 | Instalar contenido relevante desde Content hub. | Ingeniero SOC |
| 6 | Guardar funciones KQL reutilizables. | Ingeniero SOC |
| 7 | Ejecutar consultas de busqueda iniciales. | Tier 3 |
| 8 | Ajustar reglas analiticas candidatas. | Ingeniero SOC / Tier 3 |
| 9 | Definir RBAC por rol operativo. | Arquitecto / Lider |
| 10 | Configurar playbooks de notificacion y enriquecimiento. | Ingeniero SOC |
| 11 | Configurar workbooks de metricas y costos. | Ingeniero SOC |
| 12 | Establecer cadencias diaria, semanal y mensual. | Lider SOC |

## Aplicacion especifica a este paquete DHCP/DNS

Para este repositorio, la guia se aplica asi:

1. Usar `kql/functions/fn_Normalize_Windows_DHCP.kql` para estandarizar eventos DHCP.
2. Usar `kql/functions/fn_Normalize_Windows_DNS.kql` para estandarizar eventos DNS.
3. Usar `kql/functions/fn_Correlate_DHCP_DNS.kql` para unir identidad DHCP con actividad DNS.
4. Ejecutar las consultas en `kql/hunting/` como busquedas iniciales.
5. Ajustar umbrales con datos reales del ambiente.
6. Promover a reglas analiticas solo las consultas con buena precision.
7. Documentar excepciones y cambios en el repositorio.
8. Agregar notebooks cuando se requiera investigacion guiada por IP, hostname o dominio.

## Referencias sugeridas para documentacion del repositorio

Incluir enlaces oficiales al publicar el repositorio:

- Documentacion de Microsoft Sentinel.
- Guia operativa de Microsoft Sentinel.
- Planeacion de costos y facturacion de Microsoft Sentinel.
- Content hub de Microsoft Sentinel.
- Repositorio oficial Azure-Sentinel.
- Documentacion de reglas analiticas.
- Documentacion de playbooks y reglas de automatizacion.
