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
|---|---|
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
|---|---|
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

| Fuente | Tablas comunes | Valor operativo |
|---|---|---|
| Microsoft Defender XDR | `SecurityIncident`, `SecurityAlert` | Incidentes y alertas unificadas. |
| Azure Activity | `AzureActivity` | Actividad del plano de control de Azure. |
| Microsoft 365 / Office 365 | `OfficeActivity` | Actividad de Exchange, SharePoint y Teams. |
| Microsoft Defender for Cloud | `SecurityAlert` | Alertas de cargas de trabajo cloud. |
| Microsoft Entra ID Protection | `SecurityAlert` | Alertas de riesgo de identidad. |
| Microsoft Sentinel Health | `SentinelHealth` | Estado de conectores, reglas y automatizacion. |
| Windows Server DHCP | `Event`, `WindowsEvent` o tabla personalizada | Identidad de red: IP, MAC, hostname, scope y leases. |
| Windows Server DNS | `DnsEvents`, `Event`, `WindowsEvent` o tabla personalizada | Resolucion DNS, dominios consultados y comportamiento de clientes. |

> Nota: Las tablas y costos dependen del tipo de conector, licencia y configuracion. Validar siempre la facturacion esperada antes de habilitar telemetria cruda de alto volumen.

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
|---|---|---|
| Triaje de incidentes | Revisar nuevos incidentes, priorizar severidad y clasificar. | Tier 1 / Tier 2 |
| Investigacion | Correlacionar entidades, revisar evidencia y determinar alcance. | Tier 2 |
| Busqueda proactiva | Ejecutar consultas de hunting y registrar hallazgos relevantes. | Tier 3 |
| Salud de conectores | Validar que las fuentes clave sigan enviando datos. | Ingeniero SOC |
| Salud de reglas | Revisar reglas fallidas, deshabilitadas o demasiado ruidosas. | Ingeniero SOC |
| Playbooks | Revisar ejecuciones fallidas o acciones pendientes. | Ingeniero SOC |

### Tareas semanales

| Tarea | Descripcion | Responsable |
|---|---|---|
| Revision de contenido | Evaluar nuevas soluciones, reglas, workbooks y playbooks. | Ingeniero SOC |
| Ajuste de reglas ruidosas | Reducir falsos positivos y documentar excepciones. | Ingeniero SOC |
| Revision de metricas | Revisar volumen de incidentes, MTTA, MTTR y cierres por falso positivo. | Lider SOC |
| Revision de busquedas | Promover consultas utiles a reglas analiticas candidatas. | Tier 3 / Ingeniero SOC |
| Revision de costos | Validar ingesta por tabla y crecimiento anomalo. | Arquitecto / Lider |

### Tareas mensuales

| Tarea | Descripcion | Responsable |
|---|---|---|
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
|---|---|
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
|---|---|
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
|---|---|---|
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

