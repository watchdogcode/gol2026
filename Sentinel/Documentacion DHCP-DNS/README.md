# Paquete DHCP/DNS para Microsoft Sentinel — documentación

Documentación de soporte del paquete de artefactos KQL para logs de **DHCP y DNS de Windows Server** en Microsoft Sentinel / Log Analytics.

El objetivo del paquete es que cualquier equipo cargue las funciones en su propia área de trabajo, ajuste **una sola capa de normalización** y reutilice consultas, reglas y notebooks sin reescribir la lógica.

> Esta carpeta contiene **solo documentación**. Los artefactos ejecutables viven en las carpetas hermanas descritas abajo.

## Documentos de esta carpeta

| Documento | Contenido |
|---|---|
| [`source_mapping.md`](source_mapping.md) | Cómo adaptar el paquete a cualquier área de trabajo: tablas y columnas reales de DHCP y DNS, campos normalizados esperados y consultas `getschema` de validación |
| [`next_steps.md`](next_steps.md) | Ruta de adopción en cuatro fases: normalización, búsqueda operativa, reglas analíticas y notebooks |

## Estructura real del paquete

```text
Sentinel/
├── Funciones/                        capa de normalización (ajustar solo aquí)
│   ├── fn_Normalize_Windows_DHCP.kql
│   ├── fn_Normalize_Windows_DNS.kql
│   └── fn_Correlate_DHCP_DNS.kql
├── Hunting/                          6 consultas de cacería manual
│   ├── 01_dhcp_new_hosts.kql
│   ├── 02_dhcp_ip_mac_churn.kql
│   ├── 03_dns_nxdomain_spikes.kql
│   ├── 04_dns_possible_tunneling.kql
│   ├── 05_dns_rare_domains_by_host.kql
│   └── 06_investigation_ip_timeline.kql
├── Reglas de Analitica/              8 reglas YAML derivadas de las consultas
├── Notebooks/                        8 notebooks de investigación guiada
└── Documentacion DHCP-DNS/           esta carpeta
```

Enlaces: [`Funciones/`](../Funciones/) · [`Hunting/`](../Hunting/) · [`Reglas de Analitica/`](../Reglas%20de%20Analitica/) · [`Notebooks/`](../Notebooks/)

## Orden recomendado de despliegue

Las consultas, reglas y notebooks **consumen el esquema normalizado**, por lo que las funciones se publican primero:

1. [`fn_Normalize_Windows_DHCP.kql`](../Funciones/fn_Normalize_Windows_DHCP.kql)
2. [`fn_Normalize_Windows_DNS.kql`](../Funciones/fn_Normalize_Windows_DNS.kql)
3. [`fn_Correlate_DHCP_DNS.kql`](../Funciones/fn_Correlate_DHCP_DNS.kql)
4. Consultas de [`Hunting/`](../Hunting/)

Pasos:

1. Copiar los archivos de [`Funciones/`](../Funciones/) en Microsoft Sentinel o Log Analytics como funciones guardadas.
2. Validar que las funciones regresen datos con una ventana corta, por ejemplo `7d`.
3. Ajustar nombres de tablas y columnas si el área de trabajo usa fuentes diferentes (ver [`source_mapping.md`](source_mapping.md)).
4. Ejecutar las consultas de [`Hunting/`](../Hunting/).
5. Ajustar umbrales por volumen, sitio, segmento o criticidad.
6. Promover las consultas con mejor señal a [`Reglas de Analitica/`](../Reglas%20de%20Analitica/) o a un workbook.

## Casos de uso principales

- Identificar equipos nuevos observados por DHCP.
- Detectar IPs asociadas a múltiples direcciones MAC.
- Detectar direcciones MAC que cambian de IP con frecuencia.
- Investigar picos de NXDOMAIN.
- Identificar posibles patrones de tunelización DNS.
- Encontrar dominios raros o de baja prevalencia.
- Reconstruir una línea de tiempo por IP usando DHCP + DNS.

## Compatibilidad

Las consultas están diseñadas para ser genéricas y reutilizables en cualquier Microsoft Sentinel, siempre que el área de trabajo tenga logs DHCP y/o DNS ingeridos.

Las fuentes más comunes contempladas son:

- `Event`: eventos Windows recolectados por agente.
- `DnsEvents`: tabla especializada de eventos DNS, cuando existe.
- `DHCP_CL`: ejemplo de tabla personalizada para logs DHCP.

Si el área de trabajo usa otros nombres de tablas o columnas, **solo se deben ajustar las funciones de [`Funciones/`](../Funciones/)**. Las consultas de [`Hunting/`](../Hunting/) consumen el esquema normalizado y no deberían requerir cambios mayores.

## Esquema normalizado DHCP

| Campo | Descripción |
|---|---|
| `TimeGenerated` | Fecha y hora del evento |
| `SourceSystem` | Fuente lógica usada por la función |
| `DeviceName` | Servidor DHCP o controlador de dominio que generó el evento |
| `EventId` | ID de evento, si existe |
| `EventAction` | Acción normalizada del evento DHCP |
| `ClientIp` | IP del cliente |
| `ClientMac` | MAC address normalizada |
| `HostName` | Nombre del host reportado |
| `ScopeId` | Scope DHCP, si existe |
| `RawMessage` | Mensaje original usado para investigación |

## Esquema normalizado DNS

| Campo | Descripción |
|---|---|
| `TimeGenerated` | Fecha y hora del evento |
| `SourceSystem` | Fuente lógica usada por la función |
| `DeviceName` | Servidor DNS o controlador de dominio |
| `ClientIp` | IP que hizo la consulta |
| `QueryName` | Nombre DNS consultado |
| `QueryRootDomain` | Dominio raíz calculado |
| `QueryType` | Tipo de consulta, por ejemplo A, AAAA, PTR o TXT |
| `ResponseCode` | Código de respuesta, por ejemplo NOERROR o NXDOMAIN |
| `Answers` | Respuestas DNS, si existen |
| `QueryLength` | Longitud del nombre consultado |
| `LabelCount` | Número de etiquetas del nombre DNS |
| `MaxLabelLength` | Longitud máxima de una etiqueta DNS |
| `IsReverseLookup` | Indica si es una consulta reversa |
| `IsInternalName` | Indica si parece ser un nombre interno |
| `RawMessage` | Mensaje original usado para investigación |

## Notas

- No contiene datos de cliente, IPs reales, dominios reales ni información sensible.
- Los valores como `TargetIp` son placeholders y deben reemplazarse antes de ejecutar.
- Los umbrales son iniciales y deben ajustarse según el volumen normal de cada organización.
- Los comentarios de los archivos `.kql` están en español sin acentos para facilitar su adopción.

---

Punto de entrada del pilar: [`../README.md`](../README.md) · Modelo operativo general: [`../Guia Operativa/`](../Guia%20Operativa/guia_operativa_microsoft_sentinel.md)