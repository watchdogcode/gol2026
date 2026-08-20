# Paquete KQL para DHCP y DNS en Microsoft Sentinel

Este repositorio contiene artefactos KQL reutilizables para explotar logs de DHCP y DNS de Windows Server en Microsoft Sentinel / Log Analytics.

El objetivo es que cualquier persona pueda cargar estas consultas en su propia area de trabajo, ajustar una sola capa de normalizacion y reutilizar las consultas de investigacion sin reescribir la logica.

## Que incluye

- Funciones KQL para normalizar logs DHCP.
- Funciones KQL para normalizar logs DNS.
- Funcion de correlacion DHCP + DNS por IP.
- Consultas de busqueda listas para usar como punto de partida.
- Documentacion para mapear tablas y columnas reales.

## Casos de uso principales

- Identificar equipos nuevos observados por DHCP.
- Detectar IPs asociadas a multiples direcciones MAC.
- Detectar direcciones MAC que cambian de IP con frecuencia.
- Investigar picos de NXDOMAIN.
- Identificar posibles patrones de tunelizacion DNS.
- Encontrar dominios raros o de baja prevalencia.
- Reconstruir una linea de tiempo por IP usando DHCP + DNS.

## Compatibilidad

Las consultas estan disenadas para ser genericas y reutilizables en cualquier Microsoft Sentinel, siempre que el area de trabajo tenga logs DHCP y/o DNS ingestados.

Las fuentes mas comunes contempladas son:

- `Event`: eventos Windows recolectados por agente.
- `DnsEvents`: tabla especializada de eventos DNS, cuando existe.
- `DHCP_CL`: ejemplo de tabla personalizada para logs DHCP.

Si el area de trabajo usa otros nombres de tablas o columnas, solo se deben ajustar las funciones en `kql/functions/`. Las consultas en `kql/hunting/` consumen el esquema normalizado y no deberian requerir cambios mayores.

## Estructura del repositorio

```text
kql/
  functions/
    fn_Normalize_Windows_DHCP.kql
    fn_Normalize_Windows_DNS.kql
    fn_Correlate_DHCP_DNS.kql
  hunting/
    01_dhcp_new_hosts.kql
    02_dhcp_ip_mac_churn.kql
    03_dns_nxdomain_spikes.kql
    04_dns_possible_tunneling.kql
    05_dns_rare_domains_by_host.kql
    06_investigation_ip_timeline.kql
docs/
  source_mapping.md
  next_steps.md
```

## Como usar

1. Copiar los archivos de `kql/functions/` en Microsoft Sentinel o Log Analytics como funciones guardadas.
2. Validar que las funciones regresen datos con una ventana corta, por ejemplo `7d`.
3. Ajustar nombres de tablas y columnas si el area de trabajo usa fuentes diferentes.
4. Ejecutar las consultas de `kql/hunting/`.
5. Ajustar umbrales por volumen, sitio, segmento o criticidad.
6. Convertir las consultas con mejor senal en reglas analiticas o libros de trabajo.

## Orden recomendado de despliegue

1. `fn_Normalize_Windows_DHCP.kql`
2. `fn_Normalize_Windows_DNS.kql`
3. `fn_Correlate_DHCP_DNS.kql`
4. Consultas de `kql/hunting/`

## Esquema normalizado DHCP

| Campo | Descripcion |
|---|---|
| `TimeGenerated` | Fecha y hora del evento |
| `SourceSystem` | Fuente logica usada por la funcion |
| `DeviceName` | Servidor DHCP o controlador de dominio que genero el evento |
| `EventId` | ID de evento, si existe |
| `EventAction` | Accion normalizada del evento DHCP |
| `ClientIp` | IP del cliente |
| `ClientMac` | MAC address normalizada |
| `HostName` | Nombre del host reportado |
| `ScopeId` | Scope DHCP, si existe |
| `RawMessage` | Mensaje original usado para investigacion |

## Esquema normalizado DNS

| Campo | Descripcion |
|---|---|
| `TimeGenerated` | Fecha y hora del evento |
| `SourceSystem` | Fuente logica usada por la funcion |
| `DeviceName` | Servidor DNS o controlador de dominio |
| `ClientIp` | IP que hizo la consulta |
| `QueryName` | Nombre DNS consultado |
| `QueryRootDomain` | Dominio raiz calculado |
| `QueryType` | Tipo de consulta, por ejemplo A, AAAA, PTR o TXT |
| `ResponseCode` | Codigo de respuesta, por ejemplo NOERROR o NXDOMAIN |
| `Answers` | Respuestas DNS, si existen |
| `QueryLength` | Longitud del nombre consultado |
| `LabelCount` | Numero de etiquetas del nombre DNS |
| `MaxLabelLength` | Longitud maxima de una etiqueta DNS |
| `IsReverseLookup` | Indica si es una consulta reversa |
| `IsInternalName` | Indica si parece ser un nombre interno |
| `RawMessage` | Mensaje original usado para investigacion |

## Notas para GitHub

- No contiene datos de cliente, IPs reales, dominios reales ni informacion sensible.
- Los valores como `TargetIp` son placeholders y deben reemplazarse antes de ejecutar.
- Los umbrales son iniciales y deben ajustarse segun el volumen normal de cada organizacion.
- Los comentarios estan en espanol para facilitar adopcion por equipos de seguridad de habla hispana.
