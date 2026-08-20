# Notebooks de investigacion DHCP y DNS para Microsoft Sentinel

Esta carpeta contiene notebooks de Jupyter para investigar eventos DHCP y DNS de Windows Server almacenados en Microsoft Sentinel. Los notebooks complementan las consultas KQL, las reglas analiticas y la guia operativa del proyecto; no reemplazan el triaje ni el registro de evidencias en el incidente.

## Objetivo

Ayudar al analista SOC a partir de una IP, hostname, direccion MAC o dominio y avanzar de forma guiada hasta obtener contexto util para una investigacion.

Con estos notebooks se puede:

- Relacionar una IP con una direccion MAC y un hostname mediante DHCP.
- Revisar los dominios consultados por un dispositivo.
- Construir lineas de tiempo de actividad.
- Identificar equipos nuevos, dominios poco frecuentes y respuestas NXDOMAIN.
- Analizar indicios de DGA, tunelizacion o posible exfiltracion mediante DNS.
- Visualizar relaciones entre IP, MAC, hostname y dominio.

## Que se encuentra actualmente en esta carpeta

| Elemento | Contenido |
| --- | --- |
| Ocho archivos `.ipynb` | Investigaciones guiadas por IP, dispositivo, tunelizacion DNS, DGA/NXDOMAIN, equipos nuevos, dominios raros, linea base y relaciones entre entidades. |
| `common/kql_reference.md` | Referencia rapida de las funciones KQL que utilizan los notebooks. |
| `config.sample.json` | Plantilla para indicar el workspace, tenant y periodo de consulta predeterminado. No contiene credenciales. |
| `requirements.txt` | Dependencias Python sugeridas para ejecutar y visualizar los resultados. |
| `README.md` | Explicacion del objetivo, requisitos y orden recomendado de uso. |

Los notebooks son plantillas operativas: antes de ejecutarlos se deben configurar los datos del entorno y validar que las tablas y funciones KQL requeridas existan en el workspace.

## Prerequisitos

### Plataforma

- Microsoft Sentinel habilitado sobre un area de trabajo de Log Analytics.
- Logs DHCP y DNS ingestados en tablas como `Event`, `WindowsEvent`, `DnsEvents` o tablas personalizadas.
- Permisos de lectura sobre el area de trabajo.
- Acceso a Microsoft Sentinel Notebooks o un entorno Jupyter equivalente.

### Funciones KQL requeridas

Publicar primero estas funciones del repositorio:

1. [`fn_Normalize_Windows_DHCP.kql`](../Funciones/fn_Normalize_Windows_DHCP.kql)
2. [`fn_Normalize_Windows_DNS.kql`](../Funciones/fn_Normalize_Windows_DNS.kql)
3. [`fn_Correlate_DHCP_DNS.kql`](../Funciones/fn_Correlate_DHCP_DNS.kql)

### Paquetes Python sugeridos

Instalar los paquetes de `requirements.txt` segun el entorno donde se ejecuten los notebooks.

## Notebooks incluidos

| Notebook | Uso principal |
| --- | --- |
| `01_investigacion_por_ip.ipynb` | Reconstruir identidad DHCP y actividad DNS desde una IP. |
| `02_investigacion_por_hostname_mac.ipynb` | Seguir un dispositivo por hostname o direccion MAC aunque cambie de IP. |
| `03_posible_tunelizacion_dns.ipynb` | Analizar patrones compatibles con tunelizacion o exfiltracion DNS. |
| `04_dga_nxdomain.ipynb` | Investigar picos de NXDOMAIN y posibles dominios generados automaticamente. |
| `05_dispositivos_nuevos.ipynb` | Identificar equipos nuevos y revisar su actividad DNS inicial. |
| `06_dominios_raros.ipynb` | Encontrar dominios de baja prevalencia y los hosts que los consultaron. |
| `07_linea_base_dns_servidor.ipynb` | Construir linea base de volumen DNS por servidor o controlador de dominio. |
| `08_grafo_ip_mac_host_dominio.ipynb` | Visualizar relaciones entre IP, MAC, host y dominio. |

## Orden recomendado de uso

1. `01_investigacion_por_ip.ipynb`
2. `03_posible_tunelizacion_dns.ipynb`
3. `04_dga_nxdomain.ipynb`
4. `05_dispositivos_nuevos.ipynb`
5. `06_dominios_raros.ipynb`
6. `02_investigacion_por_hostname_mac.ipynb`
7. `07_linea_base_dns_servidor.ipynb`
8. `08_grafo_ip_mac_host_dominio.ipynb`

## Buenas practicas

- Reemplazar todos los valores `REEMPLAZAR_CON_*` antes de ejecutar.
- Ejecutar primero con ventanas pequenas, por ejemplo 24h o 7d.
- Validar falsos positivos antes de convertir hallazgos en reglas analiticas.
- No guardar salidas con datos sensibles dentro del repositorio.
- Documentar hallazgos relevantes en el incidente de Sentinel.

## Relacion con el resto del repositorio

- Las funciones reutilizables estan en [`../Funciones/`](../Funciones/).
- Las busquedas manuales estan en [`../Hunting/`](../Hunting/).
- Las reglas de deteccion estan en [`../Reglas de Analitica/`](../Reglas%20de%20Analitica/).
- La guia general de operacion esta en [`../Guia Operativa/guia_operativa_microsoft_sentinel.md`](../Guia%20Operativa/guia_operativa_microsoft_sentinel.md).
