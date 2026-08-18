# Notebooks de investigacion DHCP y DNS para Microsoft Sentinel

Esta carpeta contiene plantillas de Jupyter Notebooks para investigaciones de seguridad usando logs DHCP y DNS de Windows Server en Microsoft Sentinel.

## Objetivo

Ayudar al analista a pasar de una entidad inicial —IP, hostname, direccion MAC o dominio— a una investigacion guiada con contexto DHCP, actividad DNS, lineas de tiempo, dominios raros, NXDOMAIN y posibles patrones de tunelizacion DNS.

## Prerequisitos

### Plataforma

- Microsoft Sentinel habilitado sobre un area de trabajo de Log Analytics.
- Logs DHCP y DNS ingestados en tablas como `Event`, `WindowsEvent`, `DnsEvents` o tablas personalizadas.
- Permisos de lectura sobre el area de trabajo.
- Acceso a Microsoft Sentinel Notebooks o un entorno Jupyter equivalente.

### Funciones KQL requeridas

Publicar primero estas funciones del repositorio:

1. `kql/functions/fn_Normalize_Windows_DHCP.kql`
2. `kql/functions/fn_Normalize_Windows_DNS.kql`
3. `kql/functions/fn_Correlate_DHCP_DNS.kql`

### Paquetes Python sugeridos

Instalar los paquetes de `requirements.txt` segun el entorno donde se ejecuten los notebooks.

## Notebooks incluidos

| Notebook | Uso principal |
|---|---|
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

- Las funciones KQL viven en `../kql/functions/`.
- Las busquedas manuales viven en `../kql/hunting/`.
- Las reglas analiticas viven en `../kql/analytics-rules/`.
- La guia operativa vive en `../docs/guia_operativa_microsoft_sentinel.md`.
