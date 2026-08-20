# Reglas analiticas para DHCP y DNS

Este directorio contiene reglas analiticas independientes para Microsoft Sentinel basadas en las funciones de normalizacion del paquete.

## Requisito previo

Antes de importar estas reglas, guardar en Log Analytics las funciones:

1. `fn_Normalize_Windows_DHCP`
2. `fn_Normalize_Windows_DNS`
3. `fn_Correlate_DHCP_DNS`

## Reglas incluidas

| Archivo | Objetivo | Severidad inicial |
|---|---|---|
| `01_dhcp_new_host_observed.yaml` | Host o direccion MAC nueva observada por DHCP. | Media |
| `02_dhcp_ip_multiple_macs.yaml` | IP asociada a multiples direcciones MAC. | Media |
| `03_dhcp_mac_multiple_ips.yaml` | Direccion MAC asociada a multiples IPs. | Baja |
| `04_dns_nxdomain_spike_by_client.yaml` | Pico de NXDOMAIN por cliente. | Media |
| `05_dns_possible_tunneling.yaml` | Posible tunelizacion o exfiltracion por DNS. | Alta |
| `06_dns_rare_domain_by_client.yaml` | Dominio raro consultado por pocos clientes. | Baja |
| `07_dns_high_txt_query_ratio.yaml` | Alta proporcion de consultas TXT. | Media |
| `08_new_dhcp_host_with_suspicious_dns.yaml` | Host nuevo por DHCP con comportamiento DNS anomalo. | Alta |

## Ajustes recomendados antes de habilitar

- Validar que las funciones normalizadas regresen datos.
- Ajustar ventanas `queryFrequency` y `queryPeriod`.
- Ajustar umbrales de volumen segun el ambiente.
- Revisar falsos positivos en modo observacion.
- Confirmar entidades mapeadas.
- Asociar tacticas y tecnicas MITRE segun el caso de uso.
- Habilitar automatizacion solo despues de validar precision.

