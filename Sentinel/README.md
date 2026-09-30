# Microsoft Sentinel — Proyecto GOL

Pilar **Sentinel/** del marco SecOps GOL. A diferencia del resto de los pilares del repositorio (que se organizan por producto de Defender), esta carpeta agrupa **tres bloques independientes** que no comparten prerequisitos ni ciclo de vida. Elija el que corresponde a su objetivo antes de abrir cualquier archivo.

| Si su objetivo es… | Vaya a | Requiere |
|---|---|---|
| Operar Sentinel como SIEM/SOAR: cadencias, salud de conectores, costos, ciclo de vida de contenido | [Guía operativa](#1-guía-operativa-de-sentinel) | Sentinel habilitado |
| Detectar e investigar sobre logs **DHCP y DNS** de Windows Server | [Paquete DHCP/DNS](#2-paquete-dhcpdns) | Logs DHCP/DNS ingeridos |
| Diseñar un **SOC agéntico** con Security Copilot, Copilot Studio y el Sentinel MCP server | [AI SOC](#3-ai-soc--playbook-agéntico) | Licenciamiento Security Copilot (SCU) |
| Publicar el **reporte diario ejecutivo** dentro de Sentinel | [Workbook](#4-workbook-de-reporte-diario) | Conectores de Defender XDR |

> Los tres bloques son autónomos. No es necesario adoptar uno para usar otro.

---

## 1. Guía operativa de Sentinel

**Objetivo.** Establecer un modelo operativo estándar, repetible y medible para equipos que usan Sentinel como SIEM/SOAR.

| Archivo | Contenido |
|---|---|
| [`Guia Operativa/guia_operativa_microsoft_sentinel.md`](Guia%20Operativa/guia_operativa_microsoft_sentinel.md) | Operación diaria, gestión de incidentes, salud de conectores/reglas/agentes/playbooks, gobernanza de costos, ciclo de vida de contenido KQL, respaldo de artefactos, KPIs y checklist de implementación |

Es el documento transversal: aplica tanto al paquete DHCP/DNS como a cualquier otro contenido que se despliegue en el espacio de trabajo.

---

## 2. Paquete DHCP/DNS

**Objetivo.** Explotar logs de DHCP y DNS de Windows Server con artefactos reutilizables, de modo que cada organización ajuste **una sola capa de normalización** y reutilice el resto sin reescribir la lógica.

### Orden de despliegue (obligatorio)

Las consultas, reglas y notebooks **consumen el esquema normalizado**. Publicar primero las funciones como funciones guardadas en Log Analytics:

1. [`Funciones/fn_Normalize_Windows_DHCP.kql`](Funciones/fn_Normalize_Windows_DHCP.kql) — normaliza eventos DHCP (`ClientIp`, `ClientMac`, `HostName`, `ScopeId`…)
2. [`Funciones/fn_Normalize_Windows_DNS.kql`](Funciones/fn_Normalize_Windows_DNS.kql) — normaliza eventos DNS (`QueryName`, `QueryRootDomain`, `QueryType`, `ResponseCode`…)
3. [`Funciones/fn_Correlate_DHCP_DNS.kql`](Funciones/fn_Correlate_DHCP_DNS.kql) — correlaciona ambos por IP

Si el espacio de trabajo usa otras tablas o columnas (`Event`, `WindowsEvent`, `DnsEvents`, `DHCP_CL` o personalizadas), **solo se modifican estas tres funciones**.

### Artefactos que consumen las funciones

| Carpeta | Objetivo | Cuándo se usa |
|---|---|---|
| [`Hunting/`](Hunting/) | 6 consultas de cacería manual: equipos nuevos por DHCP, churn IP/MAC, picos de NXDOMAIN, posible tunelización DNS, dominios raros y línea de tiempo por IP | Exploración y validación de señal |
| [`Reglas de Analitica/`](Reglas%20de%20Analitica/) | 8 reglas analíticas YAML derivadas de las consultas anteriores | Detección continua, tras validar falsos positivos |
| [`notebooks/`](notebooks/) | 8 notebooks Jupyter de investigación guiada a partir de una IP, hostname, MAC o dominio, más un grafo de relaciones | Investigación profunda de un incidente ya abierto |
| [`Documentacion DHCP-DNS/`](Documentacion%20DHCP-DNS/) | Documentación del paquete: mapeo de tablas y columnas reales ([`source_mapping.md`](Documentacion%20DHCP-DNS/source_mapping.md)) y ruta de adopción en cuatro fases ([`next_steps.md`](Documentacion%20DHCP-DNS/next_steps.md)) | Antes de desplegar y al adaptar el esquema |

El flujo previsto es: **normalizar → cazar en `Hunting/` → promover lo que da señal a `Reglas de Analitica/` → investigar los disparos con `notebooks/`**.

---

## 3. AI SOC — Playbook agéntico

**Objetivo.** Documentar el modelo de SOC asistido por agentes (ISOC/AI-SOC): arquitectura de referencia, catálogo de agentes nativos y personalizados, gobierno, runbooks, KPIs y ruta de adopción.

| Recurso | Contenido |
|---|---|
| [`AI SOC/README.md`](AI%20SOC/README.md) | **Punto de entrada.** Índice de las 17 secciones (00 a 16) |
| [`AI SOC/06-kql.md`](AI%20SOC/06-kql.md) | 23 consultas KQL de medición del SOC, actividad de agentes, higiene de datos y cacería |
| [`AI SOC/arquitectura/`](AI%20SOC/arquitectura/) | Diagramas, diseño de agentes y criterios de tiering de datos |
| [`AI SOC/configuracion/`](AI%20SOC/configuracion/) | Configuración paso a paso: licenciamiento, roles, conector de Security Copilot, Sentinel MCP server, Logic Apps SOAR y checklist de readiness |

A diferencia de los otros bloques, es **documentación de diseño y adopción**, no artefactos desplegables. Varias capacidades que describe están en versión preliminar; cada sección lo declara.

---

## 4. Workbook de reporte diario

| Archivo | Objetivo |
|---|---|
| [`Workbook/Sentinel_Workbook_GOL.json`](Workbook/Sentinel_Workbook_GOL.json) | Workbook de Sentinel que reproduce el **Reporte Diario de Operaciones de Seguridad** del Proyecto GOL: estado general de riesgo, KPIs, análisis comparativo diario, detecciones personalizadas y secciones por pilar (MDO, MDE, MDI, MDA) |

No pertenece al paquete DHCP/DNS. Es el equivalente dentro de Sentinel de los reportes HTML de [`../XDR/`](../XDR/) y depende de que los conectores de Defender XDR estén ingiriendo en el espacio de trabajo.

---

## Convenciones y advertencias

- **Umbrales.** Todos los valores de umbral son iniciales y deben calibrarse contra el volumen normal de cada organización antes de habilitar automatización.
- **Placeholders.** Reemplace `TargetIp`, `REEMPLAZAR_CON_*` y los valores entre corchetes (`[organización]`, `[90]` días) antes de ejecutar.
- **Sin datos reales.** El contenido no incluye IPs, dominios, hostnames ni información de cliente. No versione salidas con datos sensibles.
- **Idioma.** El paquete DHCP/DNS está escrito sin acentos por compatibilidad; la guía operativa y AI SOC usan ortografía completa.

## Relación con el resto del repositorio

| Pilar | Relación con Sentinel |
|---|---|
| [`../MDO/`](../MDO/) [`../MDE/`](../MDE/) [`../MDI/`](../MDI/) [`../MDA/`](../MDA/) [`../EntraID/`](../EntraID/) | Producen las alertas y la telemetría que Sentinel correlaciona |
| [`../IR/`](../IR/) | Los playbooks de respuesta consumen las investigaciones iniciadas aquí |
| [`../XDR/`](../XDR/) | Reportería equivalente vía API, fuera de Sentinel |
| [`../Requisitos.md`](../Requisitos.md) | Licenciamiento, App Registration y dependencias de PowerShell |
