# Mapeo de fuentes - DHCP y DNS Windows

## Objetivo

Este documento explica como adaptar el paquete a cualquier area de trabajo de Microsoft Sentinel o Log Analytics.

Las consultas de busqueda consumen funciones normalizadas. Por eso, el ajuste principal se hace en las funciones de `kql/functions/`.

## DHCP Windows Server

### Fuentes comunes

1. Tabla `Event`
   - Eventos del canal DHCP Server o del proveedor DHCP.
   - Campos frecuentes:
     - `TimeGenerated`
     - `Computer`
     - `EventID`
     - `Source`
     - `EventLog`
     - `RenderedDescription`
     - `EventData`

2. Tabla personalizada `DHCP_CL`
   - Usada cuando se ingieren logs de auditoria DHCP como texto, CSV o log personalizado.
   - Columnas posibles:
     - `TimeGenerated`
     - `Computer`
     - `ServerName_s`
     - `EventId_d`
     - `IPAddress_s`
     - `MACAddress_s`
     - `HostName_s`
     - `ScopeId_s`
     - `Message`

### Campos normalizados esperados

| Campo normalizado | Campo real a mapear |
|---|---|
| `DeviceName` | Servidor DHCP o controlador de dominio |
| `EventId` | ID de evento o codigo DHCP |
| `EventAction` | Accion del evento |
| `ClientIp` | IP asignada, renovada o liberada |
| `ClientMac` | MAC address del cliente |
| `HostName` | Nombre del host del cliente |
| `ScopeId` | Scope DHCP |
| `RawMessage` | Mensaje original |

## DNS Windows Server / controladores de dominio

### Fuentes comunes

1. Tabla `DnsEvents`
   - Tabla especializada de eventos DNS, cuando esta disponible.
   - Columnas posibles:
     - `TimeGenerated`
     - `Computer`
     - `Name`
     - `QueryName`
     - `ClientIP`
     - `QueryType`
     - `QueryStatus`
     - `ResponseCode`
     - `IPAddresses`

2. Tabla `Event`
   - Eventos del proveedor DNS Server.
   - Campos frecuentes:
     - `TimeGenerated`
     - `Computer`
     - `EventID`
     - `Source`
     - `RenderedDescription`
     - `EventData`

### Campos normalizados esperados

| Campo normalizado | Campo real a mapear |
|---|---|
| `DeviceName` | Servidor DNS o controlador de dominio |
| `ClientIp` | Cliente que hizo la consulta |
| `QueryName` | Dominio o nombre consultado |
| `QueryType` | A, AAAA, PTR, TXT, MX, etc. |
| `ResponseCode` | NOERROR, NXDOMAIN, SERVFAIL, etc. |
| `Answers` | Respuesta DNS |
| `RawMessage` | Mensaje original |

## Consultas utiles para validar tablas

Ejecutar estas consultas antes de ajustar las funciones:

```kql
Event
| getschema
```

```kql
DnsEvents
| getschema
```

```kql
DHCP_CL
| getschema
```

Si una tabla no existe, se puede remover su bloque correspondiente de la funcion o reemplazarlo por la tabla real del area de trabajo.
