# Siguientes pasos recomendados

## Fase 1 - Normalizacion

1. Confirmar tablas reales de DHCP y DNS.
2. Confirmar nombres de columnas.
3. Ajustar `column_ifexists()` y `extract()` en las funciones.
4. Guardar las funciones en Log Analytics / Microsoft Sentinel.

## Fase 2 - Busqueda operativa

1. Ejecutar las consultas con ventanas de 7, 14 y 30 dias.
2. Validar falsos positivos.
3. Ajustar umbrales por sitio, segmento, volumen o controlador de dominio.
4. Separar consultas para investigacion manual de consultas candidatas a alerta.

## Fase 3 - Reglas analiticas

Consultas candidatas a convertirse en reglas analiticas:

- Posible tunelizacion DNS.
- Picos de NXDOMAIN por host.
- Host nuevo con actividad DNS anomala.
- IP con cambios frecuentes de MAC.
- MAC address moviendose entre multiples IPs.
- Controlador de dominio consultando dominios externos inusuales.

## Fase 4 - Notebooks

Notebooks recomendados:

- Investigacion por IP: lease DHCP + linea de tiempo DNS.
- Investigacion por hostname: actividad historica y dominios consultados.
- Linea base DNS por controlador de dominio.
- Clustering de dominios por comportamiento.
