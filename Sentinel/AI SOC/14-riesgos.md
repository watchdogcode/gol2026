<!-- AI-SOC Playbook v2.0 · Arturo Mandujano (Cloud Solution Architect) · 28 de septiembre de 2026 -->
[← 13. Casos de uso priorizados](13-casos-de-uso.md) | [Índice](README.md) | [15. Cómo empezar: laboratorio de 5 días autoguiado →](15-laboratorio-5-dias.md)

---

# 14. Riesgos y limitaciones conocidas

## 14.1 Registro de riesgos y limitaciones conocidas

| Riesgo | Probabilidad | Impacto | Mitigación |
|----|----|----|----|
| Capacidades en versión preliminar cambian de comportamiento o de modelo de licenciamiento antes de alcanzar disponibilidad general | Media | Medio | Separar en el diseño lo que está en GA de lo que está en preview; no construir procesos críticos exclusivamente sobre preview; revisar el roadmap trimestralmente |
| El despliegue del Phishing Triage Agent deshabilita reglas de alert tuning y se pierden supresiones intencionales | Alta | Medio | Inventariar y documentar todas las reglas de alert tuning en la Fase 0 antes del despliegue |
| Consumo de SCU superior al previsto por el pool compartido del tenant | Media | Medio | Presupuesto por caso de uso, revisión semanal del monitoreo de uso, dimensionamiento sobre el percentil alto y previsión del cambio de modelo del Dynamic Threat Detection Agent |
| Baja calidad de los veredictos del agente por falta de retroalimentación del equipo | Media | Alto | Runbook 9.5 con propietario, cadencia y meta de tasa de reclasificación; la retroalimentación es tarea asignada, no voluntaria |
| Contenido no confiable induce al agente a un comportamiento no deseado (prompt injection) | Media | Alto | Restricción del conjunto de herramientas por agente; agentes de triage limitados a niveles N0 a N2; revisión del razonamiento expuesto; muestreo específico de casos anómalos |
| Cobertura incompleta por dispositivos no administrados o conectores rotos | Alta | Alto | Consultas 6.3.2 y 6.3.3 en el dashboard diario; despliegue de Azure Arc; SOC optimization |
| Costo de ingesta creciente sin valor de detección proporcional | Alta | Medio | Política de tiering de la sección 4.3.1 y revisión mensual con la consulta 6.3.1 |
| La capacidad humana liberada se reabsorbe en más tickets y el modelo operativo no cambia | Media | Alto | Tiempo protegido para ingeniería de detecciones y cacería; medición de alertas por analista por turno |
| Requisitos de residencia de datos en sectores regulados (público, financiero, salud) limitan alguna capacidad | Media | Medio | Validación temprana con cumplimiento en la Fase 0 y diseño de retención por tier |
| Consumo de SCU no controlado por agentes programados de Copilot Studio y Power Automate que se ejecutan aunque nadie consuma su salida | Media | Alto | Presupuesto de SCU por agente en la tabla 30; ventana horaria y frecuencia fijas; parámetro Plugins del conector para acotar el planificador; revisión semanal de consumo (agente CS-10 y reporte de la tabla 32); desactivación automática del flujo si el consumo semanal excede el umbral acordado |
| Dependencia de los permisos delegados del usuario que creó la conexión del conector de Security Copilot: si esa persona deja la organización o pierde el rol, todos los agentes que usan la conexión dejan de funcionar | Alta | Alto | Crear la conexión con una cuenta de servicio nominal dedicada, propiedad del equipo de ingeniería de agentes, con Copilot Contributor y los roles de lectura necesarios; documentarla en el inventario de identidades no humanas; procedimiento de re-autenticación en el runbook de salida de personal; solución de Power Platform con propietario secundario |
| Estado preview de la integración del Sentinel MCP server con Copilot Studio y de las herramientas de grafo: cambios de contrato, de herramientas o de autenticación durante el proyecto | Media | Medio | Aislar las herramientas MCP en agentes específicos (CS-2, CS-3, CS-7, CS-9, CS-10); conservar en cada uno una ruta alterna mediante el conector de Security Copilot o KQL directo; verificar la documentación de Learn en cada revisión mensual de calidad; no comprometer SLA sobre capacidades preview |
| Escritura no autorizada de un agente sobre incidentes o tickets por una instrucción inyectada en el contenido analizado | Baja | Alto | Patrón draft-first: toda escritura (comentario en incidente, ticket, cambio) requiere aprobación explícita en Teams o se ejecuta sólo en flujos sin entrada de contenido externo; identidad de escritura separada de la identidad de lectura; registro en AuditLogs y en Purview audit |

*Tabla 37. Registro de riesgos, limitaciones conocidas y mitigaciones.*

## 14.2 Supuestos de la guía

- La organización cuenta con licenciamiento Microsoft 365 E5 o E7, o puede incorporarlo dentro del horizonte de adopción.

- Existe un espacio de trabajo de Microsoft Sentinel que puede consolidarse, o la decisión de consolidar está tomada.

- El equipo de seguridad puede dedicar personas a las actividades de habilitación descritas en la ruta de adopción (parámetro [número de analistas] del anexo D).

- Se conoce el volumen de ingesta actual y se dispone de su desglose por tabla (parámetro [volumen de ingesta GB/día] del anexo D).

- Las capacidades identificadas como preview mantienen su comportamiento documentado a septiembre de 2026 durante la adopción; cualquier cambio documentado por Microsoft debe revisarse en la evaluación mensual de calidad de la sección 11.7.

## 14.3 Dependencias

- Aprobación del modelo de gobierno de agentes por el comité de seguridad antes de la Fase 2.

- Disponibilidad del equipo de identidad para la creación de roles URBAC e identidades agénticas.

- Disponibilidad del equipo de infraestructura y de red para los requisitos de conectividad y el despliegue de Azure Arc.

- Validación de las cifras de SCU y de licenciamiento contra la página oficial de precios; en esta guía son indicativas públicas a la fecha de elaboración.

- Participación de los propietarios de aplicación para la clasificación de activos críticos.

## 14.4 Consideraciones de capacidad y costo

La optimización de costo se ejecuta con tres mecanismos ya descritos, que conviene leer juntos. SOC optimization entrega recomendaciones dinámicas sobre datos y cobertura, y los clientes que las implementaron aumentaron su cobertura de seguridad hasta 17% y la utilización de datos 31% (Microsoft, Coordinated Defense, 2025). El tiering entre analytics y data lake evita pagar precio de detección por datos cuyo valor es forense, y el formato abierto Delta Parquet elimina la re-ingesta al investigar. El gobierno de SCU evita que la capacidad agéntica se consuma en casos de uso de bajo valor y que el sobreconsumo se facture al precio superior.

El modelo de negocio de cada organización debe construirse en la Fase 0 con sus propios datos. La referencia externa disponible proyecta hasta 348% de ROI y 1.76 millones de dólares de valor presente neto a tres años (Forrester New Technology: Projected Total Economic Impact of Microsoft Security Copilot, noviembre 2024); es una referencia de orden de magnitud, no una promesa. Las cifras de SCU de la sección 7.2 son indicativas públicas a la fecha de elaboración; la fuente vigente es la página oficial de precios de Microsoft Security Copilot (https://www.microsoft.com/en-us/security/pricing/microsoft-security-copilot/) y la calculadora pública de SCU (https://securitycopilot.microsoft.com/calculator). Esta guía no contiene cotizaciones ni condiciones comerciales.


---

[← 13. Casos de uso priorizados](13-casos-de-uso.md) | [Índice](README.md) | [15. Cómo empezar: laboratorio de 5 días autoguiado →](15-laboratorio-5-dias.md)
