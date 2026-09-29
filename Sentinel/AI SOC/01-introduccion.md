<!-- AI-SOC Playbook v2.0 · Arturo Mandujano (Cloud Solution Architect) · 28 de septiembre de 2026 -->
[← Portada, cómo usar esta guía y cómo contribuir](00-portada-y-como-usar.md) | [Índice](README.md) | [2. Contexto: el cambio a la era agéntica →](02-contexto.md)

---

# 1. Introducción y alcance

## 1.1 Para quién es esta guía y qué problema aborda

Esta guía está escrita para tres perfiles. Los arquitectos de seguridad y de nube encontrarán en las secciones 3, 4 y 7 la arquitectura de referencia, las decisiones de tiering de datos y los requisitos para construirla. Los ingenieros y analistas de SOC encontrarán en las secciones 5, 6, 9 y 11 el catálogo de agentes, las consultas KQL, los runbooks y las cadencias que se pueden adoptar tal cual o adaptar. Los líderes de seguridad encontrarán en las secciones 1, 2, 8, 10, 12 y 14 el porqué del modelo, el marco de gobierno, los roles de referencia, la ruta de adopción y los riesgos conocidos.

Es un documento de referencia, no una receta: cada organización parte de una madurez, un licenciamiento y un perfil de amenazas distintos, y la guía señala en cada caso qué es un patrón recomendado y qué es una decisión que debe tomarse localmente. El problema que aborda es el siguiente.

La economía del atacante cambió. Los ciberatacantes ya utilizan agentes para automatizar la ejecución de sus campañas a una escala sin precedentes: lo que antes requería equipos enteros hoy requiere un solo operador y un marco de agentes (Microsoft Source LATAM, septiembre 2026). Frente a eso, la mayoría de los centros de operaciones de seguridad conserva una arquitectura lineal heredada, en la que la protección y las operaciones se construyeron como sistemas separados. Cada traspaso, cada integración y cada límite entre productos ralentiza a los defensores, y los agentes que se incorporen sobre esa base heredan la misma complejidad.

El costo de esa fricción es medible. El 32% de los incidentes que investigan los equipos de SOC resultan no ser una amenaza (IBM Global SOC Study, marzo 2023), los activos cibernéticos crecieron 133% interanual (Microsoft Digital Defense Report, 2024) y el 83% de las organizaciones enfrenta brechas repetidas (Microsoft Digital Defense Report, 2024). Un modelo operativo basado en aumentar la plantilla de Tier 1 para absorber ese volumen ya no es viable ni financiera ni operativamente para la mayoría de las organizaciones.

## 1.2 Qué cubre esta guía

Esta guía describe cómo transformar un SOC tradicional en un Centro Integrado de Operaciones de Seguridad (ISOC): un modelo que reúne el SIEM y la protección contra amenazas sobre una base de datos y de contexto compartida, de modo que las personas y los agentes puedan ver, entender y actuar sobre todo el entorno como un solo sistema. El patrón de referencia se apoya en cuatro piezas que muchas organizaciones ya licencian total o parcialmente: Microsoft Sentinel como plataforma de datos (SIEM, data lake y graph), Microsoft Defender XDR como plano de protección y respuesta, Microsoft Security Copilot como capa de razonamiento agéntico, y Microsoft Purview y Microsoft Entra como planos de datos e identidad.

La transformación no consiste en ensamblar una capa agéntica separada ni en adoptar un nuevo modelo operativo paralelo. Los profesionales de seguridad multiplican su experiencia donde ya trabajan: el portal de Defender, las consultas de advanced hunting y los procesos de respuesta existentes. Lo que cambia es qué trabajo hace la máquina y qué trabajo queda reservado al juicio humano.

La guía cubre seis bloques. Primero, la arquitectura de referencia y las decisiones de diseño de datos (secciones 3 y 4). Segundo, el catálogo de agentes nativos de la plataforma y una capa de diez agentes personalizados construidos en Microsoft Copilot Studio (secciones 5.4 a 5.8) que conversan con los analistas en Teams, se ejecutan en horarios fijos o reaccionan a incidentes, delegan el razonamiento a Security Copilot mediante su conector certificado y acceden al data lake mediante el Sentinel MCP server. Tercero, una biblioteca de consultas KQL listas para copiar al repositorio (sección 6). Cuarto, requisitos, gobierno y niveles de autonomía N0 a N5 (secciones 7 y 8). Quinto, runbooks, roles de referencia y una guía operativa de cadencias que fija con qué frecuencia debe ejecutarse cada agente, quién revisa su salida y cómo se mide mensualmente su calidad (secciones 9 a 11). Sexto, una ruta de adopción de referencia, un laboratorio autoguiado de cinco días y los anexos que permiten llevar todo al repositorio (secciones 12 a 16).

## 1.3 Resultados de referencia

| Resultado | Evidencia de referencia | Indicador objetivo de referencia |
|----|----|----|
| Reducción del tiempo medio de resolución | 30% de reducción en MTTR de incidentes, con recuperación de 2.7 horas por día por analista ("Generative AI and Security Operations Center Productivity: Evidence from Live Operations", Microsoft, noviembre 2024) | MTTR p50 de [valor actual] a la línea base menos 30% al cierre de la Fase 2 |
| Mayor precisión en la decisión | 35% más de precisión en decisiones de operaciones de seguridad (Randomized Controlled Trials for Security Copilot for IT Administrators, Microsoft, noviembre 2024) | Tasa de reclasificación de veredictos del agente por debajo del 10% en muestreo semanal |
| Retorno económico de referencia | Hasta 348% de ROI y 1.76 millones de dólares de valor presente neto a tres años (Forrester New Technology: Projected Total Economic Impact of Microsoft Security Copilot, noviembre 2024) | Modelo de negocio validado en la Fase 0 con datos reales de la organización |
| Contención de ransomware casi en tiempo real | Attack disruption detiene ataques de ransomware en un promedio de 3 minutos (Microsoft, Coordinated Defense, 2025) | Tiempo de contención por debajo de 15 minutos para el 90% de los incidentes de severidad alta |
| Optimización de cobertura y de datos | Los clientes que implementaron las recomendaciones de SOC optimization aumentaron su cobertura de seguridad hasta 17% y la utilización de datos 31% (Microsoft, Coordinated Defense, 2025) | Cobertura MITRE ATT&CK de [valor actual] a la meta acordada en la Fase 1 |

*Tabla 1. Resultados de referencia y evidencia publicada que los sustenta.*

## 1.4 Qué no cubre y supuestos

Esta guía no es una cotización ni un plan de servicios: no incluye precios negociados, alcances contractuales ni estimaciones de esfuerzo de consultoría. Tampoco sustituye la documentación oficial de cada producto, que es la fuente de verdad para prerequisitos, roles y límites vigentes; donde la guía cita una capacidad, el anexo B enlaza la página de Microsoft Learn o la publicación correspondiente. No cubre la migración detallada desde otros SIEM (el agente CS-7 y el runbook 9.4 dan el patrón, no el procedimiento por producto), ni la configuración de conectores de terceros, ni el diseño de red y de residencia de datos específico de una jurisdicción. Las consideraciones de capacidad y costo de las secciones 7.2 y 14.4 se limitan a cifras públicas indicativas con su fecha y su fuente.

Los supuestos de partida son cuatro: la organización dispone de licenciamiento Microsoft 365 E5 o E7, o de los componentes equivalentes; existe, o se ha decidido consolidar, un espacio de trabajo de Microsoft Sentinel; el equipo de seguridad puede dedicar personas a las actividades de habilitación descritas en la ruta de adopción; y las capacidades identificadas como preview conservan el comportamiento documentado a septiembre de 2026. Los valores que dependen de cada entorno (nombre de la organización, volumen de ingesta, número de analistas, zona horaria del SOC, retenciones y umbrales) aparecen entre corchetes a lo largo del texto y se concentran en el anexo D para completarlos una sola vez. El efecto esperado sobre el costo de operación no proviene de reducir personal, sino de reasignarlo: el trabajo repetitivo de triage de primer nivel se traslada a agentes supervisados y la capacidad humana liberada se reinvierte en ingeniería de detecciones, cacería proactiva e ingeniería de agentes.


---

[← Portada, cómo usar esta guía y cómo contribuir](00-portada-y-como-usar.md) | [Índice](README.md) | [2. Contexto: el cambio a la era agéntica →](02-contexto.md)
