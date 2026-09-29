<!-- AI-SOC Playbook v2.0 · Arturo Mandujano (Cloud Solution Architect) · 28 de septiembre de 2026 -->
[← 15. Cómo empezar: laboratorio de 5 días autoguiado](15-laboratorio-5-dias.md) | [Índice](README.md) | fin →

---

# 16. Anexos

## Anexo A. Glosario

| Término | Definición |
|----|----|
| ISOC | Centro Integrado de Operaciones de Seguridad. Reúne el SIEM y la protección contra amenazas en una base compartida para que personas y agentes vean, entiendan y actúen sobre todo el entorno. |
| AI-SOC | Denominación operativa del SOC que incorpora razonamiento agéntico en sus procesos de detección, investigación y respuesta. |
| Agente | Componente de software que percibe, razona y actúa sobre una tarea acotada, con herramientas y permisos definidos y bajo supervisión humana explícita. |
| Bucle de protección integrado | Mecanismo que rompe los flujos lineales y convierte continuamente lo que los defensores aprenden en protección previa a la brecha más fuerte. |
| Attack disruption | Capacidad que detecta, predice y se adapta al atacante mientras el ataque está en desarrollo, y utiliza información de exposición para reforzar la protección casi en tiempo real. |
| Señales y sensores | Primera capa del modelo ISOC: la conciencia del sistema, es decir, la telemetría recolectada. |
| Contexto | Segunda capa del modelo ISOC: convierte las señales en comprensión. |
| Actuadores | Tercera capa del modelo ISOC: convierten la percepción en acción protectora. |
| Project Perception | Conjunto de modelos, arnés y agentes especializados para percibir, razonar y actuar a velocidad de máquina, introducido en julio de 2026 junto con la pila cibernética de extremo a extremo. |
| Sentinel data lake | Almacenamiento centralizado de telemetría estructurada y semiestructurada en formato abierto Delta Parquet, que separa almacenamiento de indexación y admite varios motores sobre una sola copia. |
| Sentinel graph | Representación de las relaciones entre identidades, dispositivos, archivos, alertas y otras entidades, que hace explícito e indexable el razonamiento de rutas de ataque. |
| MCP server | Servidor unificado y hospedado que expone colecciones de herramientas por escenario y permite consultas en lenguaje natural sin escribir KQL. |
| SCU | Security Compute Unit. Unidad de medida de la capacidad de cómputo de Security Copilot, facturada por hora sobre un pool compartido del tenant. |
| URBAC | Control de acceso unificado basado en roles del portal de Microsoft Defender. |
| Identidad agéntica | Cuenta no humana asociada a un agente, que debe recibir el mínimo privilegio necesario y quedar inventariada y auditada. |
| Human-in-the-loop | Modo de supervisión en el que una persona aprueba antes de que la acción del agente se ejecute. |
| Human-on-the-loop | Modo de supervisión en el que el agente ejecuta dentro de límites predefinidos y una persona supervisa mediante muestreo y revisión posterior. |
| SOC optimization | Conjunto de recomendaciones dinámicas de Microsoft Sentinel sobre cobertura de detección y uso de datos. |
| MTTA / MTTR | Tiempo medio de atención y tiempo medio de resolución de incidentes. |
| Delta Parquet | Formato abierto de almacenamiento columnar utilizado por el Sentinel data lake. |
| Copilot Studio | Microsoft Copilot Studio. Plataforma de bajo código de Power Platform para construir, publicar y gobernar agentes conversacionales y autónomos; se conecta a Security Copilot mediante un conector certificado y al Sentinel MCP server mediante herramientas MCP (esta última integración en preview). |
| Power Automate | Servicio de flujos de trabajo de Power Platform. En esta guía programa la ejecución de agentes (disparadores de recurrencia), orquesta el par Submit/Fetch del conector de Security Copilot y publica resultados en Teams, correo o sistemas de tickets. |
| Promptbook | Secuencia guardada de prompts de Security Copilot que se ejecuta como una unidad con parámetros de entrada (por ejemplo, un identificador de incidente o el nombre de un actor de amenaza). El conector de Logic Apps puede invocarla con la acción Submit a Security Copilot promptbook. |
| Direct skill | Invocación directa de una habilidad (skill) de Security Copilot por su nombre, omitiendo el planificador. Se usa en flujos donde la respuesta debe ser determinista y de menor consumo, mediante los parámetros Direct Skill Name y Direct Skill Inputs del conector de Logic Apps. |
| Agentic user | Cuenta no humana que Microsoft Defender crea para un agente nativo, con el patrón SecurityCopilotAgentUser-`<guid>`@`<dominio>`. Debe inventariarse, recibir mínimo privilegio y monitorearse con las consultas 6.2.4 y 8.4. |
| MCP (Model Context Protocol) | Protocolo abierto que estandariza cómo un modelo o agente descubre e invoca herramientas expuestas por un servidor. El Sentinel MCP server publica colecciones de herramientas (exploración de datos, triage, grafo) consumibles desde Security Copilot, Copilot Studio, Microsoft Foundry y VS Code. |
| Evaluación (evaluation) | Unidad de trabajo de Security Copilot creada por un prompt enviado desde el conector. El flujo la consulta con Fetch a Security Copilot prompt status hasta obtener el resultado; cada evaluación consume SCUs. |
| Human-on-the-loop con muestreo | Modo de supervisión en el que el agente cierra casos de forma autónoma y una persona revisa una muestra periódica (por ejemplo, el 10% diario de los falsos positivos cerrados) para medir precisión y tasa de reversión. |

*Tabla 39. Glosario de términos del modelo ISOC y agéntico.*

## Anexo B. Referencias y fuentes

Las fuentes siguientes son las únicas utilizadas para los hechos, las métricas y las capacidades descritas en esta guía.

- Rob Lefferts, vicepresidente de Microsoft Threat Protection. "ISOC en Microsoft Defender: el futuro del SOC impulsado por IA". Microsoft Source LATAM, 23 de septiembre de 2026. https://news.microsoft.com/source/latam/company-news-es/isoc-microsoft-defender-soc-ia/

- Microsoft. "Coordinated Defense: Building an AI-powered, unified SOC" (eBook), 2025.

- Microsoft. Microsoft Digital Defense Report, 2024.

- Microsoft. "Generative AI and Security Operations Center Productivity: Evidence from Live Operations", noviembre de 2024.

- Microsoft. "Randomized Controlled Trials for Security Copilot for IT Administrators", noviembre de 2024.

- Forrester Consulting. "New Technology: Projected Total Economic Impact of Microsoft Security Copilot", noviembre de 2024.

- IBM. Global Security Operations Center Study, marzo de 2023.

- Microsoft Learn. Phishing Triage Agent en Microsoft Defender. https://learn.microsoft.com/en-us/defender-xdr/phishing-triage-agent

- Microsoft Learn. Threat Intelligence Briefing Agent. https://learn.microsoft.com/en-us/copilot/security/threat-intel-briefing-agent

- Microsoft Learn. Microsoft Sentinel MCP server overview. https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-overview

- Microsoft Learn. Get started with the Microsoft Sentinel MCP server. https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-get-started

- Microsoft Security Blog. "Empowering defenders in the era of agentic AI with Microsoft Sentinel", 30 de septiembre de 2025. https://www.microsoft.com/en-us/security/blog/2025/09/30/empowering-defenders-in-the-era-of-agentic-ai-with-microsoft-sentinel/

- Microsoft Tech Community. Economía y licenciamiento de Microsoft Security Copilot (Security Compute Units), junio de 2026.

- Microsoft. Whitepaper "SOC Agéntico: el nuevo modelo operativo para la defensa continua".

- Microsoft Learn. Microsoft Security Copilot connector for Microsoft Copilot Studio. https://learn.microsoft.com/en-us/copilot/security/connector-copilot-studio

- Microsoft Learn. Microsoft Security Copilot connector for Azure Logic Apps. https://learn.microsoft.com/en-us/copilot/security/connector-logicapp

- Microsoft Learn. Use the Microsoft Sentinel MCP server in Microsoft Copilot Studio (preview). https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-use-tool-copilot-studio

- Microsoft Learn. Microsoft Sentinel MCP data exploration tool collection. https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-data-exploration-tool

- GitHub, Azure/Security-Copilot. Aceleradores de Logic Apps para Security Copilot (SecCopilot-UserReportedPhishing, SecurityCopilot-Sentinel-Incident-Investigation, DailyThreatExposureReport-Copilot, ThreatBulletinCopilot, ThreatactorCopilot, SecurityCopilot-SOCshift-reporting-transfer, ciso-reporting, KQL-Migrator, entre otros). https://github.com/Azure/Security-Copilot/tree/main/Logic%20Apps

- GitHub, microsoft/sentinel-data-exploration-mcp. Casos de exploración de datos con el servidor MCP de Sentinel (password spray de baja frecuencia, viaje imposible, picos de fallas de MFA, reactivación de cuentas dormidas).

- Microsoft Tech Community. "Build a Local Sentinel Triage Agent": patrón de evidencia primero, superficie de herramientas pequeña y escritura con aprobación explícita.

## Anexo C. Plantilla de prompts para Security Copilot

Los prompts siguientes están redactados en español y listos para usarse. Sustituya los valores entre corchetes por los datos del caso. Recuerde que la salida de un prompt es un insumo de análisis, no una conclusión: el criterio de cierre lo fija el runbook correspondiente.

### Triage

1. "Resume el incidente [número de incidente]: qué ocurrió, qué entidades están involucradas, cuál es la severidad real y qué acciones recomiendas en orden de prioridad."

2. "Explica por qué esta alerta fue clasificada como [clasificación] y qué evidencia sustenta el veredicto. Indica qué información adicional cambiaría la conclusión."

3. "Compara este incidente con los incidentes similares de los últimos 30 días e indica si forma parte de una campaña en curso."

### Investigación

1. "Construye la línea de tiempo del compromiso de la cuenta [UPN] en las últimas 72 horas: autenticaciones, dispositivos, aplicaciones accedidas y cambios de configuración de identidad."

2. "Evalúa si la cuenta [UPN] presenta indicios de persistencia: métodos de autenticación multifactor registrados recientemente, reglas de reenvío de buzón y consentimientos de aplicación."

3. "A partir del dispositivo [nombre del dispositivo], identifica qué cuentas autenticaron en él en los últimos siete días y cuáles de ellas tienen acceso a activos críticos."

### Cacería

1. "Busca en los últimos siete días indicios de la técnica [T####] de MITRE ATT&CK en el entorno y resume los hallazgos con su nivel de confianza."

2. "Encuentra los tres usuarios con mayor riesgo en este momento y explica por qué cada uno está en riesgo."

3. "Identifica las rutas de ataque que llegan a los activos clasificados como críticos y ordénalas por número de saltos y por facilidad de explotación."

### Reporte ejecutivo

1. "Redacta un resumen de dos párrafos para la dirección sobre la actividad de seguridad de la semana: volumen, incidentes relevantes, tiempos de respuesta y riesgos abiertos, sin lenguaje técnico."

2. "Genera el briefing de inteligencia de amenazas del mes enfocado en los actores y vulnerabilidades relevantes para el sector [sector] en [país], e indica qué hipótesis de cacería se derivan."

### Generación de KQL

1. "Escribe una consulta KQL para advanced hunting que detecte [comportamiento] en las tablas [tablas] durante los últimos [ventana], con un umbral de [umbral], y explica cada cláusula."

2. "Revisa esta consulta KQL, corrige los errores de sintaxis, optimiza su desempeño y explica qué cambiaste: [pegar consulta]."

*Nota operativa: el KQL generado debe revisarse y ajustarse manualmente antes de convertirse en una regla analítica de producción, conforme al paso 4 del runbook 9.4.*

## Anexo D. Parámetros a ajustar por organización

Esta guía se escribió para ser reutilizable por cualquier organización. Los valores que dependen de cada entorno aparecen entre corchetes a lo largo del texto, de los prompts y de las consultas KQL; la tabla siguiente los concentra con una descripción, un valor de ejemplo y el lugar de la guía donde se usan, de modo que un equipo pueda completarlos una sola vez antes de adoptar los artefactos.

| Parámetro | Descripción | Valor de ejemplo | Dónde se usa en la guía |
|----|----|----|----|
| [organización] | Nombre con el que los agentes se refieren al SOC en sus instrucciones de sistema y en los reportes que redactan | Contoso | Instrucciones de sistema y prompts de los agentes CS-1 a CS-10 (tablas 9 a 18) |
| [volumen de ingesta GB/día] | Volumen facturable diario actual del espacio de trabajo, con desglose por tabla | 250 GB/día | Sección 1.4 y 14.2 (supuestos); consulta 6.3.1; decisión de tiering de la tabla 5 |
| [número de analistas] | Personas del equipo de seguridad dedicadas a las actividades de habilitación de la ruta de adopción | 3 personas a tiempo parcial | Sección 1.4 y 14.2; RACI de la tabla 27 |
| [hora local del SOC] / huso horario | Zona horaria en la que se programan recurrencias, ventanas de ejecución y traspasos de turno | America/Mexico_City (UTC-6) | Flujos 5.7.2 y 5.7.3; fichas CS-4 y CS-6 (tablas 12 y 14); cadencia maestra (tabla 30); calendario operativo (tabla 31) |
| [sector] | Sector económico que orienta el boletín de actores de amenaza y el briefing de inteligencia | Financiero | Ficha CS-5 (tabla 13); prompts de reporte ejecutivo del anexo C |
| [país] / geografía | País o región que acota la inteligencia de amenazas y el requisito de residencia de datos | México | Sección 7.6; ficha CS-5; anexo C |
| [90] días de retención en analytics | Ventana de retención activa en el tier de analytics, alineada a la ventana de detección | 90 días | Tablas 4 y 5; sección 7.6 |
| [12-24] meses de retención en data lake | Retención forense extendida en el data lake, alineada al requisito regulatorio | 18 meses | Tablas 4 y 5; sección 7.6; consultas 6.4.10 y 6.4.12 |
| [10%] / [20] casos de muestreo | Proporción y mínimo de veredictos revisados en la evaluación de calidad de agentes | 10% con mínimo de 20 casos por agente | Runbook 9.5; procedimiento mensual de la sección 11.7 |
| [90] días de rotación de secretos | Vida máxima de un secreto de cliente o credencial de las herramientas MCP personalizadas | 90 días | Sección 7.4; tabla 23; paso 3 de la sección 5.5.3 |
| [20%] de umbral de deriva de costo | Crecimiento semanal del volumen facturable por tabla que dispara una revisión de tiering | 20% | Ficha CS-10 (tabla 18); consulta 6.3.1 |
| Matriz MITRE ATT&CK priorizada | Lista de técnicas que el perfil de amenazas de la organización considera prioritarias | T1078, T1110, T1566, T1021, T1490 … | Consulta 6.4.13; reporte de cobertura de la tabla 32 |
| Lista de exclusión de cuentas de servicio | Cuentas de servicio y de administración de inventario que autentican legítimamente contra muchos destinos | svc-sccm, svc-backup | Consulta 6.4.3 (movimiento lateral) |
| Watchlist de IP de VPN y proxy | Rangos de salida corporativos que producen viajes imposibles legítimos | Watchlist VPN_Proxy_Egress | Consulta 6.4.9 (viaje imposible) |
| [valor actual] de MTTR p50 y de cobertura | Línea base medida antes de la Fase 1 contra la que se comparan los resultados | MTTR p50 = 6 h; cobertura = 45% de la matriz priorizada | Tabla 1; consultas 6.1.1 y 6.4.13 |
| Presupuesto de SCU por agente | Consumo máximo semanal de Security Compute Units autorizado a cada agente o caso de uso | CS-4: 10 SCU/semana | Sección 8.6; tabla 30; ficha de agente del anexo F |
| Inventario de activos críticos | Etiquetado de activos críticos en Exposure Management que alimenta las rutas de ataque | Etiqueta Critical en controladores de dominio y servidores de pago | Consulta 6.4.6; reporte diario de exposición (CS-4); dependencia de la sección 14.3 |
| Umbrales de las consultas de detección | Valores parametrizados al inicio de cada consulta (usuarios distintos, destinos, ventanas) | Password spray: 20 usuarios en 24 h | Encabezado de cada consulta de la sección 6 |

Tabla 40. Parámetros a ajustar por organización, con valor de ejemplo y referencia de uso.

## Anexo E. Estructura sugerida del repositorio

La guía está pensada para vivir en un repositorio público de GitHub junto con los artefactos que describe, de modo que cada consulta, agente, flujo y plantilla pueda versionarse, probarse y recibir contribuciones por separado. La estructura siguiente es una sugerencia: el criterio es que cada artefacto tenga una carpeta previsible, un archivo por unidad reutilizable y un nombre que remita a la sección de la guía de la que proviene.

```text
ai-soc-playbook/
├── README.md                 resumen, alcance, cómo usar la guía, enlaces
├── LICENSE                   licencia del repositorio (ver portada)
├── CONTRIBUTING.md           issues, pull requests, convención de carpetas
├── CHANGELOG.md              historial de versiones (anexo G)
├── SECURITY.md               reporte responsable de problemas
├── docs/
│   ├── ai-soc-playbook.md    esta guía en Markdown (fuente de verdad)
│   ├── ai-soc-playbook.pdf   exportación en PDF de la misma versión
│   └── img/                  figuras 1 a 3
├── kql/                      una consulta por archivo (número de sección y tema)
│   ├── 06-01-01-mtta-mttr-por-severidad.kql
│   ├── 06-04-09-viaje-imposible.kql
│   ├── 08-04-anomalias-identidades-agenticas.kql
│   └── README.md             índice: tier sugerido y tablas requeridas
├── agents/
│   ├── copilot-studio/       un archivo por agente CS-1 a CS-10 (ficha del anexo F)
│   │   ├── CS-01-asistente-triage-teams.md
│   │   ├── CS-04-reporte-diario-exposicion.md
│   │   └── …
│   └── security-copilot-agent-builder/   los tres agentes de la tabla 7
├── playbooks/
│   └── logic-apps/           ARM o Bicep de ejemplo; enlazan a Azure/Security-Copilot
├── workbooks/                tablero de higiene de ingesta y KPIs de la tabla 28
├── runbooks/                 runbooks 9.1 a 9.5, uno por archivo
└── reports/                  plantillas del catálogo de la tabla 32
```

Convenciones de nombres. Las consultas usan el prefijo numérico de la sección y un tema en minúsculas separado por guiones (06-04-09-viaje-imposible.kql), de modo que el orden alfabético del directorio coincida con el orden de la guía. Los agentes usan el identificador de la ficha (CS-01 a CS-10) más un tema. Cada carpeta lleva un README.md breve con el índice de sus artefactos, y cualquier artefacto que dependa de una capacidad en versión preliminar lo declara en su primera línea.

La tabla siguiente mapea cada sección del documento al artefacto del repositorio que la materializa, para que una contribución sepa dónde vive el cambio y para que la guía y el código no se desalineen.

| Sección de la guía | Artefacto del repositorio | Formato |
|----|----|----|
| Portada, Cómo usar esta guía y Cómo contribuir | README.md, CONTRIBUTING.md, LICENSE | Markdown |
| 1 a 3. Introducción, contexto y visión objetivo | docs/ai-soc-playbook.md (capítulos 1 a 3) | Markdown y PDF |
| 4. Arquitectura de referencia (figuras 1 a 3, tablas 3 a 5) | docs/ai-soc-playbook.md y docs/img/ | Markdown, texto de las figuras |
| 5.1 a 5.3. Agentes nativos y agent builder (tablas 6 y 7) | agents/security-copilot-agent-builder/ | Un archivo por agente |
| 5.4 a 5.8. Agentes de Copilot Studio (tablas 8 a 20) | agents/copilot-studio/CS-01 … CS-10 | Ficha del anexo F por agente |
| 5.5.4 y 5.7. Flujos y variante Logic Apps | playbooks/logic-apps/ | ARM o Bicep de ejemplo con enlace al acelerador público |
| 6. Biblioteca de consultas KQL (23 consultas) | kql/ | Un archivo .kql por consulta con el encabezado de comentario estándar |
| 7. Requisitos y lista de verificación de readiness (tablas 21 a 24) | docs/readiness-checklist.md | Markdown con casillas |
| 8. Gobierno, niveles de autonomía y consulta de anomalías | docs/governance.md y kql/08-04-anomalias-identidades-agenticas.kql | Markdown y KQL |
| 9. Runbooks 9.1 a 9.5 | runbooks/ | Un archivo por runbook |
| 10. Modelo operativo y RACI de referencia | docs/operating-model.md | Markdown |
| 11. KPIs, cadencias, catálogos de reportes y análisis (tablas 28 a 34) | reports/ y workbooks/ | Plantillas de reporte y workbooks de Sentinel |
| 12. Ruta de adopción de referencia | docs/adoption-path.md | Markdown |
| 13. Casos de uso priorizados | docs/use-cases.md | Markdown |
| 14. Riesgos y limitaciones conocidas | docs/risks.md; issues etiquetadas como known-limitation | Markdown e issues |
| 15. Laboratorio autoguiado de cinco días | docs/lab-5-days.md | Markdown con entregables por día |
| Anexo A. Glosario | docs/glossary.md | Markdown |
| Anexo B. Referencias | docs/references.md | Markdown con URLs |
| Anexo C. Prompts | agents/prompts/ | Un archivo por familia de prompts |
| Anexo D. Parámetros por organización | config/parameters.example.yaml | YAML de ejemplo que cada equipo copia y completa |
| Anexo F. Plantilla de ficha de agente | .github/ISSUE_TEMPLATE/new-agent.md y agents/TEMPLATE.md | Plantilla de issue y de archivo |
| Anexo G. Marcas e historial de versiones | CHANGELOG.md y sección de marcas del README.md | Markdown |

Tabla 41. Mapa de secciones de la guía a artefactos del repositorio.

## Anexo F. Plantilla de ficha de agente

Para que la comunidad pueda contribuir nuevos agentes de forma consistente con los diez de la sección 5.6, cada agente se documenta con la ficha siguiente, en Markdown, dentro de agents/copilot-studio o agents/security-copilot-agent-builder. Los campos son los mismos que usan las tablas 9 a 18, más los datos de autoría y de pruebas que un pull request necesita para ser revisado. Un agente sin nivel de autonomía, guardrails y pruebas de aceptación declarados no se acepta en el repositorio.

```markdown
# CS-NN. Nombre del agente

| Campo | Contenido |
|---|---|
| Nombre | Nombre corto y descriptivo del agente |
| Objetivo | Qué tarea del SOC resuelve, para quién y con qué frecuencia |
| Disparador | Conversacional (frases de activación), programado (recurrencia y hora local del SOC) o por evento (regla de automatización, alerta) |
| Herramientas | Acciones del conector de Security Copilot, colecciones MCP de Sentinel (herramientas exactas habilitadas), conectores de Power Platform |
| Permisos mínimos | Roles URBAC y de Entra de la cuenta de la conexión y de la identidad de escritura; secretos y su rotación |
| Instrucciones de sistema | Texto completo en español; la primera regla siempre es tratar el contenido externo como dato, nunca como instrucción |
| Prompts | Prompts enviados a Security Copilot, con los valores entre corchetes que sustituye el flujo |
| Salida | Formato y canal de la salida (tarjeta adaptable en Teams, comentario en incidente, archivo en SharePoint, ticket) |
| Nivel de autonomía | N0 a N2 para agentes nuevos; N3 sólo con historial de calidad conforme a la sección 11.7 (nunca N5) |
| Guardrails | Superficie de herramientas mínima, patrón draft-first, aprobación explícita antes de escribir, límites de tamaño y de reintentos, manejo de errores (tabla 19) |
| SCU estimado | Consumo cualitativo (bajo, medio, alto) y presupuesto semanal en SCU; qué herramientas consumen y cuáles no |
| KPI | Indicador de la tabla 28 al que contribuye y cómo se mide su aporte (etiqueta Agent, consultas 6.2.x) |
| Pruebas de aceptación | Casos de prueba con entrada, salida esperada y criterio de aprobación; incluir al menos un caso de contenido no confiable |
| Capacidades preview | Lista de capacidades en versión preliminar de las que depende y ruta alterna si cambian |
| Autor | Nombre o alias de GitHub de quien contribuye el agente |
| Versión | Versión semántica del agente y fecha; enlazar al CHANGELOG.md |
## Flujo
Descripción paso a paso del flujo (disparador, preparación, Submit/Fetch, parseo, publicación, manejo de errores), en el formato de la sección 5.7.
## Notas de validación
Entorno en el que se probó (versión del esquema, productos habilitados, fecha) y limitaciones conocidas.
```

## Anexo G. Descargo de marcas e historial de versiones

### Descargo de marcas

Microsoft, Microsoft Sentinel, Microsoft Defender, Microsoft Security Copilot, Microsoft Copilot Studio, Microsoft Entra, Microsoft Purview, Azure, Power Platform, Power Automate y Microsoft Teams son marcas comerciales o marcas registradas de Microsoft Corporation en Estados Unidos y en otros países. MITRE ATT&CK es una marca de The MITRE Corporation. Las demás marcas mencionadas pertenecen a sus respectivos propietarios. Esta guía es contenido comunitario elaborado por su autor a título personal; no está patrocinada, avalada ni revisada por Microsoft, y las menciones de productos se hacen únicamente con fines descriptivos.

### Historial de versiones

| Versión | Fecha | Cambios principales |
|----|----|----|
| 1.0 | Septiembre de 2026 | Documento base: contexto, visión ISOC, arquitectura de referencia, catálogo de agentes nativos, dieciocho consultas KQL, requisitos, gobierno, runbooks, modelo operativo, KPIs, ruta en cuatro fases, casos de uso, riesgos y anexos A a C |
| 1.1 | 26 de septiembre de 2026 | Diez agentes personalizados en Microsoft Copilot Studio (secciones 5.4 a 5.8), guía operativa de cadencias (secciones 11.3 a 11.7), profundidad adicional en tiering, identidades, permisos y auditoría, y cinco consultas KQL nuevas (6.4.9 a 6.4.13) |
| 2.0 | 28 de septiembre de 2026 | Conversión a guía abierta de la comunidad: nuevo título y portada con nota de licencia y de uso, secciones Cómo usar esta guía y Cómo contribuir, eliminación del enfoque comercial y de los marcadores específicos de cliente, introducción y alcance, ruta de adopción con rangos típicos, laboratorio autoguiado de cinco días, encabezado de comentario estándar en las 23 consultas KQL y anexos D a G para el repositorio de GitHub |

Tabla 42. Historial de versiones del documento.


---

[← 15. Cómo empezar: laboratorio de 5 días autoguiado](15-laboratorio-5-dias.md) | [Índice](README.md) | fin →
