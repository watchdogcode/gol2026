<!-- AI-SOC Playbook v2.0 · Arturo Mandujano (Cloud Solution Architect) · 28 de septiembre de 2026 -->
[← 14. Riesgos y limitaciones conocidas](14-riesgos.md) | [Índice](README.md) | [16. Anexos A a G →](16-anexos.md)

---

# 15. Cómo empezar: laboratorio de 5 días autoguiado

El argumento central de esta guía puede resumirse en una sola línea: la ventaja del atacante hoy proviene de la automatización, y la respuesta no consiste en añadir inteligencia artificial sobre una arquitectura fragmentada, sino en unificar la base de datos y de contexto para que personas y agentes operen sobre un solo sistema. Como lo formuló Rob Lefferts, "el próximo SOC no se definirá por cuántas características de IA tiene, sino por si las personas y agentes pueden percibir, razonar y actuar en un entorno como un solo sistema" (Microsoft Source LATAM, septiembre 2026).

Para la mayoría de las organizaciones el camino empieza por lo que ya existe. Buena parte de las piezas suele estar licenciada o parcialmente desplegada; lo que falta es la unificación de la capa de datos, el gobierno que hace confiables a los agentes y el modelo operativo que convierte la capacidad liberada en cobertura. El ISOC en Microsoft Defender está disponible en versión preliminar, lo que permite iniciar la evaluación sin esperar. El laboratorio siguiente está pensado para que cualquier equipo lo recorra por su cuenta, en un tenant de pruebas o en un alcance acotado de su tenant productivo, sin acompañamiento externo: cada día tiene un entregable verificable y usa únicamente artefactos de esta guía.

## 15.1 Antes de empezar

1. Definir el alcance del laboratorio y quién participa: un arquitecto de seguridad, un ingeniero de SOC y una persona del equipo de identidad son suficientes; nombrar a quien será propietario de los agentes.

2. Ejecutar la lista de verificación de readiness de la tabla 24 y capturar la línea base con las consultas 6.1.1, 6.1.3 y 6.3.1.

3. Recorrer el laboratorio de cinco días descrito a continuación, registrando en el repositorio los ajustes hechos a consultas, prompts y parámetros (anexo D).

4. Construir el caso de negocio interno con los datos reales obtenidos y presentarlo al liderazgo de seguridad para decidir la ruta de adopción de la sección 12.

5. Revisar el whitepaper "SOC Agéntico: el nuevo modelo operativo para la defensa continua" con el equipo técnico como lectura previa al laboratorio.

## 15.2 Agenda del laboratorio de cinco días

| Día | Tema | Actividades | Entregable del día |
|----|----|----|----|
| Día 1 | Línea base y readiness | Revisión del inventario de licencias, conectores y reglas; ejecución de la lista de verificación; medición de MTTA, MTTR y tasa de falsos positivos con las consultas 6.1.1 y 6.1.3 | Informe de readiness preliminar y línea base medida |
| Día 2 | Fundación de datos | Diseño del tiering entre analytics y data lake; revisión de la higiene de ingesta con la consulta 6.3.1; verificación de conectores con 6.3.2 y 6.3.3; revisión de SOC optimization | Borrador de política de tiering y plan de conectores |
| Día 3 | Agentes en operación | Habilitación del Phishing Triage Agent en un alcance acotado; configuración de identidades y roles; ejecución guiada del Threat Hunting Agent y generación de un briefing con el Threat Intelligence Briefing Agent | Agentes operando en alcance de prueba con veredictos observables |
| Día 4 | Investigación asistida y MCP | Recorrido del runbook 9.2 sobre un caso real o simulado; uso de las colecciones del Sentinel MCP server con consultas en lenguaje natural; prueba de los prompts del anexo C | Registro de la investigación asistida y biblioteca de prompts adaptada |
| Día 5 | Gobierno, KPIs y plan | Definición del modelo de autonomía por tipo de acción; diseño del muestreo de calidad del runbook 9.5; construcción del dashboard operativo; cierre del caso de negocio | Modelo de gobierno acordado, dashboard inicial y plan de fases con fechas |

*Tabla 38. Agenda de referencia del laboratorio autoguiado de cinco días.*


---

[← 14. Riesgos y limitaciones conocidas](14-riesgos.md) | [Índice](README.md) | [16. Anexos A a G →](16-anexos.md)
