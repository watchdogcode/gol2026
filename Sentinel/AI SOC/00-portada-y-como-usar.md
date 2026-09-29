<!-- AI-SOC Playbook v2.0 · Arturo Mandujano (Cloud Solution Architect) · 28 de septiembre de 2026 -->
← inicio | [Índice](README.md) | [1. Introducción y alcance →](01-introduccion.md)

---

# AI-SOC Playbook — Portada, cómo usar esta guía y cómo contribuir

**Autor: Arturo Mandujano**

Versión 2.0 — Guía abierta de la comunidad (conversión de la versión 1.1 a guía de referencia)

Fecha: 28 de septiembre de 2026

Licencia: [Elegir licencia del repositorio] — MIT para el código, las consultas KQL, las plantillas y los flujos; o Creative Commons Attribution 4.0 Internacional (CC BY 4.0) para el texto de la guía. Hasta que el repositorio fije una, se conservan ambas como opción.

*Nota de uso. Este documento se distribuye tal cual (as-is), sin garantías de ningún tipo. Su contenido es orientativo, es una contribución personal del autor a la comunidad y no representa una posición oficial ni un compromiso de Microsoft. Las capacidades descritas se identifican explícitamente como disponibilidad general (GA) o versión preliminar (preview) a la fecha de elaboración; las capacidades marcadas como preview pueden cambiar de comportamiento, de alcance o de modelo de licenciamiento sin previo aviso. Las cifras de precio y capacidad son indicativas públicas a la fecha y deben contrastarse con la página oficial de precios. Todas las consultas KQL, los prompts y los flujos deben validarse en cada entorno antes de usarse en producción.*

## Cómo usar esta guía

La guía puede leerse de principio a fin o por bloques según el perfil del lector (véase la sección 1.1). Cada sección técnica termina en artefactos concretos: tablas de decisión, consultas KQL con encabezado de comentario listas para copiar, fichas de agente con instrucciones de sistema y prompts, runbooks con criterios de cierre y catálogos de reportes. Los valores que dependen de cada organización aparecen entre corchetes y se concentran en el anexo D; conviene completarlos antes de adoptar cualquier artefacto.

Las capacidades de producto se marcan como GA o preview a la fecha de elaboración. Antes de construir un proceso crítico sobre una capacidad preview, verifique su estado en Microsoft Learn (las URL están en el anexo B) y conserve la ruta alterna que la guía indica en cada caso. Ninguna consulta, prompt o flujo debe pasar a producción sin validarse en el entorno propio; el laboratorio autoguiado de la sección 15 es el camino recomendado para hacerlo en cinco días.

La versión de referencia de este texto vive en el repositorio de GitHub descrito en el anexo E, en Markdown y en PDF, junto con los artefactos en carpetas separadas (/kql, /agents, /playbooks, /workbooks, /runbooks, /reports). El historial de cambios está en el anexo G y en el archivo CHANGELOG.md.

## Cómo contribuir

Las contribuciones se reciben mediante issues y pull requests en el repositorio. Un issue sirve para reportar un error en una consulta, un cambio de comportamiento en una capacidad preview, una cifra desactualizada o una propuesta de nuevo agente; use las plantillas de issue del repositorio y adjunte la versión del esquema y la fecha en que reprodujo el problema. Un pull request debe tocar una sola cosa (una consulta, un agente, un runbook o una sección de la guía), explicar qué cambia y por qué, y actualizar el CHANGELOG.md.

La convención de carpetas del repositorio está en el anexo E: una consulta por archivo en /kql, nombrada por número de sección y tema; un archivo por agente en /agents/copilot-studio y /agents/security-copilot-agent-builder, siguiendo la ficha del anexo F; los flujos de Logic Apps en /playbooks/logic-apps; los runbooks, workbooks y plantillas de reporte en sus carpetas homónimas. Toda contribución que dependa de una capacidad preview debe declararlo en su primera línea, y todo agente nuevo debe llegar con nivel de autonomía, guardrails y pruebas de aceptación definidos. Al contribuir se acepta que el aporte se publique bajo la licencia del repositorio y las reglas de conducta y de reporte responsable descritas en CONTRIBUTING.md y SECURITY.md.


---

← inicio | [Índice](README.md) | [1. Introducción y alcance →](01-introduccion.md)
