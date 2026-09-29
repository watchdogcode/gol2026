# 3. Conector de Microsoft Security Copilot en Copilot Studio (paso a paso)

Configuración: [1. Prerequisitos y licenciamiento](01-prerequisitos-y-licenciamiento.md) · [2. Roles e identidades](02-roles-e-identidades.md) · [3. Conector Security Copilot](03-conector-security-copilot-copilot-studio.md) · [4. Sentinel MCP](04-sentinel-mcp-en-copilot-studio.md) · [5. Logic Apps SOAR](05-logic-apps-soar.md) · [6. Checklist](06-checklist-readiness.md)

Sección 5.5.1 de la guía. El conector certificado Microsoft Security Copilot expone dos acciones: **Submit a Security Copilot prompt** y **Fetch a Security Copilot prompt status**; el mismo conector está disponible en Power Automate y Power Apps. Sólo admite permisos delegados: el agente hace exactamente lo que la cuenta de la conexión puede hacer.

Prerequisitos: Security Copilot habilitado por el administrador del tenant; una cuenta de servicio con acceso a Security Copilot y a los datos de los productos que el agente consultará (incidentes de Defender, registros de MFA de Entra, etcétera); un entorno de Power Platform dedicado al SOC. La conexión se crea en Power Apps, en el mismo entorno donde vivirá el agente de Copilot Studio, porque los agentes sólo ven las conexiones de su entorno.

1. En Copilot Studio, dentro del entorno del SOC, crear el agente con su nombre, descripción e instrucciones de sistema (los textos de la sección 5.6).

2. En el agente, abrir Actions (o Tools, según la versión del portal) y elegir Add an action; buscar "Microsoft Security Copilot" y seleccionar la acción Submit a Security Copilot prompt.

3. Seleccionar o crear la conexión con la cuenta de servicio; completar el nombre de la acción, la descripción que verá el orquestador (por ejemplo, "Envía una pregunta de seguridad a Security Copilot y devuelve la respuesta") y revisar las entradas (contenido del prompt, identificador de sesión opcional) y las salidas (identificadores de sesión, evaluación y prompt, y el resultado).

4. Repetir el paso anterior para la acción Fetch a Security Copilot prompt status, que recibe los identificadores de sesión, evaluación y prompt devueltos por Submit y entrega el estado y el resultado.

5. En Settings, sección Generative AI, activar la orquestación generativa (Generative) para que el agente decida cuándo invocar cada acción a partir de la conversación y de las instrucciones.

6. Probar en el panel de pruebas con una pregunta real (por ejemplo, "resume el incidente 12345") y pedir explícitamente al agente que incluya en la respuesta el Session Id, el Evaluation Id y el Prompt Id; con ellos se verifica en el historial de sesiones de Security Copilot que la evaluación existe y quién la ejecutó.

7. Publicar el agente en el canal de Teams del SOC, restringir su uso al grupo de analistas y registrar en el inventario la cuenta de la conexión, el propietario del agente y su presupuesto de SCU.


## Advertencias de diseño (sección 5.4)

- Un flujo o agente que envía prompts a Security Copilot puede incrementar el consumo de SCUs de forma significativa y debe monitorearse; cada agente declara un consumo cualitativo y tiene presupuesto en la [cadencia maestra](../../operaciones/cadencias.md).
- El conector sólo admite permisos delegados: si la cuenta de la conexión pierde acceso, todos los agentes que dependen de ella dejan de funcionar. Cree la conexión con una cuenta de servicio nominal (véase [Roles e identidades](02-roles-e-identidades.md)).

## Manejo de errores del par Submit/Fetch

La tabla 19 de la guía (sección 5.7) fija la respuesta a cada condición: tiempo de espera agotado, capacidad SCU agotada, plugin sin datos, permisos insuficientes, herramienta MCP que falla y contenido no confiable. Está reproducida en las fichas [CS-01](../../agents/copilot-studio/CS-01-asistente-triage-incidentes-teams.md), [CS-04](../../agents/copilot-studio/CS-04-reporte-diario-exposicion.md) y [CS-06](../../agents/copilot-studio/CS-06-traspaso-de-turno.md).

Fuente: Microsoft Learn, *Microsoft Security Copilot connector for Microsoft Copilot Studio* — https://learn.microsoft.com/en-us/copilot/security/connector-copilot-studio
