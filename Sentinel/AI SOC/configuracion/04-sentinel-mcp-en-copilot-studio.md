> **Preview.** Esta configuración depende de la integración del Sentinel MCP server con Copilot Studio y de las herramientas de grafo, ambas en versión preliminar a la fecha de la guía. Conserve la ruta alterna (conector de Security Copilot o KQL directo) descrita en cada ficha de agente.

# 4. Sentinel MCP server en Copilot Studio: colección estándar y herramientas personalizadas

Configuración: [1. Prerequisitos y licenciamiento](01-prerequisitos-y-licenciamiento.md) · [2. Roles e identidades](02-roles-e-identidades.md) · [3. Conector Security Copilot](03-conector-security-copilot-copilot-studio.md) · [4. Sentinel MCP](04-sentinel-mcp-en-copilot-studio.md) · [5. Logic Apps SOAR](05-logic-apps-soar.md) · [6. Checklist](06-checklist-readiness.md)

Secciones 5.5.2 y 5.5.3 de la guía.

## 5.5.2 Colección MCP de Sentinel en Copilot Studio (preview)

Prerequisitos: onboarding al Sentinel data lake; el usuario que probará el agente debe tener al menos Security Reader (Security Operator o Security Administrator para la colección de triage, que además requiere Defender XDR, Defender for Endpoint o Sentinel en el portal de Defender); Security Copilot Contributor si se usarán los analizadores de entidades; lectura en Microsoft Security Exposure Management para las herramientas de grafo. La documentación recomienda un modelo GPT-5 o posterior, con ventana de contexto mayor, para los agentes que usan estas herramientas.

1. En el agente, abrir Tools y elegir Add a tool; buscar "Sentinel" y seleccionar la colección MCP que corresponda al agente (exploración de datos para CS-2, CS-7, CS-9 y CS-10; triage cuando el agente deba trabajar sobre incidentes).

2. En el tipo de autenticación elegir Microsoft Entra ID Integrated, de modo que el agente actúe con el token del usuario que conversa y no con un secreto compartido; pulsar Create.

3. Elegir Add and configure para revisar las herramientas que la colección expone y desactivar las que el agente no necesita: la superficie de herramientas pequeña es un control de seguridad, no una optimización.

4. Escribir en las instrucciones del agente cuándo usar cada herramienta (por ejemplo, "usa search_tables antes de escribir KQL para confirmar el esquema" y "usa analyze_user_entity sólo cuando tengas el identificador de objeto de Entra y la pregunta sea sobre un usuario concreto").

5. Probar con los casos documentados por Microsoft para esta colección: password spray de baja frecuencia a lo largo de meses, viaje imposible, picos de fallas de MFA por usuario, IP o ventana, y reactivación de cuentas dormidas.

La colección de exploración de datos se publica en el punto de conexión https://sentinel.microsoft.com/mcp/data-exploration y contiene: search_tables (búsqueda semántica del catálogo de tablas y esquemas), query_lake (ejecuta KQL contra un espacio de trabajo del data lake), list_sentinel_workspaces, analyze_user_entity (veredicto asistido por IA sobre un usuario, con ventana máxima de 7 días y a partir del identificador de objeto de Entra), analyze_url_entity (veredicto sobre una URL o dominio con inteligencia de amenazas de Microsoft, indicadores de la plataforma de TI, clics, correo, conexiones y watchlists) y get_entity_analysis (sondeo del resultado de un análisis en curso). Los analizadores consumen SCUs; las demás herramientas no. Las herramientas de grafo, en versión preliminar, operan sobre los grafos de exposición, cacería y riesgo de datos.


## 5.5.3 Registro de aplicación en Entra para herramientas MCP personalizadas

Cuando el SOC expone sus propias herramientas mediante una colección personalizada del Sentinel MCP server, Copilot Studio se autentica con OAuth manual contra un registro de aplicación de Entra. Se usa una sola aplicación para todas las colecciones personalizadas y un secreto distinto por colección.

1. En Microsoft Entra, registrar una aplicación (por ejemplo, "SOC-MCP-Tools") con tipo de cuenta de un solo tenant.

2. En API permissions, agregar el permiso delegado de la API Sentinel Platform Services con alcance SentinelPlatform.DelegatedAccess y otorgar el consentimiento de administrador.

3. En Certificates and secrets, crear un secreto de cliente para la colección; registrar su fecha de caducidad en el inventario y almacenarlo en Azure Key Vault o en una variable de entorno segura de Power Platform.

4. En Copilot Studio, dentro del agente, elegir + New tool y luego Model Context Protocol; indicar el punto de conexión de la colección personalizada y elegir autenticación OAuth 2.0 manual.

5. Completar: Client ID (identificador de la aplicación), Client secret, Authorization URL `https://login.microsoftonline.com/<tenant ID>/oauth2/v2.0/authorize`, Token URL y Refresh URL `https://login.microsoftonline.com/<tenant ID>/oauth2/v2.0/token`, y Scope 4500ebfb-89b6-4b14-a480-7f749797bfcd/.default.

6. Copilot Studio genera una URI de redirección; regresar al registro de aplicación y agregarla en Authentication como plataforma Web. Sin este paso la primera autenticación falla.

7. Probar la herramienta con el usuario de servicio, verificar en los registros de inicio de sesión de la aplicación que el consentimiento y el token se emitieron, y programar la rotación del secreto conforme a la tabla 23.


## Resumen de valores exactos

| Elemento | Valor |
|----|----|
| Punto de conexión de la colección de exploración de datos | `https://sentinel.microsoft.com/mcp/data-exploration` |
| Herramientas de la colección | `search_tables`, `query_lake`, `list_sentinel_workspaces`, `analyze_user_entity`, `analyze_url_entity`, `get_entity_analysis` |
| Consumo de SCU | Sólo los analizadores de entidades (`analyze_user_entity`, `analyze_url_entity`); `query_lake` y `search_tables` no |
| Autenticación recomendada (colección estándar) | Microsoft Entra ID Integrated (token del usuario que conversa) |
| Permiso de API (colección personalizada) | Sentinel Platform Services, alcance delegado `SentinelPlatform.DelegatedAccess`, con consentimiento de administrador |
| Authorization URL | `https://login.microsoftonline.com/<tenant ID>/oauth2/v2.0/authorize` |
| Token URL y Refresh URL | `https://login.microsoftonline.com/<tenant ID>/oauth2/v2.0/token` |
| Scope | `4500ebfb-89b6-4b14-a480-7f749797bfcd/.default` |
| Rotación del secreto | Cada `[90]` días; almacenado en Azure Key Vault o variable de entorno segura de Power Platform |

## Agentes que usan estas herramientas

[CS-02](../../agents/copilot-studio/CS-02-verificador-compromiso-usuario.md), [CS-03](../../agents/copilot-studio/CS-03-analizador-url-dominio.md), [CS-07](../../agents/copilot-studio/CS-07-generador-validador-kql.md), [CS-09](../../agents/copilot-studio/CS-09-cazador-cuentas-dormidas-spray.md) y [CS-10](../../agents/copilot-studio/CS-10-revisor-higiene-ingesta-costo.md).

## Fuentes (Anexo B)

- Microsoft Sentinel MCP server overview — https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-overview
- Get started with the Microsoft Sentinel MCP server — https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-get-started
- Use the Microsoft Sentinel MCP server in Microsoft Copilot Studio (preview) — https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-use-tool-copilot-studio
- Microsoft Sentinel MCP data exploration tool collection — https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-data-exploration-tool
- GitHub, microsoft/sentinel-data-exploration-mcp (casos de password spray de baja frecuencia, viaje imposible, picos de MFA y cuentas dormidas).
