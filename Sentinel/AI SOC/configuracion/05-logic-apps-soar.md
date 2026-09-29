# 5. Variante con Azure Logic Apps para flujos SOAR

Configuración: [1. Prerequisitos y licenciamiento](01-prerequisitos-y-licenciamiento.md) · [2. Roles e identidades](02-roles-e-identidades.md) · [3. Conector Security Copilot](03-conector-security-copilot-copilot-studio.md) · [4. Sentinel MCP](04-sentinel-mcp-en-copilot-studio.md) · [5. Logic Apps SOAR](05-logic-apps-soar.md) · [6. Checklist](06-checklist-readiness.md)

Sección 5.5.4 de la guía. Cuando el disparador es un incidente de Sentinel, el patrón recomendado sigue siendo un playbook de Logic Apps invocado por una regla de automatización.

Cuando el disparador es un incidente de Sentinel, el patrón recomendado sigue siendo un playbook de Logic Apps invocado por una regla de automatización: las reglas de automatización continúan siendo el mecanismo que vincula reglas analíticas con playbooks. El conector de Security Copilot para Logic Apps (planes Standard y Consumption) ofrece la acción Submit a Security Copilot prompt con los parámetros Prompt Content (obligatorio), Session ID (opcional, para dar continuidad a una conversación entre acciones), Plugins (opcional, para acotar qué plugins puede usar el planificador y evitar colisiones), Direct Skill Name (opcional, para invocar una habilidad concreta sin pasar por el planificador) y Direct Skill Inputs en JSON; y la acción Submit a Security Copilot promptbook, con Promptbook Name, entradas dinámicas como `<SENTINEL_INCIDENT_ID>`, `<DEFENDER_INCIDENT_ID>` o `<THREATACTORNAME>`, y Session ID opcional. El playbook itera las entidades del incidente, envía los prompts y escribe el resultado como comentario del incidente, que se sincroniza con Defender XDR. Los aceleradores públicos del repositorio Azure/Security-Copilot (SecCopilot-UserReportedPhishing, SecurityCopilot-Sentinel-Incident-Investigation, Copilot-Sentinel_investigation-DynamicSev, Copilot-isUserTravel, InvestigateFailedSignins, entre otros) son el punto de partida de los diseños de la sección 5.7.


## Parámetros del conector de Security Copilot para Logic Apps

| Acción | Parámetro | Obligatorio | Uso |
|----|----|----|----|
| Submit a Security Copilot prompt | Prompt Content | Sí | Prompt en lenguaje natural |
| Submit a Security Copilot prompt | Session ID | No | Continuidad de la conversación entre acciones |
| Submit a Security Copilot prompt | Plugins | No | Acota qué plugins puede usar el planificador y evita colisiones (por ejemplo, sólo DVM y EASM en CS-04) |
| Submit a Security Copilot prompt | Direct Skill Name | No | Invoca una habilidad concreta sin pasar por el planificador |
| Submit a Security Copilot prompt | Direct Skill Inputs | No | Entradas de la habilidad en JSON |
| Submit a Security Copilot promptbook | Promptbook Name | Sí | Promptbook a ejecutar |
| Submit a Security Copilot promptbook | Entradas dinámicas | Según promptbook | `<SENTINEL_INCIDENT_ID>`, `<DEFENDER_INCIDENT_ID>`, `<THREATACTORNAME>` |
| Submit a Security Copilot promptbook | Session ID | No | Continuidad de sesión |

## Aceleradores públicos del repositorio Azure/Security-Copilot

Punto de partida de los diseños de la sección 5.7 y de las fichas CS-01 a CS-10. Repositorio: https://github.com/Azure/Security-Copilot/tree/main/Logic%20Apps

| Acelerador (Azure/Security-Copilot) | Qué hace | Agente o runbook de esta guía que lo toma como patrón |
|----|----|----|
| SecCopilot-UserReportedPhishing | Triage de correo reportado por el usuario | CS-03; runbook RB-01 |
| SecurityCopilot-Sentinel-Incident-Investigation | Investigación de incidente de Sentinel disparada por regla de automatización | CS-01 (variante por evento) |
| Copilot-Sentinel_investigation-DynamicSev | Investigación con severidad dinámica | CS-01 |
| Copilot-isUserTravel | Verificación de viaje del usuario | CS-02 |
| InvestigateFailedSignins | Investigación de inicios de sesión fallidos | CS-02 |
| DailyThreatExposureReport-Copilot | Reporte diario de exposición | CS-04 |
| Get-CfS-Risky-Incidents-Report | Reporte de incidentes de riesgo | CS-04 |
| ThreatBulletinCopilot | Boletín de amenazas | CS-05 |
| ThreatactorCopilot | Perfil de actor de amenaza | CS-05 |
| LatestCISAVulnerabilities | Vulnerabilidades recientes de CISA | CS-05 |
| SecurityCopilot-SOCshift-reporting-transfer | Traspaso de turno del SOC | CS-06 |
| CfS-SendPromptbookResultsByEmail | Envío de resultados de promptbook por correo | CS-06 |
| KQL-Migrator | Migración de reglas a KQL | CS-07 |
| ciso-reporting | Reporte para el CISO | CS-08 |
| Copilot-SendSummaryToJira | Resumen enviado a Jira | CS-10 |

## Identidad de los playbooks

Identidad administrada de Logic Apps con **Microsoft Sentinel Responder** en el espacio de trabajo (leer incidentes y escribir comentarios) y **Security Reader** para consultas; las acciones del conector de Security Copilot siguen usando una conexión delegada con la cuenta de servicio. Los playbooks se despliegan desde plantillas (ARM o Bicep) con control de versiones. Detalle en [Roles e identidades](02-roles-e-identidades.md).

## Cuándo usar Logic Apps y cuándo Copilot Studio

Regla práctica de la sección 5.8: todo lo que se dispara desde un incidente de Sentinel y termina en un comentario va a Logic Apps; todo lo que involucra a una persona conversando, aprobando o recibiendo un reporte en Teams va a Copilot Studio. Comparativa completa en [agents/README.md](../../agents/README.md).

Fuente: Microsoft Learn, *Microsoft Security Copilot connector for Azure Logic Apps* — https://learn.microsoft.com/en-us/copilot/security/connector-logicapp
