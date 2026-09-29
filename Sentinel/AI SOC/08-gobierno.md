<!-- AI-SOC Playbook v2.0 · Arturo Mandujano (Cloud Solution Architect) · 28 de septiembre de 2026 -->
[← 7. Requisitos, prerequisitos y readiness](07-requisitos-readiness.md) | [Índice](README.md) | [9. Guías operacionales (runbooks) →](09-runbooks.md)

---

# 8. Gobierno de agentes y seguridad responsable

## 8.1 El principio rector

Un agente amplía la capacidad de ejecución del SOC, no su autoridad. La autoridad para tomar decisiones irreversibles permanece en la capa 7 del modelo, la de operaciones potenciadas por personas. Todo el marco de gobierno que sigue traduce ese principio en controles verificables.

## 8.2 Supervisión humana: en el bucle y sobre el bucle

Se distinguen dos modos. En el modo human-in-the-loop el agente propone y una persona aprueba antes de que la acción se ejecute; es el modo obligatorio para cualquier acción que modifique configuración, afecte disponibilidad o sea difícil de revertir. En el modo human-on-the-loop el agente ejecuta dentro de límites predefinidos y una persona supervisa mediante muestreo y revisión posterior; es el modo apropiado para clasificación, enriquecimiento y generación de reportes.

## 8.3 Niveles de autonomía por tipo de acción

| Nivel | Tipo de acción | Ejemplos | Modo de supervisión | Reversibilidad |
|----|----|----|----|----|
| N0 | Lectura y síntesis | Briefing de inteligencia de amenazas, resumen de incidente, generación de KQL | Human-on-the-loop con revisión editorial | Total |
| N1 | Clasificación y priorización | Veredicto de phishing, priorización de alertas, etiquetado de incidentes | Human-on-the-loop con muestreo semanal | Alta: la reclasificación es inmediata |
| N2 | Enriquecimiento y recolección | Detonación de URL, consulta de advanced hunting, recolección de evidencia | Human-on-the-loop | Total: no modifica el entorno |
| N3 | Contención reversible | Aislamiento de dispositivo, revocación de sesión, cuarentena de correo | Human-in-the-loop, salvo attack disruption bajo política aprobada | Media: requiere acción explícita para revertir |
| N4 | Cambio de configuración | Modificación de política de acceso condicional, cambio de regla analítica | Human-in-the-loop con aprobación y despliegue por fases | Baja: requiere gestión de cambios |
| N5 | Acción irreversible o de alto impacto | Deshabilitación masiva de cuentas, bloqueo de un servicio de negocio | Exclusivamente humana; no se delega a un agente | Nula en la práctica |

*Tabla 25. Niveles de autonomía y supervisión por tipo de acción.*

Attack disruption constituye la excepción deliberada al nivel N3. Su valor depende de actuar mientras el ataque está en desarrollo, y detiene ataques de ransomware en un promedio de tres minutos (Microsoft, Coordinated Defense, 2025); someterlo a aprobación humana anularía ese beneficio. La contrapartida de gobierno es una política documentada de alcance, una validación posterior a cada interrupción y un procedimiento de reversión, descritos en el runbook 9.3.

## 8.4 Auditoría de la actividad agéntica

La auditoría se construye sobre tres fuentes. La primera es CloudAppEvents, con la limitación verificada de que registra actividad únicamente del Phishing Triage Agent y del Conditional Access Optimization Agent; la consulta 6.2.3 la explota. La segunda es AuditLogs de Entra, para toda operación de directorio asociada a las identidades agénticas, mediante la consulta 6.2.4. La tercera es la evidencia de portal: los agentes en uso en security.microsoft.com/security-copilot/agents, los roles URBAC en security.microsoft.com/mtp_roles y el consumo en securitycopilot.microsoft.com/usage-monitoring.

La política de referencia es que toda identidad agéntica quede registrada en el inventario de identidades no humanas con propietario nombrado, fecha de creación, permisos asignados y fecha de revisión, y que se revise trimestralmente junto con las cuentas de servicio.

Los agentes de Copilot Studio añaden una cuarta fuente de auditoría que no pasa por CloudAppEvents. Su actividad se registra en tres lugares: en la auditoría unificada de Microsoft Purview, donde las actividades de Copilot Studio y de Power Automate (creación y edición de agentes, publicación, cambios de conexiones, ejecuciones de flujos) quedan asociadas al usuario o a la cuenta de servicio que las realizó; en la analítica de Copilot Studio, que muestra sesiones, resultados y tasa de escalación por agente; y en el historial de sesiones y el monitoreo de uso de Security Copilot, donde cada prompt enviado por el conector aparece como una evaluación con sus identificadores de sesión, evaluación y prompt, atribuida a la cuenta delegada de la conexión. La política de referencia es que cada agente de Copilot Studio se publique desde una solución de Power Platform con propietario nombrado, que la cuenta de la conexión sea una cuenta de servicio nominal y que las tres fuentes se revisen en la evaluación mensual de calidad de la sección 11.7.

Las identidades agénticas también deben vigilarse por comportamiento, no sólo por permisos. La consulta siguiente construye el patrón de los últimos 30 días de cada cuenta agéntica (direcciones IP, aplicaciones y horas del día en que autentica) y señala cualquier inicio de sesión del último día que se salga de ese patrón o que falle. Un agente nativo autentica desde la infraestructura de Microsoft con una aplicación fija y a horas predecibles, de modo que una IP nueva, una aplicación nueva o una franja horaria nueva merecen investigación inmediata.

```kql
// Nombre: 8.4 Anomalías de identidades agénticas
// Objetivo: IP, aplicación u hora fuera del patrón de 30 días de cada cuenta agéntica (último día)
// Tablas: SigninLogs (variantes: AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs)
// Tier sugerido: analytics tier (Microsoft Sentinel); convertir en regla analítica horaria
// Validado en: [versión/fecha]
// Autor: Arturo Mandujano (AI-SOC Playbook, comunidad)
// Archivo sugerido: kql/08-04-anomalias-identidades-agenticas.kql
// Anomalias de identidades agenticas: IP, aplicacion u hora fuera del patron - linea base 30 dias
let LineaBase = 30d;
let Reciente = 1d;
let Agenticas = SigninLogs
| where TimeGenerated > ago(LineaBase)
| where UserPrincipalName startswith "SecurityCopilotAgentUser";
let Patron = Agenticas
| where TimeGenerated < ago(Reciente)
| summarize IPsConocidas = make_set(IPAddress, 200),
    AppsConocidas = make_set(AppDisplayName, 50),
    HorasConocidas = make_set(hourofday(TimeGenerated), 24)
    by UserPrincipalName;
Agenticas
| where TimeGenerated >= ago(Reciente)
| join kind=leftouter Patron on UserPrincipalName
| extend IPNueva = not(set_has_element(IPsConocidas, IPAddress)),
    AppNueva = not(set_has_element(AppsConocidas, AppDisplayName)),
    HoraNueva = not(set_has_element(HorasConocidas, hourofday(TimeGenerated))),
    Fallido = ResultType != "0"
| where IPNueva or AppNueva or HoraNueva or Fallido
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType,
    IPNueva, AppNueva, HoraNueva, Fallido
| order by TimeGenerated desc
```

*Nota de validación: SigninLogs registra inicios interactivos. Para cubrir las identidades no interactivas y los principales de servicio de las herramientas MCP personalizadas, ejecute la misma lógica sobre AADNonInteractiveUserSignInLogs y AADServicePrincipalSignInLogs (en esta última el campo de identidad es ServicePrincipalName). Convierta la consulta en regla analítica programada cada hora con severidad media y agrúpela por UserPrincipalName.*

## 8.5 Prompt injection y contenido no confiable

Los agentes de seguridad procesan por definición contenido controlado por el atacante: cuerpos de correo, URLs, nombres de archivo, cadenas de comando y páginas web detonadas. Ese contenido debe tratarse como dato, nunca como instrucción. Los controles recomendados son cuatro. Primero, restringir el conjunto de herramientas que cada agente puede invocar al mínimo necesario, de modo que una instrucción inyectada no encuentre una acción peligrosa disponible. Segundo, mantener los agentes de triage en niveles N0 a N2, donde una salida manipulada produce un veredicto incorrecto revisable y no un cambio en el entorno. Tercero, revisar el razonamiento en lenguaje natural que el agente expone, que en el caso del Phishing Triage Agent incluye una representación visual de su análisis. Cuarto, incluir en el muestreo de calidad del runbook 9.5 una revisión específica de casos con contenido anómalo.

## 8.6 Retroalimentación, falsos positivos y control de costos

El Phishing Triage Agent aprende de la retroalimentación del analista, por lo que la calidad del veredicto depende directamente de la disciplina con que el equipo corrija las clasificaciones erróneas. La retroalimentación deja de ser una cortesía y se convierte en una tarea con propietario y cadencia definidos en el runbook 9.5.

Debe anticiparse una interacción operativa relevante: el agente no tría alertas resueltas por alert tuning y, al desplegarse, deshabilita automáticamente las reglas de alert tuning existentes. El inventario previo de esas reglas evita que supresiones intencionales se pierdan sin registro.

En cuanto al costo, el pool de SCUs es compartido por el tenant. Los controles propuestos son: asignar un presupuesto de consumo por caso de uso, revisar semanalmente el monitoreo de uso, dimensionar la capacidad aprovisionada sobre el percentil alto de la demanda para evitar el precio de sobreconsumo, y prever el cambio de modelo del Dynamic Threat Detection Agent cuando alcance disponibilidad general.


---

[← 7. Requisitos, prerequisitos y readiness](07-requisitos-readiness.md) | [Índice](README.md) | [9. Guías operacionales (runbooks) →](09-runbooks.md)
