<!-- AI-SOC Playbook v2.0 · Arturo Mandujano (Cloud Solution Architect) · 28 de septiembre de 2026 -->
[← 6. Biblioteca de consultas KQL](06-kql.md) | [Índice](README.md) | [8. Gobierno de agentes y seguridad responsable →](08-gobierno.md)

---

# 7. Requisitos, prerequisitos y readiness

## 7.1 Licenciamiento

El licenciamiento base elegible típico para las capacidades descritas en esta guía es Microsoft 365 E5 o E7 (Microsoft Tech Community, junio 2026). Sobre esa base, cada capacidad del ISOC requiere que el componente correspondiente esté licenciado y desplegado.

| Capacidad del ISOC | Licencia o producto requerido | Comentario de referencia |
|----|----|----|
| Triage autónomo de phishing | Microsoft Defender for Office 365 Plan 2 y Security Copilot | Requisito duro del Phishing Triage Agent |
| Protección y respuesta en endpoints | Microsoft Defender for Endpoint Plan 2 | Fuente de DeviceEvents, DeviceProcessEvents y DeviceLogonEvents, y de los datos de Defender Vulnerability Management |
| Detección de riesgo de identidad | Microsoft Entra ID P2 | Habilita ID Protection y las señales de riesgo de usuario y de sesión |
| Protección de cargas de trabajo en la nube | Microsoft Defender for Cloud (planes por tipo de recurso) | Alimenta el modelado de rutas de ataque y las señales de exposición |
| Postura y triage de seguridad de datos | Microsoft Purview con los complementos correspondientes | Requisito de los agentes de Purview |
| Razonamiento agéntico | Microsoft Security Copilot con capacidad SCU | Ver el modelo de capacidad en 7.2 |
| Plataforma de datos | Microsoft Sentinel con onboarding al data lake | Prerequisito del MCP server y del graph |

*Tabla 21. Requisitos de licenciamiento por capacidad.*

## 7.2 Modelo de capacidad: Security Compute Units

La capacidad de Security Copilot se mide en Security Compute Units. Las cifras públicas indicativas a la fecha de elaboración son de 4 dólares por SCU aprovisionada por hora y de 6 dólares por SCU de sobreconsumo por hora, con facturación horaria; las organizaciones con 1,000 licencias de Microsoft 365 E5 reciben 400 SCUs incluidas, que se comparten en un pool común del tenant, con escalamiento dinámico y una retención de datos de sesión cercana a 90 días aun sin SCU activa (Microsoft Tech Community, junio 2026). Estas cifras no constituyen una cotización: la fuente vigente es la página oficial de precios de Microsoft Security Copilot (https://www.microsoft.com/en-us/security/pricing/microsoft-security-copilot/) y la calculadora pública de SCU (https://securitycopilot.microsoft.com/calculator), que deben consultarse antes de dimensionar cualquier entorno.

Tres consecuencias de diseño se derivan de este modelo. La primera es que el pool es compartido: un agente mal parametrizado puede consumir capacidad que otro caso de uso necesita, por lo que el gobierno del consumo descrito en la sección 8.6 no es opcional. La segunda es que el sobreconsumo tiene un precio superior al aprovisionado, de modo que conviene dimensionar la capacidad base sobre el percentil alto del uso esperado. La tercera es que el Dynamic Threat Detection Agent es gratuito durante la versión preliminar y consumirá SCUs al alcanzar disponibilidad general: ese cambio debe estar previsto en el presupuesto de la organización.

## 7.3 Onboarding al Sentinel data lake

El onboarding al data lake es el prerequisito que habilita tanto la retención forense larga como el servidor MCP. El orden recomendado es: habilitar el data lake sobre el espacio de trabajo principal, definir la política de tiering de la sección 4.3.1, migrar las fuentes de alto volumen y bajo valor de detección al tier de lake, y solo después habilitar las colecciones de herramientas del MCP server.

## 7.4 Roles, URBAC e identidades agénticas

El control de acceso unificado basado en roles (URBAC) es el mecanismo con el que se asignan permisos en el portal de Defender, y es requisito explícito del Phishing Triage Agent y del Threat Hunting Agent. Cada agente que requiera identidad propia debe recibir un rol personalizado con el mínimo privilegio necesario para su función, nunca un rol administrativo genérico.

| Identidad o rol | Alcance | Permisos mínimos | Justificación |
|----|----|----|----|
| Cuenta agéntica del Phishing Triage Agent (SecurityCopilotAgentUser-...@`<dominio>`) | Defender for Office 365 | Lectura de mensajes reportados y capacidad de triage de alertas de correo | Se crea automáticamente al desplegar el agente; debe inventariarse y monitorearse |
| Rol personalizado del Threat Hunting Agent | Advanced hunting en Defender XDR | Lectura de las tablas de cacería necesarias | El agente genera y ejecuta KQL; no requiere permisos de acción |
| Identidad del Threat Intelligence Briefing Agent | Defender XDR y Security Copilot | Rol personalizado "Threat Intel Agent - Read Only" con Vulnerability management – Read bajo Posture management, asignado con Defender for Endpoint como fuente de datos; rol Security Copilot Contributor; opcionalmente lectura en Exposure Management | Configuración verificada en la documentación del agente |
| Consumo del Sentinel MCP server | Sentinel data lake | Rol Security reader para listar e invocar herramientas; según la colección, acceso a Sentinel en el portal de Defender, a Defender XDR o Defender for Endpoint, o a Security Copilot | Permite consultas en lenguaje natural sin otorgar permisos de escritura |
| Ingeniería de agentes | Security Copilot | Permisos de creación y publicación de agentes en el agent builder | Separado del rol de operación para mantener segregación de funciones |

*Tabla 22. Identidades agénticas y principio de mínimo privilegio.*

La capa de agentes personalizados introduce identidades adicionales que no existen en el modelo de agentes nativos, y cada una tiene un modo distinto de autenticarse, un conjunto de roles exactos y un ciclo de vida propio. La tabla siguiente las enumera con el principio de mínimo privilegio aplicado. Dos reglas transversales: ningún rol de Security Administrator se asigna con el único propósito de habilitar Security Copilot (el acceso se otorga mediante un grupo con Copilot Contributor), y ningún secreto vive fuera de un almacén gestionado ni supera los [90] días sin rotación.

| Identidad | Se utiliza en | Roles exactos y permisos mínimos | Ciclo de vida y rotación |
|----|----|----|----|
| Cuenta agéntica de Defender (SecurityCopilotAgentUser-`<guid>`@`<dominio>`) | Phishing Triage Agent, Threat Hunting Agent, Threat Intelligence Briefing Agent, Conditional Access Optimization Agent | Rol URBAC personalizado por agente con permisos de lectura de datos de seguridad; para el Threat Intelligence Briefing Agent, Vulnerability management (Read) y lectura de Threat Intelligence; sin roles de directorio de Entra; nunca Security Administrator | Se crea al desplegar el agente; se registra en el inventario de identidades no humanas con propietario; revisión trimestral con la consulta 6.2.4 y la consulta de la sección 8.4; se elimina al retirar el agente |
| Cuenta delegada de la conexión del conector de Security Copilot (Copilot Studio y Power Automate) | Agentes CS-1 a CS-10; flujos programados | Cuenta de servicio nominal con Security Copilot Contributor mediante grupo; Security Reader en Defender XDR para leer incidentes y alertas; Microsoft Sentinel Responder en el espacio de trabajo únicamente si el flujo escribe comentarios en incidentes; acceso a los datos de cada plugin habilitado (Defender, Entra, Intune) según el agente | Autenticación OAuth con código de autorización, sólo permisos delegados; la conexión se crea en Power Apps en el mismo entorno del agente; el flujo deja de operar si la cuenta pierde el rol o abandona la organización, por lo que se documenta un procedimiento de re-autenticación y un propietario secundario; revisión trimestral de consentimientos |
| Identidad del usuario final en Copilot Studio (autenticación Microsoft Entra ID Integrated para la colección MCP de Sentinel) | CS-2, CS-3, CS-7, CS-9 y CS-10 cuando usan herramientas MCP | El usuario que conversa con el agente debe tener al menos Security Reader (Security Operator o Security Administrator para acciones de triage); Security Copilot Contributor para analyze_user_entity y analyze_url_entity; lectura en Microsoft Security Exposure Management para las herramientas de grafo | Sin secretos: el agente actúa con el token del usuario; los permisos efectivos son los del analista, lo que evita la escalada de privilegios a través del agente |
| Registro de aplicación de Entra para herramientas MCP personalizadas | Colecciones personalizadas del Sentinel MCP server en Copilot Studio | Permiso de API Sentinel Platform Services con alcance SentinelPlatform.DelegatedAccess; el usuario delegado necesita Security Reader como mínimo; identificador de cliente y secreto configurados en la herramienta con OAuth manual | Una sola aplicación para todas las colecciones personalizadas, un secreto por colección; secretos guardados en Azure Key Vault o en variables de entorno de Power Platform, nunca en las instrucciones del agente; rotación cada [90] días; URI de redirección restringida a la que Copilot Studio genera |
| Identidad administrada de Logic Apps (playbooks SOAR) | Playbooks disparados por reglas de automatización de Sentinel (variante Logic Apps de CS-1, CS-4 y CS-6) | Microsoft Sentinel Responder en el espacio de trabajo para leer incidentes y escribir comentarios; Security Reader para consultas; las acciones del conector de Security Copilot siguen usando una conexión delegada con la cuenta de servicio anterior | Sin secretos para las acciones de Sentinel; la conexión delegada del conector se revisa junto con la cuenta de servicio; los playbooks se despliegan desde plantillas con control de versiones |
| Ingeniería de agentes (personas) | Creación, publicación y ajuste de agentes en Copilot Studio y en el agent builder de Security Copilot | Creador de entorno de Power Platform en el entorno del SOC; Copilot Contributor; sin permisos de operación sobre incidentes | Segregación de funciones respecto a Tier 1 y Tier 2; los cambios se publican desde soluciones con revisión de un segundo ingeniero |

*Tabla 23. Identidades de la capa de agentes personalizados, roles exactos y ciclo de vida.*

El punto más delicado de esta tabla es la cuenta delegada del conector. Al ser permisos delegados y no de aplicación, todo lo que los agentes de Copilot Studio hacen en Security Copilot ocurre con la identidad de la persona que creó la conexión; si esa persona deja la organización o pierde el rol, todos los agentes que dependen de la conexión fallan en silencio hasta que alguien re-autentica. Por eso la conexión se crea con una cuenta de servicio nominal, se registra como riesgo en la sección 14.1 y su verificación forma parte del traspaso de turno de los lunes.

## 7.5 Conectores de datos mínimos

El conjunto mínimo para habilitar los casos de uso priorizados de la sección 13 es el siguiente: Defender for Endpoint, Defender for Office 365, Defender for Identity, Defender for Cloud Apps, Defender for Cloud, Microsoft Entra ID (inicios de sesión interactivos y no interactivos, y registros de auditoría), Microsoft Purview y el conector de incidentes de Defender XDR hacia Sentinel. Más de 350 conectores preconfigurados están disponibles para las fuentes adicionales de cada organización, y cada una debe justificar su costo de ingesta conforme al criterio de tiering.

## 7.6 Residencia, retención y red

La residencia de datos debe confirmarse contra el requisito regulatorio de la organización, con especial atención en sectores regulados (público, financiero, salud) y en la jurisdicción donde opera. La retención se define en dos niveles según la tabla 4: ventana activa en el tier de analytics y retención extendida en el data lake, donde el formato abierto Delta Parquet permite conservar telemetría sin re-ingesta.

Para la cobertura de servidores y cargas de trabajo fuera de Azure se requiere Azure Arc, que proyecta los equipos locales o de otras nubes como recursos gobernables y habilita la incorporación de Defender for Cloud y Defender for Endpoint. Los requisitos de red asociados —salida a los puntos de conexión del servicio, resolución de nombres y, en su caso, proxy o punto de conexión privado— deben validarse con el equipo de infraestructura de la organización antes de la Fase 1.

## 7.7 Lista de verificación de readiness

| # | Elemento de readiness | Responsable | Estado |
|----|----|----|----|
| 1 | Licenciamiento Microsoft 365 E5 o E7 confirmado | [Responsable] | Sí / No / Parcial |
| 2 | Defender for Office 365 Plan 2 desplegado | [Responsable] | Sí / No / Parcial |
| 3 | Defender for Endpoint Plan 2 desplegado en el [%] de los dispositivos | [Responsable] | Sí / No / Parcial |
| 4 | Microsoft Entra ID P2 habilitado | [Responsable] | Sí / No / Parcial |
| 5 | Defender for Cloud habilitado en las suscripciones en alcance | [Responsable] | Sí / No / Parcial |
| 6 | Microsoft Purview desplegado con etiquetado de sensibilidad | [Responsable] | Sí / No / Parcial |
| 7 | Espacio de trabajo de Sentinel consolidado | [Responsable] | Sí / No / Parcial |
| 8 | Onboarding al Sentinel data lake completado | [Responsable] | Sí / No / Parcial |
| 9 | Política de tiering analytics / data lake definida | [Responsable] | Sí / No / Parcial |
| 10 | Conectores mínimos de la sección 7.5 conectados y con latido verificado | [Responsable] | Sí / No / Parcial |
| 11 | URBAC habilitado para Defender for Office 365 | [Responsable] | Sí / No / Parcial |
| 12 | Opción "Monitor reported messages in Outlook" activada | [Responsable] | Sí / No / Parcial |
| 13 | Política de alerta "Email reported by user as malware or phish" encendida | [Responsable] | Sí / No / Parcial |
| 14 | Inventario de reglas de alert tuning documentado antes del despliegue del agente | [Responsable] | Sí / No / Parcial |
| 15 | Capacidad SCU aprovisionada o derecho por modelo de inclusión confirmado | [Responsable] | Sí / No / Parcial |
| 16 | Roles personalizados e identidades agénticas creados con mínimo privilegio | [Responsable] | Sí / No / Parcial |
| 17 | Azure Arc desplegado para servidores fuera de Azure | [Responsable] | Sí / No / Parcial |
| 18 | Requisitos de residencia y retención validados con cumplimiento | [Responsable] | Sí / No / Parcial |
| 19 | Línea base de MTTA, MTTR y tasa de falsos positivos capturada | [Responsable] | Sí / No / Parcial |
| 20 | Modelo de gobierno de agentes aprobado por el comité de seguridad | [Responsable] | Sí / No / Parcial |

*Tabla 24. Lista de verificación de readiness para la Fase 0.*


---

[← 6. Biblioteca de consultas KQL](06-kql.md) | [Índice](README.md) | [8. Gobierno de agentes y seguridad responsable →](08-gobierno.md)
