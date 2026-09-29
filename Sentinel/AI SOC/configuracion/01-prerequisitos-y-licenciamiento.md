# 1. Prerequisitos, licenciamiento, capacidad SCU, conectores y red

Configuración: [1. Prerequisitos y licenciamiento](01-prerequisitos-y-licenciamiento.md) · [2. Roles e identidades](02-roles-e-identidades.md) · [3. Conector Security Copilot](03-conector-security-copilot-copilot-studio.md) · [4. Sentinel MCP](04-sentinel-mcp-en-copilot-studio.md) · [5. Logic Apps SOAR](05-logic-apps-soar.md) · [6. Checklist](06-checklist-readiness.md)

Secciones 7.1, 7.2, 7.3, 7.5 y 7.6 de la guía. Las cifras de precio y capacidad son indicativas públicas a la fecha de elaboración y deben contrastarse con la página oficial de precios.

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

## 7.5 Conectores de datos mínimos

El conjunto mínimo para habilitar los casos de uso priorizados de la sección 13 es el siguiente: Defender for Endpoint, Defender for Office 365, Defender for Identity, Defender for Cloud Apps, Defender for Cloud, Microsoft Entra ID (inicios de sesión interactivos y no interactivos, y registros de auditoría), Microsoft Purview y el conector de incidentes de Defender XDR hacia Sentinel. Más de 350 conectores preconfigurados están disponibles para las fuentes adicionales de cada organización, y cada una debe justificar su costo de ingesta conforme al criterio de tiering.

## 7.6 Residencia, retención y red

La residencia de datos debe confirmarse contra el requisito regulatorio de la organización, con especial atención en sectores regulados (público, financiero, salud) y en la jurisdicción donde opera. La retención se define en dos niveles según la tabla 4: ventana activa en el tier de analytics y retención extendida en el data lake, donde el formato abierto Delta Parquet permite conservar telemetría sin re-ingesta.

Para la cobertura de servidores y cargas de trabajo fuera de Azure se requiere Azure Arc, que proyecta los equipos locales o de otras nubes como recursos gobernables y habilita la incorporación de Defender for Cloud y Defender for Endpoint. Los requisitos de red asociados —salida a los puntos de conexión del servicio, resolución de nombres y, en su caso, proxy o punto de conexión privado— deben validarse con el equipo de infraestructura de la organización antes de la Fase 1.

## Siguiente paso

Continúe con [2. Roles e identidades](02-roles-e-identidades.md) y verifique todo con la [lista de readiness](06-checklist-readiness.md).
