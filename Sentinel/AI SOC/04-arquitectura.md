<!-- AI-SOC Playbook v2.0 · Arturo Mandujano (Cloud Solution Architect) · 28 de septiembre de 2026 -->
[← 3. Visión objetivo: el modelo ISOC / AI-SOC](03-vision-isoc.md) | [Índice](README.md) | [5. Catálogo de agentes y agentes personalizados en Copilot Studio →](05-agentes.md)

---

# 4. Arquitectura de referencia

## 4.1 Componentes y responsabilidades

La arquitectura de referencia asigna una responsabilidad clara a cada componente, evitando la duplicación de funciones que caracteriza a los entornos heredados. Ningún componente se incorpora sin un papel definido en una de las tres capas del modelo ISOC.

| Componente | Papel en el ISOC | Capa del modelo | Estado |
|----|----|----|----|
| Microsoft Sentinel (SIEM) | Ingesta, normalización, reglas analíticas, gestión de incidentes y automatización; más de 350 conectores nativos | Señales y contexto | GA |
| Sentinel data lake | Almacenamiento centralizado de telemetría estructurada y semiestructurada en formato abierto Delta Parquet; separa almacenamiento de indexación y admite múltiples motores (Kusto, Spark, ML) sobre una sola copia | Señales | GA desde el 30 de septiembre de 2025 |
| Sentinel graph | Mapea relaciones entre identidades, dispositivos, archivos, alertas y otras entidades; hace explícito e indexable el razonamiento de rutas de ataque | Contexto | Preview |
| Sentinel MCP server | Servidor unificado y hospedado que expone colecciones de herramientas por escenario y habilita consultas en lenguaje natural sin escribir KQL | Contexto | Preview |
| Microsoft Defender XDR | Protección y respuesta en endpoints, identidad, Office 365 y aplicaciones en la nube; correlación de incidentes y attack disruption | Señales y actuadores | GA |
| Microsoft Defender for Cloud | Postura y protección de cargas de trabajo en la nube; alimenta el modelado de rutas de ataque | Señales y contexto | GA |
| Microsoft Entra ID Protection | Detección de riesgo de identidad y sesión; acceso condicional como actuador | Señales y actuadores | GA |
| Microsoft Purview | Postura y triage de seguridad de datos; contexto de sensibilidad para priorizar incidentes | Contexto | GA (agentes en preview) |
| Microsoft Security Copilot | Capa de razonamiento: agentes, análisis en lenguaje natural, generación de KQL y síntesis de reportes | Contexto y actuadores | GA (agentes específicos en preview) |
| ISOC en Microsoft Defender | Experiencia integrada que reúne SIEM y protección contra amenazas en una base compartida | Transversal | Preview |

*Tabla 3. Componentes de la arquitectura de referencia y su estado de disponibilidad.*

## 4.2 Flujo de datos

El flujo de datos se diseña en una sola dirección de ingesta y múltiples direcciones de consumo. La telemetría entra una vez, se normaliza una vez y se consume desde tantos motores como haga falta, lo que elimina la re-ingesta y la duplicación de costo que hoy se produce cuando el mismo dato existe en el SIEM y en un archivo frío separado.

```text
  FUENTES                 INGESTA / TIERING            CONSUMO
  ---------------------   --------------------------   ---------------------
  Defender for Endpoint   >  analytics tier            >  reglas analíticas
  Defender for Office     >  (KQL interactivo,         >  advanced hunting
  Defender for Identity      retención corta)          >  incidentes y SOAR
  Defender for Cloud Apps
  Defender for Cloud      >  data lake tier            >  Spark / notebooks
  Entra ID (Signin,          (Delta Parquet,           >  ML y modelos
    Audit, NonInteractive)   retención larga,          >  acceso vectorizado
  Purview                    sin re-ingesta)              para LLM y agentes
  Firewall / proxy / red
  Aplicaciones de negocio >  graph                     >  rutas de ataque
  Fuentes de terceros        (entidades y relaciones)  >  hunting de relaciones

                             MCP server  --------------->  Security Copilot
                             (colecciones por escenario)   Copilot Studio
                                                           Microsoft Foundry
                                                           VS Code
```

*Figura 2. Flujo de datos y consumo multi-motor sobre una sola copia del dato.*

## 4.3 Decisiones de diseño

### 4.3.1 Tiering: qué va a analytics y qué va al data lake

La regla de asignación es funcional, no de volumen. Va al tier de analytics toda fuente que participa en una detección en tiempo cercano al real, en una correlación de incidentes o en una consulta de triage interactivo: alertas, eventos de endpoint de alto valor, inicios de sesión, eventos de auditoría de identidad y señales de correo. Va al data lake toda fuente cuyo valor es forense, de cumplimiento o de análisis a gran escala: registros de red de alto volumen, eventos de proxy, telemetría de aplicaciones, histórico extendido de cualquier tabla y todo aquello que se consulta en investigación retrospectiva pero no dispara una regla.

El data lake permite retención forense larga sin re-ingesta, porque separa el almacenamiento de la indexación y admite que Kusto, Spark y los motores de aprendizaje automático operen sobre una sola copia del dato. Ese es el fundamento del ahorro: no se paga dos veces por el mismo evento y no se necesita rehidratar para investigar.

| Criterio | Analytics tier | Data lake tier |
|----|----|----|
| Caso de uso principal | Detección, correlación, triage interactivo | Investigación forense, cumplimiento, analítica a escala y entrenamiento de modelos |
| Retención sugerida | [90] días, alineada a la ventana de detección activa | [12-24] meses, alineada al requisito regulatorio de la organización |
| Motor de consulta | Kusto (KQL interactivo) | Kusto, Spark y aprendizaje automático sobre Delta Parquet |
| Perfil de costo | Costo por GB ingerido más alto; se justifica por la latencia de detección | Costo de almacenamiento menor; sin re-ingesta para consultar |
| Ejemplos de fuentes | AlertInfo, AlertEvidence, SecurityIncident, SigninLogs, EmailEvents, DeviceLogonEvents | Registros de firewall y proxy, telemetría de aplicaciones, histórico extendido de DeviceProcessEvents y CloudAppEvents |

*Tabla 4. Criterios de asignación entre tiers de datos.*

La regla funcional anterior se traduce en una decisión concreta por tabla. La tabla siguiente asigna las fuentes habituales de una organización a un tier, justifica la asignación por su papel en las detecciones y consultas de la sección 6, y sugiere la retención; la columna final indica cómo se promueve una fuente del data lake al analytics tier cuando una investigación lo exige, sin re-ingesta.

| Tabla o fuente | Tier | Justificación | Retención sugerida | Promoción bajo demanda |
|----|----|----|----|----|
| SecurityAlert, SecurityIncident | Analytics | Núcleo del triage, de los KPIs (consultas 6.1.1 a 6.1.3) y de la cobertura MITRE (6.4.13); volumen bajo | [90] días en analytics con espejo en el data lake a [12-24] meses para tendencias | No aplica: siempre en analytics |
| SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs | Analytics | Detecciones de identidad en tiempo cercano al real: password spray (6.4.1), viaje imposible (6.4.9), picos de MFA (6.4.11), identidades agénticas (6.2.4 y 8.4) | [90] días en analytics; espejo en el data lake a [12] meses para cuentas dormidas (6.4.10) y spray lento | Las cacerías largas se ejecutan con query_lake sobre el espejo; no requieren promoción |
| DeviceEvents, DeviceProcessEvents, DeviceLogonEvents (Defender XDR) | Analytics (conector de Defender XDR) | Ransomware temprano (6.4.4, 6.4.5) y movimiento lateral (6.4.3) exigen latencia mínima | [90] días; retención adicional en el data lake según el requisito forense | No aplica |
| DeviceNetworkEvents (Defender XDR) | Analytics con evaluación de volumen | Correlación de indicadores (6.4.12) y AiTM; es la tabla de mayor volumen de Defender | [30-90] días en analytics; [12] meses en el data lake | Si el costo lo exige, mover al data lake y promover por dispositivo o rango de fechas en investigaciones |
| EmailEvents, EmailPostDeliveryEvents, UrlClickEvents | Analytics | Phishing, AiTM (6.4.2) y remediación posterior a la entrega (6.4.8) | [90] días | No aplica |
| CommonSecurityLog (firewall, proxy, WAF) de alto volumen | Data lake | Valor principalmente forense y de correlación semanal con inteligencia de amenazas (6.4.12); costo por GB elevado en analytics | [12] meses en el data lake | Promoción al analytics tier del rango de fechas y equipos de una investigación; reglas de resumen para agregados diarios en analytics |
| Syslog de Linux y de dispositivos de red | Data lake | Mismo perfil que CommonSecurityLog; uso esporádico en detección | [12] meses | Igual que CommonSecurityLog |
| AWS CloudTrail, AWS VPC Flow Logs, GCP VPC Flow Logs | Data lake | Flujos de red de nube de volumen masivo; detección mediante Defender for Cloud y reglas de resumen | [12] meses | Promover subconjuntos por cuenta o proyecto en investigaciones |
| DNS (DnsEvents o esquema ASIM DNS), proxy web, NetFlow | Data lake | Cacería retrospectiva y correlación de dominios con inteligencia de amenazas; volumen muy alto | [12] meses | Promover los dominios y rangos que coincidan con indicadores; agregados por hora en analytics mediante reglas de resumen |
| ThreatIntelligenceIndicator (o ThreatIntelIndicators) | Analytics | Coincidencia con telemetría en tiempo cercano al real y correlación semanal | Según la expiración de los indicadores; [12] meses de histórico en el data lake | No aplica |
| Usage, Heartbeat | Analytics | Higiene y costo (6.3.1, 6.3.2); volumen bajo | [90] días | No aplica |
| ExposureGraphNodes y ExposureGraphEdges | Defender XDR (sin ingesta al espacio de trabajo) | Rutas de ataque (6.4.6) y grafo del MCP server; se consultan en advanced hunting | La del servicio | No aplica |

*Tabla 5. Decisión de tiering por tabla, con justificación, retención sugerida y mecanismo de promoción.*

El fundamento técnico del tiering es que el data lake almacena la telemetría en formato abierto Delta Parquet, columnar y con transacciones, sobre el que operan tres motores sin copiar los datos: Kusto (KQL interactivo, la misma sintaxis que el analytics tier, expuesta también por query_lake), Spark en notebooks para analítica a escala, aprendizaje automático y transformaciones, y los agentes a través del MCP server. Promover una tabla del data lake al analytics tier no re-ingiere: activa la indexación de un subconjunto para consulta interactiva y detección, y ese subconjunto se factura al precio de analytics sólo mientras esté promovido. Por eso la política de tiering de cada organización debe definir quién autoriza una promoción, por cuánto tiempo y con qué criterio de reversión, como parte de la revisión trimestral de tiering de la tabla 32.

### 4.3.2 Normalización

La normalización se apoya en el modelo de datos de seguridad de la capa unificada y en los esquemas normalizados de Sentinel, de manera que una consulta de cacería no dependa del proveedor que originó el evento. La recomendación operativa es normalizar primero las tres familias con mayor número de fuentes heterogéneas: autenticación, actividad de red y eventos de proceso. Las fuentes nativas de Microsoft ya llegan normalizadas y no requieren trabajo adicional.

### 4.3.3 Costo

El control de costo descansa en tres palancas. La primera es el tiering descrito arriba. La segunda es SOC optimization, cuyas recomendaciones dinámicas identifican tanto datos ingeridos sin valor de detección como brechas de cobertura; los clientes que las implementaron aumentaron su cobertura de seguridad hasta 17% y la utilización de datos 31% (Microsoft, Coordinated Defense, 2025). La tercera es el gobierno del consumo de SCU descrito en la sección 8.6, que evita que la capacidad agéntica se consuma en casos de uso de bajo valor.

### 4.3.4 Sentinel MCP server como interfaz de los agentes

El servidor MCP de Sentinel es la pieza que convierte la plataforma de datos en una superficie consumible por agentes. Es un servidor unificado, totalmente hospedado, que no requiere desplegar infraestructura y que utiliza Microsoft Entra para identidad. Expone colecciones de herramientas orientadas a escenarios —exploración de datos, triage y cacería— y permite formular consultas en lenguaje natural sin conocer el esquema ni escribir KQL. Se conecta desde Security Copilot, Copilot Studio, Microsoft Foundry y Visual Studio Code. Se encuentra en versión preliminar.

Sus prerequisitos son el onboarding al Sentinel data lake, el rol Security reader para listar e invocar herramientas y, según la colección que se utilice, Sentinel en el portal de Defender, Defender XDR o Defender for Endpoint, o bien Security Copilot. Ejemplos de consultas verificadas que el servidor resuelve en lenguaje natural:

- "Find the top three users that are at risk and explain why"

- "Find sign-in failures in the last 24 hours and summarize key findings"

- "Investigate users with a password spray alert in the last seven days and tell me if any of them are compromised"


---

[← 3. Visión objetivo: el modelo ISOC / AI-SOC](03-vision-isoc.md) | [Índice](README.md) | [5. Catálogo de agentes y agentes personalizados en Copilot Studio →](05-agentes.md)
