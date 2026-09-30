# Tiering de datos: analytics tier frente a data lake tier

Contenido de la sección 4.3.1 de la guía (tablas 4 y 5). La regla de asignación es funcional, no de volumen. Los valores entre corchetes (`[90]` días, `[12-24]` meses) se ajustan por organización.

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


## Relación con otras piezas del repositorio

- Las consultas de higiene de ingesta que sustentan la decisión: [6.3.1](../06-kql.md#631-costo-e-higiene-de-ingesta-por-tabla), [6.3.2](../06-kql.md#632-fuentes-en-silencio-latido-de-los-agentes-de-datos) y [6.3.3](../06-kql.md#633-cobertura-de-conectores-por-proveedor-de-alertas).
- El agente que detecta la deriva de costo semanal: [CS-10](../05-agentes.md#cs-10-revisor-de-higiene-de-ingesta-y-costo).
- La revisión trimestral de tiering y retención: [Cadencias](../11-reportes-kpis-cadencias.md#113-guía-operativa-cadencia-de-ejecución-por-agente) y [Reportes](../11-reportes-kpis-cadencias.md#115-catálogo-de-reportes).
- Onboarding al data lake: [Prerequisitos y licenciamiento](../configuracion/01-prerequisitos-y-licenciamiento.md).
