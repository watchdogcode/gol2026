<!-- AI-SOC Playbook v2.0 · Arturo Mandujano (Cloud Solution Architect) · 28 de septiembre de 2026 -->
[← 10. Modelo operativo y roles](10-modelo-operativo.md) | [Índice](README.md) | [12. Ruta de adopción de referencia →](12-ruta-de-adopcion.md)

---

# 11. Reportes, KPIs y guía operativa de cadencias

## 11.1 Tabla de indicadores

| KPI | Definición | Fórmula | Fuente de datos | Meta sugerida |
|----|----|----|----|----|
| MTTA | Tiempo medio desde la creación del incidente hasta su primera atención | percentile(datetime_diff('minute', FirstModifiedTime, CreatedTime), 50) | SecurityIncident (consulta 6.1.1) | Menos de [15] minutos en severidad alta |
| MTTR | Tiempo medio desde la creación hasta el cierre del incidente | percentile(datetime_diff('minute', ClosedTime, CreatedTime), 50) | SecurityIncident (consultas 6.1.1 y 6.1.2) | Línea base menos 30% al cierre de la Fase 2 |
| Incidentes resueltos con participación de agentes | Proporción de incidentes atendidos o etiquetados por un agente | Incidentes con EsAgente verdadero / total de incidentes | SecurityIncident (consulta 6.2.2) | [40%] del volumen de Tier 1 al cierre de la Fase 3 |
| Tasa de falsos positivos | Proporción de incidentes cerrados como falso positivo o benigno | (FalsosPositivos + BenignosPositivos) / Total | SecurityIncident (consulta 6.1.3) | Reducción sostenida frente a la línea base; referencia externa del 32% (IBM, marzo 2023) |
| Tasa de reclasificación de veredictos del agente | Proporción de veredictos muestreados que el analista corrige | Veredictos corregidos / veredictos muestreados | Muestreo del runbook 9.5 | Por debajo del [10%] |
| Cobertura MITRE ATT&CK | Técnicas con al menos una detección activa observada | Técnicas observadas / técnicas priorizadas en el perfil de amenaza | AlertInfo (consulta 6.4.7) y SOC optimization | Incremento acorde al hasta 17% observado en clientes que aplicaron SOC optimization (Microsoft, 2025) |
| Tiempo de contención | Tiempo desde la primera señal hasta la contención efectiva | Marca de tiempo de la acción de contención menos primera detección | AlertEvidence, DeviceEvents y bitácora de attack disruption | Menos de [15] minutos en el 90% de los casos de severidad alta |
| Alertas por analista por turno | Carga de trabajo efectiva del equipo | Alertas atendidas / analistas por turno | SecurityAlert y SecurityIncident | Reducción sostenida sin aumento del MTTR |
| Consumo de SCU por caso de uso | Capacidad agéntica consumida por escenario | SCUs consumidas por agente y por periodo | Monitoreo de uso en el portal de Security Copilot | Dentro del presupuesto asignado por caso de uso |
| Costo por GB ingerido | Costo de la plataforma de datos por unidad de telemetría | sum(Quantity)/1024 multiplicado por el precio por GB | Usage (consulta 6.3.1) | Reducción por efecto del tiering sin pérdida de cobertura |

*Tabla 28. Indicadores del AI-SOC, su fórmula y su fuente.*

## 11.2 Paquete de reportes

| Reporte | Cadencia | Audiencia | Contenido | Generación |
|----|----|----|----|----|
| Dashboard operativo diario | Diaria | Equipo del SOC | Volumen por severidad, incidentes abiertos, MTTA y MTTR del día, fuentes en silencio y actividad de agentes | Libro de trabajo de Sentinel alimentado por las consultas 6.1.1, 6.2.1, 6.2.3 y 6.3.2 |
| Reporte semanal de incidentes | Semanal | Liderazgo del SOC y dueños de aplicación | Incidentes significativos, tendencia de falsos positivos, contribución de agentes y tasa de reclasificación del muestreo | Agente personalizado de resumen ejecutivo semanal (sección 5.3) con revisión editorial |
| Briefing mensual de inteligencia de amenazas | Mensual | SOC, ingeniería de detecciones y CISO | Actividad de actores de amenaza, vulnerabilidades internas y externas relevantes, e hipótesis de cacería derivadas | Threat Intelligence Briefing Agent, con Defender EASM y Defender for Endpoint activos para mejor resultado |
| Reporte ejecutivo trimestral de postura y ROI | Trimestral | Dirección y comité de riesgos | Evolución de los KPIs, cobertura, incidentes relevantes, costo y retorno observado frente al modelo de negocio | Elaborado por el liderazgo del SOC con datos de las consultas de la sección 6 |

*Tabla 29. Paquete de reportes del AI-SOC.*

## 11.3 Guía operativa: cadencia de ejecución por agente

Un agente sin cadencia definida produce dos fallas opuestas: o se ejecuta de más y consume capacidad SCU sin que nadie lea su salida, o se ejecuta de menos y el SOC vuelve a depender de la memoria de las personas. La tabla siguiente fija, para cada agente nativo y para cada agente de Copilot Studio de la sección 5.6, el tipo de ejecución, la frecuencia, la ventana horaria en hora local del SOC, el rol que revisa la salida y el tiempo máximo en que debe hacerlo. Las frecuencias son la recomendación inicial para la Fase 2; el procedimiento de la sección 11.7 las ajusta con evidencia.

| Agente o proceso | Tipo y frecuencia | Ventana (hora local) | Rol responsable | SLA de revisión humana | Salida y canal | SCU |
|----|----|----|----|----|----|----|
| Dynamic Threat Detection Agent | Continuo; siempre activo | 24x7 | Tier 1 en turno | Las alertas entran al triage normal (MTTA de la tabla 28) | Alertas en el portal de Defender | Nulo en preview; SCU al GA |
| Phishing Triage Agent / Security Alert Triage Agent | Por evento; cada correo reportado o alerta elegible | 24x7 | Tier 1 en turno | Amenazas validadas en menos de [30] min; muestreo diario del 10% de los falsos positivos cerrados | Veredicto y razonamiento en el incidente | Medio, según volumen |
| Threat Hunting Agent | A demanda en investigaciones; campaña semanal de 2 horas con hipótesis | Martes 10:00 a 12:00 | Threat hunter | Hallazgos clasificados al cierre de la campaña | Reglas, consultas guardadas, matriz MITRE | Medio-alto en campaña |
| Threat Intelligence Briefing Agent | Programado semanal (lunes); ad hoc ante campaña activa | Lunes 08:00 | Threat intelligence | Revisión editorial en menos de 4 horas | Briefing en Teams y correo | Bajo-medio |
| Security Analyst Agent | A demanda dentro de investigaciones de Tier 2 | Horario de la investigación | Tier 2 / IR | Inmediata (human-in-the-loop) | Análisis en el incidente | Medio por caso |
| Conditional Access Optimization Agent | Programado; semanal en despliegue, quincenal después | Miércoles 09:00 | Ingeniería de identidad | Aprobación explícita antes de aplicar (N4) | Recomendaciones en Entra | Bajo |
| Data Security Posture Agent | Programado semanal | Jueves 08:00 | Ingeniería de datos (Purview) | Revisión semanal | Postura de datos en Purview | Bajo |
| Data Security Triage Agent | Por evento; cada alerta de datos | 24x7 | Tier 1 de datos | Muestreo diario del 10% de veredictos cerrados | Veredicto en la alerta de Purview | Medio |
| CS-1 Asistente de triage en Teams | A demanda; cada incidente que el analista abre | Todos los turnos | Tier 1 y Tier 2 | El analista aprueba cada escritura | Resumen en Teams; comentario aprobado en el incidente | Medio |
| CS-2 Verificador de compromiso de usuario | A demanda y por evento (runbooks 9.1 y 9.2) | 24x7 | Tier 2 | Inmediata; el analista decide la contención | Veredicto y línea de tiempo en Teams | Medio-alto |
| CS-3 Analizador de URL o dominio | A demanda y por evento; cada URL reportada | 24x7 | Tier 1 | Inmediata | Veredicto en Teams con evidencia de TI | Medio |
| CS-4 Reporte diario de exposición | Programado; diario, días hábiles | 07:00 | Ingeniería de detecciones y exposición | Antes del arranque del turno matutino; menos de 1 hora | Canal de Teams de exposición | Medio |
| CS-5 Boletín semanal de actores e IOCs | Programado semanal (lunes); ad hoc ante campaña | Lunes 08:30 | Threat intelligence | Revisión editorial en menos de 4 horas | Teams y correo; IOCs correlacionados | Medio |
| CS-6 Traspaso de turno | Programado; tres veces al día | 06:45, 14:45 y 22:45 | Líder del turno saliente | Confirmación del turno entrante en menos de 15 min | Mensaje en el canal del SOC | Bajo-medio |
| CS-7 Generador y validador de KQL | A demanda; campaña de migración de reglas | Horario laboral | Ingeniería de detecciones | Revisión obligatoria antes de producción (runbook 9.4) | Regla propuesta con mapeo MITRE | Medio |
| CS-8 Reporte ejecutivo CISO | Programado mensual; primer día hábil | 08:00 | Líder del SOC | Revisión y edición en menos de 2 días hábiles | Documento y correo al CISO | Medio |
| CS-9 Cazador de cuentas dormidas y spray lento | Programado semanal (viernes) | 06:00 | Threat hunter | Revisión en la campaña semanal siguiente | Lista de hallazgos en Teams | Medio-alto |
| CS-10 Revisor de higiene de ingesta y costo | Programado semanal (lunes) | 06:30 | Ingeniería de la plataforma de datos | Revisión en menos de 1 día hábil | Reporte en Teams; ticket por fuente silenciosa | Bajo |
| Revisión de consumo de SCU | Proceso semanal (viernes) | Cualquier hora | Ingeniería de agentes | Ajuste de presupuesto la misma semana | Reporte de consumo (tabla 32) | No aplica |
| Revisión de calidad de agentes (11.7) | Proceso mensual | Primera semana del mes | Líder de Tier 1 e ingeniería de agentes | Decisión de autonomía documentada | Acta de calidad y ajustes | No aplica |

*Tabla 30. Cadencia maestra de ejecución por agente y proceso.*

Las cadencias responden a una lógica que conviene hacer explícita. La detección dinámica es continua porque su valor depende de correlacionar señales en el momento en que ocurren y no tiene costo de SCU durante la versión preliminar. El triage de phishing y de alertas es por evento porque cada alerta tiene un reloj de MTTA propio; el muestreo diario del 10% de los veredictos de falso positivo cerrados existe porque es el único veredicto que no pasa por un analista, y por tanto el único donde un error se vuelve invisible. La cacería con el Threat Hunting Agent se programa como campaña semanal de dos horas con hipótesis definidas porque la cacería sin hipótesis consume SCU y produce ruido; la ejecución a demanda queda para las investigaciones abiertas.

El briefing de inteligencia de amenazas y el boletín de actores se emiten los lunes para alimentar la campaña de cacería del martes y la revisión de acceso condicional del miércoles; se repiten ad hoc únicamente cuando hay una campaña activa contra el sector de la organización. El Conditional Access Optimization Agent corre semanal mientras las políticas cambian con frecuencia y pasa a quincenal cuando dos revisiones consecutivas no producen recomendaciones nuevas. El reporte de exposición se genera a las 07:00 para que el turno matutino arranque con la lista priorizada; el traspaso de turno se ejecuta quince minutos antes de cada cambio para que el turno entrante lo lea antes de asumir la guardia. La higiene de ingesta y el consumo de SCU son semanales porque la deriva de costo se acumula en días, no en horas; la calidad de los agentes se revisa mensualmente porque el muestreo necesita volumen estadístico suficiente.

## 11.4 Calendario operativo tipo

El calendario siguiente traduce la tabla anterior en un ritmo operativo. Las horas corresponden al huso horario del SOC y suponen tres turnos de ocho horas; si el SOC opera en dos turnos o con un servicio administrado nocturno, las actividades del turno nocturno se trasladan al inicio del matutino.

| Horizonte | Momento | Actividad | Agente, consulta o reporte | Responsable |
|----|----|----|----|----|
| Diario, turno matutino (07:00 a 15:00) | 06:45 | Lectura del traspaso de turno nocturno | CS-6 | Líder de turno entrante |
|  | 07:00 | Reporte diario de exposición y vulnerabilidades críticas; asignación de los hallazgos | CS-4; consulta 6.4.6 | Ingeniería de detecciones |
|  | 07:30 | Revisión del dashboard operativo: incidentes abiertos, MTTA del turno anterior, fuentes silenciosas | Workbook con consultas 6.1.1, 6.3.2 y 6.3.3 | Tier 1 |
|  | Durante el turno | Triage asistido de incidentes nuevos; verificación de usuarios y URLs a demanda | CS-1, CS-2, CS-3; Phishing Triage Agent | Tier 1 y Tier 2 |
|  | 14:00 | Muestreo del 10% de los falsos positivos cerrados por agentes desde el turno anterior | Consulta 6.2.2; portal de Defender | Líder de Tier 1 |
|  | 14:45 | Generación y publicación del traspaso de turno | CS-6 | Líder de turno saliente |
| Diario, turno vespertino (15:00 a 23:00) | 15:00 | Lectura del traspaso; continuidad de investigaciones abiertas | CS-6 | Líder de turno |
|  | Durante el turno | Triage por evento; escalaciones a los runbooks 9.1 a 9.3 | Agentes nativos; CS-1 a CS-3 | Tier 1 y Tier 2 |
|  | 22:45 | Traspaso de turno | CS-6 | Líder de turno saliente |
| Diario, turno nocturno (23:00 a 07:00) | Continuo | Triage por evento con supervisión mínima; contención sólo dentro de la política de attack disruption | Agentes nativos; CS-1 | Tier 1 nocturno o servicio administrado |
| Semanal | Lunes 06:30 | Revisión de higiene de ingesta y costo; tickets por fuente silenciosa | CS-10; consultas 6.3.1 a 6.3.3 | Ingeniería de la plataforma de datos |
|  | Lunes 08:00 y 08:30 | Briefing de inteligencia de amenazas y boletín de actores e IOCs; definición de hipótesis de cacería | Threat Intelligence Briefing Agent; CS-5 | Threat intelligence |
|  | Martes 10:00 a 12:00 | Campaña de cacería con hipótesis del lunes | Threat Hunting Agent; MCP server; consultas 6.4.x | Threat hunter |
|  | Miércoles 09:00 | Revisión de recomendaciones de acceso condicional | Conditional Access Optimization Agent | Ingeniería de identidad |
|  | Jueves 08:00 | Revisión de postura de seguridad de datos | Data Security Posture Agent | Ingeniería de datos |
|  | Viernes 06:00 | Cacería programada de cuentas dormidas y password spray de baja frecuencia | CS-9; consultas 6.4.10 y 6.4.11 | Threat hunter |
|  | Viernes 15:00 | Resumen semanal de incidentes y falsos positivos; revisión de consumo de SCU y ajuste de presupuestos | Agente de resumen semanal (tabla 7); consulta 6.1.3; portal de uso | Líder del SOC e ingeniería de agentes |
| Mensual | Primer día hábil, 08:00 | Reporte ejecutivo CISO | CS-8; consultas 6.1.1 a 6.2.2 | Líder del SOC |
|  | Primera semana | Revisión de calidad y retroalimentación de agentes; decisión sobre niveles de autonomía | Procedimiento de la sección 11.7 | Líder de Tier 1 e ingeniería de agentes |
|  | Segunda semana | Actualización de la cobertura MITRE ATT&CK y del backlog de detecciones | Consultas 6.4.7 y 6.4.13; CS-7 | Ingeniería de detecciones |
| Trimestral | Último mes del trimestre | Reporte de postura y ROI; revisión de tiering y retención; revisión de identidades agénticas y rotación de secretos | Consultas 6.3.1, 6.2.4 y 8.4; tabla 5 | Líder del SOC, plataforma de datos e ingeniería de agentes |

*Tabla 31. Calendario operativo tipo por turno, semana, mes y trimestre.*

## 11.5 Catálogo de reportes

El paquete de reportes de la tabla 29 se amplía con los reportes que los agentes de Copilot Studio y las consultas de la sección 6 hacen posibles. Cada reporte tiene un dueño nombrado; un reporte sin dueño se descontinúa en la revisión trimestral.

| Reporte | Audiencia | Frecuencia | Contenido | Fuente | Formato y canal | Dueño |
|----|----|----|----|----|----|----|
| Dashboard operativo en tiempo real | Analistas y líder de turno | Continuo | Incidentes abiertos por severidad y antigüedad, MTTA del turno, alertas por agente, fuentes silenciosas, latido de conectores | Workbook de Sentinel con las consultas 6.1.1, 6.2.1, 6.3.2 y 6.3.3 | Workbook en el portal; pantalla del SOC | Ingeniería de detecciones |
| Resumen diario de turno | Turno entrante y líder del SOC | Tres veces al día | Incidentes abiertos con estado y siguiente acción, contenciones activas, alertas de agentes pendientes de validar, riesgos del turno | CS-6 (Security Copilot sobre SecurityIncident) | Mensaje en el canal del SOC en Teams | Líder de turno |
| Exposición diaria | Ingeniería de detecciones, dueños de aplicación | Diario, 07:00 | Vulnerabilidades críticas nuevas, activos expuestos en Internet, rutas de ataque hacia activos críticos, cambios respecto al día anterior | CS-4 (Defender Vulnerability Management, EASM, ExposureGraph) | Mensaje en Teams con tabla de hasta diez hallazgos | Ingeniería de exposición |
| Resumen semanal de incidentes y falsos positivos | Liderazgo del SOC, dueños de aplicación | Semanal, viernes | Volumen y severidad, incidentes significativos, tasa de falsos positivos por fuente, reglas candidatas a ajuste | Agente de resumen semanal (tabla 7); consulta 6.1.3 | Documento breve en Teams y correo | Líder del SOC |
| Boletín semanal de inteligencia de amenazas | SOC, ingeniería de detecciones, CISO | Semanal, lunes | Actores relevantes para el sector, TTPs, IOCs correlacionados contra la telemetría propia, hipótesis de cacería derivadas | Threat Intelligence Briefing Agent; CS-5; consulta 6.4.12 | Documento en Teams y correo | Threat intelligence |
| Consumo de SCU y costo de ingesta | Ingeniería de agentes, plataforma de datos, líder del SOC | Semanal, viernes | SCU por agente y caso de uso frente a presupuesto, sobreconsumo, GB facturables por tabla, deriva frente a la semana anterior | Portal de monitoreo de uso de Security Copilot; CS-10; consulta 6.3.1 | Tabla en Teams; hoja de cálculo mensual | Ingeniería de agentes |
| Calidad de agentes | Ingeniería de agentes, líder de Tier 1, comité de gobierno | Mensual | Precisión por agente, tasa de reversión, tiempo ahorrado estimado, incidentes de contenido no confiable, decisión de nivel de autonomía | Procedimiento 11.7; consultas 6.2.2 y 6.2.3 | Acta y tabla de métricas (tabla 34) | Ingeniería de agentes |
| Cobertura MITRE ATT&CK | Ingeniería de detecciones, CISO | Mensual | Técnicas cubiertas, técnicas priorizadas sin detección, cambios del mes, backlog de reglas | Consultas 6.4.7 y 6.4.13; agente de validación de cobertura (tabla 7) | Matriz por táctica en documento | Ingeniería de detecciones |
| Reporte ejecutivo CISO | CISO y dirección | Mensual | Narrativa sin lenguaje técnico: riesgos abiertos, incidentes relevantes, tendencia de KPIs, decisiones requeridas | CS-8 (patrón ciso-reporting) | Documento de dos páginas y correo | Líder del SOC |
| Postura y ROI | Comité de riesgos y dirección | Trimestral | Evolución de KPIs frente a la línea base, horas de analista liberadas, costo de plataforma y SCU, avance de fases | Consultas 6.1.1 a 6.3.1; datos de la tabla 28 | Presentación ejecutiva | Líder del SOC |
| Revisión de tiering y retención | Plataforma de datos, cumplimiento | Trimestral | Tablas por tier, volumen y costo, promociones al analytics tier solicitadas, cumplimiento de retención regulatoria | Consulta 6.3.1; tabla 5 | Documento de decisión | Plataforma de datos |

*Tabla 32. Catálogo de reportes del AI-SOC: audiencia, frecuencia, fuente y dueño.*

## 11.6 Catálogo de análisis recomendados

Los análisis se distinguen de los reportes en que responden una pregunta concreta y terminan en una decisión: ajustar una regla, cambiar un tier, subir o bajar el nivel de autonomía de un agente, abrir una investigación. La tabla indica la técnica recomendada y la consulta o prompt de referencia; cuando la técnica es un entity analyzer del MCP server o el Threat Hunting Agent, el análisis consume SCU y debe respetar la cadencia de la tabla 30.

| Análisis | Pregunta que responde | Frecuencia | Técnica | Referencia |
|----|----|----|----|----|
| MTTA y MTTR por severidad | ¿El tiempo de atención y de resolución mejora tras cada fase y en qué severidad se concentra el retraso? | Semanal y mensual | KQL sobre SecurityIncident | Consultas 6.1.1 y 6.1.2 |
| Falsos positivos por fuente | ¿Qué productos y reglas generan el ruido que consume al equipo? | Semanal | KQL; SOC optimization | Consulta 6.1.3 |
| Eficacia de agentes | ¿Los incidentes atendidos por agentes se resuelven más rápido y con qué tasa de reversión? | Mensual | KQL y muestreo del procedimiento 11.7 | Consultas 6.2.2 y 6.2.3; tabla 34 |
| Cobertura MITRE ATT&CK | ¿Qué técnicas priorizadas carecen de detección observada y cuáles dejaron de disparar? | Mensual | KQL frente a la matriz de técnicas priorizadas; agente de validación de cobertura | Consultas 6.4.7 y 6.4.13 |
| Fuentes silenciosas y conectores rotos | ¿Qué equipos o conectores dejaron de reportar antes de que un incidente lo revele? | Diario | KQL sobre Heartbeat y SecurityAlert | Consultas 6.3.2 y 6.3.3 |
| Deriva de costo de ingesta | ¿Qué tablas crecen sin aportar detecciones y son candidatas al data lake tier? | Semanal | KQL sobre Usage; CS-10 vía query_lake | Consulta 6.3.1; tabla 5 |
| Password spray rápido y AiTM | ¿Hay un origen que prueba pocas contraseñas contra muchas cuentas, o clics de phishing seguidos de sesión exitosa? | Diario (regla analítica) y por evento | KQL; Phishing Triage Agent; CS-3 | Consultas 6.4.1 y 6.4.2 |
| Password spray de baja frecuencia | ¿Existe un origen que distribuye intentos fallidos a lo largo de semanas para evadir los umbrales horarios? | Semanal | query_lake sobre SigninLogs en el data lake con ventanas largas; CS-9 | Consulta 6.4.1 ejecutada con ventana de 30 días y umbral bajo por día |
| Viaje imposible | ¿Qué cuentas autentican desde dos ubicaciones incompatibles con el tiempo transcurrido? | Diario | KQL con geo_distance_2points; analyze_user_entity para confirmar | Consulta 6.4.9 |
| Cuentas dormidas que reviven | ¿Qué cuentas sin actividad durante 90 días volvieron a autenticar en los últimos 7? | Semanal | KQL; CS-9; analyze_user_entity | Consulta 6.4.10 |
| Picos de fallas de MFA | ¿Hay usuarios o IPs con ráfagas anómalas de fallas de MFA (fatiga de MFA o robo de contraseña)? | Diario | KQL con make-series y series_decompose_anomalies | Consulta 6.4.11 |
| Movimiento lateral | ¿Qué cuentas autentican contra un número inusual de destinos? | Diario y por incidente | KQL; Security Analyst Agent | Consulta 6.4.3 |
| Rutas de ataque hacia activos críticos | ¿Qué relaciones permiten llegar a un activo crítico y cuáles cambiaron esta semana? | Semanal y en cada reporte de exposición | Sentinel graph; ExposureGraph en advanced hunting; herramientas de grafo del MCP server (preview) | Consulta 6.4.6; prompt de cacería 3 del anexo C |
| Exposición de credenciales e identidades | ¿Qué identidades con privilegios están expuestas por dispositivos vulnerables o permisos excesivos? | Semanal | Exposure Management; grafo de exposición; CS-4 | Consulta 6.4.6; CS-4 |
| Correlación de indicadores de amenaza | ¿Algún indicador del boletín semanal aparece en la telemetría de red o de endpoints? | Semanal y ad hoc | KQL sobre ThreatIntelligenceIndicator contra DeviceNetworkEvents y CommonSecurityLog; analyze_url_entity | Consulta 6.4.12; CS-5 |
| SCU por caso de uso | ¿Qué agente o caso de uso consume más capacidad y con qué retorno en tiempo ahorrado? | Semanal | Portal de monitoreo de uso; cruce con la tabla 34 | Reporte de consumo de la tabla 32 |
| Anomalías de identidades agénticas | ¿Alguna cuenta agéntica autentica desde IPs, aplicaciones u horarios fuera de su patrón? | Diario (regla analítica) | KQL sobre SigninLogs y AuditLogs | Consultas 6.2.4 y 8.4 |

*Tabla 33. Catálogo de análisis recomendados, técnica y referencia.*

## 11.7 Procedimiento mensual de revisión de calidad y retroalimentación de agentes

El runbook 9.5 fija el muestreo semanal del Phishing Triage Agent. Este procedimiento lo generaliza a todos los agentes, nativos y de Copilot Studio, con una revisión mensual que produce tres salidas: las métricas de la tabla 34, la retroalimentación registrada en cada agente y una decisión documentada sobre el nivel de autonomía de cada uno. Lo ejecutan el líder de Tier 1 y la ingeniería de agentes durante la primera semana del mes, y su acta se anexa al reporte de calidad de agentes.

1. Construir la muestra. Para cada agente, extraer las ejecuciones del mes (consulta 6.2.2 para incidentes etiquetados, consulta 6.2.3 para CloudAppEvents, Copilot Studio analytics y el historial de sesiones de Security Copilot para los agentes CS-1 a CS-10) y seleccionar al azar al menos el [10%] con un mínimo de [20] casos por agente; para los agentes de reporte (CS-4, CS-5, CS-6, CS-8) revisar todas las ediciones del mes.

2. Clasificar cada caso como correcto, incorrecto o discutible, contrastando el veredicto o la salida del agente con el resultado final del incidente, con la evidencia del portal y con el juicio del revisor. Registrar el tiempo que habría tomado producir la misma salida manualmente.

3. Calcular las métricas de la tabla 34 por agente y compararlas con la meta y con el mes anterior. El recall es aproximado por definición: se estima con los casos que el agente clasificó como falso positivo y que después resultaron amenaza (reaperturas y escalaciones), no con una verdad de referencia completa.

4. Registrar la retroalimentación en el lugar que cada agente admite: en el Phishing Triage Agent y en los agentes de Defender, mediante la opción de retroalimentación del veredicto en el incidente; en el Conditional Access Optimization Agent, aceptando o rechazando cada recomendación con comentario; en los agentes de Copilot Studio, ajustando las instrucciones de sistema, los ejemplos y los prompts que envían a Security Copilot, y anotando el cambio en la solución de Power Platform; en Security Copilot, con la calificación de cada respuesta en la sesión.

5. Revisar los casos con contenido anómalo: instrucciones embebidas en correos, URLs o nombres de archivo que intentaron desviar al agente. Cada caso se documenta como incidente de contenido no confiable y alimenta los guardrails de la sección 8.5.

6. Decidir el nivel de autonomía de cada agente con los criterios siguientes y registrar la decisión en el acta y en la tabla 30 si cambia la cadencia o el SLA de revisión.

| Métrica | Definición | Fórmula | Meta sugerida | Acción si se incumple |
|----|----|----|----|----|
| Precisión | Proporción de salidas correctas entre las muestreadas | Correctos / (correctos + incorrectos + discutibles) | Mayor o igual a [90%] en agentes de clasificación; [95%] en agentes de reporte | Revisar instrucciones y prompts; reducir alcance; bajar un nivel de autonomía |
| Recall aproximado | Proporción de amenazas reales que el agente no clasificó como falso positivo | 1 menos (reaperturas o escalaciones de casos cerrados por el agente / amenazas reales del periodo) | Mayor o igual a [95%] | Suspender el cierre autónomo; volver a human-in-the-loop |
| Tasa de reversión | Proporción de acciones o veredictos del agente revertidos por un analista | Revertidos / total de acciones o veredictos | Menor o igual a [10%] | Investigar la causa por tipo de alerta; ajustar umbrales o excluir el tipo |
| Tiempo ahorrado | Horas de analista que el agente evitó en el mes | Suma de (tiempo manual estimado menos tiempo de revisión) sobre los casos correctos | Creciente mes a mes; insumo del ROI trimestral | Si es negativo, el agente cuesta más de lo que aporta: rediseñar o retirar |
| Costo por caso | SCU consumidas por caso o ejecución | SCU del agente en el mes / ejecuciones | Dentro del presupuesto de la tabla 30 | Acotar plugins, reducir frecuencia o usar direct skill |
| Incidentes de contenido no confiable | Casos donde el contenido intentó manipular al agente | Conteo mensual y resultado (contenido, mitigado) | Cero contenidos exitosos | Reforzar guardrails; restringir herramientas |

*Tabla 34. Métricas mensuales de calidad de agentes y acciones asociadas.*

Criterios para subir de nivel de autonomía: tres meses consecutivos con precisión y recall dentro de meta, tasa de reversión por debajo de la meta, cero incidentes de contenido no confiable exitosos y un plan de reversión probado para la acción que se automatizaría. El ascenso es de un nivel a la vez y nunca alcanza N5, reservado a personas. Criterios para bajar de nivel: dos meses consecutivos fuera de meta en cualquier métrica, un incidente de contenido no confiable exitoso, un cambio de comportamiento documentado por Microsoft en una capacidad preview, o una reversión con impacto en el negocio. El descenso es inmediato y no requiere esperar la revisión mensual.


---

[← 10. Modelo operativo y roles](10-modelo-operativo.md) | [Índice](README.md) | [12. Ruta de adopción de referencia →](12-ruta-de-adopcion.md)
