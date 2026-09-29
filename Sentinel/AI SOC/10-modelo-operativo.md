<!-- AI-SOC Playbook v2.0 · Arturo Mandujano (Cloud Solution Architect) · 28 de septiembre de 2026 -->
[← 9. Guías operacionales (runbooks)](09-runbooks.md) | [Índice](README.md) | [11. Reportes, KPIs y guía operativa de cadencias →](11-reportes-kpis-cadencias.md)

---

# 10. Modelo operativo y roles

## 10.1 Cómo cambia la estructura del SOC

El AI-SOC no elimina funciones: redistribuye capacidad. El trabajo repetitivo de primer nivel —clasificar, enriquecer, recolectar evidencia— se traslada a agentes supervisados, y la capacidad humana liberada se reinvierte en funciones que hoy están subdotadas en la mayoría de los SOC: ingeniería de detecciones, cacería y ahora ingeniería de agentes. El sentido económico de esa redistribución es directo cuando se considera que el 32% de los incidentes investigados resulta no ser una amenaza (IBM Global SOC Study, marzo 2023).

| Función | Antes | En el AI-SOC | Cambio principal |
|----|----|----|----|
| Tier 1 | Clasificación manual de todas las alertas; principal consumidor de horas | Equipo reducido dedicado a validar veredictos de agentes, atender excepciones y registrar retroalimentación | De ejecutar el triage a supervisar el triage |
| Tier 2 / investigación | Investigación manual con reconstrucción de contexto entre consolas | Investigación asistida por Security Copilot y Sentinel graph, con el contexto ya reconstruido | Menos recolección, más análisis y decisión |
| Ingeniería de detecciones | Función frecuentemente compartida y sin tiempo dedicado | Función dedicada que convierte hallazgos de cacería y retroalimentación en detecciones | Se vuelve el destino natural de la capacidad liberada |
| Threat hunting | Esporádico y dependiente de disponibilidad | Cadencia mensual formal con agente y MCP server (runbook 9.4) | De actividad excepcional a proceso |
| Ingeniería de agentes y automatización | Inexistente o limitada a playbooks de SOAR | Función nueva: diseña, publica, parametriza y mide agentes; gobierna el consumo de SCU | Rol nuevo del modelo operativo |
| Threat intelligence | Consumo de fuentes externas con poca contextualización interna | Briefings generados en minutos y enfocados en las amenazas relevantes para el entorno | De recopilar a priorizar |

*Tabla 26. Evolución de las funciones del SOC.*

## 10.2 RACI de referencia

| Actividad | Tier 1 | Tier 2 / IR | Ing. detecciones | Ing. agentes | Threat intel | CISO |
|----|----|----|----|----|----|----|
| Triage de phishing reportado | R | C | I | C | I | I |
| Validación de veredictos del agente | R | C | I | A | I | I |
| Investigación de compromiso de identidad | C | R | I | I | C | I |
| Contención de ransomware | I | R | C | I | C | A |
| Cacería proactiva mensual | I | C | C | C | R | I |
| Diseño y publicación de agentes | I | C | C | R | I | A |
| Gobierno de identidades agénticas | I | I | I | R | I | A |
| Control de consumo de SCU | I | I | I | R | I | A |
| Reporte ejecutivo trimestral | I | C | C | C | C | A |

*Tabla 27. RACI de referencia, adaptable a la estructura de cada organización. R: responsable de ejecutar; A: aprueba; C: consultado; I: informado.*

## 10.3 Cómo cambia el trabajo del analista

El cambio más relevante no es de herramienta sino de pregunta. El analista deja de preguntarse qué ocurrió —porque el contexto ya está reconstruido— y empieza a preguntarse si la conclusión del sistema es correcta y qué debe cambiar para que el evento no se repita. La evidencia disponible indica que ese cambio libera 2.7 horas por día y mejora la precisión de las decisiones en 35% (Microsoft, noviembre 2024).

Para que esa transición ocurra hacen falta dos condiciones explícitas. La primera es formación: el analista debe saber interpretar y cuestionar el razonamiento de un agente, no solo aceptarlo. La segunda es tiempo protegido: si la capacidad liberada se reabsorbe en más tickets, el modelo operativo no cambia y el beneficio se pierde.


---

[← 9. Guías operacionales (runbooks)](09-runbooks.md) | [Índice](README.md) | [11. Reportes, KPIs y guía operativa de cadencias →](11-reportes-kpis-cadencias.md)
