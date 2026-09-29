<!-- AI-SOC Playbook v2.0 · Arturo Mandujano (Cloud Solution Architect) · 28 de septiembre de 2026 -->
[← 1. Introducción y alcance](01-introduccion.md) | [Índice](README.md) | [3. Visión objetivo: el modelo ISOC / AI-SOC →](03-vision-isoc.md)

---

# 2. Contexto: el cambio a la era agéntica y por qué el SOC tradicional no escala

## 2.1 El atacante ya opera con agentes

El punto de partida del análisis no es una proyección: es una observación. Los atacantes emplean agentes para automatizar la ejecución de campañas a una escala sin precedentes, de forma que operaciones que antes exigían equipos completos hoy pueden sostenerse con un solo operador apoyado en un marco de agentes (Microsoft Source LATAM, septiembre 2026). La consecuencia directa es una asimetría de velocidad: el adversario itera a velocidad de máquina y el defensor responde a velocidad de proceso.

Los datos de telemetría confirman la magnitud del volumen que esa automatización produce. En el último año se detectaron 775 millones de correos con malware; el 99% de los ataques de identidad diarios siguen siendo basados en contraseña; los ataques de phishing de tipo adversary-in-the-middle crecieron 46%; el 92% de los ataques de cifrado remoto exitosos explotó vulnerabilidades en dispositivos no administrados; el 22% de las organizaciones tenía una ruta de ataque identificada en la nube; y entre enero y junio de 2024 se expusieron 1.5 millones de credenciales en repositorios (Microsoft Digital Defense Report, 2024).

## 2.2 Por qué la arquitectura heredada es el cuello de botella

La seguridad no puede operar a velocidad de inteligencia artificial cuando la protección y las operaciones se construyen como sistemas separados (Microsoft Source LATAM, septiembre 2026). En el SOC tradicional, el endpoint protege, el SIEM correlaciona, el equipo de identidad investiga y el de nube remedia, y entre cada uno de esos planos existe un traspaso. Cada traspaso introduce latencia, pérdida de contexto y una decisión humana que podría haberse resuelto con información que el sistema ya poseía en otro lugar.

Ese diseño impone tres costos concretos sobre cualquier equipo de SOC. El primero es de ruido: casi un tercio de las investigaciones termina en un no-evento (IBM Global SOC Study, marzo 2023), y ese esfuerzo no genera aprendizaje reutilizable. El segundo es de cobertura: el inventario de activos crece más rápido que la capacidad de instrumentarlo, con un incremento de 133% interanual en activos cibernéticos (Microsoft Digital Defense Report, 2024). El tercero es de recurrencia: el 83% de las organizaciones enfrenta brechas repetidas (Microsoft Digital Defense Report, 2024), lo que indica que el aprendizaje derivado de un incidente rara vez se convierte en protección preventiva.

## 2.3 El error de añadir agentes sobre una base fragmentada

La tentación natural es incorporar agentes de inteligencia artificial sobre la arquitectura existente. El problema es que los agentes heredan la complejidad del entorno sobre el que se despliegan: si el contexto está repartido entre siete consolas y tres modelos de datos, el agente tendrá que resolver los mismos traspasos que hoy resuelve el analista, con menos criterio y más velocidad. Por eso esta guía no inicia por los agentes, sino por la base compartida de datos y de contexto sobre la cual los agentes se vuelven confiables.

En julio de 2026 Microsoft introdujo la pila cibernética de extremo a extremo junto con Project Perception, un conjunto de modelos, arnés y agentes especializados para percibir, razonar y actuar a velocidad de máquina (Microsoft Source LATAM, septiembre 2026). El ISOC en Microsoft Defender, disponible hoy en versión preliminar, es la materialización de ese trabajo en el producto. La tesis que ordena toda esta guía la formuló Rob Lefferts, vicepresidente de Microsoft Threat Protection: "El próximo SOC no se definirá por cuántas características de IA tiene, sino por si las personas y agentes pueden percibir, razonar y actuar en un entorno como un solo sistema" (Microsoft Source LATAM, septiembre 2026).


---

[← 1. Introducción y alcance](01-introduccion.md) | [Índice](README.md) | [3. Visión objetivo: el modelo ISOC / AI-SOC →](03-vision-isoc.md)
