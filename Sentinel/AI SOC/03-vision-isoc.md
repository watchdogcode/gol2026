<!-- AI-SOC Playbook v2.0 · Arturo Mandujano (Cloud Solution Architect) · 28 de septiembre de 2026 -->
[← 2. Contexto: el cambio a la era agéntica](02-contexto.md) | [Índice](README.md) | [4. Arquitectura de referencia →](04-arquitectura.md)

---

# 3. Visión objetivo: el modelo ISOC / AI-SOC

## 3.1 Definición

ISOC significa Centro Integrado de Operaciones de Seguridad. Su definición operativa es precisa: reúne el SIEM y la protección contra amenazas sobre una base compartida, para que tanto las personas como los agentes puedan ver, entender y actuar sobre todo el entorno (Microsoft Source LATAM, septiembre 2026). No es un producto adicional ni una consola nueva; es la eliminación de las fronteras que hoy obligan a reconstruir el contexto en cada paso de una investigación.

## 3.2 Las tres capas del modelo: señales, contexto y actuadores

El modelo ISOC se describe en tres capas funcionales. Las señales y los sensores constituyen la conciencia del sistema: es la telemetría cruda que se recolecta de endpoints, identidades, correo, aplicaciones en la nube, cargas de trabajo y datos. El contexto convierte esas señales en comprensión: correlaciona entidades, reconstruye relaciones y determina qué significa una señal dentro del entorno específico de la organización. Los actuadores convierten la percepción en acción protectora: aíslan un dispositivo, deshabilitan una cuenta, revocan una sesión o bloquean un remitente (Microsoft Source LATAM, septiembre 2026).

La utilidad de esta descomposición es práctica. Permite evaluar cualquier brecha del SOC actual preguntando en qué capa está el problema: si falta señal, si la señal existe pero no se convierte en contexto, o si el contexto existe pero no llega a un actuador capaz de ejecutar la respuesta. En la sección 7 se traduce esa pregunta a una lista de verificación de readiness.

## 3.3 El bucle de protección integrado

El elemento que distingue al ISOC de un SOC bien integrado es el bucle de protección integrado. Su efecto es romper los flujos lineales: en lugar de que una investigación termine en un ticket cerrado, lo que los defensores aprenden se convierte continuamente en protección previa a la brecha más fuerte (Microsoft Source LATAM, septiembre 2026).

Attack Disruption es la expresión más visible de ese bucle. No se limita a detectar: predice y se adapta al atacante mientras el ataque está en desarrollo, y utiliza información de exposición para reforzar la protección casi en tiempo real, con la inteligencia de amenazas enfocando el bucle en las amenazas que más importan (Microsoft Source LATAM, septiembre 2026). En términos medibles, attack disruption detiene ataques de ransomware en un promedio de tres minutos (Microsoft, Coordinated Defense, 2025).

Representado como flujo, el bucle opera así:

```text
  señales y sensores            contexto                 actuadores
  ------------------   ->   -----------------   ->   ----------------
  endpoints                 correlación             aislar dispositivo
  identidades               graph de entidades      revocar sesión
  correo                    rutas de ataque         bloquear remitente
  apps en la nube           exposición              contener cuenta
  cargas de trabajo         threat intelligence     aplicar política
  datos                     razonamiento agéntico   disrupción de ataque
         ^                                                    |
         |                                                    v
         +----  aprendizaje convertido en protección  <-------+
                previa a la brecha (bucle integrado)
```

*Figura 1. Bucle de protección integrado del modelo ISOC.*

## 3.4 La arquitectura de siete capas del SOC unificado

El eBook Coordinated Defense: Building an AI-powered, unified SOC (Microsoft, 2025) describe la misma visión con un nivel de detalle mayor, en siete capas que van del dato crudo a la operación humana. Esta es la estructura que esta guía adopta como referencia de diseño.

| # | Capa | Contenido | Implicación de diseño |
|----|----|----|----|
| 1 | Datos crudos e información | Más de 350 conectores preconfigurados, señales nativas de la plataforma Microsoft y cualquier otra fuente | Priorizar conectores nativos; toda fuente adicional debe justificar su costo de ingesta |
| 2 | Capa de datos unificada | Modelo de datos de seguridad; representaciones graph, tabular y vectorial; data lake; zonas raw, normalize y stores | Una sola copia del dato, varios motores encima; decidir tiering analytics vs data lake |
| 3 | Analítica de seguridad a hiperescala | Inteligencia de amenazas adaptativa en tiempo real, agentes de IA y correlación avanzada de incidentes | La correlación deja de ser una regla escrita a mano y pasa a ser una propiedad de la plataforma |
| 4 | SecOps potenciado por IA | Attack disruption automática, exposure insights, incidentes priorizados, correlación de alertas, attack path modeling, automatización y orquestación curada, enriquecimiento automatizado de inteligencia de amenazas | Es la capa donde se define qué se automatiza y con qué nivel de autonomía |
| 5 | Servicios administrados | Detección y respuesta, threat hunting y respuesta a incidentes | Opción de complemento para cobertura fuera de horario o especialidades escasas |
| 6 | Experiencia unificada del analista | Asistente de IA generativa, investigación simplificada, respuesta automatizada y gestión de casos | Un solo lugar de trabajo; el agente y el analista comparten la misma superficie |
| 7 | Operaciones potenciadas por personas | El juicio, la priorización del riesgo de negocio y la decisión irreversible permanecen humanos | Define el límite de la autonomía agéntica (sección 8) |

*Tabla 2. Arquitectura de siete capas del SOC unificado (Microsoft, Coordinated Defense, 2025).*

Leída de abajo hacia arriba, la arquitectura responde a una sola pregunta: qué necesita un agente para ser confiable. Necesita datos completos (capa 1), un modelo común que los relacione (capa 2), un motor que razone sobre ellos a escala (capa 3), acciones disponibles y curadas (capa 4), una superficie compartida con el analista (capa 6) y un punto de control humano explícito (capa 7).


---

[← 2. Contexto: el cambio a la era agéntica](02-contexto.md) | [Índice](README.md) | [4. Arquitectura de referencia →](04-arquitectura.md)
