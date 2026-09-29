<!-- AI-SOC Playbook v2.0 · Arturo Mandujano (Cloud Solution Architect) · 28 de septiembre de 2026 -->
[← 8. Gobierno de agentes y seguridad responsable](08-gobierno.md) | [Índice](README.md) | [10. Modelo operativo y roles →](10-modelo-operativo.md)

---

# 9. Guías operacionales (runbooks)

Los runbooks siguientes están escritos para ser adoptados como procedimiento operativo de referencia con ajustes mínimos. Cada uno define roles, entradas, pasos, criterios de decisión y criterios de cierre. Los tiempos objetivo son sugeridos y deben calibrarse contra la línea base medida con las consultas de la sección 6.

## 9.1 Runbook 1: triage de phishing reportado por el usuario

Roles: Phishing Triage Agent como ejecutor del triage inicial; analista de Tier 1 como revisor; ingeniería de detecciones como destinatario de las mejoras derivadas.

Entradas: correo reportado por un usuario mediante el botón de reporte en Outlook; alerta "Email reported by user as malware or phish"; contexto del buzón y del remitente.

Pasos:

1. El usuario reporta el mensaje. La política de alerta genera la alerta correspondiente y el agente la recoge automáticamente.

2. El agente ejecuta su análisis con análisis de contenido del correo, detonación de archivos y URLs, análisis de capturas de pantalla, inteligencia de amenazas y advanced hunting entre fuentes.

3. El agente emite un veredicto de amenaza real o falso positivo y publica su razonamiento en lenguaje natural con representación visual. Etiqueta el incidente con "Agent".

4. Si el veredicto es falso positivo, el incidente se cierra y entra al muestreo de calidad del runbook 9.5. No se requiere acción humana adicional.

5. Si el veredicto es amenaza real, el analista de Tier 1 valida el razonamiento y confirma el alcance: destinatarios adicionales del mismo mensaje, clics registrados y credenciales potencialmente comprometidas. La consulta 6.4.8 apoya este paso.

6. Se ejecuta la remediación posterior a la entrega sobre todos los mensajes del mismo grupo: eliminación, bloqueo del remitente o del dominio, e indicadores añadidos a la inteligencia de amenazas.

7. Si existe evidencia de clic con sesión posterior exitosa, se escala al runbook 9.2 sin cerrar el incidente.

8. El analista registra la retroalimentación sobre el veredicto del agente, acierte o no. Esta retroalimentación alimenta el aprendizaje del agente.

Criterios de decisión: la escalación al runbook 9.2 procede cuando existe al menos un clic seguido de autenticación exitosa dentro de los 30 minutos posteriores; la escalación a respuesta a incidentes procede cuando el mensaje contiene un adjunto que detonó con comportamiento malicioso y fue ejecutado en un endpoint.

Criterios de cierre: veredicto emitido y validado, todos los mensajes del grupo remediados, indicadores publicados, retroalimentación registrada y, si aplica, escalación abierta con número de incidente.

## 9.2 Runbook 2: investigación de compromiso de identidad y AiTM

Roles: analista de Tier 2 como responsable; Security Copilot y Sentinel graph como apoyo de investigación; administrador de identidad para las acciones de contención.

Entradas: alerta de riesgo de Entra ID Protection, escalación desde el runbook 9.1, o hallazgo de la consulta 6.4.2.

Pasos:

1. Confirmar la señal inicial: ejecutar la consulta 6.4.2 para establecer la coincidencia entre el clic en la URL y la sesión exitosa, y la consulta 6.4.1 si se sospecha una campaña de password spray asociada.

2. Solicitar a Security Copilot un resumen del usuario en riesgo. El prompt de referencia es el número 2 del anexo C.

3. Consultar Sentinel graph para reconstruir las relaciones de la identidad: dispositivos donde autenticó, aplicaciones a las que accedió, permisos efectivos y proximidad a activos críticos. La consulta 6.4.6 complementa con las rutas de exposición.

4. Determinar si existe persistencia: nuevos métodos de autenticación multifactor registrados, reglas de reenvío de buzón creadas, consentimientos de aplicación otorgados o tokens de actualización emitidos después del evento.

5. Contener: revocar sesiones, forzar restablecimiento de credenciales, eliminar los métodos de autenticación no reconocidos y revertir las reglas de buzón creadas por el atacante.

6. Evaluar el movimiento lateral con la consulta 6.4.3 sobre la cuenta afectada y sobre cualquier cuenta con la que haya autenticado.

7. Cerrar el bucle de protección: proponer el ajuste de acceso condicional correspondiente. Si el Conditional Access Optimization Agent está habilitado, revisar su recomendación y aprobarla explícitamente antes del despliegue por fases.

Criterios de decisión: se declara compromiso confirmado cuando existe autenticación exitosa desde un contexto no reconocido más al menos un indicio de persistencia; se declara intento fallido cuando no hay sesión exitosa posterior al clic.

Criterios de cierre: sesiones revocadas, credenciales restablecidas, persistencia eliminada, movimiento lateral descartado o contenido, ajuste de política propuesto y registrado, y línea de tiempo del incidente documentada.

## 9.3 Runbook 3: contención de ransomware con attack disruption

Roles: attack disruption como actuador automático; analista de Tier 2 como validador; líder de respuesta a incidentes para la decisión de escalar a crisis; propietario de la aplicación afectada como interlocutor de negocio.

Entradas: incidente multi-etapa de alta severidad; notificación de interrupción automática; hallazgos de las consultas 6.4.4 y 6.4.5.

Pasos:

1. Reconocer la interrupción. Attack disruption detecta, predice y se adapta al atacante mientras el ataque está en desarrollo, y contiene en un promedio de tres minutos (Microsoft, Coordinated Defense, 2025); el primer paso humano es confirmar qué acciones se ejecutaron y sobre qué entidades.

2. Validar el alcance de la contención: dispositivos aislados, cuentas deshabilitadas o con sesión revocada, y procesos detenidos.

3. Ejecutar la consulta 6.4.4 para confirmar si hubo destrucción de copias sombra o de respaldos, y la consulta 6.4.5 para medir la concentración de detecciones por dispositivo.

4. Determinar el punto de entrada y la ruta recorrida. La consulta 6.4.3 sobre las cuentas implicadas y la 6.4.6 sobre los activos críticos alcanzados establecen el perímetro real del incidente.

5. Evaluar el impacto en el negocio con el propietario de la aplicación: disponibilidad de los sistemas contenidos y necesidad de restauración desde respaldo.

6. Decidir sobre la reversión de la contención. La reversión procede únicamente cuando se ha confirmado la erradicación en el dispositivo o la cuenta, nunca por presión de disponibilidad sin esa confirmación.

7. Erradicar y endurecer: aplicar parches sobre las vulnerabilidades explotadas, reducir la superficie de dispositivos no administrados —el 92% de los ataques de cifrado remoto exitosos explota vulnerabilidades en dispositivos no administrados (Microsoft Digital Defense Report, 2024)— y ajustar las políticas de reducción de superficie de ataque.

8. Documentar la lección aprendida y convertirla en protección previa a la brecha: nueva detección, nuevo control de exposición o nueva regla de reducción de superficie.

Criterios de decisión: se escala a crisis cuando el cifrado afectó un sistema clasificado como crítico para el negocio o cuando la contención no logró detener la propagación en 30 minutos.

Criterios de cierre: propagación detenida, erradicación confirmada, servicios restaurados, causa raíz identificada, endurecimiento aplicado y lección convertida en control.

## 9.4 Runbook 4: cacería proactiva mensual

Roles: threat hunter como responsable; Threat Hunting Agent y Sentinel MCP server como apoyo; ingeniería de detecciones como destinatario de los hallazgos.

Entradas: briefing mensual del Threat Intelligence Briefing Agent; hipótesis de cacería priorizadas; matriz de cobertura de la consulta 6.4.7.

Pasos:

1. Partir del briefing de inteligencia de amenazas, que se genera en minutos con actividad de actores de amenaza e información de vulnerabilidades internas y externas, y seleccionar entre tres y cinco hipótesis relevantes para el perfil de amenazas de la organización.

2. Formular cada hipótesis como una pregunta en lenguaje natural y entregarla al Threat Hunting Agent, que genera y ejecuta KQL en advanced hunting y devuelve gráficos, preguntas de seguimiento dinámicas y recomendaciones de remediación.

3. Para la exploración amplia sobre el data lake, utilizar las colecciones de exploración de datos y de cacería del Sentinel MCP server, que permiten consultar sin conocer el esquema ni escribir KQL.

4. Revisar y ajustar manualmente el KQL generado antes de convertirlo en un artefacto permanente. El código generado es un punto de partida, no una detección lista para producción.

5. Clasificar cada hallazgo: actividad maliciosa, actividad sospechosa que requiere seguimiento, higiene de configuración o falso positivo de la hipótesis.

6. Convertir los hallazgos con valor en artefactos: una regla analítica nueva, una consulta guardada de cacería o una recomendación de exposición.

7. Actualizar la matriz de cobertura MITRE ATT&CK con la consulta 6.4.7 y registrar qué técnicas quedaron cubiertas con la iteración.

Criterios de decisión: una hipótesis se abandona cuando dos iteraciones de consulta no producen evidencia y el costo de profundizar excede el valor esperado; se escala a incidente en cuanto aparece evidencia de actividad maliciosa activa.

Criterios de cierre: todas las hipótesis resueltas o formalmente abandonadas, hallazgos convertidos en artefactos, matriz de cobertura actualizada y resumen entregado al comité mensual.

## 9.5 Runbook corto: revisión de la calidad del agente

Roles: líder de Tier 1 como responsable del muestreo; ingeniería de agentes como responsable del ajuste.

Entradas: incidentes etiquetados con "Agent" en la semana; resultados de la consulta 6.2.2; retroalimentación registrada por los analistas.

Pasos:

1. Seleccionar una muestra aleatoria de al menos el [10%] de los veredictos emitidos por el agente en la semana, con un mínimo de [20] casos, cubriendo tanto veredictos de amenaza real como de falso positivo.

2. Revisar el razonamiento expuesto por el agente en cada caso muestreado y clasificar el veredicto como correcto, incorrecto o discutible.

3. Registrar la retroalimentación correspondiente en la herramienta para cada caso incorrecto o discutible; el agente aprende de esa retroalimentación.

4. Calcular la tasa de reclasificación de la semana y compararla contra la meta de la sección 11.

5. Revisar específicamente los casos con contenido anómalo, como instrucciones embebidas en el cuerpo del mensaje, conforme al control de la sección 8.5.

6. Si la tasa de reclasificación supera la meta durante dos semanas consecutivas, escalar a ingeniería de agentes para revisar alcance, parámetros y fuentes disponibles del agente.

Criterios de cierre: muestra completada, retroalimentación registrada, tasa calculada y publicada en el reporte semanal, y acciones de ajuste asignadas cuando corresponda.


---

[← 8. Gobierno de agentes y seguridad responsable](08-gobierno.md) | [Índice](README.md) | [10. Modelo operativo y roles →](10-modelo-operativo.md)
