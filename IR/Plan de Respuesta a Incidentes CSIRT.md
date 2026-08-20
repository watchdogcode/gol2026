# Plan de Respuesta a Incidentes (CSIRT) — Proyecto GOL

> Pilar **IR/** del marco SecOps GOL para Microsoft Defender XDR.
> Repositorio: `gol2026/IR/` · Versión: 1.0 · Estado: Aprobado para operación
> Última actualización: `[YYYY-MM-DD]` · Propietario: `[Nombre del IC]`

---

## 1. Propósito y alcance

El Proyecto GOL es un marco de operaciones de seguridad (SecOps) construido sobre **Microsoft Defender XDR** cuyo objetivo es **cerrar la brecha entre el equipo técnico y el CISO**, convirtiendo telemetría compleja en información accionable. Este documento formaliza el pilar **IR/ (Respuesta a Incidentes)**, que completa el ciclo de vida operativo: mientras los pilares existentes (MDO, MDE, MDI, Entra ID, MDA y XDR) cubren con solidez la **Preparación** y la **Detección/Análisis**, el pilar IR estandariza la **Contención → Erradicación → Recuperación → Post-incidente**.

**Alcance.** Aplica a todo incidente de seguridad detectado, reportado o sospechado que afecte a los activos cubiertos por Defender XDR: correo (MDO), endpoints (MDE), identidad on-premise (MDI), identidad en la nube (Entra ID) y aplicaciones/SaaS (MDA). Cubre personas (CSIRT), procesos (ciclo de vida NIST) y tecnología (herramientas y automatización de Microsoft).

**Fuera de alcance.** Incidentes de continuidad de negocio no relacionados con ciberseguridad, gestión de vulnerabilidades rutinaria (cubierta por otros pilares) y respuesta física.

**Principio rector.** Cada acción de respuesta debe producir un artefacto accionable y trazable — apto para el analista T1 en la trinchera y para el reporte ejecutivo del CISO.

---

## 2. Marco de referencia y mapeo de fases

El pilar IR adopta **NIST SP 800-61** como columna vertebral metodológica y lo alinea con el **proceso de respuesta a incidentes de Microsoft** (Detect → Investigate → Contain/Eradicate → Recover → Learn), operacionalizado dentro de Defender XDR.

| Fase NIST SP 800-61 | Proceso Microsoft | Estado del incidente GOL |
|---|---|---|
| Preparación | Prepare / Baselines | (transversal) |
| Detección y Análisis | Detect + Investigate | Nuevo → Triage → Investigación/Análisis |
| Contención, Erradicación y Recuperación | Contain + Eradicate + Recover | Contención → Erradicación → Recuperación |
| Actividad Post-Incidente | Post-incident / Learn | Cierre → Post-Incident Review |

El mapeo permite que un mismo incidente se rija por un vocabulario común independientemente de la herramienta que lo detecte, y que las métricas (MTTA/MTTC/MTTR) se midan de forma homogénea entre pilares.

---

## 3. Definiciones

- **Evento:** cualquier ocurrencia observable en un sistema o red (p. ej., un inicio de sesión, un correo entregado). No implica impacto.
- **Alerta:** evento (o correlación de eventos) que una detección de Defender XDR marca como potencialmente malicioso y que requiere valoración.
- **Incidente:** una o más alertas correlacionadas que representan una violación real o inminente de las políticas de seguridad y que exige respuesta coordinada del CSIRT.
- **Brecha (data breach):** incidente confirmado con **acceso, exfiltración o divulgación no autorizada** de datos protegidos; activa obligaciones legales/regulatorias y la participación de Legal/RH.

---

## 4. Roles y responsabilidades del CSIRT

- **Incident Commander (IC):** dirige el incidente extremo a extremo, decide la severidad, autoriza acciones de contención de alto impacto y es el punto único de decisión.
- **Analista SOC T1:** monitorea la cola, ejecuta el triage inicial, acusa (MTTA) y escala.
- **Analista SOC T2:** investigación profunda, Advanced Hunting, valida alcance y ejecuta contención guiada.
- **Threat Hunter:** caza proactiva, determina el alcance completo (blast radius), identifica IOCs/TTPs y persistencia.
- **Enlace CISO / Comunicaciones:** traduce el estado técnico a lenguaje ejecutivo, gestiona comunicación interna/externa.
- **Owner del sistema/negocio:** aporta contexto del activo, autoriza ventanas de intervención y valida la recuperación.
- **Legal / RH:** interviene ante brecha de datos, implicación de personal o requerimientos regulatorios.

### Matriz RACI por fase del ciclo

| Fase | IC | SOC T1 | SOC T2 | Threat Hunter | Enlace CISO | Owner sistema | Legal/RH |
|---|---|---|---|---|---|---|---|
| Preparación | A | R | R | C | C | C | I |
| Detección y Análisis | A | R | R | C | I | I | I |
| Contención | A/R | C | R | C | I | C | I |
| Erradicación | A | I | R | R | I | C | I |
| Recuperación | A | I | R | C | I | R | I |
| Post-Incidente | R | C | C | C | A | C | C |

*R = Responsable · A = Aprobador · C = Consultado · I = Informado.*

---

## 5. Clasificación de severidad y SLAs

La severidad determina los tiempos objetivo (SLA) y el nivel de escalamiento. Es la **fuente única de verdad** para todo el pilar IR.

| Severidad | Ejemplos representativos | MTTA (acuse) | MTTC (contención) | MTTR (resolución) |
|---|---|---|---|---|
| **Crítico** | Ransomware activo, exfiltración de datos, compromiso de identidad privilegiada | ≤ 15 min | ≤ 1 h | ≤ 8 h |
| **Alto** | Compromiso confirmado de usuario/endpoint, BEC, clic en phishing | ≤ 30 min | ≤ 4 h | ≤ 24 h |
| **Medio** | Actividad sospechosa contenida, malware remediado por AIR | ≤ 2 h | ≤ 8 h | ≤ 72 h |
| **Bajo** | Bajo impacto, falsos positivos por validar | ≤ 8 h | ≤ 24 h | ≤ 5 días |

La severidad inicial la propone el analista T1 y la confirma el IC; puede reclasificarse conforme evoluciona la investigación (documentando la justificación).

---

## 6. Ciclo de vida del incidente

### 6.1 Preparación

Se apoya en los pilares GOL ya operativos. Antes de cualquier incidente deben estar vigentes:

- **Líneas base y políticas** por pilar (MDO/MDE/MDI/Entra/MDA), revisadas en las guías operativas diaria/semanal/mensual.
- **Paquetes KQL Advanced Hunting** por pilar, versionados en el repositorio.
- **Scripts PowerShell 7+** de respuesta (aislamiento, revocación de sesiones, bloqueo de remitentes), con **autenticación por certificado (client credentials)** contra Microsoft Graph API y M365 Defender API.
- Roles CSIRT asignados, cadena de escalamiento probada y accesos verificados.

### 6.2 Detección y Análisis

- **Cola de incidentes de Defender XDR** como fuente primaria de trabajo: <https://security.microsoft.com/incidents> y alertas en <https://security.microsoft.com/alerts>.
- **Triage T1:** acuse (marca MTTA), verificación de severidad, descarte de falsos positivos evidentes y asignación.
- **Advanced Hunting:** investigación con KQL en <https://security.microsoft.com/v2/advanced-hunting>, usando los **Paquetes KQL** del pilar afectado para determinar alcance, IOCs y cronología.
- **Correlación cross-domain (XDR):** aprovechar la unión automática de alertas de Defender para reconstruir la historia del ataque de extremo a extremo.
- Salida de la fase: severidad confirmada, alcance preliminar, hipótesis de causa raíz y decisión de contención.

### 6.3 Contención, Erradicación y Recuperación

**Contención**
- **Automated Investigation & Response (AIR):** contención automática de amenazas de rutina.
- **Attack Disruption:** interrupción automática de ataques de alta confianza (deshabilita cuentas, aísla dispositivos) para detener ransomware/BEC en curso.
- **Acciones manuales asistidas:** aislar endpoint (MDE), suspender/forzar revocación de sesiones de usuario (Entra ID), bloquear remitente/URL (MDO), revocar consentimientos OAuth (MDA).
- Distinguir **contención a corto plazo** (detener el sangrado) de **contención a largo plazo** (parches temporales, segmentación).

**Erradicación**
- Eliminar persistencia: malware, reglas de reenvío maliciosas, tokens/consentimientos, cuentas creadas por el atacante.
- Validar remediaciones en el **Action Center** (<https://security.microsoft.com/action-center>).

**Recuperación**
- Restaurar sistemas a estado de confianza, reactivar cuentas con credenciales nuevas y MFA, monitoreo reforzado post-restauración.
- El **Owner del sistema/negocio** valida la vuelta a operación normal.

**Automatización.** Para respuesta orquestada y a escala se emplean **playbooks de Microsoft Sentinel / Logic Apps** (enriquecimiento, notificación, tickets, contención condicionada), reservando la aprobación humana del IC para acciones de alto impacto.

### 6.4 Post-incidente

- **Revisión (Post-Incident Review)** dentro de los `[X]` días hábiles del cierre.
- **Lecciones aprendidas:** causa raíz, tiempos reales vs. SLA, qué funcionó y qué falló.
- **Ajuste de detecciones:** afinar reglas, actualizar los Paquetes KQL y líneas base de los pilares afectados, crear/depurar playbooks.
- Registro de acciones de mejora con responsable y fecha.

---

## 7. Flujo de escalamiento y matriz de comunicación

**Escalamiento por severidad**
- **Crítico:** T1 → IC (inmediato) → Enlace CISO → CISO; activar Legal/RH si hay brecha.
- **Alto:** T1 → T2 → IC; notificar al Enlace CISO.
- **Medio:** T1 → T2; IC informado.
- **Bajo:** gestionado por T1; resumido en el reporte diario.

**Matriz de comunicación**

| Audiencia | Canal | Cuándo | Responsable |
|---|---|---|---|
| CSIRT (operación) | Teams `[canal-csirt]` | Continuo durante el incidente | IC |
| CISO / Dirección | Correo + reunión | Crítico/Alto: al confirmar | Enlace CISO |
| Owner del sistema | Teams / llamada | Antes de contener/recuperar | IC |
| Legal / RH | Canal confidencial | Ante brecha de datos | Enlace CISO |
| Usuarios afectados | Correo `[plantilla]` | Tras aprobación del IC | Enlace CISO |

**Plantilla breve de notificación al CISO**

```
Asunto: [SEV: Crítico/Alto] Incidente [ID] — [título breve]

- Qué ocurrió: [descripción en 1-2 líneas, no técnica]
- Severidad y estado: [Crítico/Alto] · [Contención/Investigación...]
- Impacto: [usuarios/sistemas/datos afectados; brecha sí/no]
- Acciones en curso: [contención aplicada / próximos pasos]
- Necesito de usted: [decisión / recurso / ninguna acción por ahora]
- Próxima actualización: [hora]
IC: [Nombre del IC] · Contacto: [correo-soc@empresa]
```

---

## 8. Manejo de evidencia y cadena de custodia

- **Preservar antes de erradicar:** capturar evidencia (línea de tiempo de Advanced Hunting, resultados KQL, artefactos del Action Center, logs de Entra/MDE) antes de acciones destructivas.
- **Integridad:** exportar con marca de tiempo, calcular hash (p. ej. SHA-256) y almacenar en repositorio de solo lectura con acceso restringido.
- **Registro de custodia:** documentar quién recolectó, qué, cuándo, dónde se almacena y cada transferencia.
- **Confidencialidad:** evidencia con datos personales o de brecha se maneja bajo dirección de Legal/RH.
- **Retención:** conforme a la política `[política de retención]` y requisitos regulatorios aplicables.

---

## 9. Métricas, KPIs e informes

Se miden y publican de forma consistente:

- **MTTA** — tiempo medio de acuse (Nuevo → Triage).
- **MTTC** — tiempo medio de contención (Triage → Contención).
- **MTTR** — tiempo medio de resolución (Nuevo → Cierre).
- **% de cumplimiento de SLA** — por severidad, contra la matriz de la sección 5.

Complementarios: nº de incidentes por pilar, tasa de falsos positivos, % de contención automatizada (AIR/Attack Disruption) y tiempo de detección.

**Publicación.** Los KPIs se difunden en el **reporte diario HTML** del proyecto (visión operativa) y en el **Workbook de Microsoft Sentinel** de GOL (visión de tendencia y ejecutiva), materializando el objetivo técnico ↔ CISO.

---

## 10. Integración con los pilares GOL y los playbooks

Cada pilar aporta telemetría, detecciones y su **Paquete KQL Advanced Hunting** a la respuesta:

| Pilar | Aporta a la respuesta | Paquete KQL |
|---|---|---|
| **MDO** (Office 365) | Phishing, BEC, URLs/adjuntos maliciosos, reglas de reenvío | Hunting de correo/URL/entrega |
| **MDE** (Endpoint) | Detección de malware/ransomware, aislamiento, procesos | Hunting de dispositivo/proceso |
| **MDI** (Identity) | Movimiento lateral, ataques a AD on-premise | Hunting de identidad on-prem |
| **Entra ID** | Inicios de sesión de riesgo, MFA, sesiones, consentimientos | Hunting de sign-in/riesgo |
| **MDA** (Cloud Apps) | OAuth malicioso, Shadow IT, exfiltración SaaS | Hunting de apps/OAuth |
| **XDR** | Correlación cross-domain e historia del ataque | Reportes cross-domain |

**Mapeo a los 4 playbooks operativos**

1. **Phishing / BEC** — MDO + Entra ID (contención de correo, revocación de sesión).
2. **Ransomware / Endpoint** — MDE + MDI (aislamiento, Attack Disruption).
3. **Compromiso de Identidad** — Entra ID + MDI (deshabilitar cuenta, reset, revocar tokens).
4. **OAuth / Shadow IT** — MDA + Entra ID (revocar consentimientos, bloquear app).

Cada playbook hereda severidad, SLAs, roles y estados de este pilar IR, garantizando coherencia operativa.

---

## 11. Anexos

### Anexo A — Matriz de severidad (referencia rápida)

| Severidad | MTTA | MTTC | MTTR |
|---|---|---|---|
| Crítico | ≤ 15 min | ≤ 1 h | ≤ 8 h |
| Alto | ≤ 30 min | ≤ 4 h | ≤ 24 h |
| Medio | ≤ 2 h | ≤ 8 h | ≤ 72 h |
| Bajo | ≤ 8 h | ≤ 24 h | ≤ 5 días |

### Anexo B — Lista de contactos (a completar por el equipo)

| Rol | Nombre | Correo | Teléfono | Respaldo |
|---|---|---|---|---|
| Incident Commander | `[Nombre del IC]` | `[correo-ic@empresa]` | `[ ]` | `[ ]` |
| SOC T1 (guardia) | `[ ]` | `[correo-soc@empresa]` | `[ ]` | `[ ]` |
| SOC T2 | `[ ]` | `[ ]` | `[ ]` | `[ ]` |
| Threat Hunter | `[ ]` | `[ ]` | `[ ]` | `[ ]` |
| Enlace CISO / Comms | `[ ]` | `[ ]` | `[ ]` | `[ ]` |
| Owner de sistema | `[ ]` | `[ ]` | `[ ]` | `[ ]` |
| Legal / RH | `[ ]` | `[ ]` | `[ ]` | `[ ]` |

### Anexo C — Referencias

- NIST SP 800-61 — *Computer Security Incident Handling Guide*.
- Microsoft Defender XDR — Respuesta a incidentes.
- Cola de incidentes: <https://security.microsoft.com/incidents>
- Alertas: <https://security.microsoft.com/alerts>
- Advanced Hunting: <https://security.microsoft.com/v2/advanced-hunting>
- Action Center: <https://security.microsoft.com/action-center>
- Repositorio del proyecto: <https://github.com/watchdogcode/gol2026>
