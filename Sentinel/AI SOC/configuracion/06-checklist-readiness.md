# 6. Lista de verificación de readiness (Fase 0)

Configuración: [1. Prerequisitos y licenciamiento](01-prerequisitos-y-licenciamiento.md) · [2. Roles e identidades](02-roles-e-identidades.md) · [3. Conector Security Copilot](03-conector-security-copilot-copilot-studio.md) · [4. Sentinel MCP](04-sentinel-mcp-en-copilot-studio.md) · [5. Logic Apps SOAR](05-logic-apps-soar.md) · [6. Checklist](06-checklist-readiness.md)

Sección 7.7 de la guía (tabla 24). Marque cada casilla cuando el elemento esté confirmado; registre el responsable y el estado (Sí / No / Parcial). Ninguna fase de la [ruta de adopción](../12-ruta-de-adopcion.md) inicia si la anterior no cumplió sus criterios.

- [ ] **1.** Licenciamiento Microsoft 365 E5 o E7 confirmado — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **2.** Defender for Office 365 Plan 2 desplegado — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **3.** Defender for Endpoint Plan 2 desplegado en el [%] de los dispositivos — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **4.** Microsoft Entra ID P2 habilitado — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **5.** Defender for Cloud habilitado en las suscripciones en alcance — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **6.** Microsoft Purview desplegado con etiquetado de sensibilidad — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **7.** Espacio de trabajo de Sentinel consolidado — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **8.** Onboarding al Sentinel data lake completado — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **9.** Política de tiering analytics / data lake definida — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **10.** Conectores mínimos de la sección 7.5 conectados y con latido verificado — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **11.** URBAC habilitado para Defender for Office 365 — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **12.** Opción "Monitor reported messages in Outlook" activada — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **13.** Política de alerta "Email reported by user as malware or phish" encendida — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **14.** Inventario de reglas de alert tuning documentado antes del despliegue del agente — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **15.** Capacidad SCU aprovisionada o derecho por modelo de inclusión confirmado — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **16.** Roles personalizados e identidades agénticas creados con mínimo privilegio — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **17.** Azure Arc desplegado para servidores fuera de Azure — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **18.** Requisitos de residencia y retención validados con cumplimiento — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **19.** Línea base de MTTA, MTTR y tasa de falsos positivos capturada — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`
- [ ] **20.** Modelo de gobierno de agentes aprobado por el comité de seguridad — Responsable: `[Responsable]` — Estado: `Sí / No / Parcial`

## Línea base que acompaña al checklist (punto 19)

- MTTA y MTTR por severidad: [6.1.1](../06-kql.md#611-mtta-y-mttr-por-severidad)
- Tasa de falsos positivos por origen: [6.1.3](../06-kql.md#613-volumen-y-tasa-de-falsos-positivos-por-origen-de-detección)
- Costo e higiene de ingesta: [6.3.1](../06-kql.md#631-costo-e-higiene-de-ingesta-por-tabla)

## Advertencias de secuencia (sección 12)

- El inventario de reglas de alert tuning (punto 14) debe completarse **antes** de desplegar el Phishing Triage Agent, porque el despliegue las deshabilita automáticamente.
- El Dynamic Threat Detection Agent está habilitado automáticamente y es gratuito en preview, pero consumirá SCUs al alcanzar disponibilidad general: prevéalo en el presupuesto (punto 15).
