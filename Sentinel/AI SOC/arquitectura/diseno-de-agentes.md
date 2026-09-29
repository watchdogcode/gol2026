# Diseño de agentes e interacción entre capas

Este diagrama resume cómo se relacionan los agentes del AI-SOC: quién los dispara, dónde razonan, de qué datos se alimentan y por dónde escriben. Es la vista gráfica de la Figura 3 de la guía (sección 5.4) y de la tabla maestra de cadencias (sección 11.3).

![Diseño de agentes e interacción entre capas](img/arquitectura-agentes-aisoc.png)

## Lectura del diagrama

| Capa | Qué contiene | Identidad con la que opera |
|---|---|---|
| **1 · Canal y personas** | Analistas del SOC, Microsoft Teams / M365 Copilot (conversación), Power Automate (programado), Sentinel automation rules (por evento), portal Microsoft Defender | Usuario final autenticado |
| **2 · Orquestación** | Los 10 agentes de Copilot Studio (CS-1 a CS-10) con sus instrucciones de sistema, guardrails y nivel de autonomía N0–N5 | Entorno de Power Platform del SOC |
| **3 · Razonamiento y acceso a datos** | **[A]** Conector Microsoft Security Copilot (*Submit prompt* / *Fetch status*) → Security Copilot (planner + plugins). **[B]** Sentinel MCP server (preview): `search_tables`, `query_lake`, `analyze_user_entity`, `analyze_url_entity`, grafo. **[C]** Agentes nativos de Security Copilot en Defender | [A] cuenta delegada OAuth · [B] Entra ID Integrated, rol mínimo Security Reader · [C] agentic users con URBAC |
| **4 · Datos y señales** | Sentinel analytics tier, Sentinel data lake (Delta Parquet), Sentinel graph (preview), Defender XDR / Entra / Purview / Defender for Cloud | Roles del producto |
| **5 · Escritura controlada** | Comentario en incidente, ticket, mensaje en Teams, aprobaciones y auditoría; patrón *draft-first* con identidad de escritura separada | Identidad de escritura dedicada (p. ej. Microsoft Sentinel Responder) |

Las líneas discontinuas representan la supervisión humana: los analistas revisan veredictos, aprueban escrituras y retroalimentan a los agentes; ese ciclo es el que permite subir o bajar el nivel de autonomía (sección 11.7).

## Versión Mermaid (renderizada por GitHub)

```mermaid
flowchart TB
    subgraph L1["1 · Canal y personas"]
        A1[Analistas del SOC]
        A2[Microsoft Teams / M365 Copilot]
        A3[Power Automate<br/>disparadores programados]
        A4[Sentinel automation rules<br/>evento de incidente]
        A5[Portal Microsoft Defender]
    end

    subgraph L2["2 · Orquestación — Copilot Studio (N0–N5)"]
        direction LR
        CS1[CS-1 Triage en Teams]
        CS2[CS-2 Compromiso de usuario]
        CS3[CS-3 URL / dominio]
        CS4[CS-4 Exposición diaria]
        CS5[CS-5 Boletín TI semanal]
        CS6[CS-6 Traspaso de turno]
        CS7[CS-7 Generador KQL]
        CS8[CS-8 Reporte CISO]
        CS9[CS-9 Cuentas dormidas / spray]
        CS10[CS-10 Higiene de ingesta]
    end

    subgraph L3["3 · Razonamiento y acceso a datos"]
        RA["[A] Conector Security Copilot<br/>Submit prompt · Fetch status<br/>→ Security Copilot (planner + plugins)"]
        RB["[B] Sentinel MCP server (preview)<br/>search_tables · query_lake<br/>analyze_user_entity · analyze_url_entity · grafo"]
        RC["[C] Agentes nativos en Defender<br/>Phishing/Alert Triage · Dynamic Threat Detection<br/>Threat Hunting · TI Briefing · Security Analyst · CA Optimization · Purview"]
    end

    subgraph L4["4 · Datos y señales"]
        D1[Sentinel analytics tier]
        D2[Sentinel data lake<br/>Delta Parquet]
        D3[Sentinel graph<br/>preview]
        D4[Defender XDR · Entra · Purview · MDC]
    end

    subgraph L5["5 · Escritura controlada (draft-first)"]
        W1[Comentario en incidente<br/>sólo con aprobación]
        W2[Ticket<br/>Jira / ServiceNow]
        W3[Mensaje / reporte en Teams]
        W4[Aprobaciones]
        W5[Auditoría<br/>CloudAppEvents · AuditLogs · Purview]
    end

    A2 -- conversación --> CS1 & CS2 & CS3 & CS7
    A3 -- programado --> CS4 & CS5 & CS6 & CS8 & CS9 & CS10
    A4 -- por evento --> CS1
    A1 -. supervisión / feedback .-> L2
    A5 -. revisan alertas e incidentes .-> RC

    L2 -- prompts / promptbooks --> RA
    L2 -- herramientas MCP --> RB
    RA <-. MCP también desde Security Copilot .-> RB
    RC -. veredictos y alertas .-> L2

    RA -- plugins --> D1 & D4
    RB -- query_lake / search_tables --> D2
    RB -- grafo --> D3
    RC -- señales XDR --> D4

    L2 -- salida controlada N2–N3 --> W1 & W2 & W3
    W1 & W2 & W3 --> W4 --> W5
    RC -- attack disruption / contención --> D4
    W5 -. retroalimentación .-> A1
```

## Interacciones clave entre agentes

1. **Dynamic Threat Detection Agent → Alert Triage Agent → CS-1.** El primero genera alertas con origen *Security Copilot*; el segundo las tría por evento; CS-1 permite al analista pedir en Teams el resumen del incidente resultante y, con aprobación, escribir el comentario.
2. **CS-2 y CS-3 apoyan a CS-1.** Cuando el incidente involucra un usuario o una URL, CS-1 puede delegar el veredicto a `analyze_user_entity` o `analyze_url_entity`, las mismas herramientas MCP que usan CS-2 y CS-3.
3. **Threat Intelligence Briefing Agent → CS-5.** El boletín semanal parte del briefing nativo y lo correlaciona contra `ThreatIntelligenceIndicator` con `query_lake`.
4. **CS-4, CS-10 → CS-8.** El reporte CISO mensual agrega la exposición diaria, la higiene de ingesta y los KPIs de las consultas 6.1.x y 6.2.x.
5. **CS-7 → reglas analíticas → todo lo anterior.** El generador de KQL alimenta la ingeniería de detecciones cuya cobertura mide la consulta 6.4.13.
6. **CS-6** consume el estado de los incidentes abiertos y los veredictos de los agentes anteriores para el traspaso de turno tres veces al día.
