# Diagramas de la arquitectura (figuras 1 a 3)

Diagramas ASCII tomados de la guía AI-SOC Playbook. Se conservan en texto para que puedan versionarse y comentarse en pull requests.

## Figura 1. Bucle de protección integrado del modelo ISOC (sección 3.3)

Las tres capas del modelo —señales y sensores, contexto y actuadores— y el bucle que convierte lo aprendido en protección previa a la brecha.

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

## Figura 2. Flujo de datos y consumo multi-motor sobre una sola copia del dato (sección 4.2)

La telemetría entra una vez, se normaliza una vez y se consume desde tantos motores como haga falta (analytics tier, data lake tier, graph y MCP server).

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

## Figura 3. Arquitectura de integración por capas de los agentes de Copilot Studio (sección 5.4)

Copilot Studio orquesta y conversa, el conector delega el razonamiento a Security Copilot, el MCP server (preview) aporta datos y veredictos sobre el data lake, y una capa final de escritura controlada publica el resultado.

```text
CANAL
    Microsoft Teams  |  Microsoft 365 Copilot  |  Power Apps
        |
        v
ORQUESTACION
    Microsoft Copilot Studio: orquestacion generativa, instrucciones de sistema, temas, flujos de agente, guardrails
        |
        v
RAZONAMIENTO
    [A] Conector Security Copilot (Submit prompt / Fetch status)  ->  Microsoft Security Copilot
        planner + plugins: Defender XDR, Sentinel, Entra, Intune, Threat Intelligence, DVM, EASM
    [B] Sentinel MCP server (preview): search_tables, query_lake, analyze_user_entity,
        analyze_url_entity, herramientas de grafo
    [C] Conectores Power Platform: Sentinel, Teams, Outlook, Approvals, Jira / ServiceNow
        |
        v
DATOS
    Sentinel data lake  |  analytics tier  |  Sentinel graph  |  Defender XDR
        |
        v
ESCRITURA CONTROLADA
    Comentario en incidente (aprobado)  |  Ticket  |  Mensaje en Teams
    identidad de escritura separada, patron draft-first, registro en auditoria
```

Véase el texto completo en [3. Visión objetivo](../03-vision-isoc.md), [4. Arquitectura de referencia](../04-arquitectura.md) y [5.4 Arquitectura de integración](../05-agentes.md).


> Versión gráfica (PNG y Mermaid) del diseño de agentes: [diseno-de-agentes.md](diseno-de-agentes.md).
