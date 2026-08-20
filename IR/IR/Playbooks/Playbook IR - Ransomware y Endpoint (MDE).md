# Playbook IR - Ransomware y Endpoint (MDE)

**Proyecto GOL 2026 — Marco SecOps Microsoft Defender XDR**
**Pilar:** Microsoft Defender for Endpoint (MDE)
**Repositorio:** `gol2026/IR/Playbooks/`

---

## 1. Escenario y alcance

Actividad de **ransomware** y compromiso de endpoint: ejecución de payload, cifrado masivo de archivos, borrado de *shadow copies*, despliegue lateral y comando y control (C2). El alcance cubre dispositivos onboarded en MDE (Windows/macOS/Linux/servidores). Incluye las fases previas al cifrado (*hands-on-keyboard*, herramientas de descubrimiento) para permitir contención temprana.

Handoffs: si el vector de entrada fue correo, coordinar con *Playbook IR - Phishing y BEC*; si hubo robo de credenciales o cuentas de servicio, coordinar con *Playbook IR - Compromiso de Identidad*.

## 2. Indicadores / disparadores

- Alertas MDE: *"Ransomware behavior detected"*, *"Suspicious sequence of exploration activities"*, *"'Ransom' malware was detected"*, *"Possible ransomware activity"*, detecciones de *behavior blocking*.
- Eliminación de copias de sombra (`vssadmin delete shadows`), desactivación de defensas, `bcdedit` para deshabilitar recuperación.
- Aumento anómalo de renombrado/escritura de archivos (extensiones cifradas); notas de rescate (`readme.txt`, `*.hta`).
- Conexiones salientes a IP/dominios C2 conocidos; uso de herramientas *dual-use* (PsExec, Cobalt Strike, Rclone).

## 3. Severidad sugerida

| Situación | Severidad | MTTA | MTTC | MTTR |
|---|---|---|---|---|
| Cifrado activo o propagación a múltiples hosts/servidores | **Crítico** | ≤15 min | ≤1 h | ≤8 h |
| Payload detonado en un host, sin propagación confirmada | **Alto** | ≤30 min | ≤4 h | ≤24 h |
| Precursor (herramientas/descubrimiento) bloqueado | **Medio** | ≤2 h | ≤8 h | ≤72 h |
| Detección aislada, contenida por *behavior blocking* | **Bajo** | ≤8 h | ≤24 h | ≤5 días |

## 4. Detección y Análisis

> **Referencia:** utilizar el **Paquete KQL Advanced Hunting — MDE** del Proyecto GOL para caza de TTPs (persistencia, ejecución, *defense evasion*). Las consultas siguientes acotan el incidente concreto.

**a) Perfil del dispositivo afectado y árbol de procesos (DeviceProcessEvents):**

```kql
DeviceProcessEvents
| where Timestamp > ago(3d)
| where DeviceName == "[nombre_dispositivo]"
| where FileName in~ ("vssadmin.exe","wbadmin.exe","bcdedit.exe","cipher.exe")
     or ProcessCommandLine has_any ("delete shadows","recoveryenabled no","/all /quiet")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| sort by Timestamp desc
```

**b) Actividad de cifrado / escritura masiva de archivos (DeviceFileEvents):**

```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where DeviceName == "[nombre_dispositivo]"
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| summarize FileCount = count(), Extensions = make_set(tostring(split(FileName,".")[-1]), 20)
        by bin(Timestamp, 5m), InitiatingProcessFileName, InitiatingProcessAccountName
| where FileCount > 200
| sort by Timestamp desc
```

**c) Conexiones C2 / exfiltración (DeviceNetworkEvents) y hosts relacionados (DeviceInfo):**

```kql
DeviceNetworkEvents
| where Timestamp > ago(3d)
| where DeviceName == "[nombre_dispositivo]"
| where RemoteUrl has_any ("[dominio_c2]") or RemoteIP in ("[ip_c2]")
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

**Análisis:** determinar paciente cero, cuenta comprometida, mecanismo de propagación (SMB/PsExec/GPO), alcance de hosts (pivotar `SHA256`/`RemoteIP` sobre `DeviceInfo`/toda la flota) y si hubo exfiltración previa al cifrado (*double extortion*).

## 5. Contención

1. **Aislar el dispositivo (Isolate machine)** — desde la página del dispositivo en Defender XDR (*Response actions > Isolate device*). Automatizable con **M365 Defender API**: `POST /api/machines/{id}/isolate` (Full isolation). Aislar en cadena todos los hosts implicados.
2. **Detener y poner en cuarentena el archivo** — *Stop and Quarantine File* desde la alerta/dispositivo o API `POST /api/machines/{id}/StopAndQuarantineFile` con el `SHA1`; propaga a todos los dispositivos con el mismo hash.
3. **Restringir la ejecución de aplicaciones** — *Restrict app execution* (solo binarios firmados por Microsoft) desde *Response actions*; API `POST /api/machines/{id}/restrictCodeExecution`.
4. **Recolectar paquete de investigación** — *Collect investigation package* (Response actions) o API `POST /api/machines/{id}/collectInvestigationPackage` para forense.
5. **Bloquear IOC** — añadir hash/IP/URL a *Indicators* (Settings > Endpoints > Indicators) con acción *Block and remediate*.
6. Deshabilitar cuentas comprometidas usadas para la propagación (coordinar con *Playbook de Identidad*).

## 6. Erradicación

- Ejecutar *Automated Investigation & Response (AIR)* y remediar artefactos; eliminar persistencia (tareas programadas, servicios, *run keys*).
- Reconstruir (*reimage*) los hosts cifrados desde imagen dorada limpia; no confiar en limpieza in-place para ransomware.
- Rotar credenciales locales y de cuentas de servicio expuestas; invalidar Kerberos tickets si aplica.

## 7. Recuperación

- Restaurar datos desde **backups inmutables/offline** verificados como no comprometidos; validar integridad.
- Levantar el aislamiento (*Release from isolation*) solo tras confirmar host limpio y monitorizado.
- Reonboarding y monitorización reforzada 72 h; validar con el Owner del sistema el retorno a producción.

## 8. Post-incidente

- **Lecciones aprendidas:** vector inicial, dwell time, eficacia del aislamiento y de backups.
- **Tuning de detecciones:** crear reglas de detección personalizadas (Advanced Hunting) para las TTPs observadas, ajustar ASR rules, *tamper protection* y política de *behavior blocking*. Actualizar el **Paquete KQL MDE** con las consultas nuevas.
- Verificar cobertura de EDR en toda la flota y estrategia 3-2-1 de backups.

## 9. Roles involucrados (RACI) y enlaces

| Actividad | IC | SOC T1/T2 | Threat Hunter | Enlace CISO/Com | Owner | Legal/RH |
|---|---|---|---|---|---|---|
| Triage y aislamiento | A | R | C | I | I | - |
| Investigación KQL / forense | I | C | R | I | C | - |
| Contención (isolate/quarantine) | A | R | C | I | C | - |
| Recuperación desde backup | A | C | I | I | R | - |
| Notificación (extorsión/datos) | A | I | I | R | C | R |
| Post-Incident Review | R | C | C | C | C | C |

**Enlaces Defender XDR:**
- Incidentes: `https://security.microsoft.com/incidents`
- Inventario de dispositivos: `https://security.microsoft.com/machines`
- Advanced Hunting: `https://security.microsoft.com/v2/advanced-hunting`
- Indicators: `https://security.microsoft.com/preferences2/indicators`
