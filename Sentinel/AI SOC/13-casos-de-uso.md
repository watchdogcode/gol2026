<!-- AI-SOC Playbook v2.0 · Arturo Mandujano (Cloud Solution Architect) · 28 de septiembre de 2026 -->
[← 12. Ruta de adopción de referencia](12-ruta-de-adopcion.md) | [Índice](README.md) | [14. Riesgos y limitaciones conocidas →](14-riesgos.md)

---

# 13. Casos de uso priorizados

Los cinco escenarios siguientes provienen del eBook Coordinated Defense (Microsoft, 2025) y se presentan con su cadena completa de ataque, acción de plataforma y resultado. La priorización de referencia considera el impacto esperado y el esfuerzo de habilitación típico; cada organización debe reordenarlos según su propia exposición.

| # | Escenario | Cadena ataque → acción de plataforma → resultado | Capacidades involucradas | Impacto | Esfuerzo | Prioridad |
|----|----|----|----|----|----|----|
| 1 | Identidades | Phishing AiTM o password spray compromete credenciales → Entra ID Protection y Defender for Identity detectan el riesgo, Security Copilot reconstruye el contexto y el acceso condicional revoca la sesión → compromiso contenido antes del movimiento lateral | Entra ID P2, Defender for Identity, Security Copilot, acceso condicional | Alto | Medio | 1 |
| 2 | Endpoints | Explotación de una vulnerabilidad en un dispositivo no administrado y despliegue de ransomware → Defender for Endpoint detecta y attack disruption interrumpe la cadena → cifrado detenido en un promedio de tres minutos | Defender for Endpoint P2, attack disruption, exposure insights | Alto | Medio | 2 |
| 3 | SIEM y XDR organizacional | Campaña multi-etapa que cruza correo, identidad y endpoint → correlación avanzada de incidentes sobre la capa de datos unificada y priorización asistida por agentes → una sola investigación en lugar de tres alertas inconexas | Sentinel (SIEM, data lake, graph), Defender XDR, Dynamic Threat Detection Agent | Alto | Alto | 3 |
| 4 | Aplicaciones nativas de la nube | Configuración incorrecta o identidad de carga de trabajo excesivamente permisiva abre una ruta hacia un activo crítico → Defender for Cloud y el modelado de rutas de ataque hacen explícita la ruta → exposición cerrada antes de ser explotada | Defender for Cloud, exposure management, Sentinel graph | Medio | Medio | 4 |
| 5 | Datos | Exfiltración o acceso anómalo a información sensible → Purview aporta contexto de sensibilidad y sus agentes trían y priorizan → la respuesta se ordena por valor real de la información afectada | Purview, Data Security Posture Agent, Data Security Triage Agent | Medio | Medio | 5 |

*Tabla 36. Matriz de casos de uso priorizados (escenarios de Microsoft, Coordinated Defense, 2025).*

El orden de referencia responde a la evidencia de exposición: el 99% de los ataques de identidad diarios son basados en contraseña y los ataques AiTM crecieron 46%, mientras que el 92% de los ataques de cifrado remoto exitosos explota vulnerabilidades en dispositivos no administrados (Microsoft Digital Defense Report, 2024). Identidades y endpoints concentran, por tanto, el mayor retorno inmediato.


---

[← 12. Ruta de adopción de referencia](12-ruta-de-adopcion.md) | [Índice](README.md) | [14. Riesgos y limitaciones conocidas →](14-riesgos.md)
