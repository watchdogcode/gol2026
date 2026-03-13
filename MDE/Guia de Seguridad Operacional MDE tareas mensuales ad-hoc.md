# Guía de Seguridad Operacional Mensual/Ad-Hoc: Microsoft Defender for Endpoint 🛡️
## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

Esta guía establece los procedimientos Mensual/Ad-Hoc para analizar tendencias de amenazas, ejecutar hunting proactivo, gestionar vulnerabilidades y revisar la postura de seguridad de endpoints en Microsoft Defender for Endpoint (MDE).

## Alcance
Esta guía describe actividades **operativas mensuales y ad‑hoc** para Microsoft Defender for Endpoint (MDE), enfocadas en:

---

## Índice
1. [Revisión mensual de novedades (What's new)](#1-revisa-qué-hay-de-nuevo-con-microsoft-defender-para-endpoint-mensual)
2. [Revisión ad‑hoc de configuraciones, reglas y políticas de endpoint](#2-revisar-la-configuración-del-endpoint-reglas-configuraciones-de-políticas-ad-hoc)

---

## 1. Revisa qué hay de nuevo con Microsoft Defender para Endpoint (Mensual)

### Objetivo
Asegurar que el equipo de seguridad:
- Conozca cambios funcionales en MDE
- Anticipe impacto operativo
- Actualice runbooks, configuraciones y procesos cuando aplique

---

### Roles
- Security Architect  
- SOC Lead  
- Security Administrator

---

### Fuentes / Consolas
- Microsoft Defender Portal  
- Microsoft 365 Message Center  
- Documentación oficial “What’s new” de MDE

---

### Procedimiento paso a paso

#### 1. Revisar anuncios de servicio
1. Ir a: https://admin.microsoft.com/#/MessageCenter
2. Filtrar por:
   - Microsoft Defender
   - Endpoint
3. Identificar anuncios relacionados con:
   - EDR
   - ASR (Attack Surface Reduction)
   - Sensores
   - Cambios de licenciamiento
   - Cambios en comportamiento por defecto

---

#### 2. Revisar novedades específicas de MDE
1. Consultar la sección **What’s new** de Microsoft Defender for Endpoint
2. Identificar:
   - Nuevas detecciones
   - Cambios en reglas ASR
   - Nuevas capacidades de respuesta
   - Cambios en experiencia del portal

---

#### 3. Evaluar impacto
Para cada cambio relevante, responder:
- ¿Requiere acción técnica?
- ¿Impacta a usuarios finales, SOC o IT?
- ¿Debe comunicarse o documentarse?

---

#### 4. Actualizar documentación
- Registrar cambios en:
  - Bitácora mensual de seguridad
  - Runbooks SOC
  - Procedimientos operativos

---

### Resultado esperado (DoD)
- Cambios relevantes documentados
- Ajustes planificados cuando aplique
- Sin impactos operativos no anticipados

---

## 2. Revisar la configuración del endpoint, reglas, configuraciones de políticas (Ad-Hoc)

### Objetivo
Validar que la **postura de seguridad de endpoints** se mantenga:
- Consistente
- Alineada a mejores prácticas
- Sin deriva de configuración

---

### Roles
- SOC Operator  
- Security Administrator  
- Endpoint / Intune Administrator (cuando aplique)

---

### Consola principal
- Microsoft Defender Portal  
  https://security.microsoft.com

---

### Procedimiento paso a paso

---

### A. Revisión de estado general de endpoints

1. Navegar a:  
   **Assets → Devices**
2. Validar:
   - Estado de onboarding
   - Salud del sensor (EDR)
   - Última comunicación
   - Sistema operativo y versión

**Acción:**
- Investigar dispositivos:
  - Inactive
  - Can be onboarded
  - Sensor issues

---

### B. Revisión de configuraciones y políticas

1. Navegar a:  
   **Endpoints → Configuration management → Dashboard**
2. Revisar:
   - Device compliance
   - Configuraciones aplicadas
   - Conflictos entre Intune y GPO

---

### C. Revisión de Attack Surface Reduction (ASR)

1. Ir a:  
   **Reports → Endpoints → Attack surface reduction rules**
2. Validar reglas críticas en modo **Block**, por ejemplo:
   - Block credential stealing from LSASS
   - Block Office apps from creating child processes
   - Block executable content from email
3. Analizar:
   - Volumen de eventos
   - Posibles falsos positivos

**Acción:**
- Ajustar exclusiones solo si están:
  - Justificadas
  - Documentadas
  - Con responsable asignado

---

### D. Revisión de Device Discovery (si aplica)

1. Navegar a:  
   **Settings → Endpoints → Device discovery**
2. Validar:
   - Modo **Standard discovery**
   - Subnets corporativas correctamente monitoreadas
3. Revisar:
   - Dispositivos no gestionados detectados

---

### Resultado esperado (DoD)
- Sin configuraciones críticas desconocidas
- ASR alineado al riesgo real del entorno
- Cambios documentados y trazables

---

## Principios operativos clave

- Lo nuevo que no se revisa se convierte en riesgo
- Toda exclusión debe tener dueño, razón y fecha
- ASR en modo Audit **no protege**
- La deriva de configuración es una amenaza silenciosa

---
