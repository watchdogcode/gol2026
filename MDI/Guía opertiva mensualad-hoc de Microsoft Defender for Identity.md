# 🛡️ Guía de Seguridad Operacional Diaria: Microsoft Defender for Identity

La guía mensual y ad‑hoc de MDI permite evaluar la postura de seguridad de identidades, ajustar controles y responder a eventos extraordinarios que pueden impactar la continuidad del negocio.

---
## Índice
- [Revisar Microsoft Service Health antes de troubleshooting (Mensual)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20opertiva%20mensualad-hoc%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-microsoft-service-health-antes-de-troubleshooting-mensual)
- [Revisar proceso de alta de servidores para incluir sensores MDI (Ad-Hoc)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20opertiva%20mensualad-hoc%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-proceso-de-alta-de-servidores-para-incluir-sensores-mdi-ad-hoc)
- [Validar configuración del dominio con Test‑MDIConfiguration (PowerShell) (Ad-Hoc)](https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20opertiva%20mensualad-hoc%20de%20Microsoft%20Defender%20for%20Identity.md#validar-configuraci%C3%B3n-del-dominio-con-testmdiconfiguration-powershell-ad-hoc)

---
## Revisar Microsoft Service Health antes de troubleshooting (Mensual)

### Propósito
Evitar troubleshooting innecesario cuando exista una degradación del servicio a nivel Microsoft.

### Paso a paso
1. Ante una degradación, abrir **Service Health**:
   - https://admin.microsoft.com/#/servicehealth
2. Si existe un incidente:
   - Registrar **ID**, **alcance** y **ETA**.
   - Comunicar la información al equipo.
3. Si no existe incidente:
   - Continuar con validación interna (health issues, conectividad, etc.).

### Salida / DoD
- Confirmación documentada del estado del servicio.
- Decisión registrada (**esperar** / **accionar**).

---

## Revisar proceso de alta de servidores para incluir sensores MDI (Ad-Hoc)

### Propósito
Asegurar que nuevos **DC / AD CS / AD FS** queden protegidos desde el inicio.

> Referencia: documentación interna de la organización. El artículo oficial indica revisar el proceso interno.

### Paso a paso
1. Tomar el flujo actual de alta de servidores (DC / ADCS / ADFS).
2. Verificar que incluya explícitamente:
   - Instalación del **sensor MDI**.
   - Verificación **post‑instalación**.
3. Si falta alguno de los puntos:
   - Actualizar el checklist.
   - Definir evidencia obligatoria en cada alta.

### Salida / DoD
- Proceso actualizado o validado.
- Evidencia requerida claramente definida.

---

## Validar configuración del dominio con Test‑MDIConfiguration (PowerShell) (Ad-Hoc)

### Propósito
Comprobar **Advanced Audit Policy**. Una mala configuración puede causar brechas de eventos y cobertura.

### Dónde
- PowerShell en servidores con **sensor MDI** (DC / servidores correspondientes).
- Referencia oficial (guía quarterly / ad‑hoc):
  - https://learn.microsoft.com/en-us/defender-for-identity/ops-guide/ops-guide-quarterly

### Paso a paso
1. En un DC (o servidor con sensor), abrir **PowerShell** con permisos de administrador.
2. Ejecutar el comando:
   ```powershell
   Test-MDIConfiguration
   ```
3. Revisar resultados:
   - Si existe auditoría incompleta o mal configurada:
     - Abrir ticket a **AD / Infraestructura** para corregir **GPO / Audit Policy**.
4. Repetir la validación tras aplicar correcciones.
5. Documentar el **estado final**.

### Salida / DoD
- Evidencia de cumplimiento **o** plan de remediación documentado.
- Estado final validado para auditoría y cobertura.
