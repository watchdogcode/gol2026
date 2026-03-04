# 🛡️ Guía de Seguridad Operacional Mensual/Ad-Hoc: Microsoft EntraID

## *La tecnología permite la seguridad, pero es la disciplina la que garantiza su efectividad.*

La operación efectiva de Microsoft Entra ID requiere monitoreo continuo, control de cambios y revisión periódica de privilegios para reducir riesgos de identidad y garantizar continuidad del negocio.

---
## Índice
- [Revisión de roles privilegiados](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Mensuales%20AdHoc.md#revisi%C3%B3n-de-roles-privilegiados)
- [Validación de políticas de Conditional Access](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Mensuales%20AdHoc.md#validaci%C3%B3n-de-pol%C3%ADticas-de-conditional-access)
- [Actualización de componentes on-premises](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Mensuales%20AdHoc.md#actualizaci%C3%B3n-de-componentes-on-premises)
- [Pruebas de cambios importantes (Ad-Hoc)](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Mensuales%20AdHoc.md#pruebas-de-cambios-importantes-ad-hoc)

---

## Revisión de roles privilegiados

### Objetivo
Aplicar el **principio de mínimo privilegio** para reducir el riesgo asociado a cuentas con altos privilegios.

### Pasos operativos
1. Revisar quién tiene asignados los siguientes roles:
   - **Global Administrator**
   - **Privileged Role Administrator**
   - **Security Administrator**
2. Validar para cada asignación:
   - Uso de **Privileged Identity Management (PIM)**.
   - Justificación documentada para accesos **permanentes**.

### Herramienta recomendada
Se recomienda la ejecución del script: [Get-M365RoleReport](https://github.com/watchdogcode/gol2026/blob/main/EntraID/Scripts/Get-M365RoleReport.ps1)

### Salida / DoD
- Listado actualizado de roles privilegiados.
- Evidencia de uso de PIM o justificación formal de accesos permanentes.

---

## Validación de políticas de Conditional Access

### Objetivo
Asegurar que las políticas de **Conditional Access** continúen alineadas con el riesgo actual del entorno.

### Pasos operativos
1. Acceder al portal de Conditional Access:
   - https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies/menuId//fromNav/Identity

### Acciones clave
- Revisar **exclusiones** (usuarios, grupos, ubicaciones).
- Eliminar **políticas obsoletas**.
- Evaluar el impacto de:
  - Nuevas aplicaciones.
  - Nuevas ubicaciones o países.

### Salida / DoD
- Políticas validadas y alineadas al riesgo.
- Cambios documentados.

---

## Actualización de componentes on-premises

### Objetivo
Mantener **compatibilidad**, **rendimiento** y **seguridad** en entornos híbridos.

### Componentes a validar
- Microsoft Entra Connect.
- Pass-Through Authentication Agents.
- Connect Health Agents.

### Recomendaciones
- Usar **auto-upgrade** siempre que sea posible.
- Verificar versiones soportadas.

Referencia oficial:
- [Microsoft Entra Connect – Version release history](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-version-history)

### Salida / DoD
- Componentes actualizados o plan de actualización definido.

---

## Pruebas de cambios importantes (Ad-Hoc)

### Objetivo
Reducir el riesgo operativo al implementar cambios significativos de autenticación o acceso.

### Escenarios comunes
- Cambio de método de autenticación (**Federated ↔ PHS / PTA**).
- Implementación de nuevas políticas de acceso.

### Buenas prácticas
- **Staged rollout**.
- Uso de **grupos piloto**.
- Uso de **tenant de prueba** cuando aplique.

### Salida / DoD
- Evidencia de pruebas controladas.
- Plan de rollback definido.
