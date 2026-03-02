
#Tareas Diarias de Seguridad Operacional en Microsoft Defender for Office 365
#Revisar alertas activas
$Revisar_alertas_activas = @(
    "https://security.microsoft.com/alerts",
    "https://github.com/watchdogcode/gol2026/blob/main/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#monitoreo-de-alertas"
)
$Revisar_alertas_activas | ForEach-Object { Start-Process $_ }

#Monitoreo de Incidentes
$Monitoreo_de_Incidentes = @(
    "https://security.microsoft.com/incidents",
    "https://github.com/watchdogcode/gol2026/blob/main/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#monitoreo-de-incidentes"
)
$Monitoreo_de_Incidentes | ForEach-Object { Start-Process $_ }

#Triage de Mensajes de Teams Reportados por Usuarios
$Triage_de_Mensajes_de_Teams_Reportados_por_Usuarios = @(
    "https://admin.teams.microsoft.com/policies/messaging?view=reportedsafety",
    "https://github.com/watchdogcode/gol2026/blob/main/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#triage-de-mensajes-de-teams-reportados-por-usuarios"
)
$Triage_de_Mensajes_de_Teams_Reportados_por_Usuarios | ForEach-Object { Start-Process $_ }

#Revisar y actuar sobre los AIRs (Investigación y Respuesta Automatizada)
$Revisar_y_Actuar_sobre_los_AIRs = @(
    "https://security.microsoft.com/action-center/pending",
    "https://github.com/watchdogcode/gol2026/blob/main/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#revisar-y-actuar-sobre-los-airs"
)
$Revisar_y_Actuar_sobre_los_AIRs | ForEach-Object { Start-Process $_ }

#Revisar las Tendencias de Detección de Correo en Microsoft Defender for Office 365
$Revisar_las_Tendencias_de_Detección_de_Correo_en_Microsoft_Defender_for_Office_365 = @(    
    "https://security.microsoft.com/reports/TPSAggregateReportATP",
    "https://github.com/watchdogcode/gol2026/blob/main/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#revisar-las-tendencias-de-detección-de-correo-en-microsoft-defender-for-office-365"
)
$Revisar_las_Tendencias_de_Detección_de_Correo_en_Microsoft_Defender_for_Office_365 | ForEach-Object { Start-Process $_ }

#Revisar Campañas de Phishing y Malware que Resultaron en Correos Entregados
$Revisar_Campañas_de_Phishing_y_Malware_que_Resultaron_en_Correos_Entregados = @(
    "https://security.microsoft.com/threatexplorerv3",
    "https://github.com/watchdogcode/gol2026/blob/main/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#revisar-campa%C3%B1as-de-phishing-y-malware-que-resultaron-en-correos-entregados"
)
$Revisar_Campañas_de_Phishing_y_Malware_que_Resultaron_en_Correos_Entregados | ForEach-Object { Start-Process $_ }

#Revisión de Top Targeted Users
$Revisión_de_Top_Targeted_Users = @(
    "https://security.microsoft.com/threatexplorerv3",
    "https://github.com/watchdogcode/gol2026/blob/main/MDO/01%20Guia%20de%20Seguridad%20Operacional%20MDO%20tareas%20diarias.md#revisi%C3%B3n-de-top-targeted-users"
)
$Revisión_de_Top_Targeted_Users | ForEach-Object { Start-Process $_ }


#Tareas Semanales de Seguridad Operacional en Microsoft Defender for Office 365
#Revisar Tendencias de Detección de Correo en Microsoft Defender for Office 365
$Revisar_Tendencias_de_Detección_de_Correo_en_Microsoft_Defender_for_Office_365 = @(
    "https://security.microsoft.com/emailandcollabreport",
    "https://github.com/watchdogcode/gol2026/blob/main/MDO/02%20Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md#revisar-tendencias-de-detecci%C3%B3n-de-correo-en-microsoft-defender-for-office-365"
)
$Revisar_Tendencias_de_Detección_de_Correo_en_Microsoft_Defender_for_Office_365 | ForEach-Object { Start-Process $_ }

#Identificar Usuarios Más Atacados por Malware y Phishing
$Identificar_Usuarios_Más_Atacados_por_Malware_y_Phishing = @(
    "https://security.microsoft.com/emailandcollabreport",
    "https://github.com/watchdogcode/gol2026/blob/main/MDO/02%20Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md#identificar-usuarios-m%C3%A1s-atacados-por-malware-y-phishing"
)
$Identificar_Usuarios_Más_Atacados_por_Malware_y_Phishing | ForEach-Object { Start-Process $_ }

#Revisar Campañas de Malware y Phishing 
$Revisar_Campañas_de_Malware_y_Phishing = @(
    "https://security.microsoft.com/threatexplorerv3",
    "https://github.com/watchdogcode/gol2026/blob/main/MDO/02%20Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md#revisar-campa%C3%B1as-de-malware-y-phishing-campaigns--mdo-p2"
)
$Revisar_Campañas_de_Malware_y_Phishing | ForEach-Object { Start-Process $_ }


#Tareas diarias de Seguridad Operacional en Microsoft Defender for Identity

#Revisar ITDR Dashboard (Identities > Dashboard)
$Revisar_ITDR_Dashboard = @(
    "https://security.microsoft.com/identities/dashboard",
    "https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-itdr-dashboard-identities--dashboard"
)
$Revisar_ITDR_Dashboard | ForEach-Object { Start-Process $_ }

#Triage de incidentes por prioridad (Incidents & alerts)
$Triage_de_Incidentes_por_Prioridad = @(
    "https://security.microsoft.com/incidents",
    "https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#triage-de-incidentes-por-prioridad-incidents--alerts"
)
$Triage_de_Incidentes_por_Prioridad | ForEach-Object { Start-Process $_ }

#Configurar tuning para benign / false positives (Advanced hunting)
$Configurar_Tuning_para_Benign_False_Positives = @(
    "https://security.microsoft.com/advanced-hunting",
    "https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#configurar-tuning-para-benign--false-positives-advanced-hunting"
    )
$Configurar_Tuning_para_Benign_False_Positives | ForEach-Object { Start-Process $_ }

#Proactive hunting (diario o semanal, según madurez)
$Proactive_hunting_diario_o_semanal = @(
    "https://security.microsoft.com/v2/advanced-hunting",
    "https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#proactive-hunting-diario-o-semanal-seg%C3%BAn-madurez"
)
$Proactive_hunting_diario_o_semanal | ForEach-Object { Start-Process $_ }

#Revisar Health issues (Global y Sensor)
$Revisar_Health_Issues_Global_y_Sensor = @(
    "https://security.microsoft.com/identities/health-issues",
    "https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20diaria%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-health-issues-global-y-sensor"
)
$Revisar_Health_Issues_Global_y_Sensor | ForEach-Object { Start-Process $_ }

#Tareas semanales de Seguridad Operacional en Microsoft Defender for Identity

#Revisar recomendaciones de Secure Score (por producto)
$Revisar_recomendaciones_de_Secure_Score = @(
    "https://security.microsoft.com/securescore",
    "https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-recomendaciones-de-secure-score-por-producto"
)
$Revisar_recomendaciones_de_Secure_Score | ForEach-Object { Start-Process $_ }

#Revisar y responder a amenazas emergentes (custom detections)
$Revisar_y_responder_a_amenazas_emergentes = @(
    "https://security.microsoft.com/advanced-hunting",
    "https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-y-responder-a-amenazas-emergentes-custom-detections"
)
$Revisar_y_responder_a_amenazas_emergentes | ForEach-Object { Start-Process $_ }

#Tareas darias de seguridad operaccional en Microsoft EntraID

#Monitorear eventos de inicio de sesión y autenticación
$Monitorear_eventos_de_inicio_de_sesión_y_autenticación = @(
    "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/SignInLogsList.ReactView/timeRangeType/last24hours/showApplicationSignIns~/true ",
    "https://github.com/watchdogcode/gol2026/blob/main/EntraID/Gu%C3%ADa%20Operacional%20Microsoft%20EntraID%20Diaria.md#monitorear-eventos-de-inicio-de-sesi%C3%B3n-y-autenticaci%C3%B3n"
)
$Monitorear_eventos_de_inicio_de_sesión_y_autenticación | ForEach-Object { Start-Process $_ }

#Revisión de Usuarios con Riesgo (Alto / Medio)
$Revisión_de_Usuarios_con_Riesgo_Alto_Medio = @(
    "https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskyUsers",
    "https://github.com/watchdogcode/gol2026/blob/main/EntraID/Gu%C3%ADa%20Operacional%20Microsoft%20EntraID%20Diaria.md#revisi%C3%B3n-de-usuarios-con-riesgo-alto--medio"
)
$Revisión_de_Usuarios_con_Riesgo_Alto_Medio | ForEach-Object { Start-Process $_ }

#Revisión de Inicios de Sesión con Riesgo
$Revisión_de_Inicios_de_Sesión_con_Riesgo = @(
    "https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskySignIns",
    "https://github.com/watchdogcode/gol2026/blob/main/EntraID/Gu%C3%ADa%20Operacional%20Microsoft%20EntraID%20Diaria.md#revisi%C3%B3n-de-inicios-de-sesi%C3%B3n-con-riesgo"
)
$Revisión_de_Inicios_de_Sesión_con_Riesgo | ForEach-Object { Start-Process $_ }

#Revisar alertas de Microsoft Entra Connect Health (entornos híbridos)
$Revisar_alertas_de_Microsoft_Entra_Connect_Health = @(
    "https://entra.microsoft.com/#view/Microsoft_AAD_Connect_Health/ConnectHealthMenuBlade/~/overview",
    "https://github.com/watchdogcode/gol2026/blob/main/EntraID/Gu%C3%ADa%20Operacional%20Microsoft%20EntraID%20Diaria.md#revisar-alertas-de-microsoft-entra-connect-health-entornos-h%C3%ADbridos"
)
$Revisar_alertas_de_Microsoft_Entra_Connect_Health | ForEach-Object { Start-Process $_ }

#Tareas semanales de seguridad operaccional en Microsoft EntraID

#Revisión de cambios administrativos
$Revisión_de_cambios_administrativos = @(
    "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuditLogList.ReactView",
    "https://github.com/watchdogcode/gol2026/blob/main/EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Semanales.md#revisi%C3%B3n-de-cambios-administrativos"
)
$Revisión_de_cambios_administrativos | ForEach-Object { Start-Process $_ }

#Seguimiento del Identity Secure Score
$Seguimiento_del_Identity_Secure_Score = @(
    "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/EntraRecommendationsIdentitySecureScore.ReactView",
    "https://github.com/watchdogcode/gol2026/blob/main/EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Semanales.md#seguimiento-del-identity-secure-score"
)
$Seguimiento_del_Identity_Secure_Score | ForEach-Object { Start-Process $_ }

#Revisión de errores de sincronización antiguos
$Revisión_de_errores_de_sincronización_antiguos = @(
    "https://entra.microsoft.com/#view/Microsoft_AAD_Connect_Provisioning/CrossTenantSynchronizationConfiguration.ReactView",
    "https://github.com/watchdogcode/gol2026/blob/main/EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Semanales.md#revisi%C3%B3n-de-errores-de-sincronizaci%C3%B3n-antiguos"
)
$Revisión_de_errores_de_sincronización_antiguos | ForEach-Object { Start-Process $_ }
