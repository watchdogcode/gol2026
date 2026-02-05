# Microsoft Defender XDR: SecOps Report

📋 Descripción General

Este proyecto proporciona una plantilla de reporte diario y semanal automatizado diseñada para sintetizar datos críticos de Microsoft Defender XDR. El objetivo es cerrar la brecha de comunicación entre el equipo técnico y la alta gerencia (CISO), transformando telemetría compleja en información accionable.



Nota: Este reporte está diseñado para cubrir periodos de actividad de hasta 24 horas, permitiendo una visión clara de incidentes y tendencias recientes.



## 🎯 Valor de Negocio

Para el CISO (Executive View)

Visibilidad de Alto Nivel: KPIs claros sobre exposición y riesgo.



Indicadores de Salud: Resumen de higiene de identidades y aplicaciones OAuth.



Eficiencia: Visualización rápida de si existen incidentes críticos sin necesidad de entrar a la consola.



Para Administradores de Infraestructura (Operational View)

Accionabilidad: Listado de actividades diarias recomendadas para el mantenimiento del tenant.



Foco en Identidad: Reporte detallado de intentos de fuerza bruta y usuarios de alto riesgo (MDI).



Higiene de Email: Seguimiento de campañas de phishing entregadas y usuarios objetivo (MDO).



## 🚀 Características Principales

Diseño Limpio: Interfaz basada en Segoe UI para coherencia visual con el ecosistema Microsoft.



Grid de KPIs: Métricas clave (Alertas MDE, Phishing, High Risk Users) en la parte superior para lectura rápida.



Secciones por Dominio:



MDO: Email y colaboración (campañas y usuarios objetivo).



MDE: Seguridad de endpoints y severidad de alertas.



MDI: Seguridad de identidad (fuerza bruta y riesgo de inicio de sesión).



MDA: Aplicaciones en la nube y consentimientos OAuth.



## 🛠️ Tecnologías Utilizadas

KQL (Kusto Query Language): Para la extracción de datos de Microsoft Defender y Sentinel.



HTML5 / CSS3: Para la estructura y el diseño visual del reporte.



PowerShell / Graph API (Opcional): Para la automatización y generación del archivo.





## ⚙️ Configuración y Uso

Clonar el repositorio: git clone https://github.com/watchdogcode/gol2026



Personalización: Actualiza el archivo HTML con tu Tenant ID y ajusta los estilos según tu marca corporativa.



Inyección de Datos: Utiliza tus queries de KQL para alimentar las tablas del reporte.



## ⚠️ Disclaimer

Este reporte es una herramienta de visualización. Los datos mostrados dependen de la correcta configuración de las licencias y conectores de Microsoft Defender XDR en tu entorno.

