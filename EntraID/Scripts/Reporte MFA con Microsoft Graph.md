# Guía Operacional - Reporte MFA con Microsoft Graph

## Objetivo
Este documento describe cómo ejecutar y soportar el script de reporte MFA que audita métodos de autenticación en usuarios de Microsoft Entra ID.

Script principal:
- EntraID/Scripts/Get-MFAAuthenticationMethodsReport.ps1

El script entrega:
- Resumen de usuarios revisados.
- Conteo de usuarios por método de autenticación registrado.
- Archivo CSV con:
  - DisplayName
  - UserPrincipalName
  - AccountEnabled
  - DefaultAuthenticationMethod
  - RegisteredAuthenticationMethods

---

## Requisitos previos
1. PowerShell 7+ (recomendado) o Windows PowerShell 5.1.
2. Módulo Microsoft Graph PowerShell instalado.
3. Cuenta con permisos suficientes en Entra ID.

Instalación del módulo (si no existe):

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

Importación opcional:

```powershell
Import-Module Microsoft.Graph
```

---

## Permisos y roles requeridos
El script solicita estos scopes delegados al conectarse:
- User.Read.All
- UserAuthenticationMethod.Read.All

Para consultar métodos de autenticación de todos los usuarios, la cuenta que ejecuta debe tener un rol adecuado en Entra ID. Recomendado:
- Global Reader (lectura amplia)

También pueden ser válidos según política del tenant:
- Authentication Administrator
- Privileged Authentication Administrator

Si en tu organización se exige consentimiento de administrador para estos scopes, un Global Administrator debe aprobarlos.

---

## Ejecución
Ejemplo básico:

```powershell
.\EntraID\Scripts\Get-MFAAuthenticationMethodsReport.ps1
```

Ejemplo con carpeta de salida personalizada:

```powershell
.\EntraID\Scripts\Get-MFAAuthenticationMethodsReport.ps1 -OutputFolder "C:\Scripts\EntraID"
```

Ejemplo especificando nube:

```powershell
.\EntraID\Scripts\Get-MFAAuthenticationMethodsReport.ps1 -CloudEnvironment Commercial
```

Parámetros:
- CloudEnvironment: Commercial, USGovGCC, USGovGCCHigh, USGovDoD, China
- OutputFolder: carpeta donde se genera el CSV
- CsvFileName: nombre del archivo CSV (opcional)

---

## Salida esperada
En consola:
- Usuarios revisados (total)
- Conteo por método (por ejemplo: Microsoft Authenticator, Phone, FIDO2 Security Key, etc.)
- Ruta del CSV generado

En CSV:
- Una fila por usuario
- Método predeterminado detectado desde signInPreferences
- Todos los métodos registrados en una sola columna separada por punto y coma

---

## Troubleshooting
### 1) Error: comando no reconocido (Connect-MgGraph / Invoke-MgGraphRequest)
Causa probable:
- Módulo Microsoft Graph no instalado/importado.

Acción:
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Import-Module Microsoft.Graph
```

### 2) Error: Insufficient privileges to complete the operation
Causa probable:
- Faltan scopes delegados o rol insuficiente.

Acción:
1. Confirmar que la sesión de Graph tenga:
   - User.Read.All
   - UserAuthenticationMethod.Read.All
2. Verificar rol del operador en Entra ID (ej. Global Reader).
3. Solicitar consentimiento de administrador si aplica.

### 3) Error de consentimiento (admin consent required)
Causa probable:
- El tenant bloquea consentimientos por usuario.

Acción:
- Solicitar a un Global Administrator otorgar consentimiento de administrador para los scopes requeridos.

### 4) El campo DefaultAuthenticationMethod aparece como "No disponible"
Causa probable:
- Restricción en el endpoint beta de signInPreferences para ese usuario o permisos insuficientes.

Acción:
- Revisar permisos/rol y volver a ejecutar.
- Validar que el usuario tenga preferencias configuradas.

### 5) Lentitud en tenants grandes
Causa probable:
- Consulta por usuario de métodos y preferencias.

Acción:
- Ejecutar fuera de horario pico.
- Mantener sesión estable y evitar interrupciones.

### 6) CSV no se genera
Causa probable:
- Ruta sin permisos de escritura o carpeta inexistente.

Acción:
- Usar una carpeta accesible con -OutputFolder.
- Probar manualmente crear archivo en la ruta.

---

## Buenas prácticas operativas
- Ejecutar con cuenta dedicada de operación (mínimo privilegio viable).
- Resguardar el CSV porque contiene inventario de factores de autenticación.
- Programar ejecución periódica (semanal/mensual) y comparar tendencias.
- Correlacionar resultados con políticas de Acceso Condicional para cierre de brechas.

---

## Referencia rápida de validación
Después de ejecutar, confirmar:
1. Se muestra total de usuarios revisados en consola.
2. Se imprime conteo por método.
3. Existe el CSV en la ruta indicada.
4. El CSV contiene columnas esperadas y datos de métodos por usuario.
