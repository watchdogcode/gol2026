# Firma de Scripts PowerShell (AuthentiCode) – **SIN PKI corporativa**

## *La tecnología habilita la seguridad, pero es la disciplina la que garantiza su efectividad.*

> **Objetivo:** firmar scripts PowerShell con un **certificado autofirmado** y hacer que el sistema **solo ejecute scripts firmados** (ExecutionPolicy **AllSigned**), incluyendo una prueba de integridad.

---

## Alcance y consideraciones

- Este flujo es ideal para **laboratorios**, **entornos aislados** o **máquinas controladas**.
- Con un certificado **autofirmado**, la confianza se logra **importándolo explícitamente** en los almacenes de confianza.
- **Impacto:** al habilitar **AllSigned**, scripts no firmados o modificados serán bloqueados.

---

## Requisitos previos

- **PowerShell 7** (recomendado) o Windows PowerShell.
- Ejecutar como **Administrador** si usarás el almacén **LocalMachine**.
- Carpeta de trabajo (ejemplo): `C:\Temp` y `C:\Scripts`.

---

## Flujo (resumen)

1. Crear certificado autofirmado de **Code Signing**.
2. Confiar en el certificado (Root + TrustedPublisher).
3. Firmar el script.
4. Validar la firma.
5. Forzar ejecución solo de scripts firmados (**AllSigned**).
6. Probar bloqueo al modificar el script (integridad).

---

## 1) Crear un certificado autofirmado para **Code Signing**

Ejecuta **PowerShell como Administrador**:

```powershell
$cert = New-SelfSignedCertificate `
  -Subject "CN=PowerShell Script Signing - Lab" `
  -Type CodeSigningCert `
  -CertStoreLocation "Cert:\LocalMachine\My" `
  -KeyAlgorithm RSA `
  -KeyLength 2048 `
  -HashAlgorithm SHA256 `
  -NotAfter (Get-Date).AddYears(3)
```

**Salida esperada (conceptual):**

```text
Se crea un certificado de tipo CodeSigningCert en Cert:\LocalMachine\My
```

Verifica que existe:

```powershell
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like '*PowerShell Script Signing*' }
```

**Salida esperada (ejemplo):**

```text
Subject: CN=PowerShell Script Signing - Lab
EnhancedKeyUsageList: Code Signing
```

---

## 2) Confiar en el certificado (PASO CRÍTICO)

> Si omites este paso, el script puede quedar **firmado**, pero el equipo lo verá como **no confiable**.

### 2.1 Exportar el certificado (solo público)

```powershell
New-Item -ItemType Directory -Path C:\Temp -Force | Out-Null
Export-Certificate -Cert $cert -FilePath "C:\Temp\PSScriptSigning.cer"
```

**Salida esperada (ejemplo):**

```text
La exportación del certificado se completa correctamente.
```

### 2.2 Importarlo como CA raíz confiable (Trusted Root)

```powershell
Import-Certificate -FilePath "C:\Temp\PSScriptSigning.cer" -CertStoreLocation Cert:\LocalMachine\Root
```

**Salida esperada (ejemplo):**

```text
Certificado importado en Cert:\LocalMachine\Root
```

### 2.3 Importarlo como Publisher confiable (Trusted Publishers)

```powershell
Import-Certificate -FilePath "C:\Temp\PSScriptSigning.cer" -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

**Salida esperada (ejemplo):**

```text
Certificado importado en Cert:\LocalMachine\TrustedPublisher
```

✅ Esto permite:

- Confiar automáticamente en scripts firmados con este cert.
- Evitar *prompts* interactivos de editor/desconocido.

---

## 3) Firmar el script PowerShell

Ejemplo: `C:\Scripts\MiScript.ps1`

```powershell
Set-AuthenticodeSignature -FilePath "C:\Scripts\MiScript.ps1" -Certificate $cert
```

**Salida esperada (ejemplo):**

```text
Status: Valid
```

---

## 4) Validar la firma

```powershell
Get-AuthenticodeSignature "C:\Scripts\MiScript.ps1"
```

**Salida esperada (ejemplo):**

```text
Status            : Valid
SignerCertificate : CN=PowerShell Script Signing - Lab
```

> Si ves `NotTrusted` o errores, revisa el **Paso 2** (Root + TrustedPublisher).

---

## 5) Forzar ejecución SOLO de scripts firmados (AllSigned)

> ⚠️ **Cambiar la ExecutionPolicy impacta el comportamiento de ejecución de scripts.**

### 5.1 Aplicar política a nivel de máquina

```powershell
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine
```

### 5.2 Verificar

```powershell
Get-ExecutionPolicy -List
```

**Salida esperada (ejemplo):**

```text
Scope       ExecutionPolicy
-----       ---------------
MachinePolicy       Undefined
UserPolicy          Undefined
Process             Undefined
CurrentUser         Undefined
LocalMachine        AllSigned
```

✅ Comportamiento esperado:

- Scripts **no firmados** → bloqueados.
- Scripts **modificados** → firma inválida → bloqueados.
- Scripts firmados con el cert confiado → permitidos.

---

## 6) Prueba de integridad (demostración clave)

### 6.1 Modifica el script (cambio mínimo)

Agrega un espacio o comentario al final del archivo:

```powershell
# cambio mínimo
```

### 6.2 Revisa la firma

```powershell
Get-AuthenticodeSignature "C:\Scripts\MiScript.ps1"
```

**Salida esperada:**

```text
Status : HashMismatch
```

### 6.3 Intenta ejecutarlo

```powershell
.\MiScript.ps1
```

**Resultado esperado:**

```text
PowerShell bloquea la ejecución por firma inválida (AllSigned).
```

✅ Objetivo cumplido.

---

## 7) Respaldo de la clave privada (PFX) — **para firmar desde otro equipo**

> Recomendado si el mismo firmante (certificado) se usará en **más de una máquina**.

### 7.1 Exportar a PFX (incluye clave privada)

```powershell
$pwd = Read-Host -AsSecureString "Contraseña para proteger el PFX"
Export-PfxCertificate -Cert $cert -FilePath "C:\Temp\PSScriptSigning.pfx" -Password $pwd
```

**Salida esperada (ejemplo):**

```text
La exportación del PFX se completa correctamente.
```

### 7.2 Importar el PFX en otro equipo (almacén Personal)

```powershell
$pwd = Read-Host -AsSecureString "Contraseña del PFX"
Import-PfxCertificate -FilePath "C:\Temp\PSScriptSigning.pfx" -CertStoreLocation Cert:\LocalMachine\My -Password $pwd
```

> Además, en el **equipo destino** también debes importar el `.cer` a `Root` y `TrustedPublisher` (Paso 2) para que el firmante sea confiable.

---

## 8) Buenas prácticas de seguridad (recomendadas)

- **Minimiza la exposición de la clave privada**:
  - Guarda el `.pfx` en un repositorio seguro (Vault/HSM/almacenamiento cifrado) y limita accesos.
  - Evita dejar el `.pfx` en discos locales o shares sin control.
- **Control de acceso a la clave privada**:
  - Restringe quién puede acceder al certificado en el almacén (`LocalMachine\My`).
  - Considera firmar desde un equipo dedicado (build/signing host) con controles adicionales.
- **Rotación/expiración planificada**:
  - Define una política de renovación (por ejemplo, renovar antes de 30–90 días de expiración).
  - Mantén un inventario de scripts/artefactos firmados y su cert de firma.
- **Separación de entornos**:
  - Usa certificados diferentes para Lab/Dev/Prod.
- **Auditoría**:
  - Documenta quién firmó qué, cuándo y con qué certificado (thumbprint).

---

## 9) Troubleshooting rápido

- `Status: NotTrusted` → falta importar el `.cer` a `Root` y/o `TrustedPublisher` (Paso 2).
- `Status: HashMismatch` → el script fue modificado después de firmar (re-firmar).
- Bloqueos inesperados con AllSigned → revisa `Get-ExecutionPolicy -List` y si aplica GPO (`MachinePolicy`/`UserPolicy`).

