# Firma de Scripts PowerShell (AuthentiCode) – SIN PKI corporativa

## Visión general del flujo

1. Crear certificado autofirmado para *Code Signing*.
2. Confiar explícitamente en el certificado (*Trusted Root* + *Trusted Publishers*).
3. Firmar el script.
4. Validar la firma.
5. Forzar ejecución solo de scripts firmados (*AllSigned*).
6. Probar el comportamiento ante modificación.

---

## 1️⃣ Crear un certificado autofirmado para Code Signing
Ejecuta **PowerShell 7** como **Administrador**:

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

✅ **Resultado esperado**:
- Certificado solo para firmar código
- RSA 2048 / SHA256
- Guardado en: `Cert:\LocalMachine\My`

Verifícalo:

```powershell
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*PowerShell Script Signing*" }
```

---

## 2️⃣ Confiar en el certificado (PASO CRÍTICO)
Si no haces esto, el script estará firmado pero **NO será confiable**.

### 2.1 Exportar el certificado (solo público)

```powershell
Export-Certificate `
   -Cert $cert `
   -FilePath "C:\Temp\PSScriptSigning.cer"
```

### 2.2 Importarlo como CA raíz confiable

```powershell
Import-Certificate `
   -FilePath "C:\Temp\PSScriptSigning.cer" `
   -CertStoreLocation Cert:\LocalMachine\Root
```

### 2.3 Importarlo como Publisher confiable

```powershell
Import-Certificate `
   -FilePath "C:\Temp\PSScriptSigning.cer" `
   -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

✅ Esto permite:
- Confiar automáticamente en scripts firmados con este cert
- Evitar *prompts* interactivos

---

## 3️⃣ Firmar el script PowerShell
Ejemplo: `C:\Scripts\MiScript.ps1`

```powershell
Set-AuthenticodeSignature `
   -FilePath "C:\Scripts\MiScript.ps1" `
   -Certificate $cert
```
Resultado esperado:
```text
Status: Valid
```

---

## 4️⃣ Validar la firma

```powershell
Get-AuthenticodeSignature "C:\Scripts\MiScript.ps1"
```
Debe mostrar algo similar a:
```text
Status            : Valid
SignerCertificate : CN=PowerShell Script Signing - Lab
```
✅ Si ves `UnknownError` o `NotTrusted`, revisa el **paso 2**.

---

## 5️⃣ Forzar ejecución SOLO de scripts firmados
Opción recomendada (máquina completa):

```powershell
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine
```
Verifica:

```powershell
Get-ExecutionPolicy -List
```

✅ Comportamiento:
- Scripts no firmados → bloqueados
- Scripts modificados → firma inválida → bloqueados
- Scripts firmados con tu cert → permitidos

---

## 6️⃣ Prueba de integridad (demostración clave)
### 6.1 Modifica el script (agrega un espacio o comentario)
```powershell
# cambio mínimo
```
### 6.2 Revisa firma
```powershell
Get-AuthenticodeSignature "C:\Scripts\MiScript.ps1"
```
Resultado esperado:
```text
Status : HashMismatch
```
### 6.3 Intenta ejecutarlo
```powershell
.\MiScript.ps1
```
⛔ Bloqueado por PowerShell

✅ **Objetivo cumplido**

---

## Sugerencias de mejora (no cambian el flujo)
- **Evita ‘Show more lines’**: parece texto copiado de una UI. Elimínalo para que el documento sea ejecutable tal cual.
- **Separa comandos y salidas**: usa bloques `powershell` para comandos y `text` para resultados (como arriba).
- **Considera CurrentUser para laboratorios**: si no quieres tocar el almacén de *LocalMachine*, puedes usar `Cert:\CurrentUser\My` y confiar en `CurrentUser\Root` / `CurrentUser\TrustedPublisher` (requiere que el usuario ejecute el script).
- **Respaldo de la clave privada**: si vas a firmar en más de un equipo, exporta el certificado con clave privada a PFX y protégelo con contraseña (almacenamiento seguro).
- **Buenas prácticas de seguridad**: limita el uso del certificado (quién puede acceder a la clave privada) y establece rotación/expiración planificada.
