# Sigilo A33 — v0.2.0 (Etapa 8D/2)

App web mobile‑first para cifrar y descifrar mensajes entre contactos usando “candados” (clave pública), con identidad local y libreta de contactos.

## Qué incluye
- **Encriptar / Desencriptar** (1‑a‑1)
- **Contactos** (agregar, escanear QR, eliminar)
- **Perfil** (identidad, candado, huella)
- **Backup / Restore con contraseña** (identidad + perfil + contactos)

## Backup (formato)
El backup se exporta como texto (archivo descargable) en el formato:

`SIGILOA33:BACKUP:1:<base64url-json>`

Contenido cifrado con:
- KDF: **PBKDF2‑SHA256**
- AEAD: **AES‑GCM** (integridad autenticada)

## Notas
- La **llave privada nunca se muestra en claro**.
- Si ya existe una identidad y el backup trae otra, se pide confirmación fuerte para reemplazar.

