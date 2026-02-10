# Sigilo A33 — v0.2.11 (Etapa 3/5)

App web mobile‑first para cifrar y descifrar mensajes entre contactos usando “candados” (clave pública), con identidad local y libreta de contactos.

## Qué incluye
- **Encriptar / Desencriptar** (1‑a‑1)
- **Contactos** (agregar, escanear QR, eliminar)
- **Perfil** (identidad, candado, huella)
- **SW versionado + salida de emergencia**: botón “Reparar caché” para salir de un Service Worker viejo pegado
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


## Etapa 1A
- Limpieza de Perfil (sin tocar Mi QR).

## Etapa 1B
- Modal “Mi QR” ya no genera en vivo: solo muestra QR guardado (SVG/PNG) o placeholder.
- “Detalles” muestra si hay QR guardado y su timestamp.

## Etapa 2A
- Detecta “QR desactualizado” comparando hash del payload de identidad (sin autogenerar).

## Etapa 2B
- Botón “Generar mi QR” / “Actualizar QR” (solo genera bajo demanda).
- Guardado robusto (SVG preferido) + meta (ts/build/hash/len/lastGenOk/lastErrCode).
- Si falla la generación/guardado, NO borra el QR guardado previo y muestra código corto.

## Etapa 3
- SW puente + SW versionado alineados a v0.2.11 (caches/build coherentes).
- “Detalles” ahora puede mostrar el **SW file** incluso si aún no está “controlando” (mejor para iPad/PWA post‑repair).
