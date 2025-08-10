# Blockchain-photo-notifier-v.2.1
Captura in-app o nativa según permisos. - Extracción automática de EXIF, sensores y ID de dispositivo. - Generación de hash SHA-256 y firma digital. - Interacción con Ethereum vía Web3.py. - Notarización on-chain y verificación pública.

## FLUJO: ()

[1] Capturar/seleccionar FOTO (archivo final, sin más ediciones) | v

[2] Calcular HASH SHA-256 del archivo completo | v

[3] FIRMAR el hash con tu CLAVE PRIVADA (en keystore / HW wallet) |
| --> (opcional) Guardar firma + dirección en metadatos XMP v

[4] ENVIAR TX a Ethereum -> anchor(hash) | v

[5] BLOCKCHAIN registra: (hash, address, timestamp) en evento/estado | v

[6] Guardas en tu app: hash, txHash, address, block#, receipt

## VERIFICACION PUBLICA (DE CUALQUIER TERCERO):

A) Recalcular SHA-256 del archivo recibido

B) Consultar en el contrato si ese hash está anclado: - ¿Qué address lo ancló? ¿Cuándo (timestamp / block)?

C) Comprobar que la firma ECDSA del hash corresponde a esa address (si incluyes sig)

D) (Opcional) Vincular esa address a tu identidad (ENS / web con firma / acta notarial) => Si A, B y C pasan: integridad + control; con D: atribución a tu persona.

Python 3.9 pip

Licencia: CC BY-NC 4.0 – No se permite el uso comercial de este software.
