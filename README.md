# Blockchain-photo-notifier-v.2.1
Captura in-app o nativa según permisos. - Extracción automática de EXIF, sensores y ID de dispositivo. - Generación de hash SHA-256 y firma digital. - Interacción con Ethereum vía Web3.py. - Notarización on-chain y verificación pública.

## FLUJO: ()
[0.5] Conectar contrato

[1] Capturar/seleccionar FOTO (archivo final, sin más ediciones) | v

[2] Calcular HASH SHA-256 del archivo completo | v

[2.5] Crear claves publicas y privadas si no las tenemos.

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

### COMANDOS PARA BROWNIE:

Para crear contrato nuevo y obtener direccion de contrato, automaticamente el 
programa lo copia en .env

    brownie run scripts/deploy.py

Para realizar los test en ganache.

    brownie test

Solo en caso de reiniciar todo el programa desde cero....
Para crear el contrato, tener configurado brownie-config.yaml
Desde una carpeta vaca, /Contract

    brownie init

Esto crea las carpetas del framework, guardamos scripts/deploy.py, 
tests/test_smoke.py, tests/test_phot_resgistry.py
y compilamos

    brownie compile

Con esto ya tendremos Contract/build/contracts/PhotRegistry.json, necesario
para ejecutar, es donde se guardan los datos del contrato...

Python 3.9 pip

Licencia: CC BY-NC 4.0 – No se permite el uso comercial de este software.
