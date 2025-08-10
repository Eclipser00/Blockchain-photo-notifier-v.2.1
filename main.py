import os
from kivy.app import App

# 1) Cargar .env ANTES de leer variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass  # si no usas python-dotenv, ignora

from anchor_module import AnchorWidget
from photo_anchor.service import AnchorConfig  # o desde donde tengas AnchorConfig

class Demo(App):
    def build(self):
        # 2) Leer y LIMPIAR (strip) las variables de entorno
        rpc_url = os.getenv("PHOTO_RPC", "http://127.0.0.1:8545").strip()
        contract_addr = os.getenv("PHOTO_REGISTRY_ADDR", "0x44a83C3C87B76bB8E120BE7e14137953659A310b").strip()
        abi_path = os.getenv("PHOTO_ABI_PATH", "build/contracts/PhotoRegistry.json").strip()
        dev_pk = (os.getenv("DEV_PRIVATE_KEY") or "").strip()
        chain_id_str = os.getenv("PHOTO_CHAIN_ID", "1337").strip()

        # 3) Convertir chain_id de forma segura
        try:
            chain_id = int(chain_id_str)
        except ValueError:
            chain_id = 1337

        # 4) NO pongas una dirección por defecto hardcodeada aquí.
        #    Mejor vacía para que uses la de .env (o la metas en la UI).
        cfg = AnchorConfig(
            rpc_url=rpc_url,
            contract_address=contract_addr,     # <- desde .env, ya sin espacios
            abi_path=abi_path,
            private_key=dev_pk if dev_pk else None,  # None si está vacío
            chain_id=chain_id,
        )

        # (opcional) prints de diagnóstico en consola
        print(f"[CFG] RPC={rpc_url}  chainId={chain_id}")
        print(f"[CFG] CONTRACT={contract_addr}  ABI={abi_path}")
        print(f"[CFG] DEV_PK={'set' if dev_pk else 'not set'}")

        return AnchorWidget(cfg)

if __name__ == "__main__":
    Demo().run()

