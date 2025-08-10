from dotenv import load_dotenv
# main.py
import os
from kivy.app import App
from photo_anchor.service import AnchorConfig
from photo_anchor.ui import AnchorWidget

class Demo(App):
    def build(self):
        cfg = AnchorConfig(
            rpc_url=os.getenv("PHOTO_RPC","http://127.0.0.1:8545"),
            contract_address=os.getenv("PHOTO_REGISTRY_ADDR",""),
            abi_path=os.getenv("PHOTO_ABI_PATH","build/contracts/PhotoRegistry.json"),
            private_key=os.getenv("DEV_PRIVATE_KEY"),   # solo dev
            chain_id=int(os.getenv("PHOTO_CHAIN_ID","1337")),
        )
        return AnchorWidget(cfg)

if __name__ == "__main__":
    Demo().run()
