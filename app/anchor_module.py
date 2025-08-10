# anchor_module.py
# -*- coding: utf-8 -*-
import os
import json
import hashlib
import threading
from dataclasses import dataclass
from typing import Optional, Dict, Any

from kivy.app import App
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserIconView
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput

from web3 import Web3
from eth_account import Account

# ---------------------------
# Config por defecto (Ganache)
# ---------------------------
DEFAULT_RPC = "http://127.0.0.1:8545"
DEFAULT_CHAIN_ID = 1337  # usa `ganache -i 1337`
CHUNK_SIZE = 1024 * 1024  # 1MB

# ---------------------------
# Utilidades
# ---------------------------
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()

def load_abi(artifact_path: str) -> Dict[str, Any]:
    with open(artifact_path, "r", encoding="utf-8") as f:
        artifact = json.load(f)
    return artifact["abi"]

# ---------------------------
# Servicio Web3 anclaje/lectura
# ---------------------------
@dataclass
class AnchorConfig:
    rpc_url: str = DEFAULT_RPC
    contract_address: str = ""  # 0x...
    abi_path: str = "build/contracts/PhotoRegistry.json"
    private_key: Optional[str] = None  # SOLO dev. En prod: WalletConnect/keystore
    chain_id: int = DEFAULT_CHAIN_ID
    gas: int = 200000
    gas_price_gwei: Optional[float] = 1.0  # Ganache acepta gasPrice fijo

class AnchorService:
    def __init__(self, cfg: AnchorConfig):
        self.cfg = cfg
        self.w3 = Web3(Web3.HTTPProvider(cfg.rpc_url))
        if not self.w3.is_connected():
            raise RuntimeError(f"No se pudo conectar a RPC: {cfg.rpc_url}")
        abi = load_abi(cfg.abi_path)
        self.contract = self.w3.eth.contract(address=cfg.contract_address, abi=abi)

    def anchor(self, file_path: str) -> Dict[str, Any]:
        """Ancla el hash del archivo. Devuelve dict con hash, txHash, block."""
        if not self.cfg.private_key:
            raise RuntimeError("No hay private_key configurada (solo dev).")

        hexd = sha256_file(file_path)               # "abcdef..."
        h32 = "0x" + hexd                           # bytes32
        acct = Account.from_key(self.cfg.private_key)

        tx = self.contract.functions.anchor(h32).build_transaction({
            "from": acct.address,
            "nonce": self.w3.eth.get_transaction_count(acct.address),
            "gas": self.cfg.gas,
            "chainId": self.cfg.chain_id
        })
        # Gas price (Ganache)
        if self.cfg.gas_price_gwei is not None:
            tx["gasPrice"] = self.w3.to_wei(self.cfg.gas_price_gwei, "gwei")

        signed = acct.sign_transaction(tx)
        txh = self.w3.eth.send_raw_transaction(signed.rawTransaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(txh)

        return {
            "fileHash": h32,
            "txHash": txh.hex(),
            "block": receipt.blockNumber,
            "address": acct.address,
        }

    def verify(self, file_path: str) -> Dict[str, Any]:
        """Lee claims[hash] y devuelve owner/timestamp."""
        hexd = sha256_file(file_path)
        h32 = "0x" + hexd
        owner, ts = self.contract.functions.claims(h32).call()
        registered = int(owner, 16) != 0
        return {
            "fileHash": h32,
            "owner": owner,
            "timestamp": ts,
            "registered": registered
        }

    def transfer_by_file(self, file_path: str, new_owner: str) -> dict:
        if not self.cfg.private_key:
            raise RuntimeError("No hay private_key configurada (solo dev).")
        if not (new_owner.startswith("0x") and len(new_owner) == 42):
            raise RuntimeError("Dirección destino inválida")

        hexd = sha256_file(file_path)
        h32 = "0x" + hexd
        from eth_account import Account
        acct = Account.from_key(self.cfg.private_key)

        tx = self.contract.functions.transferOwner(h32, new_owner).build_transaction({
            "from": acct.address,
            "nonce": self.w3.eth.get_transaction_count(acct.address),
            "gas": self.cfg.gas,
            "chainId": self.cfg.chain_id
        })
        if self.cfg.gas_price_gwei is not None:
            tx["gasPrice"] = self.w3.to_wei(self.cfg.gas_price_gwei, "gwei")

        signed = acct.sign_transaction(tx)
        txh = self.w3.eth.send_raw_transaction(signed.rawTransaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(txh)
        return {"fileHash": h32, "to": new_owner, "txHash": txh.hex(), "block": receipt.blockNumber}

# ---------------------------
# UI Kivy lista para integrar
# ---------------------------
class AnchorWidget(BoxLayout):
    """
    Widget vertical con:
      - Selección de archivo
      - Muestra ruta y hash
      - Botón ANCLAR (tx on-chain en Ganache)
      - Botón VERIFICAR (consulta mapping)
      - Campo address contrato editable (opcional)
    """
    def __init__(self, cfg: Optional[AnchorConfig] = None, **kwargs):
        super().__init__(orientation="vertical", spacing=8, padding=12, **kwargs)

        # Config desde entorno si existe
        cfg = cfg or AnchorConfig(
            rpc_url=os.getenv("PHOTO_RPC", DEFAULT_RPC),
            contract_address=os.getenv("PHOTO_REGISTRY_ADDR", ""),
            abi_path=os.getenv("PHOTO_ABI_PATH", "build/contracts/PhotoRegistry.json"),
            private_key=os.getenv("DEV_PRIVATE_KEY", None),
            chain_id=int(os.getenv("PHOTO_CHAIN_ID", str(DEFAULT_CHAIN_ID))),
        )
        self.cfg = cfg
        self.service = None
        self.selected_path = None
        self.current_hash = None

        # UI
        self.addr_input = TextInput(
            text=self.cfg.contract_address or "",
            hint_text="0x... dirección del contrato PhotoRegistry",
            size_hint_y=None, height=44
        )
        self.rpc_label = Label(text=f"[b]RPC:[/b] {self.cfg.rpc_url}", markup=True, size_hint_y=None, height=24)

        btn_connect = Button(text="Conectar contrato", size_hint_y=None, height=48)
        btn_connect.bind(on_release=self._connect)

        btn_choose = Button(text="Elegir foto…", size_hint_y=None, height=48)
        btn_choose.bind(on_release=self._open_file_chooser)

        self.lbl_path = Label(text="[i]Sin archivo seleccionado[/i]", markup=True, halign="left", size_hint_y=None, height=24)
        self.lbl_hash = Label(text="[i]Hash pendiente[/i]", markup=True, halign="left", size_hint_y=None, height=24)

        btn_hash = Button(text="Calcular hash", size_hint_y=None, height=44)
        btn_hash.bind(on_release=lambda *_: self._compute_hash_async())

        btn_anchor = Button(text="Anclar (Ganache)", size_hint_y=None, height=48)
        btn_anchor.bind(on_release=lambda *_: self._anchor_async())

        self.dest_input = TextInput(
            text="",
            hint_text="0x... dirección destinatario para transferir",
            size_hint_y=None, height=44
        )
        btn_transfer = Button(text="Transferir propiedad", size_hint_y=None, height=48)
        btn_transfer.bind(on_release=lambda *_: self._transfer_async())

        btn_verify = Button(text="Verificar", size_hint_y=None, height=48)
        btn_verify.bind(on_release=lambda *_: self._verify_async())

        self.lbl_status = Label(text="", markup=True)

        # Layout
        self.add_widget(self.rpc_label)
        self.add_widget(self.addr_input)
        self.add_widget(btn_connect)
        self.add_widget(btn_choose)
        self.add_widget(self.lbl_path)
        self.add_widget(self.lbl_hash)
        self.add_widget(btn_hash)
        self.add_widget(btn_anchor)
        self.add_widget(self.dest_input)
        self.add_widget(btn_transfer)
        self.add_widget(btn_verify)
        self.add_widget(self.lbl_status)

    # ---------- Eventos/UI ----------
    def _connect(self, *_):
        addr = self.addr_input.text.strip()
        if not addr.startswith("0x") or len(addr) != 42:
            self._set_status("[color=ff5555]Dirección de contrato inválida[/color]")
            return
        self.cfg.contract_address = addr
        try:
            self.service = AnchorService(self.cfg)
            self._set_status("[color=5cb85c]✓ Conectado al contrato[/color]")
        except Exception as e:
            self._set_status(f"[color=ff5555]Error conectando: {e}[/color]")

    def _open_file_chooser(self, *_):
        chooser = FileChooserIconView(filters=["*.jpg", "*.jpeg", "*.png", "*.tif", "*.tiff", "*.heic"])
        pop = Popup(title="Selecciona una foto", content=chooser, size_hint=(0.9, 0.9))
        chooser.bind(on_submit=lambda _w, sel, _t: self._file_chosen(sel, pop))
        pop.open()

    def _file_chosen(self, selection, pop: Popup):
        if selection:
            self.selected_path = selection[0]
            self.lbl_path.text = f"[b]Archivo:[/b] {self.selected_path}"
            self.lbl_hash.text = "[i]Hash pendiente[/i]"
            self.current_hash = None
        pop.dismiss()

    def _compute_hash_async(self):
        if not self.selected_path:
            self._set_status("[color=ffae42]Elige un archivo primero[/color]")
            return
        self._set_status("[color=aaaaaa]Calculando SHA-256…[/color]")
        threading.Thread(target=self._compute_hash_thread, daemon=True).start()

    def _compute_hash_thread(self):
        try:
            hexd = sha256_file(self.selected_path)
            self.current_hash = hexd
            Clock.schedule_once(lambda *_: self._set_hash_ok(hexd))
        except Exception as e:
            Clock.schedule_once(lambda *_: self._set_status(f"[color=ff5555]Error hash: {e}[/color]"))

    def _set_hash_ok(self, hexd: str):
        self.lbl_hash.text = f"[b]SHA-256:[/b] {hexd}"
        self._set_status("[color=5cb85c]✓ Hash calculado[/color]")

    def _anchor_async(self):
        if not self.service:
            self._set_status("[color=ffae42]Conecta el contrato primero[/color]")
            return
        if not self.selected_path:
            self._set_status("[color=ffae42]Elige un archivo primero[/color]")
            return
        if not self.cfg.private_key:
            self._set_status("[color=ffae42]Configura DEV_PRIVATE_KEY (solo dev)[/color]")
            return
        self._set_status("[color=aaaaaa]Enviando tx de anclaje…[/color]")
        threading.Thread(target=self._anchor_thread, daemon=True).start()

    def _anchor_thread(self):
        try:
            res = self.service.anchor(self.selected_path)
            msg = f"[b]HASH:[/b] {res['fileHash']}  [b]TX:[/b] {res['txHash']}  [b]BLK:[/b] {res['block']}"
            Clock.schedule_once(lambda *_: self._set_status(f"[color=5cb85c]✓ Anclado: {msg}[/color]"))
        except Exception as e:
            Clock.schedule_once(lambda *_: self._set_status(f"[color=ff5555]Error anclando: {e}[/color]"))

    def _transfer_async(self):
        if not self.service:
            self._set_status("[color=ffae42]Conecta el contrato primero[/color]")
            return
        if not self.selected_path:
            self._set_status("[color=ffae42]Elige un archivo primero[/color]")
            return
        to = self.dest_input.text.strip()
        if not (to.startswith("0x") and len(to) == 42):
            self._set_status("[color=ffae42]Dirección destino inválida[/color]")
            return
        self._set_status("[color=aaaaaa]Transfiriendo…[/color]")
        import threading
        threading.Thread(target=self._transfer_thread, args=(to,), daemon=True).start()

    def _transfer_thread(self, to_addr: str):
        try:
            res = self.service.transfer_by_file(self.selected_path, to_addr)
            msg = f"[b]HASH[/b] {res['fileHash']}  [b]TO[/b] {res['to']}  [b]TX[/b] {res['txHash']}  [b]BLK[/b] {res['block']}"
            from kivy.clock import Clock
            Clock.schedule_once(lambda *_: self._set_status(f"[color=5cb85c]✓ Transferido: {msg}[/color]"))
        except Exception as e:
            from kivy.clock import Clock
            Clock.schedule_once(lambda *_: self._set_status(f"[color=ff5555]Error transfiriendo: {e}[/color]"))

    def _verify_async(self):
        if not self.service:
            self._set_status("[color=ffae42]Conecta el contrato primero[/color]")
            return
        if not self.selected_path:
            self._set_status("[color=ffae42]Elige un archivo primero[/color]")
            return
        self._set_status("[color=aaaaaa]Verificando…[/color]")
        threading.Thread(target=self._verify_thread, daemon=True).start()

    def _verify_thread(self):
        try:
            res = self.service.verify(self.selected_path)
            if res["registered"]:
                msg = f"[b]HASH[/b] {res['fileHash']}  [b]OWNER[/b] {res['owner']}  [b]TS[/b] {res['timestamp']}"
                Clock.schedule_once(lambda *_: self._set_status(f"[color=5cb85c]✓ VERIFICADA: {msg}[/color]"))
            else:
                Clock.schedule_once(lambda *_: self._set_status("[color=ff5555]NO REGISTRADA[/color]"))
        except Exception as e:
            Clock.schedule_once(lambda *_: self._set_status(f"[color=ff5555]Error verificando: {e}[/color]"))

    def _set_status(self, txt: str):
        self.lbl_status.text = txt

# ---------------------------
# App de ejemplo (opcional)
# ---------------------------
class AnchorDemoApp(App):
    def build(self):
        # Permite configurar por entorno:
        #   set PHOTO_REGISTRY_ADDR=0x...
        #   set DEV_PRIVATE_KEY=0x...
        #   set PHOTO_RPC=http://127.0.0.1:8545
        #   set PHOTO_CHAIN_ID=1337
        return AnchorWidget()

if __name__ == "__main__":
    AnchorDemoApp().run()
