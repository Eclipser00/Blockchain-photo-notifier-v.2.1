# photo_anchor/ui.py
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserIconView
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput
from kivy.clock import Clock
from .service import DuplicateHashError
import os
import json

import threading
from .service import AnchorConfig, AnchorService

class AnchorWidget(BoxLayout):
    def __init__(self, cfg: AnchorConfig, **kwargs):
        super().__init__(orientation="vertical", spacing=8, padding=12, **kwargs)
        # Clear any pre-existing private key so the user must enter it manually
        self.cfg = cfg
        self.cfg.private_key = ""
        # State variables
        self.service = None
        self.selected_path = None
        self.current_hash = None
        self.selected_sig_path = None  # para verificar firma
        # RPC label shown at the top
        self.rpc_label = Label(text=f"[b]RPC:[/b] {self.cfg.rpc_url}", markup=True, size_hint_y=None, height=24)
        # Text input for the Ethereum private key (hidden input)
        self.priv_input = TextInput(text="", hint_text="Clave privada (0x…)", size_hint_y=None, height=44, password=True)
        self.priv_input.bind(text=self._update_private_key)
        # Button to choose an image file
        btn_choose = Button(text="Elegir foto…", size_hint_y=None, height=48)
        btn_choose.bind(on_release=self._open_file_chooser)
        # Labels for selected path and hash
        self.lbl_path = Label(text="[i]Sin archivo seleccionado[/i]", markup=True, size_hint_y=None, height=24)
        self.lbl_hash = Label(text="[i]Hash pendiente[/i]", markup=True, size_hint_y=None, height=24)
        # Button to compute SHA-256 hash
        btn_hash = Button(text="Calcular hash", size_hint_y=None, height=44)
        btn_hash.bind(on_release=lambda *_: self._compute_hash_async())
        # Off-chain buttons: generate keys, sign, verify signature
        btn_keys = Button(text="Crear claves (keys)", size_hint_y=None, height=44)
        btn_keys.bind(on_release=lambda *_: self._gen_keys_async())
        btn_sign = Button(text="Firmar (Ed25519)", size_hint_y=None, height=44)
        btn_sign.bind(on_release=lambda *_: self._sign_async())
        btn_verify_sig = Button(text="Verificar firma", size_hint_y=None, height=44)
        btn_verify_sig.bind(on_release=lambda *_: self._verify_sig_async())
        # On-chain anchor and verify buttons
        btn_anchor = Button(text="Anclar (Ganache)", size_hint_y=None, height=48)
        btn_anchor.bind(on_release=lambda *_: self._anchor_async())
        btn_verify = Button(text="Verificar", size_hint_y=None, height=48)
        btn_verify.bind(on_release=lambda *_: self._verify_async())
        # Status label for feedback messages
        self.lbl_status = Label(text="", markup=True)
        # Add widgets in the desired order
        for w in [self.rpc_label, btn_keys, btn_choose, self.lbl_path, self.lbl_hash, btn_hash, btn_sign, btn_verify_sig, self.priv_input, btn_anchor, btn_verify, self.lbl_status]:
            self.add_widget(w)
        # Automatically attempt to connect to the contract
        self._auto_connect()

    # --- helpers UI ---
    def _auto_connect(self) -> None:
        """
        Automatically connect to the deployed smart contract using the address
        stored in the configuration.  Connection status is displayed in the UI
        and logged to the console.  This method sets up default PEM paths if
        none are provided and validates the contract address before attempting
        the connection.
        """
        addr = self.cfg.contract_address.strip()
        # Set default PEM paths for off‑chain signing if they are not already set
        self.cfg.signer_private_pem_path = self.cfg.signer_private_pem_path or os.path.join("keys", "author_private.pem")
        self.cfg.signer_public_pem_path = self.cfg.signer_public_pem_path or os.path.join("keys", "author_public.pem")
        # Validate the contract address format
        if not (addr.startswith("0x") and len(addr) == 42):
            msg = "[color=ff5555]Dirección de contrato inválida[/color]"
            self._set_status(msg)
            print("Dirección de contrato inválida")
            return
        # Inform the user that a connection attempt is underway
        self._set_status("[color=aaaaaa]Conectándose al contrato…[/color]")
        try:
            self.service = AnchorService(self.cfg)
            self._set_status("[color=5cb85c]✓ Contrato conectado[/color]")
            print("✓ Conectado")
        except Exception as e:
            err_msg = f"[color=ff5555]Error conectando: {e}[/color]"
            self._set_status(err_msg)
            print(f"Error conectando: {e}")

    def _update_private_key(self, instance, value) -> None:
        """
        Update the configuration's private key when the user edits the private
        key input field.  Leading and trailing whitespace is removed.  The
        private key is stored only in memory and is not persisted anywhere
        else.
        """
        self.cfg.private_key = value.strip() if value else ""

    def _open_file_chooser(self, *_):
        chooser = FileChooserIconView(filters=["*.jpg","*.jpeg","*.png","*.tif","*.tiff","*.heic"])
        pop = Popup(title="Selecciona una foto", content=chooser, size_hint=(0.9,0.9))
        chooser.bind(on_submit=lambda _w, sel, _t: self._file_chosen(sel, pop))
        pop.open()

    def _file_chosen(self, selection, pop):
        if selection:
            self.selected_path = selection[0]
            self.lbl_path.text = f"[b]Archivo:[/b] {self.selected_path}"
            self.lbl_hash.text = "[i]Hash pendiente[/i]"
            self.current_hash = None
        pop.dismiss()

    def _compute_hash_async(self):
        if not self.selected_path:
            self._set_status("[color=ffae42]Elige un archivo primero[/color]"); return
        self._set_status("[color=aaaaaa]Calculando SHA-256…[/color]")
        threading.Thread(target=self._compute_hash_thread, daemon=True).start()

    def _compute_hash_thread(self):
        from .service import sha256_file
        try:
            hexd = sha256_file(self.selected_path)
            self.current_hash = hexd
            Clock.schedule_once(lambda *_: self._set_hash_ok(hexd))
        except Exception as e:
            Clock.schedule_once(lambda *_, err=e: self._set_status(f"[color=ff5555]Error hash: {err}[/color]"))

    def _set_hash_ok(self, hexd):
        self.lbl_hash.text = f"[b]SHA-256:[/b] {hexd}"
        self._set_status("[color=5cb85c]✓ Hash calculado[/color]")

    def _anchor_async(self):
        if not self.service:
            self._set_status("[color=ffae42]No se ha conectado al contrato (revisa la consola)[/color]"); return
        if not self.selected_path:
            self._set_status("[color=ffae42]Elige un archivo primero[/color]"); return
        if not self.cfg.private_key:
            self._set_status("[color=ffae42]Introduce tu clave privada antes de anclar[/color]"); return
        self._set_status("[color=aaaaaa]Enviando tx…[/color]")
        threading.Thread(target=self._anchor_thread, daemon=True).start()

    def _anchor_thread(self):
        try:
            res = self.service.anchor(self.selected_path)
            msg = f"[b]HASH[/b] {res['fileHash']}  [b]TX[/b] {res['txHash']}  [b]BLK[/b] {res['block']}"
            Clock.schedule_once(lambda *_: self._set_status(f"[color=5cb85c]✓ Anclado: {msg}[/color]"))
        except DuplicateHashError as e:
            Clock.schedule_once(lambda *_, err=e: self._set_status(f"[color=ffae42]⚠: {err}[/color]"))
        except Exception as e:
            Clock.schedule_once(lambda *_, err=e: self._set_status(f"[color=ff5555]Error anclando: {err}[/color]"))

    def _verify_async(self):
        if not self.service:
            self._set_status("[color=ffae42]No se ha conectado al contrato (revisa la consola)[/color]"); return
        if not self.selected_path:
            self._set_status("[color=ffae42]Elige un archivo primero[/color]"); return
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
            Clock.schedule_once(lambda *_, err=e: self._set_status(f"[color=ff5555]Error verificando: {err}[/color]"))

        # ----------------- OFF-CHAIN: claves/firma/verificación -----------------

    def _gen_keys_async(self):
        if not self.service:
            self._set_status("[color=ffae42]No se ha conectado al contrato (revisa la consola)[/color]");
            return
        self._set_status("[color=aaaaaa]Creando claves Ed25519…[/color]")
        threading.Thread(target=self._gen_keys_thread, daemon=True).start()

    def _gen_keys_thread(self):
        try:
            os.makedirs("keys", exist_ok=True)
            priv = os.path.join("keys", "author_private.pem")
            pub = os.path.join("keys", "author_public.pem")
            res = self.service.generate_signing_keys_if_needed(priv, pub)
            Clock.schedule_once(lambda *_: self._set_status(
                f"[color=5cb85c]✓ Claves creadas[/color]\n[b]Priv:[/b] {res['private_pem']}\n[b]Pub:[/b] {res['public_pem']}"))
        except Exception as e:
            Clock.schedule_once(lambda *_, err=e: self._set_status(f"[color=ff5555]Error creando claves: {err}[/color]"))

    def _sign_async(self):
        if not self.service:
            self._set_status("[color=ffae42]No se ha conectado al contrato (revisa la consola)[/color]");
            return
        if not self.selected_path:
            self._set_status("[color=ffae42]Elige un archivo primero[/color]");
            return
        self._set_status("[color=aaaaaa]Firmando archivo (Ed25519)…[/color]")
        threading.Thread(target=self._sign_thread, daemon=True).start()

    def _sign_thread(self):
        try:
            env = self.service.sign_file_offchain(self.selected_path)  # dict
            out_path = self.selected_path + ".sig.json"
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(env, f, ensure_ascii=False, indent=2)
            Clock.schedule_once(lambda *_: self._set_status(
                f"[color=5cb85c]✓ Firma creada[/color]\n[b]Hash:[/b] {env['fileHash']}\n[b]Sig:[/b] {out_path}"))
        except Exception as e:
            Clock.schedule_once(lambda *_, err=e: self._set_status(f"[color=ff5555]Error firmando: {err}[/color]"))

    def _verify_sig_async(self):
        if not self.service:
            self._set_status("[color=ffae42]No se ha conectado al contrato (revisa la consola)[/color]");
            return
        if not self.selected_path:
            self._set_status("[color=ffae42]Elige primero el archivo a verificar[/color]");
            return
        # Selector de .sig.json
        chooser = FileChooserIconView(filters=["*.sig.json"])
        pop = Popup(title="Selecciona la firma (.sig.json)", content=chooser, size_hint=(0.9, 0.9))
        chooser.bind(on_submit=lambda _w, sel, _t: self._sig_chosen_and_verify(sel, pop))
        pop.open()

    def _sig_chosen_and_verify(self, selection, pop):
        pop.dismiss()
        if not selection:
            self._set_status("[color=ffae42]No seleccionaste firma[/color]");
            return
        self.selected_sig_path = selection[0]
        self._set_status("[color=aaaaaa]Verificando firma…[/color]")
        threading.Thread(target=self._verify_sig_thread, daemon=True).start()

    def _verify_sig_thread(self):
        try:
            env = json.load(open(self.selected_sig_path, "r", encoding="utf-8"))
            res = self.service.verify_file_offchain(self.selected_path, env)
            if res.get("ok"):
                Clock.schedule_once(lambda *_: self._set_status(
                    f"[color=5cb85c]✓ Firma válida[/color]\n[b]Hash:[/b] {res['fileHash']}  [b]Alg:[/b] {res['algorithm']}"))
            else:
                Clock.schedule_once(
                    lambda *_: self._set_status(f"[color=ff5555]Firma inválida[/color]\n{res.get('reason', '')}"))
        except Exception as e:
            Clock.schedule_once(lambda *_, err=e: self._set_status(f"[color=ff5555]Error verificando firma: {err}[/color]"))

    def _set_status(self, txt):
        self.lbl_status.text = txt


