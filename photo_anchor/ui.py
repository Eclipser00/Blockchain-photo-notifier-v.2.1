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
        self.cfg = cfg
        self.service = None
        self.selected_path = None
        self.current_hash = None
        self.selected_sig_path = None  # para verificar firma

        self.addr_input = TextInput(text=self.cfg.contract_address.strip() or "", hint_text="0x... contrato", size_hint_y=None, height=44)
        self.rpc_label = Label(text=f"[b]RPC:[/b] {self.cfg.rpc_url}", markup=True, size_hint_y=None, height=24)

        btn_connect = Button(text="Conectar contrato", size_hint_y=None, height=48)
        btn_connect.bind(on_release=self._connect)

        btn_choose = Button(text="Elegir foto…", size_hint_y=None, height=48)
        btn_choose.bind(on_release=self._open_file_chooser)

        self.lbl_path = Label(text="[i]Sin archivo seleccionado[/i]", markup=True, size_hint_y=None, height=24)
        self.lbl_hash = Label(text="[i]Hash pendiente[/i]", markup=True, size_hint_y=None, height=24)

        btn_hash = Button(text="Calcular hash", size_hint_y=None, height=44)
        btn_hash.bind(on_release=lambda *_: self._compute_hash_async())

        btn_anchor = Button(text="Anclar (Ganache)", size_hint_y=None, height=48)
        btn_anchor.bind(on_release=lambda *_: self._anchor_async())

        btn_verify = Button(text="Verificar", size_hint_y=None, height=48)
        btn_verify.bind(on_release=lambda *_: self._verify_async())

        # === NUEVOS BOTONES OFF-CHAIN ===
        btn_keys = Button(text="Crear claves (keys)", size_hint_y=None, height=44);
        btn_keys.bind(on_release=lambda *_: self._gen_keys_async())
        btn_sign = Button(text="Firmar (Ed25519)", size_hint_y=None, height=44);
        btn_sign.bind(on_release=lambda *_: self._sign_async())
        btn_verify_sig = Button(text="Verificar firma", size_hint_y=None, height=44);
        btn_verify_sig.bind(on_release=lambda *_: self._verify_sig_async())

        self.lbl_status = Label(text="", markup=True)

        for w in [self.rpc_label, self.addr_input, btn_connect, btn_choose, self.lbl_path, self.lbl_hash,
                  btn_hash, btn_anchor,btn_keys, btn_sign, btn_verify_sig, btn_verify, self.lbl_status]:
            self.add_widget(w)

    # --- helpers UI ---
    def _connect(self, *_):
        addr = self.addr_input.text.strip()
        if not (addr.startswith("0x") and len(addr) == 42):
            self._set_status("[color=ff5555]Dirección de contrato inválida[/color]"); return
        self.cfg.contract_address = addr

        # (opcional) setea rutas por defecto de PEM si no existen
        self.cfg.signer_private_pem_path = self.cfg.signer_private_pem_path or os.path.join("keys","author_private.pem")
        self.cfg.signer_public_pem_path = self.cfg.signer_public_pem_path or os.path.join("keys", "author_public.pem")

        try:
            self.service = AnchorService(self.cfg)
            self._set_status("[color=5cb85c]✓ Conectado[/color]")
        except Exception as e:
            self._set_status(f"[color=ff5555]Error conectando: {e}[/color]")

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
            self._set_status("[color=ffae42]Conecta el contrato primero[/color]"); return
        if not self.selected_path:
            self._set_status("[color=ffae42]Elige un archivo primero[/color]"); return
        if not self.cfg.private_key:
            self._set_status("[color=ffae42]Configura private_key (solo dev)[/color]"); return
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
            self._set_status("[color=ffae42]Conecta el contrato primero[/color]"); return
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
            self._set_status("[color=ffae42]Conecta el contrato primero[/color]");
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
            self._set_status("[color=ffae42]Conecta el contrato primero[/color]");
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
            self._set_status("[color=ffae42]Conecta el contrato primero[/color]");
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


