# photo_anchor/ui.py
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserIconView
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput
from kivy.clock import Clock

import threading
from .service import AnchorConfig, AnchorService

class AnchorWidget(BoxLayout):
    def __init__(self, cfg: AnchorConfig, **kwargs):
        super().__init__(orientation="vertical", spacing=8, padding=12, **kwargs)
        self.cfg = cfg
        self.service = None
        self.selected_path = None
        self.current_hash = None

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

        self.dest_input = TextInput(text="", hint_text="0x... destinatario", size_hint_y=None, height=44)
        btn_transfer = Button(text="Transferir propiedad", size_hint_y=None, height=48)
        btn_transfer.bind(on_release=lambda *_: self._transfer_async())

        btn_verify = Button(text="Verificar", size_hint_y=None, height=48)
        btn_verify.bind(on_release=lambda *_: self._verify_async())

        self.lbl_status = Label(text="", markup=True)

        for w in [self.rpc_label, self.addr_input, btn_connect, btn_choose, self.lbl_path, self.lbl_hash,
                  btn_hash, btn_anchor, self.dest_input, btn_transfer, btn_verify, self.lbl_status]:
            self.add_widget(w)

    # --- helpers UI ---
    def _connect(self, *_):
        addr = self.addr_input.text.strip()
        if not (addr.startswith("0x") and len(addr) == 42):
            self._set_status("[color=ff5555]Dirección de contrato inválida[/color]"); return
        self.cfg.contract_address = addr
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
        except Exception as e:
            Clock.schedule_once(lambda *_, err=e: self._set_status(f"[color=ff5555]Error anclando: {err}[/color]"))

    def _transfer_async(self):
        if not self.service:
            self._set_status("[color=ffae42]Conecta el contrato primero[/color]"); return
        if not self.selected_path:
            self._set_status("[color=ffae42]Elige un archivo primero[/color]"); return
        to = self.dest_input.text.strip()
        if not (to.startswith("0x") and len(to) == 42):
            self._set_status("[color=ffae42]Dirección destino inválida[/color]"); return
        self._set_status("[color=aaaaaa]Transfiriendo…[/color]")
        threading.Thread(target=self._transfer_thread, args=(to,), daemon=True).start()

    def _transfer_thread(self, to_addr):
        try:
            res = self.service.transfer_by_file(self.selected_path, to_addr)
            msg = f"[b]HASH[/b] {res['fileHash']}  [b]TO[/b] {res['to']}  [b]TX[/b] {res['txHash']}  [b]BLK[/b] {res['block']}"
            Clock.schedule_once(lambda *_: self._set_status(f"[color=5cb85c]✓ Transferido: {msg}[/color]"))
        except Exception as e:
            Clock.schedule_once(lambda *_, err=e: self._set_status(f"[color=ff5555]Error transfiriendo: {err}[/color]"))

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

    def _set_status(self, txt):
        self.lbl_status.text = txt


