# main_hash_kivy.py
import os
import hashlib
import threading

from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.filechooser import FileChooserIconView

'''
Usa un FileChooser para seleccionar la imagen.
Calcula el hash en un hilo (no bloquea la UI).
Muestra el ruta + hash y un botón para copiar al portapapeles.
'''

CHUNK_SIZE = 1024 * 1024  # 1 MB

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

class HashScreen(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation="vertical", spacing=8, padding=12, **kwargs)

        self.lbl_path = Label(text="[i]Sin archivo seleccionado[/i]", markup=True, halign="left")
        self.lbl_hash = Label(text="[i]Hash pendiente[/i]", markup=True, halign="left")
        self.lbl_status = Label(text="", markup=True)

        btn_choose = Button(text="Elegir foto…", size_hint_y=None, height=48)
        btn_choose.bind(on_release=self.open_file_chooser)

        btn_copy = Button(text="Copiar hash", size_hint_y=None, height=48)
        btn_copy.bind(on_release=self.copy_hash)

        self.add_widget(btn_choose)
        self.add_widget(self.lbl_path)
        self.add_widget(self.lbl_hash)
        self.add_widget(btn_copy)
        self.add_widget(self.lbl_status)

        self.selected_path = None
        self.current_hash = None

    def open_file_chooser(self, *_):
        chooser = FileChooserIconView(filters=["*.jpg", "*.jpeg", "*.png", "*.heic", "*.tif", "*.tiff"])
        chooser.bind(on_submit=lambda _w, sel, _touch: self._file_chosen(sel))
        chooser_popup = Popup(title="Selecciona una foto", content=chooser, size_hint=(0.9, 0.9))
        # guardamos ref para poder cerrarlo al elegir
        chooser_popup.open()
        chooser.bind(on_submit=lambda _w, sel, _t: chooser_popup.dismiss())

    def _file_chosen(self, selection):
        if not selection:
            return
        path = selection[0]
        self.selected_path = path
        self.lbl_path.text = f"[b]Archivo:[/b] {path}"
        self.lbl_hash.text = "[i]Calculando SHA-256…[/i]"
        self.lbl_status.text = ""

        # Calcula en un hilo
        threading.Thread(target=self._compute_hash_thread, args=(path,), daemon=True).start()

    def _compute_hash_thread(self, path):
        try:
            digest = sha256_file(path)
            self.current_hash = digest
            Clock.schedule_once(lambda *_: self._set_hash_ok(digest))
        except Exception as e:
            Clock.schedule_once(lambda *_: self._set_hash_err(str(e)))

    def _set_hash_ok(self, digest):
        self.lbl_hash.text = f"[b]SHA-256:[/b] {digest}"
        self.lbl_status.text = "[color=5cb85c]✓ Hash calculado[/color]"

    def _set_hash_err(self, msg):
        self.lbl_hash.text = "[color=ff5555]Error calculando hash[/color]"
        self.lbl_status.text = f"[color=ff5555]{msg}[/color]"

    def copy_hash(self, *_):
        if not self.current_hash:
            self.lbl_status.text = "[color=ffae42]Nada que copiar[/color]"
            return
        Clipboard.copy(self.current_hash)
        self.lbl_status.text = "[color=5cb85c]Hash copiado al portapapeles[/color]"

class HashApp(App):
    def build(self):
        self.title = "Hash de Foto (SHA-256)"
        return HashScreen()

if __name__ == "__main__":
    HashApp().run()
