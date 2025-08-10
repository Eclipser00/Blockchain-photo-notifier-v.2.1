from plyer import camera
from pathlib import Path
from datetime import datetime
from tkinter import Tk, filedialog
import exifread

# Tomamos foto con el movil, aunque posiblemente en el futuro mejor sera obtner siempre la foto de la galeria....
def tomar_foto_android():
    ruta = Path("/sdcard/DCIM/Camera") / f"foto_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
    def listo(_path): print("Foto guardada en:", _path)
    camera.take_picture(str(ruta), listo)

# Mostramos la galeria de windows, y seleccionamos, habra que hacer algun sistema para que pueda explorar archivos en el equipo
def seleccionar_foto_windows():
    Tk().withdraw()
    return filedialog.askopenfilename(filetypes=[("Imágenes", "*.jpg;*.jpeg;*.png;*.heic")])

# Extraemos metadatos de la foto, en el futuro añadiremos mas opciones...y que hacer si el metadato esta en blanco.....
def leer_exif(path):
    with open(path, "rb") as f:
        tags = exifread.process_file(f, details=False)
    # Algunos campos típicos (si existen)
    campos = {
        "DateTimeOriginal": str(tags.get("EXIF DateTimeOriginal")),
        "Make":             str(tags.get("Image Make")),
        "Model":            str(tags.get("Image Model")),
        "LensModel":        str(tags.get("EXIF LensModel")),
        "FNumber":          str(tags.get("EXIF FNumber")),
        "ExposureTime":     str(tags.get("EXIF ExposureTime")),
        "ISOSpeedRatings":  str(tags.get("EXIF ISOSpeedRatings")),
        "FocalLength":      str(tags.get("EXIF FocalLength")),
        "GPSLatitude":      str(tags.get("GPS GPSLatitude")),
        "GPSLatitudeRef":   str(tags.get("GPS GPSLatitudeRef")),
        "GPSLongitude":     str(tags.get("GPS GPSLongitude")),
        "GPSLongitudeRef":  str(tags.get("GPS GPSLongitudeRef")),
    }
    return {k:v for k,v in campos.items() if v != "None"}

# chatgpt me da esta funcion igual es necesaria....
def _to_deg(value):
    # value típico: [num/den, num/den, num/den]
    d = float(value.values[0].num) / float(value.values[0].den)
    m = float(value.values[1].num) / float(value.values[1].den)
    s = float(value.values[2].num) / float(value.values[2].den)
    return d + (m/60.0) + (s/3600.0)

def gps_a_decimal(tags):
    try:
        lat = _to_deg(tags["GPS GPSLatitude"])
        if str(tags["GPS GPSLatitudeRef"]).upper().startswith("S"):
            lat = -lat
        lon = _to_deg(tags["GPS GPSLongitude"])
        if str(tags["GPS GPSLongitudeRef"]).upper().startswith("W"):
            lon = -lon
        return lat, lon
    except Exception:
        return None




