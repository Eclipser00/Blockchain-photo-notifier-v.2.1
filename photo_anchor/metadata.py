# photo_anchor/metadata.py
from __future__ import annotations
import json
from typing import Any, Dict
import exifread

# Conjunto de etiquetas EXIF "estables"
EXIF_KEEP = {
    "EXIF DateTimeOriginal",
    "Image Make",
    "Image Model",
    "EXIF LensModel",
    "EXIF FNumber",
    "EXIF ExposureTime",
    "EXIF ISOSpeedRatings",         # o PhotographicSensitivity en algunas cámaras
    "Image Orientation",
    "GPS GPSLatitude",
    "GPS GPSLatitudeRef",
    "GPS GPSLongitude",
    "GPS GPSLongitudeRef",
    "GPS GPSAltitude",
    "GPS GPSAltitudeRef",
}

def _to_plain(v: Any) -> Any:
    # Convierte razones/fracciones/objetos EXIF a string estable
    try:
        s = str(v)
        if len(s) > 1024:
            return s[:1024] + "…"
        return s
    except Exception:
        return None

def extract_exif_only(file_path: str) -> Dict[str, Any]:
    """
    Extrae SOLO el subconjunto EXIF_KEEP y lo devuelve como dict simple.
    Si no hay EXIF o hay error → devuelve {} (no fallamos).
    """
    out: Dict[str, Any] = {}
    try:
        with open(file_path, "rb") as f:
            tags = exifread.process_file(f, details=False, strict=True)
        for k, v in tags.items():
            if k in EXIF_KEEP:
                out[k] = _to_plain(v)
    except Exception:
        pass
    return out

def canonical_json(data: Dict[str, Any]) -> str:
    """
    JSON estable: claves ordenadas, sin espacios extra.
    """
    return json.dumps(data or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
