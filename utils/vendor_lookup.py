"""
utils/vendor_lookup.py

Resuelve el fabricante (vendor) de un dispositivo a partir del OUI
(Organizationally Unique Identifier) de su dirección MAC: los primeros
3 octetos, que la IEEE asigna de forma única a cada fabricante de
tarjetas de red.

Diseño clave: el escaneo normal (--scan) NUNCA necesita internet. La
base de datos vive como un JSON local (config.OUI_DB_PATH), generado a
partir del oui.txt oficial de la IEEE, y se carga una sola vez en
memoria (caché a nivel de módulo). Solo `update_oui_database()` —
invocada explícitamente con --update-oui— sale a internet a refrescar
ese archivo.
"""

import json
import os
import re
import urllib.request

import config
from utils.logger import log_info, log_ok, log_err, log_warn

# Caché en memoria de la base de datos OUI ya cargada. Se mantiene a
# nivel de módulo (no por instancia) porque un mismo escaneo puede
# resolver decenas de MACs y no tiene sentido releer el JSON del disco
# en cada una.
_oui_cache = None


def _normalize_oui(mac: str) -> str:
    """
    Extrae los 3 primeros octetos de una MAC y los normaliza a
    mayúsculas sin separadores (ej. "70:C7:F2:10:E1:4A" -> "70C7F2").
    Este es el formato de clave usado en data/oui_db.json.

    Lanza ValueError si la MAC está mal formada (menos de 6 dígitos
    hexadecimales), para que el llamador pueda degradarlo a "Unknown"
    en vez de propagar una excepción hasta el escaneo completo.
    """
    solo_hex = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(solo_hex) < 6:
        raise ValueError(f"MAC mal formateada: {mac!r}")
    return solo_hex[:6].upper()


def _is_locally_administered(mac: str) -> bool:
    """
    Comprueba el bit "locally administered" (el segundo bit menos
    significativo del primer octeto de la MAC). Cuando está activo, la
    dirección NO fue asignada por la IEEE a ningún fabricante: fue
    generada aleatoriamente por el propio dispositivo.

    Esto es exactamente lo que hacen iOS y Android modernos por
    defecto al conectarse a redes WiFi (MAC randomization), para
    dificultar el tracking de dispositivos por MAC. Si no filtráramos
    este caso, buscaríamos ese prefijo en la base OUI y devolveríamos
    un fabricante real pero completamente engañoso.
    """
    solo_hex = re.sub(r"[^0-9A-Fa-f]", "", mac)
    primer_octeto = int(solo_hex[0:2], 16)
    return bool(primer_octeto & 0b00000010)


def _load_database() -> dict:
    """Carga data/oui_db.json en memoria una única vez (lazy loading + caché)."""
    global _oui_cache
    if _oui_cache is not None:
        return _oui_cache

    if not os.path.exists(config.OUI_DB_PATH):
        log_warn(f"{config.OUI_DB_PATH} not found; run --update-oui to generate it.")
        _oui_cache = {}
        return _oui_cache

    try:
        with open(config.OUI_DB_PATH, "r", encoding="utf-8") as f:
            _oui_cache = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        log_err(f"Could not read {config.OUI_DB_PATH}: {e}")
        _oui_cache = {}

    return _oui_cache


def get_vendor(mac: str) -> str:
    """
    Devuelve el nombre del fabricante asociado a una MAC, o una cadena
    descriptiva cuando no aplica una búsqueda normal.

    Orden de comprobaciones (importa el orden): primero se comprueba si
    la MAC es aleatoria, porque en ese caso CUALQUIER resultado de la
    base OUI sería incorrecto — ese prefijo nunca fue asignado a un
    fabricante real. Solo si no es aleatoria tiene sentido consultar
    data/oui_db.json.
    """
    try:
        if _is_locally_administered(mac):
            return "Randomized MAC (likely mobile device)"
        oui = _normalize_oui(mac)
    except ValueError:
        return "Unknown"

    database = _load_database()
    return database.get(oui, "Unknown")


def update_oui_database() -> bool:
    """
    Descarga el listado oficial de OUIs de la IEEE (oui.txt) y lo
    convierte a data/oui_db.json.

    Es la ÚNICA función de todo el proyecto que necesita conexión a
    internet: el resto de la herramienta (incluido el escaneo normal)
    siempre trabaja contra la copia local ya generada, precisamente
    para que --scan funcione en un laboratorio aislado sin salida real.
    """
    log_info(f"Downloading OUI database from {config.OUI_SOURCE_URL} ...")
    # standards-oui.ieee.org rechaza el User-Agent por defecto de urllib
    # (responde 418); un User-Agent de navegador normal es suficiente
    # para que sirva el archivo.
    request = urllib.request.Request(
        config.OUI_SOURCE_URL,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Internuncio-OUI-Updater/1.0)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            contenido = response.read().decode("utf-8", errors="ignore")
    except Exception as e:
        log_err(f"Could not download the OUI database: {e}")
        return False

    # Cada entrada del oui.txt de la IEEE trae una línea como:
    #   70-C7-F2   (hex)		Apple, Inc
    # Nos interesa el prefijo hexadecimal (con guiones) y el nombre del
    # fabricante que sigue a "(hex)"; el resto (dirección postal, etc.)
    # se descarta porque no lo necesitamos para el escáner.
    patron = re.compile(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", re.MULTILINE)

    base_datos = {}
    for prefijo, vendor in patron.findall(contenido):
        oui = prefijo.replace("-", "").upper()
        base_datos[oui] = vendor.strip()

    if not base_datos:
        log_err("Downloaded content did not match the expected format; database was not generated.")
        return False

    os.makedirs(os.path.dirname(config.OUI_DB_PATH), exist_ok=True)
    with open(config.OUI_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(base_datos, f, indent=2, ensure_ascii=False, sort_keys=True)

    # Invalida la caché en memoria para que la próxima búsqueda recargue
    # el archivo recién escrito en vez de seguir usando la versión vieja.
    global _oui_cache
    _oui_cache = None

    log_ok(f"OUI database updated: {len(base_datos)} vendors saved to {config.OUI_DB_PATH}")
    return True
