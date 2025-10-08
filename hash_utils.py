"""
hash_utils.py — Funciones puras de hashing/HMAC.

Qué hace:
- Provee utilidades para hashear textos y archivos de forma incremental.
- Soporta salting, peppering (inyectado por el llamador desde st.secrets) y HMAC.
- Incluye comparador seguro de hashes.

Por qué:
- Separar lógica de la UI (app.py) facilita pruebas y mantenimiento.

Riesgos/limitaciones:
- SHA-1 tiene colisiones conocidas: usar solo con fines didácticos.
- Pepper y claves no deben estar hardcodeadas.
- Para contraseñas reales: PBKDF2/Argon2/bcrypt/scrypt (no implementado aquí).
"""

import hashlib
import hmac
import secrets
from typing import Callable, Optional, Tuple

# Algoritmos soportados en hashlib (por defecto sha256):
SUPPORTED_ALGOS = ["sha256", "sha1", "sha512", "blake2b"]


def get_hasher(algorithm: str = "sha256"):
    """Devuelve un objeto hasher de hashlib según el algoritmo."""
    algo = algorithm.lower()
    if algo not in SUPPORTED_ALGOS:
        raise ValueError(f"Algoritmo no soportado: {algorithm}")
    return getattr(hashlib, algo)()


def hash_text(
    text: str,
    algorithm: str = "sha256",
    salt: Optional[bytes] = None,
    pepper: Optional[bytes] = None,
) -> Tuple[str, Optional[bytes]]:
    """
    Calcula el hash (hex) de un texto con algoritmo dado.
    - Puede añadir 'salt' (bytes) y 'pepper' (bytes) antes de hashear.
    - Devuelve (hex_digest, salt_usada_o_None).
    """
    hasher = get_hasher(algorithm)
    data = text.encode("utf-8")

    if salt:
        hasher.update(salt)  # la sal se añade y se suele almacenar junto al hash
    if pepper:
        hasher.update(pepper)  # el pepper es secreto y no se almacena con el hash

    hasher.update(data)
    return hasher.hexdigest(), salt


def hash_file_chunked(
    file_obj,
    algorithm: str = "sha256",
    chunk_size: int = 8192,
    salt: Optional[bytes] = None,
    pepper: Optional[bytes] = None,
    progress_callback: Optional[Callable[[int], None]] = None,
    size_limit_bytes: Optional[int] = 10 * 1024 * 1024,
) -> Tuple[str, Optional[bytes], int]:
    """
    Calcula hash (hex) de un archivo en modo incremental, con salt y pepper opcionales.
    - file_obj: archivo tipo BytesIO o UploadedFile de Streamlit (posee .read()).
    - progress_callback: función que recibe bytes procesados (para barra de progreso).
    - size_limit_bytes: límite de tamaño; levanta ValueError si se excede.
    Retorna (hex_digest, salt_usada_o_None, total_bytes).
    """
    # Buffer todo en memoria para conocer tamaño total con UploadedFile;
    # trade-off: simplicidad vs. consumo de RAM (está limitado a 10MB por defecto).
    file_bytes = file_obj.read()
    total_size = len(file_bytes)

    if size_limit_bytes is not None and total_size > size_limit_bytes:
        raise ValueError(
            f"Archivo supera el límite de {size_limit_bytes} bytes ({total_size} bytes)."
        )

    hasher = get_hasher(algorithm)

    if salt:
        hasher.update(salt)
    if pepper:
        hasher.update(pepper)

    processed = 0
    # Iteramos por chunks para simular lectura streaming y permitir barra de progreso
    for i in range(0, total_size, chunk_size):
        chunk = file_bytes[i : i + chunk_size]
        hasher.update(chunk)
        processed += len(chunk)
        if progress_callback:
            progress_callback(processed)

    return hasher.hexdigest(), salt, total_size


def generate_salt(length: int = 16) -> bytes:
    """Genera una sal segura (bytes) con longitud dada (por defecto 16)."""
    return secrets.token_bytes(length)


def hmac_text(
    text: str,
    key: bytes,
    algorithm: str = "sha256",
) -> str:
    """
    Calcula HMAC(hex) de un texto con clave 'key' y algoritmo dado (sha256 por defecto).
    """
    algo = algorithm.lower()
    if algo not in SUPPORTED_ALGOS:
        raise ValueError(f"Algoritmo no soportado para HMAC: {algorithm}")
    digestmod = getattr(hashlib, algo)
    mac = hmac.new(key, text.encode("utf-8"), digestmod=digestmod)
    return mac.hexdigest()


def compare_hashes(hex_a: str, hex_b: str) -> bool:
    """
    Compara dos hex-digests de forma segura para evitar timing attacks.
    """
    return hmac.compare_digest(hex_a.strip().lower(), hex_b.strip().lower())
