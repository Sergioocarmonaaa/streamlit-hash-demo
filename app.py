"""
app.py — Streamlit UI para demo de hashing.

Secciones:
1) Hash de texto
2) Hash de archivo (incremental con progreso)
3) Comparador de hashes
4) HMAC
5) Descarga de resultados (CSV)

Decisiones:
- Algoritmos estándar de hashlib para despliegue 100% web.
- Pepper y HMAC key se toman de st.secrets si existen (no se exponen).
- Límite de archivo 10 MB por defecto para evitar timeouts/memoria.

Mejoras posibles:
- Arrastrar/soltar múltiples archivos.
- Árbol de Merkle para lotes.
- Persistencia en base de datos y logs con auditoría.
"""

import io
import csv
from datetime import datetime

import streamlit as st
from hash_utils import (
    SUPPORTED_ALGOS,
    hash_text,
    hash_file_chunked,
    generate_salt,
    hmac_text,
    compare_hashes,
)

# --------- Configuración inicial de la página ---------
st.set_page_config(
    page_title="Hash Demo — SHA256/SHA1/SHA512/BLAKE2b",
    page_icon="🧩",
    layout="wide",
)

st.title("🧩 Demo Didáctica de Hash — SHA256/SHA1/SHA512/BLAKE2b")
st.caption("Integridad, salting, peppering y HMAC — 100% web con Streamlit Cloud")

# --------- Estado para resultados a descargar ---------
if "results" not in st.session_state:
    st.session_state["results"] = []  # lista de dicts

# --------- Sidebar: opciones globales ---------
st.sidebar.header("Opciones")
algorithm = st.sidebar.selectbox(
    "Algoritmo", options=SUPPORTED_ALGOS, index=SUPPORTED_ALGOS.index("sha256")
)
chunk_size = st.sidebar.number_input("Chunk (bytes)", min_value=1024, max_value=65536, value=8192, step=1024)
size_limit_mb = st.sidebar.number_input("Límite archivo (MB)", min_value=1, max_value=100, value=10)
size_limit_bytes = int(size_limit_mb * 1024 * 1024)

use_salt = st.sidebar.checkbox("Añadir SAL (salting)", value=False)
salt_len = st.sidebar.slider("Longitud de sal (bytes)", 8, 32, 16) if use_salt else 0

use_pepper = st.sidebar.checkbox("Añadir PEPPER (st.secrets)", value=False)
use_hmac = st.sidebar.checkbox("Habilitar HMAC (st.secrets)", value=False)

with st.sidebar.expander("Notas y buenas prácticas", expanded=False):
    st.markdown(
        """- **Hash ≠ cifrado**: asegura integridad, no confidencialidad.
- La **sal** no es secreta; el **pepper** sí (en `st.secrets`).
- **SHA-1** tiene colisiones conocidas → solo fines didácticos.
- Para contraseñas reales: **PBKDF2/Argon2/bcrypt/scrypt**.
        """
    )

# --------- Helpers para pepper y HMAC key ---------
def get_pepper_bytes():
    val = st.secrets.get("PEPPER", None)
    if not val:
        return None
    return str(val).encode("utf-8")

def get_hmac_key_bytes():
    val = st.secrets.get("HMAC_KEY", None)
    if not val:
        return None
    return str(val).encode("utf-8")

pepper_bytes = get_pepper_bytes() if use_pepper else None
hmac_key_bytes = get_hmac_key_bytes() if use_hmac else None

if use_pepper and pepper_bytes is None:
    st.sidebar.warning("PEPPER no está configurado en `st.secrets`.")
if use_hmac and hmac_key_bytes is None:
    st.sidebar.warning("HMAC_KEY no está configurado en `st.secrets`.")

# --------- 1) Hash de texto ---------
st.header("1) Hash de texto")
col1, col2 = st.columns([2, 1])
with col1:
    text_input = st.text_area("Introduce texto", value="", height=140, placeholder="Escribe aquí...")
with col2:
    st.write("Opciones de sal/pepper")
    current_salt = generate_salt(salt_len) if use_salt else None
    if use_salt:
        st.code(current_salt.hex(), language="text")
        st.caption("Sal generada (hex). Se comparte junto al hash para verificación.")

if st.button("Hashear texto", type="primary", use_container_width=True):
    if not text_input:
        st.error("Introduce algún texto.")
    else:
        try:
            hex_digest, salt_used = hash_text(
                text=text_input,
                algorithm=algorithm,
                salt=current_salt,
                pepper=pepper_bytes,
            )
            st.success("Hash calculado")
            st.code(hex_digest, language="text")
            meta = {
                "type": "text",
                "algorithm": algorithm,
                "with_salt": bool(salt_used),
                "salt_hex": salt_used.hex() if salt_used else "",
                "with_pepper": bool(pepper_bytes),
                "hmac": "",
                "input_preview": text_input[:30].replace("\n", " ") + ("..." if len(text_input) > 30 else ""),
                "digest": hex_digest,
                "bytes": len(text_input.encode("utf-8")),
                "ts": datetime.utcnow().isoformat() + "Z",
            }
            st.session_state["results"].append(meta)
        except Exception as e:
            st.exception(e)

st.divider()

# --------- 2) Hash de archivo (incremental) ---------
st.header("2) Hash de archivo (incremental con progreso)")
uploaded = st.file_uploader("Sube un archivo (≤ límite de la barra lateral)", type=None)

if uploaded is not None:
    progress = st.progress(0.0)
    status = st.empty()

    processed_tracker = {"value": 0}

    def _on_progress(processed_bytes: int):
        processed_tracker["value"] = processed_bytes
        if uploaded.size:
            progress.progress(min(processed_bytes / uploaded.size, 1.0))
            status.write(f"Procesado: {processed_bytes} / {uploaded.size} bytes")

    do_hash = st.button("Hashear archivo", use_container_width=True)
    if do_hash:
        # Genera sal solo si está activado (una por archivo)
        file_salt = generate_salt(salt_len) if use_salt else None
        try:
            digest, salt_used, total_bytes = hash_file_chunked(
                file_obj=uploaded,
                algorithm=algorithm,
                chunk_size=chunk_size,
                salt=file_salt,
                pepper=pepper_bytes,
                progress_callback=_on_progress,
                size_limit_bytes=size_limit_bytes,
            )
            st.success(f"Hash calculado ({total_bytes} bytes)")
            st.code(digest, language="text")
            if salt_used:
                with st.expander("Sal utilizada (hex)"):
                    st.code(salt_used.hex(), language="text")
            meta = {
                "type": "file",
                "algorithm": algorithm,
                "with_salt": bool(salt_used),
                "salt_hex": salt_used.hex() if salt_used else "",
                "with_pepper": bool(pepper_bytes),
                "hmac": "",
                "input_preview": uploaded.name,
                "digest": digest,
                "bytes": total_bytes,
                "ts": datetime.utcnow().isoformat() + "Z",
            }
            st.session_state["results"].append(meta)
        except Exception as e:
            st.exception(e)

st.divider()

# --------- 3) Comparador de hashes ---------
st.header("3) Comparador de hashes")
c1, c2 = st.columns(2)
with c1:
    h1 = st.text_input("Hash A (hex)")
with c2:
    h2 = st.text_input("Hash B (hex)")
if st.button("Comparar", use_container_width=True):
    if not h1 or not h2:
        st.error("Introduce ambos hashes.")
    else:
        equal = compare_hashes(h1, h2)
        if equal:
            st.success("✅ Los hashes son **idénticos**.")
        else:
            st.error("❌ Los hashes son **diferentes**.")

st.divider()

# --------- 4) HMAC ---------
st.header("4) HMAC (autenticación de mensaje)")
msg = st.text_area("Mensaje para HMAC", value="", height=100, placeholder="Texto del mensaje...")
algo_hmac = st.selectbox("Algoritmo HMAC", options=SUPPORTED_ALGOS, index=SUPPORTED_ALGOS.index("sha256"))
if st.button("Calcular HMAC", use_container_width=True):
    if not msg:
        st.error("Introduce un mensaje.")
    elif hmac_key_bytes is None:
        st.error("Configura `HMAC_KEY` en `st.secrets` para usar HMAC.")
    else:
        try:
            mac = hmac_text(msg, key=hmac_key_bytes, algorithm=algo_hmac)
            st.success("HMAC calculado")
            st.code(mac, language="text")
            st.session_state["results"].append(
                {
                    "type": "hmac",
                    "algorithm": algo_hmac,
                    "with_salt": False,
                    "salt_hex": "",
                    "with_pepper": False,
                    "hmac": "yes",
                    "input_preview": msg[:30].replace("\n", " ") + ("..." if len(msg) > 30 else ""),
                    "digest": mac,
                    "bytes": len(msg.encode("utf-8")),
                    "ts": datetime.utcnow().isoformat() + "Z",
                }
            )
        except Exception as e:
            st.exception(e)

st.divider()

# --------- 5) Descarga de resultados (CSV) ---------
st.header("5) Descarga de resultados (CSV)")
if st.session_state["results"]:
    # Generamos CSV en memoria
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "ts",
            "type",
            "algorithm",
            "with_salt",
            "salt_hex",
            "with_pepper",
            "hmac",
            "input_preview",
            "digest",
            "bytes",
        ],
    )
    writer.writeheader()
    for row in st.session_state["results"]:
        writer.writerow(row)
    csv_bytes = output.getvalue().encode("utf-8")
    st.download_button(
        label="Descargar CSV",
        data=csv_bytes,
        file_name=f"hash_results_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.csv",
        mime="text/csv",
        use_container_width=True,
    )
else:
    st.info("No hay resultados todavía. Genera hashes o HMAC para habilitar la descarga.")

# --------- Información didáctica ---------
with st.expander("📘 Explicación rápida: sal, pepper, HMAC y límites"):
    st.markdown(
        """- **Salting**: añade bytes aleatorios (no secretos) al input → evita tablas arcoíris y hashes iguales para entradas iguales.
- **Peppering**: añade un secreto global compartido a todos los hashes → si se filtra la base con las sales, el atacante sigue necesitando el pepper.
- **HMAC**: autentica el mensaje con una clave secreta → integridad + autenticidad.
- **Límites**: este demo limita archivos a 10 MB para estabilidad en la nube; ajusta en la barra lateral si lo necesitas.
        """
    )
