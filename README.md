# Streamlit Hash Demo — SHA256/SHA1/SHA512/BLAKE2b + Salt/Pepper + HMAC (100% Web)

App didáctica para calcular y comprender funciones hash desde el navegador:
- Hash de textos y archivos (por defecto SHA-256).
- Comparador de hashes.
- Salting (sal aleatoria) y peppering (pepper en `st.secrets`).
- HMAC (clave en `st.secrets`).
- Hash incremental con barra de progreso (chunk configurable).
- Descarga de resultados (CSV).

> **Importante**: Hash ≠ cifrado. Hash asegura integridad; HMAC aporta autenticación del mensaje con clave.

## 👩‍💻 Uso 100% Web (sin instalar nada)

### 1) Crear repo en GitHub
1. Entra a GitHub → **New repository**.
2. Nombre sugerido: `streamlit-hash-demo`.
3. Marca: *Public*, **Add .gitignore: Python**, **License: MIT**.
4. Crea el repo.

### 2) Añadir archivos
- Entra al repo → **Add file → Upload files**.
- Arrastra el contenido de esta carpeta (descomprime primero el ZIP y sube los archivos y carpetas).
- Asegúrate de ver en GitHub: `app.py`, `hash_utils.py`, `requirements.txt`, `README.md`, `tests/`, `assets/`.

### 3) Desplegar en Streamlit Cloud
1. Ve a https://share.streamlit.io/new
2. Autoriza GitHub si te lo pide.
3. **Deploy an app** → selecciona tu repo `streamlit-hash-demo`, branch `main`, y **file path**: `app.py`.
4. Pulsa **Deploy**.

### 4) Configurar `st.secrets` (en Streamlit Cloud)
1. En tu app desplegada → botón **Manage app** (o **⚙ Settings**) → **Secrets**.
2. Añade (ejemplo):
   ```toml
   PEPPER = "cámbiame-por-un-pepper-secreto-largo"
   HMAC_KEY = "cámbiame-por-una-clave-hmac"
   ```
3. **Save** y **Rerun** la app.

## 📦 Requisitos
Solo Streamlit (ver `requirements.txt`). `hashlib` y `hmac` son estándar de Python.

## 🧩 Funciones principales
- **Hash de texto/archivo** con algoritmos: `sha256` (defecto), `sha1`, `sha512`, `blake2b`.
- **Salting**: añade sal aleatoria (se expone junto al hash para verificación).
- **Peppering**: añade un secreto global (`PEPPER` en `st.secrets`), no se muestra.
- **HMAC**: genera MAC con `HMAC_KEY` (no se muestra la clave).
- **Comparador**: compara dos cadenas hex para verificar integridad.
- **CSV**: descarga resultados de la sesión.

## ⚠️ Limitaciones y buenas prácticas
- Hash **no** cifra ni “protege” datos, solo verifica integridad.
- La **sal** no es secreta: se almacena/transporta junto al hash.
- El **pepper** y claves HMAC deben mantenerse en `st.secrets`.
- SHA-1 tiene **colisiones conocidas**: usar solo con fines didácticos.
- Para contraseñas reales usar PBKDF2/Argon2/bcrypt/scrypt (solo mención).
- No reutilices claves; rota y gestiona permisos en Streamlit Cloud.

## 🧪 Pruebas manuales rápidas
- Introduce “hola” → hash sha256.
- Súbele `assets/ejemplo_entrada.txt`.
- Activa sal y pepper y observa el cambio del hash.
- Genera HMAC de un texto y verifica que cambia si cambias la clave en `st.secrets`.
- Compara dos hashes (idénticos vs diferentes).

## 📄 Licencia
MIT
