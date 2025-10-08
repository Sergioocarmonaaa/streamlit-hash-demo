# Pruebas manuales (lectura humana)

> Estos ejemplos sirven para verificar a ojo el comportamiento de `hash_utils.py`.

## Hash de texto (sin sal ni pepper)
Entrada: `"hola"`
- sha256: calcula en la app; debe ser estable
- sha1: idem
- sha512: idem
- blake2b: idem

## Salting
- Genera sal de 16 bytes para `"hola"`.
- Observa que el hash cambia frente al caso sin sal.
- Repite con la **misma sal** → el hash debe coincidir.

## Peppering
- Configura `PEPPER` en `st.secrets`.
- Activa pepper → el hash cambia frente al caso sin pepper.
- Cambia el valor de `PEPPER` → el hash cambia.

## HMAC
- Configura `HMAC_KEY` y calcula HMAC de `"hola"`.
- Cambia `HMAC_KEY` → el HMAC cambia.

## Comparación
- Compara el hash de `"hola"` consigo mismo → debe ser **idéntico**.
- Compara con cualquier otro → **diferente**.
