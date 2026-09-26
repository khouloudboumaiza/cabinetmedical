"""
Fonctions cryptographiques utilisées par l'application :
  - Hachage des mots de passe -> géré par flask-bcrypt dans auth.py
  - HMAC : signature d'intégrité pour les tokens (ex: réinitialisation de mot de passe)
  - Chiffrement AES-256-GCM : exemple de chiffrement de donnée sensible
"""

import hmac
import hashlib
import os
import base64
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# HMAC — intégrité et authenticité d'un message (ex: token de reset password)
# ---------------------------------------------------------------------------

def generate_hmac_token(secret_key: str, payload: str, expires_in: int = 3600) -> str:
    """
    Génère un token de la forme: <payload>.<expiration>.<signature>
    encodé en base64url. La signature garantit que le payload et
    l'expiration n'ont pas été modifiés.
    """
    expires_at = int(time.time()) + expires_in
    message = f"{payload}.{expires_at}".encode()
    signature = hmac.new(secret_key.encode(), message, hashlib.sha256).hexdigest()
    token = f"{payload}.{expires_at}.{signature}"
    return base64.urlsafe_b64encode(token.encode()).decode()


def verify_hmac_token(secret_key: str, token: str):
    """
    Vérifie un token généré par generate_hmac_token.
    Retourne le payload si valide, None sinon (signature invalide ou expiré).
    """
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        payload, expires_at, signature = decoded.rsplit(".", 2)
    except Exception:
        return None

    expected_message = f"{payload}.{expires_at}".encode()
    expected_signature = hmac.new(secret_key.encode(), expected_message, hashlib.sha256).hexdigest()

    # Comparaison en temps constant pour éviter les attaques par timing
    if not hmac.compare_digest(signature, expected_signature):
        return None

    if int(time.time()) > int(expires_at):
        return None  # token expiré

    return payload


# ---------------------------------------------------------------------------
# AES-256-GCM — chiffrement symétrique authentifié (démonstration)
# ---------------------------------------------------------------------------

def aes_encrypt(key: bytes, plaintext: str) -> str:
    """Chiffre une chaîne avec AES-256-GCM. Retourne nonce+ciphertext en base64."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()


def aes_decrypt(key: bytes, token: str) -> str:
    """Déchiffre une chaîne produite par aes_encrypt."""
    raw = base64.b64decode(token.encode())
    nonce, ciphertext = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


def generate_aes_key() -> bytes:
    """Génère une clé AES-256 aléatoire (32 octets)."""
    return os.urandom(32)
