import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Génère et persiste la clé AES dans un fichier local si elle n'existe pas encore
_KEY_FILE = os.path.join(BASE_DIR, "secret_aes.key")


def _load_or_create_aes_key() -> bytes:
    env_key = os.environ.get("ENCRYPTION_KEY_HEX")
    if env_key:
        return bytes.fromhex(env_key)
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, "rb") as f:
            return f.read()
    key = os.urandom(32)
    with open(_KEY_FILE, "wb") as f:
        f.write(key)
    return key


class Config:
    # Clé secrète Flask (sessions, CSRF). À changer en production.
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-moi-en-production-" + os.urandom(8).hex())

    # Base de données SQLite locale
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'app.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Clé utilisée pour signer les tokens HMAC (reset password, etc.)
    HMAC_SECRET = os.environ.get("HMAC_SECRET", "hmac-secret-a-changer")

    # Clé AES-256 pour le chiffrement des dossiers médicaux et ordonnances
    ENCRYPTION_KEY = _load_or_create_aes_key()

    # Identifiants OAuth2 Google (voir README.md pour les obtenir)
    GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "dummy-client-id.apps.googleusercontent.com")
    GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "dummy-secret")

    # Sécurité des cookies de session
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Mettre à True derrière HTTPS en production
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
    PERMANENT_SESSION_LIFETIME = 60 * 30  # 30 minutes

    # Détection d'anomalies
    BRUTE_FORCE_MAX_ATTEMPTS = 5
    BRUTE_FORCE_WINDOW_MINUTES = 5

    # Accepter l'en-tête X-Forwarded-For uniquement en mode démo ou derrière un reverse-proxy de confiance.
    # ⚠️ À désactiver en production si l'application n'est pas derrière un proxy de confiance,
    # car l'en-tête X-Forwarded-For peut être facilement falsifié par un attaquant.
    TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "false").lower() in ("1", "true")

    # Envoi d'alertes par email (optionnel, voir README.md)
    SMTP_HOST = os.environ.get("SMTP_HOST", "")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    ALERTS_BY_EMAIL = os.environ.get("ALERTS_BY_EMAIL", "false").lower() == "true"
