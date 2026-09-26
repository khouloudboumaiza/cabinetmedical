import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from app import create_app
from models import db, User, Patient
from crypto_utils import aes_encrypt, aes_decrypt, generate_hmac_token, verify_hmac_token


@pytest.fixture()
def app():
    a = create_app()
    a.config.update(TESTING=True)
    with a.app_context():
        db.create_all()
        yield a
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


# ─── Tests de base ──────────────────────────────────────────

def test_home_page(client):
    assert client.get("/").status_code in (200, 302)


def test_login_page(client):
    assert client.get("/login").status_code == 200


def test_register_page(client):
    assert client.get("/register").status_code == 200


# ─── Inscription ────────────────────────────────────────────

def test_register_creates_patient_role(client, app):
    r = client.post("/register", data={
        "email": "patient.test@exemple.com",
        "password": "Motdepasse123",
        "first_name": "Jean",
        "last_name": "Test",
    }, follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        u = User.query.filter_by(email="patient.test@exemple.com").first()
        assert u is not None
        assert u.role == "patient"
        assert u.patient_profile is not None
        assert u.patient_profile.first_name == "Jean"


def test_weak_password_rejected(client, app):
    client.post("/register", data={
        "email": "faible@exemple.com",
        "password": "123",
        "first_name": "A",
        "last_name": "B",
    })
    with app.app_context():
        assert User.query.filter_by(email="faible@exemple.com").first() is None


def test_duplicate_email_rejected(client, app):
    data = {
        "email": "double@exemple.com",
        "password": "Motdepasse123",
        "first_name": "A",
        "last_name": "B",
    }
    client.post("/register", data=data)
    r = client.post("/register", data=data, follow_redirects=True)
    # Doit afficher un message d'erreur, pas créer deux comptes
    with app.app_context():
        assert User.query.filter_by(email="double@exemple.com").count() == 1


# ─── Connexion ──────────────────────────────────────────────

def test_login_wrong_password(client):
    client.post("/register", data={
        "email": "victime@exemple.com",
        "password": "Motdepasse123",
        "first_name": "A",
        "last_name": "B",
    })
    r = client.post("/login", data={
        "email": "victime@exemple.com",
        "password": "MauvaisMot123"
    }, follow_redirects=True)
    assert "incorrect" in r.get_data(as_text=True).lower()


def test_login_success_redirects(client):
    client.post("/register", data={
        "email": "valid@exemple.com",
        "password": "Motdepasse123",
        "first_name": "A",
        "last_name": "B",
    })
    r = client.post("/login", data={
        "email": "valid@exemple.com",
        "password": "Motdepasse123",
    }, follow_redirects=False)
    assert r.status_code == 302


# ─── RBAC ───────────────────────────────────────────────────

def test_rbac_patient_forbidden_from_staff_pages(client):
    client.post("/register", data={
        "email": "p.rbac@exemple.com",
        "password": "Motdepasse123",
        "first_name": "A",
        "last_name": "B",
    })
    client.post("/login", data={
        "email": "p.rbac@exemple.com",
        "password": "Motdepasse123",
    })
    assert client.get("/patients").status_code == 403
    assert client.get("/admin/").status_code == 403


def test_unauthenticated_redirected_from_dashboard(client):
    r = client.get("/dashboard", follow_redirects=False)
    assert r.status_code == 302


# ─── Cryptographie ──────────────────────────────────────────

def test_aes256_roundtrip(app):
    key = app.config["ENCRYPTION_KEY"]
    ciphertext = aes_encrypt(key, "Diagnostic : grippe saisonnière")
    assert "grippe" not in ciphertext  # jamais en clair
    assert aes_decrypt(key, ciphertext) == "Diagnostic : grippe saisonnière"


def test_aes256_different_nonce_each_time(app):
    key = app.config["ENCRYPTION_KEY"]
    plaintext = "test de non-déterminisme"
    c1 = aes_encrypt(key, plaintext)
    c2 = aes_encrypt(key, plaintext)
    assert c1 != c2  # nonces différents à chaque chiffrement


def test_hmac_token_valid(app):
    key = app.config["HMAC_SECRET"]
    token = generate_hmac_token(key, "reset:42")
    assert verify_hmac_token(key, token) == "reset:42"


def test_hmac_token_tampered(app):
    key = app.config["HMAC_SECRET"]
    token = generate_hmac_token(key, "reset:42")
    assert verify_hmac_token(key, token[:-4] + "AAAA") is None


def test_hmac_token_wrong_key(app):
    key = app.config["HMAC_SECRET"]
    token = generate_hmac_token(key, "reset:42")
    assert verify_hmac_token("mauvaise-cle", token) is None
