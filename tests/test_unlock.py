"""
Tests pytest pour le déblocage de compte brute-force par OTP avec envoi automatique.
"""

import os
import sys
import hashlib
from datetime import datetime, timedelta
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from app import create_app
from models import db, User, LoginLog, SecurityAlert, UnlockCode, AccountUnlock
from auth import _hash_code, bcrypt as app_bcrypt
from detection import log_login_attempt


@pytest.fixture()
def app():
    a = create_app()
    a.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        BRUTE_FORCE_MAX_ATTEMPTS=5,
        BRUTE_FORCE_WINDOW_MINUTES=5,
        SECRET_KEY="test-unlock-secret",
    )
    with a.app_context():
        db.create_all()
        yield a
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def _make_user(app, email="owner@test.fr", password="MotDePasse12"):
    """Crée un utilisateur patient de test."""
    with app.app_context():
        pw_hash = app_bcrypt.generate_password_hash(password).decode("utf-8")
        user = User(email=email, password_hash=pw_hash, role="patient")
        db.session.add(user)
        db.session.commit()
        return user.id


def _log_failures(app, user_id, ip="127.0.0.1", count=5):
    """Enregistre N tentatives d'échec pour déclencher le blocage."""
    with app.app_context():
        for _ in range(count):
            log_login_attempt(user_id, ip, "TestAgent", "password", False, country="FR")


# ---------------------------------------------------------------------------
# Test 1 : Blocage après 5 échecs → Envoi automatique d'email au propriétaire
# ---------------------------------------------------------------------------
def test_auto_email_send_on_brute_force_block(app, client):
    uid = _make_user(app, email="owner@test.fr")
    _log_failures(app, uid, count=5)

    with patch("auth.send_unlock_code") as mock_send:
        resp = client.post("/login", data={"email": "owner@test.fr", "password": "MotDePasse12"})

    assert resp.status_code == 302
    # Un email d'OTP doit être envoyé automatiquement à owner@test.fr
    mock_send.assert_called_once()
    assert mock_send.call_args[0][0] == "owner@test.fr"

    with app.app_context():
        entry = UnlockCode.query.filter_by(user_id=uid).first()
        assert entry is not None
        assert entry.used is False


# ---------------------------------------------------------------------------
# Test 2 : Anti-spam : 1 seul email par 5 minutes par compte
# ---------------------------------------------------------------------------
def test_rate_limit_1_mail_per_5_minutes(app, client):
    uid = _make_user(app, email="antispam@test.fr")
    _log_failures(app, uid, count=5)

    with patch("auth.send_unlock_code") as mock_send:
        # Premier blocage → 1 email envoyé
        client.post("/login", data={"email": "antispam@test.fr", "password": "MotDePasse12"})
        assert mock_send.call_count == 1

        # Tentative répétée dans les 5 minutes → PAS de 2e email envoyé
        client.post("/login", data={"email": "antispam@test.fr", "password": "MotDePasse12"})
        assert mock_send.call_count == 1


# ---------------------------------------------------------------------------
# Test 3 : Message utilisateur exact affiché
# ---------------------------------------------------------------------------
def test_exact_flash_message_content(app, client):
    uid = _make_user(app, email="msgtest@test.fr")
    _log_failures(app, uid, count=5)

    with patch("auth.send_unlock_code"):
        resp = client.post("/login", data={"email": "msgtest@test.fr", "password": "MotDePasse12"}, follow_redirects=True)

    html = resp.get_data(as_text=True)
    assert "Compte bloqué. Un code de confirmation a été envoyé au propriétaire du compte." in html


# ---------------------------------------------------------------------------
# Test 4 : Code OTP correct → AccountUnlock avec user_id ET ip_address (UTC)
# ---------------------------------------------------------------------------
def test_correct_code_unlocks_account_with_user_and_ip(app, client):
    uid = _make_user(app, email="unlockme@test.fr")
    _log_failures(app, uid, count=5)

    with app.app_context():
        code = "123456"
        entry = UnlockCode(
            user_id=uid,
            ip_address="127.0.0.1",
            code_hash=_hash_code(code),
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            attempts=0,
            used=False,
        )
        db.session.add(entry)
        db.session.commit()

    with client.session_transaction() as sess:
        sess["unlock_user_id"] = uid

    resp = client.post("/unlock/verify", data={"code": "123456"})
    assert resp.status_code == 302
    assert "/unlock/reset-password" in resp.headers["Location"]

    with app.app_context():
        unlock = AccountUnlock.query.filter_by(user_id=uid).first()
        assert unlock is not None
        assert unlock.ip_address == "127.0.0.1"
        assert unlock.unlocked_at is not None

        alert = SecurityAlert.query.filter_by(alert_type="ACCOUNT_UNLOCKED").first()
        assert alert is not None


# ---------------------------------------------------------------------------
# Test 5 : Code faux 3 fois → UNLOCK_FAILED créé et compte reste bloqué
# ---------------------------------------------------------------------------
def test_wrong_code_x3_creates_unlock_failed_alert(app, client):
    uid = _make_user(app, email="wrongcode@test.fr")

    with app.app_context():
        code = "999999"
        entry = UnlockCode(
            user_id=uid,
            ip_address="127.0.0.1",
            code_hash=_hash_code(code),
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            attempts=0,
            used=False,
        )
        db.session.add(entry)
        db.session.commit()

    with client.session_transaction() as sess:
        sess["unlock_user_id"] = uid

    for _ in range(3):
        resp = client.post("/unlock/verify", data={"code": "000000"})

    assert resp.status_code == 302
    assert "/unlock/verify" in resp.headers["Location"]

    with app.app_context():
        alert = SecurityAlert.query.filter_by(alert_type="UNLOCK_FAILED").first()
        assert alert is not None


# ---------------------------------------------------------------------------
# Test 6 : Code expiré → refusé, UNLOCK_FAILED créé
# ---------------------------------------------------------------------------
def test_expired_code_is_rejected(app, client):
    uid = _make_user(app, email="expired@test.fr")

    with app.app_context():
        code = "654321"
        entry = UnlockCode(
            user_id=uid,
            ip_address="127.0.0.1",
            code_hash=_hash_code(code),
            expires_at=datetime.utcnow() - timedelta(minutes=1),  # déjà expiré (UTC)
            attempts=0,
            used=False,
        )
        db.session.add(entry)
        db.session.commit()

    with client.session_transaction() as sess:
        sess["unlock_user_id"] = uid

    resp = client.post("/unlock/verify", data={"code": code})
    assert resp.status_code == 302

    with app.app_context():
        alert = SecurityAlert.query.filter_by(alert_type="UNLOCK_FAILED").first()
        assert alert is not None


# ---------------------------------------------------------------------------
# Test 7 : login_logs n'est JAMAIS modifié lors du déblocage
# ---------------------------------------------------------------------------
def test_login_logs_never_modified_after_unlock(app, client):
    uid = _make_user(app, email="integrity@test.fr")
    _log_failures(app, uid, count=5)

    with app.app_context():
        logs_before = {log.id: log.entry_hash for log in LoginLog.query.all()}
        db.session.add(AccountUnlock(user_id=uid, ip_address="127.0.0.1"))
        db.session.commit()
        logs_after = {log.id: log.entry_hash for log in LoginLog.query.all()}

    assert logs_before == logs_after, "login_logs a été modifié — violation de l'intégrité HMAC"
