import os
import sys
import time
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from app import create_app
from models import db, User, SecurityAlert, LoginLog
from auth import bcrypt
from security_geo import check_login_anomaly


@pytest.fixture()
def app():
    a = create_app()
    a.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SECRET_KEY="test-secret-key-geo"
    )
    with a.app_context():
        db.create_all()
        yield a
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def create_user(email="test.user@example.com", password="Motdepasse123", role="patient"):
    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    u = User(email=email, password_hash=pw_hash, role=role)
    db.session.add(u)
    db.session.commit()
    return u.id


def test_login_same_country_direct_login(client, app):
    """Test: Connexion depuis le même pays -> connexion directe sans redirection vers /verify-geo."""
    with app.app_context():
        uid = create_user(email="same.country@example.com")
        log1 = LoginLog(user_id=uid, ip_address="81.0.0.1", country="FR", success=True)
        db.session.add(log1)
        db.session.commit()

    with patch("security_geo.get_country", return_value="FR"), \
         patch("security_geo.load_tor_exit_ips", return_value=set()):
        resp = client.post("/login", data={
            "email": "same.country@example.com",
            "password": "Motdepasse123"
        }, follow_redirects=False)

    assert resp.status_code == 302
    assert "/dashboard" in resp.location
    with client.session_transaction() as sess:
        assert "_user_id" in sess


def test_login_different_country_redirects_to_verify_geo(client, app):
    """Test: Pays différent -> redirection vers /verify-geo, utilisateur NON connecté, alerte GEO_ANOMALY créée."""
    with app.app_context():
        uid = create_user(email="diff.country@example.com")
        log1 = LoginLog(user_id=uid, ip_address="81.0.0.1", country="FR", success=True)
        db.session.add(log1)
        db.session.commit()

    with patch("security_geo.get_country", return_value="DE"), \
         patch("security_geo.load_tor_exit_ips", return_value=set()), \
         patch("auth.send_geo_code"):
        resp = client.post("/login", data={
            "email": "diff.country@example.com",
            "password": "Motdepasse123"
        }, follow_redirects=False)

    assert resp.status_code == 302
    assert "/verify-geo" in resp.location

    # L'utilisateur N'EST PAS connecté dans la session Flask-Login
    with client.session_transaction() as sess:
        assert "_user_id" not in sess
        assert sess.get("geo_user_id") == uid

    # Alerte GEO_ANOMALY créée
    with app.app_context():
        alert = SecurityAlert.query.filter_by(user_id=uid, alert_type="GEO_ANOMALY").first()
        assert alert is not None
        assert "DE" in alert.details


def test_login_tor_exit_redirects_to_verify_geo(client, app):
    """Test: Connexion via IP Tor -> redirection vers /verify-geo, alerte TOR_EXIT créée."""
    with app.app_context():
        uid = create_user(email="tor.user@example.com")

    tor_ip = "185.220.101.5"
    with patch("security_geo.get_country", return_value="US"), \
         patch("security_geo.load_tor_exit_ips", return_value={tor_ip}), \
         patch("security_geo.get_client_ip", return_value=tor_ip), \
         patch("auth.send_geo_code"):
        resp = client.post("/login", data={
            "email": "tor.user@example.com",
            "password": "Motdepasse123"
        }, follow_redirects=False)

    assert resp.status_code == 302
    assert "/verify-geo" in resp.location

    with app.app_context():
        alert = SecurityAlert.query.filter_by(user_id=uid, alert_type="TOR_EXIT").first()
        assert alert is not None


def test_verify_geo_correct_code_logs_in_user(client, app):
    """Test: Saisie d'un code OTP correct -> l'utilisateur est connecté et session nettoyée."""
    captured_code = None

    def mock_send(email, code):
        nonlocal captured_code
        captured_code = code

    with app.app_context():
        uid = create_user(email="otp.correct@example.com")
        log1 = LoginLog(user_id=uid, ip_address="81.0.0.1", country="FR", success=True)
        db.session.add(log1)
        db.session.commit()

    with patch("security_geo.get_country", return_value="TN"), \
         patch("security_geo.load_tor_exit_ips", return_value=set()), \
         patch("auth.send_geo_code", side_effect=mock_send):
        client.post("/login", data={
            "email": "otp.correct@example.com",
            "password": "Motdepasse123"
        })

    assert captured_code is not None

    # Soumission du bon code
    with patch("security_geo.get_country", return_value="TN"), \
         patch("security_geo.load_tor_exit_ips", return_value=set()):
        resp = client.post("/verify-geo", data={"code": captured_code}, follow_redirects=False)

    assert resp.status_code == 302
    assert "/dashboard" in resp.location

    # L'utilisateur est maintenant connecté
    with client.session_transaction() as sess:
        assert sess.get("_user_id") == str(uid)
        assert "geo_user_id" not in sess


def test_verify_geo_wrong_code(client, app):
    """Test: Code OTP incorrect -> l'utilisateur reste non connecté."""
    with app.app_context():
        uid = create_user(email="otp.wrong@example.com")
        log1 = LoginLog(user_id=uid, ip_address="81.0.0.1", country="FR", success=True)
        db.session.add(log1)
        db.session.commit()

    with patch("security_geo.get_country", return_value="JP"), \
         patch("security_geo.load_tor_exit_ips", return_value=set()), \
         patch("auth.send_geo_code"):
        client.post("/login", data={
            "email": "otp.wrong@example.com",
            "password": "Motdepasse123"
        })

    # Code erroné (1er essai)
    resp = client.post("/verify-geo", data={"code": "000000"})
    assert resp.status_code == 200

    with client.session_transaction() as sess:
        assert "_user_id" not in sess
        assert sess.get("geo_attempts") == 1


def test_verify_geo_3_wrong_codes_blocks_session(client, app):
    """Test: 3 échecs de code OTP -> session nettoyée, alerte GEO_BLOCKED créée."""
    with app.app_context():
        uid = create_user(email="otp.blocked@example.com")
        log1 = LoginLog(user_id=uid, ip_address="81.0.0.1", country="FR", success=True)
        db.session.add(log1)
        db.session.commit()

    with patch("security_geo.get_country", return_value="BR"), \
         patch("security_geo.load_tor_exit_ips", return_value=set()), \
         patch("auth.send_geo_code"):
        client.post("/login", data={
            "email": "otp.blocked@example.com",
            "password": "Motdepasse123"
        })

    # 3 essais erronés
    client.post("/verify-geo", data={"code": "111111"})
    client.post("/verify-geo", data={"code": "222222"})
    resp = client.post("/verify-geo", data={"code": "333333"}, follow_redirects=False)

    assert resp.status_code == 302

    # Session nettoyée
    with client.session_transaction() as sess:
        assert "geo_user_id" not in sess

    # Alerte GEO_BLOCKED créée
    with app.app_context():
        alert = SecurityAlert.query.filter_by(user_id=uid, alert_type="GEO_BLOCKED").first()
        assert alert is not None
        assert "Échec de vérification OTP" in alert.details


def test_verify_geo_expired_code(client, app):
    """Test: Code OTP expiré (plus de 300s) -> refusé et alerte GEO_BLOCKED."""
    with app.app_context():
        uid = create_user(email="otp.expired@example.com")
        log1 = LoginLog(user_id=uid, ip_address="81.0.0.1", country="FR", success=True)
        db.session.add(log1)
        db.session.commit()

    with patch("security_geo.get_country", return_value="CA"), \
         patch("security_geo.load_tor_exit_ips", return_value=set()), \
         patch("auth.send_geo_code"):
        client.post("/login", data={
            "email": "otp.expired@example.com",
            "password": "Motdepasse123"
        })

    # Simulation d'un saut de temps dans le futur (+600s)
    future_time = int(time.time()) + 600
    with patch("time.time", return_value=future_time):
        resp = client.post("/verify-geo", data={"code": "000000"}, follow_redirects=False)

    assert resp.status_code == 302
    with app.app_context():
        alert = SecurityAlert.query.filter_by(user_id=uid, alert_type="GEO_BLOCKED").first()
        assert alert is not None


def test_verify_geo_without_session_redirects_to_login(client, app):
    """Test: Accès direct à /verify-geo sans session de vérification -> redirection vers accueil/login."""
    resp = client.get("/verify-geo", follow_redirects=False)
    assert resp.status_code == 302


def test_verify_geo_page_content_renders(client, app):
    """Test: GET /verify-geo avec session active contient 'Vérification de sécurité', 'Vérifier' et le champ code."""
    with app.app_context():
        uid = create_user(email="render.test@example.com")
        log1 = LoginLog(user_id=uid, ip_address="81.0.0.1", country="FR", success=True)
        db.session.add(log1)
        db.session.commit()

    with patch("security_geo.get_country", return_value="DE"), \
         patch("security_geo.load_tor_exit_ips", return_value=set()), \
         patch("auth.send_geo_code"):
        client.post("/login", data={
            "email": "render.test@example.com",
            "password": "Motdepasse123"
        })

    # GET /verify-geo
    resp = client.get("/verify-geo")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    assert "Vérification de sécurité" in html
    assert "Connexion inhabituelle détectée" in html
    assert 'name="code"' in html
    assert 'inputmode="numeric"' in html
    assert 'maxlength="6"' in html
    assert 'autocomplete="one-time-code"' in html
    assert 'csrf_token' in html
    assert "Vérifier" in html

