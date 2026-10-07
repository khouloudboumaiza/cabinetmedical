"""
Tests pytest pour la détection Tor IPv4 / IPv6 et l'intégration des alertes new_country.
"""

import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from app import create_app
from models import db, User, SecurityAlert, LoginLog
from auth import bcrypt as app_bcrypt
from security_geo import is_tor_ip, parse_ip, _tor_cache
from detection import log_login_attempt, run_all_checks, check_new_country


@pytest.fixture()
def app():
    a = create_app()
    a.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SECRET_KEY="test-tor-secret",
    )
    with a.app_context():
        db.create_all()
        yield a
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def _make_user(app, email="test_geo@test.fr"):
    with app.app_context():
        pw_hash = app_bcrypt.generate_password_hash("MotDePasse123").decode("utf-8")
        user = User(email=email, password_hash=pw_hash, role="patient")
        db.session.add(user)
        db.session.commit()
        return user.id


# ---------------------------------------------------------------------------
# Test 1 : Détection Tor IPv4 et IPv6 avec mock requests
# ---------------------------------------------------------------------------
def test_is_tor_ip_ipv4_and_ipv6(app):
    _tor_cache["ts"] = 0
    _tor_cache["ips"] = set()

    onionoo_mock_response = MagicMock()
    onionoo_mock_response.status_code = 200
    onionoo_mock_response.json.return_value = {
        "relays": [
            {
                "exit_addresses": ["1.2.3.4"],
                "or_addresses": ["[2001:db8::1]:9001"]
            }
        ]
    }

    with app.app_context(), patch("requests.get", return_value=onionoo_mock_response):
        # IPv4 Tor exit
        assert is_tor_ip("1.2.3.4") is True
        # IPv6 Tor exit
        assert is_tor_ip("2001:db8::1") is True
        # Normalisation IPv6 (version longue 8 blocs hex)
        assert is_tor_ip("2001:0db8:0000:0000:0000:0000:0000:0001") is True
        # IP non-Tor
        assert is_tor_ip("192.168.1.1") is False
        assert is_tor_ip("2001:db8::9999") is False


# ---------------------------------------------------------------------------
# Test 2 : Intégration new_country (2 logins TN puis 1 login FR -> alerte new_country)
# ---------------------------------------------------------------------------
def test_integration_new_country_alert(app):
    uid = _make_user(app, email="traveler@test.fr")

    with app.app_context():
        # 1er login depuis TN (Tunisie)
        log_login_attempt(uid, "1.1.1.1", "Browser", "password", True, country="TN")
        run_all_checks(uid, "TN")

        # 2e login depuis TN (Tunisie)
        log_login_attempt(uid, "1.1.1.2", "Browser", "password", True, country="TN")
        run_all_checks(uid, "TN")

        # Aucune alerte new_country à ce stade
        alerts_before = SecurityAlert.query.filter(
            SecurityAlert.user_id == uid,
            SecurityAlert.alert_type.in_(["new_country", "GEO_ANOMALY"])
        ).all()
        assert len(alerts_before) == 0

        # 3e login depuis FR (France) -> Nouveau pays !
        log_login_attempt(uid, "2.2.2.2", "Browser", "password", True, country="FR")
        run_all_checks(uid, "FR")

        # Vérification qu'une SecurityAlert de type new_country a été créée
        alert = SecurityAlert.query.filter_by(user_id=uid, alert_type="new_country").first()
        assert alert is not None
        assert "FR" in alert.details
