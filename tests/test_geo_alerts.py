import os
import sys
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
        SECRET_KEY="test-secret-key"
    )
    with a.app_context():
        db.create_all()
        yield a
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def create_test_user(email="user.geo@example.com", role="patient"):
    pw_hash = bcrypt.generate_password_hash("Motdepasse123").decode("utf-8")
    u = User(email=email, password_hash=pw_hash, role=role)
    db.session.add(u)
    db.session.commit()
    return u


def test_geo_anomaly_alert_on_country_change(app):
    """Test: 1re connexion en TN, 2e en DE -> une alerte GEO_ANOMALY est créée."""
    with app.app_context():
        u = create_test_user(email="test.geo1@example.com")
        
        # 1re connexion depuis TN
        with patch("security_geo.get_country", return_value="TN"), \
             patch("security_geo.load_tor_exit_ips", return_value=set()), \
             patch("security_geo.get_client_ip", return_value="197.0.0.1"):
            check_login_anomaly(u)

        alerts_count1 = SecurityAlert.query.filter_by(user_id=u.id, alert_type="GEO_ANOMALY").count()
        assert alerts_count1 == 0

        # 2e connexion depuis DE
        with patch("security_geo.get_country", return_value="DE"), \
             patch("security_geo.load_tor_exit_ips", return_value=set()), \
             patch("security_geo.get_client_ip", return_value="80.0.0.1"):
            check_login_anomaly(u)

        alerts = SecurityAlert.query.filter_by(user_id=u.id, alert_type="GEO_ANOMALY").all()
        assert len(alerts) == 1
        assert "DE" in alerts[0].details
        assert "TN" in alerts[0].details


def test_tor_exit_alert(app):
    """Test: Connexion depuis une IP Tor -> une alerte TOR_EXIT est créée."""
    with app.app_context():
        u = create_test_user(email="test.tor@example.com")
        tor_ip = "185.220.101.5"

        with patch("security_geo.get_country", return_value="US"), \
             patch("security_geo.load_tor_exit_ips", return_value={tor_ip}), \
             patch("security_geo.get_client_ip", return_value=tor_ip):
            check_login_anomaly(u)

        alerts = SecurityAlert.query.filter_by(user_id=u.id, alert_type="TOR_EXIT").all()
        assert len(alerts) == 1
        assert tor_ip in alerts[0].details


def test_no_alert_same_country(app):
    """Test: Deux connexions depuis le même pays -> aucune alerte."""
    with app.app_context():
        u = create_test_user(email="test.same@example.com")

        # 1re connexion FR
        with patch("security_geo.get_country", return_value="FR"), \
             patch("security_geo.load_tor_exit_ips", return_value=set()), \
             patch("security_geo.get_client_ip", return_value="81.0.0.1"):
            check_login_anomaly(u)

        # 2e connexion FR
        with patch("security_geo.get_country", return_value="FR"), \
             patch("security_geo.load_tor_exit_ips", return_value=set()), \
             patch("security_geo.get_client_ip", return_value="81.0.0.2"):
            check_login_anomaly(u)

        alerts_count = SecurityAlert.query.filter_by(user_id=u.id).count()
        assert alerts_count == 0


def test_non_admin_forbidden_alerts_page(client, app):
    """Test: Un utilisateur non-admin reçoit un statut 403 en accédant à /admin/alerts."""
    with app.app_context():
        u = create_test_user(email="patient.forbidden@example.com", role="patient")

    # Connexion du patient
    client.post("/login", data={
        "email": "patient.forbidden@example.com",
        "password": "Motdepasse123"
    })

    response = client.get("/admin/alerts")
    assert response.status_code == 403


def test_resolve_alert(client, app):
    """Test: La résolution d'une alerte la marque resolved=True avec resolved_at."""
    with app.app_context():
        admin = create_test_user(email="admin.test@example.com", role="admin")
        alert = SecurityAlert(
            user_id=admin.id,
            alert_type="GEO_ANOMALY",
            details="Test alerte"
        )
        db.session.add(alert)
        db.session.commit()
        alert_id = alert.id

    # Connexion admin
    client.post("/login", data={
        "email": "admin.test@example.com",
        "password": "Motdepasse123"
    })

    # Résolution
    resp = client.post(f"/admin/alerts/{alert_id}/resolve", follow_redirects=True)
    assert resp.status_code == 200

    with app.app_context():
        resolved_alert = SecurityAlert.query.get(alert_id)
        assert resolved_alert.resolved is True
        assert resolved_alert.resolved_at is not None
