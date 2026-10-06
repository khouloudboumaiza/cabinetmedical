import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from sqlalchemy import text
from app import create_app
from models import db, User, LoginLog, SecurityAlert, TamperAttempt
from tamper_protection import (
    install_tamper_protection_triggers,
    sync_tamper_attempts,
    verify_database_integrity,
)


@pytest.fixture()
def app():
    a = create_app()
    a.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SECRET_KEY="test-secret-key-tamper"
    )
    with a.app_context():
        db.create_all()
        install_tamper_protection_triggers()
        yield a
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def test_direct_update_or_delete_logs_attempt_and_preserves_data(app):
    """
    Test 1: Une tentative directe de UPDATE ou DELETE sur login_logs insère une ligne dans tamper_attempts,
    et la donnée d'origine dans login_logs reste totalement inchangée (RAISE IGNORE).
    """
    with app.app_context():
        # Création d'une entrée de log initiale
        log = LoginLog(
            log_uid="test-uid-100",
            ip_address="192.168.1.1",
            country="FR",
            login_method="password",
            success=True,
            prev_hash="0"*64,
            entry_hash="hash-100"
        )
        db.session.add(log)
        db.session.commit()
        log_id = log.id

        # 1. Tentative directe de UPDATE via SQL brut
        db.session.execute(text("UPDATE login_logs SET country = 'DE' WHERE id = :id"), {"id": log_id})
        db.session.commit()

        # Vérification: la donnée dans login_logs n'a pas changé (toujours 'FR')
        log_after_update = db.session.get(LoginLog, log_id)
        assert log_after_update.country == "FR"

        # Vérification: une ligne a été créée dans tamper_attempts
        attempt_update = TamperAttempt.query.filter_by(table_name="login_logs", operation="UPDATE").first()
        assert attempt_update is not None
        assert str(attempt_update.row_id) == str(log_id)
        assert attempt_update.reviewed is False

        # 2. Tentative directe de DELETE via SQL brut
        db.session.execute(text("DELETE FROM login_logs WHERE id = :id"), {"id": log_id})
        db.session.commit()

        # Vérification: la ligne existe toujours dans login_logs
        log_after_delete = db.session.get(LoginLog, log_id)
        assert log_after_delete is not None

        # Vérification: une ligne DELETE est enregistrée dans tamper_attempts
        attempt_delete = TamperAttempt.query.filter_by(table_name="login_logs", operation="DELETE").first()
        assert attempt_delete is not None
        assert str(attempt_delete.row_id) == str(log_id)


def test_sync_tamper_attempts_creates_security_alert(app):
    """
    Test 2: sync_tamper_attempts() transforme les lignes tamper_attempts non revues en SecurityAlert 'DB_TAMPER_DIRECT'
    et marque reviewed=True.
    """
    with app.app_context():
        # Insertion directe d'une ligne non revue dans tamper_attempts
        attempt = TamperAttempt(
            table_name="login_logs",
            operation="DELETE",
            row_id="42",
            reviewed=False
        )
        db.session.add(attempt)
        db.session.commit()

        # Synchronisation
        sync_tamper_attempts()

        # Vérification: l'alerte DB_TAMPER_DIRECT est créée
        alert = SecurityAlert.query.filter_by(alert_type="DB_TAMPER_DIRECT").first()
        assert alert is not None
        assert "login_logs" in alert.details
        assert "DELETE" in alert.details
        assert "42" in alert.details

        # La ligne est maintenant marquée reviewed=True
        updated_attempt = db.session.get(TamperAttempt, attempt.id)
        assert updated_attempt.reviewed is True


def test_verify_database_integrity_detects_corrupted_chain(app):
    """
    Test 3: Une altération directe du hash dans login_logs est détectée par verify_database_integrity()
    qui crée une alerte 'LOG_INTEGRITY'.
    """
    with app.app_context():
        log1 = LoginLog(
            log_uid="uid-integrity-1",
            ip_address="10.0.0.1",
            country="FR",
            login_method="password",
            success=True,
            prev_hash="0"*64,
            entry_hash="hash-invalide-falsifie"
        )
        db.session.add(log1)
        db.session.commit()

        # Exécution de la vérification d'intégrité
        verify_database_integrity()

        alert = SecurityAlert.query.filter_by(alert_type="LOG_INTEGRITY").first()
        assert alert is not None
        assert "login_logs" in alert.details
        assert f"id={log1.id}" in alert.details


def test_verify_database_integrity_detects_missing_trigger(app):
    """
    Test 4: La suppression manuelle d'un trigger de sécurité entraîne la création d'une alerte 'TRIGGER_MISSING'.
    """
    with app.app_context():
        # Suppression du trigger trigger_login_logs_update
        db.session.execute(text("DROP TRIGGER IF EXISTS trigger_login_logs_update;"))
        db.session.commit()

        # Exécution de la vérification
        verify_database_integrity()

        alert = SecurityAlert.query.filter_by(alert_type="TRIGGER_MISSING").first()
        assert alert is not None
        assert "trigger_login_logs_update" in alert.details
