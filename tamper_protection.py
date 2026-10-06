import threading
import time
from datetime import datetime
from flask import current_app
from models import db, TamperAttempt, SecurityAlert, LoginLog, MessageLog
from log_integrity import verify_chain, verify_message_log_chain

EXPECTED_TRIGGERS = [
    "trigger_login_logs_update",
    "trigger_login_logs_delete",
    "trigger_message_logs_update",
    "trigger_message_logs_delete",
    "prevent_security_alerts_delete",
    "prevent_tamper_attempts_delete",
]


def install_tamper_protection_triggers():
    """
    Installe la table tamper_attempts et les triggers SQLite pour la détection et la protection anti-falsification.
    - UPDATE/DELETE sur login_logs & message_logs : insère dans tamper_attempts + RAISE(IGNORE) (l'opération échoue sans modifier la table).
    - DELETE sur security_alerts & tamper_attempts : RAISE(ABORT) (append-only).
    Idempotent.
    """
    from sqlalchemy import text
    import models
    db.create_all()

    # 1. Création idempotente de la table tamper_attempts
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS tamper_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        table_name VARCHAR(64) NOT NULL,
        operation VARCHAR(10) NOT NULL,
        row_id VARCHAR(64),
        detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        reviewed BOOLEAN DEFAULT 0
    );
    """
    db.session.execute(text(create_table_sql))

    # 2. Suppression des anciens nommages de triggers si présents (migration propre)
    old_triggers = [
        "prevent_login_logs_update",
        "prevent_login_logs_delete",
        "prevent_alerts_delete",
        "prevent_message_logs_update",
        "prevent_message_logs_delete",
        "trigger_login_logs_update",
        "trigger_login_logs_delete",
        "trigger_message_logs_update",
        "trigger_message_logs_delete",
        "prevent_security_alerts_delete",
        "prevent_tamper_attempts_delete",
    ]
    for old_trig in old_triggers:
        db.session.execute(text(f"DROP TRIGGER IF EXISTS {old_trig};"))

    # 3. Installation des triggers de protection et détection
    new_triggers = [
        """
        CREATE TRIGGER IF NOT EXISTS trigger_login_logs_update
        BEFORE UPDATE ON login_logs
        BEGIN
            INSERT INTO tamper_attempts (table_name, operation, row_id, detected_at, reviewed)
            VALUES ('login_logs', 'UPDATE', CAST(OLD.id AS TEXT), CURRENT_TIMESTAMP, 0);
            SELECT RAISE(IGNORE);
        END;
        """,
        """
        CREATE TRIGGER IF NOT EXISTS trigger_login_logs_delete
        BEFORE DELETE ON login_logs
        BEGIN
            INSERT INTO tamper_attempts (table_name, operation, row_id, detected_at, reviewed)
            VALUES ('login_logs', 'DELETE', CAST(OLD.id AS TEXT), CURRENT_TIMESTAMP, 0);
            SELECT RAISE(IGNORE);
        END;
        """,
        """
        CREATE TRIGGER IF NOT EXISTS trigger_message_logs_update
        BEFORE UPDATE ON message_logs
        BEGIN
            INSERT INTO tamper_attempts (table_name, operation, row_id, detected_at, reviewed)
            VALUES ('message_logs', 'UPDATE', CAST(OLD.id AS TEXT), CURRENT_TIMESTAMP, 0);
            SELECT RAISE(IGNORE);
        END;
        """,
        """
        CREATE TRIGGER IF NOT EXISTS trigger_message_logs_delete
        BEFORE DELETE ON message_logs
        BEGIN
            INSERT INTO tamper_attempts (table_name, operation, row_id, detected_at, reviewed)
            VALUES ('message_logs', 'DELETE', CAST(OLD.id AS TEXT), CURRENT_TIMESTAMP, 0);
            SELECT RAISE(IGNORE);
        END;
        """,
        """
        CREATE TRIGGER IF NOT EXISTS prevent_security_alerts_delete
        BEFORE DELETE ON security_alerts
        BEGIN
            SELECT RAISE(ABORT, 'security_alerts est en lecture seule (append-only)');
        END;
        """,
        """
        CREATE TRIGGER IF NOT EXISTS prevent_tamper_attempts_delete
        BEFORE DELETE ON tamper_attempts
        BEGIN
            SELECT RAISE(ABORT, 'tamper_attempts est en lecture seule (append-only)');
        END;
        """,
    ]

    for sql in new_triggers:
        db.session.execute(text(sql))
    db.session.commit()


def sync_tamper_attempts(app=None):
    """
    Transforme chaque ligne tamper_attempts non revue (reviewed=False) en une alerte
    SecurityAlert de type 'DB_TAMPER_DIRECT' (accès direct hors application),
    puis marque reviewed=True.
    """
    def _sync():
        unreviewed = TamperAttempt.query.filter_by(reviewed=False).all()
        for attempt in unreviewed:
            msg = (
                f"Falsification directe en base sur la table '{attempt.table_name}' "
                f"(opération: {attempt.operation}, row_id: {attempt.row_id}, date: {attempt.detected_at}). "
                f"Accès direct hors application, IP et utilisateur inconnus."
            )
            existing = SecurityAlert.query.filter_by(
                alert_type="DB_TAMPER_DIRECT",
                details=msg,
                resolved=False
            ).first()
            if not existing:
                db.session.add(SecurityAlert(kind="DB_TAMPER_DIRECT", message=msg))
            attempt.reviewed = True
        db.session.commit()

    if app:
        with app.app_context():
            _sync()
    else:
        _sync()


def verify_database_integrity(app=None):
    """
    1. Exécute la vérification de la chaîne d'intégrité sur login_logs et message_logs.
       Si invalide, crée une SecurityAlert kind='LOG_INTEGRITY' avec broken_at (sans doublon).
    2. Vérifie que les triggers attendus existent dans SQLite.
       Sinon crée une SecurityAlert kind='TRIGGER_MISSING' avec le nom du trigger (sans doublon).
    """
    def _verify():
        from sqlalchemy import text
        hmac_secret = current_app.config.get("HMAC_SECRET", "hmac-secret-a-changer")

        # 1. Vérification chaîne login_logs
        login_logs = LoginLog.query.order_by(LoginLog.id.asc()).all()
        res_login = verify_chain(login_logs, hmac_secret)
        if not res_login["valid"]:
            broken_at = res_login.get("broken_at")
            msg = f"Chaîne d'intégrité cryptographique rompue sur 'login_logs' à la ligne id={broken_at}."
            existing = SecurityAlert.query.filter(
                SecurityAlert.alert_type == "LOG_INTEGRITY",
                SecurityAlert.details.like("%login_logs%"),
                SecurityAlert.resolved.is_(False)
            ).first()
            if not existing:
                db.session.add(SecurityAlert(kind="LOG_INTEGRITY", message=msg))

        # 2. Vérification chaîne message_logs
        msg_logs = MessageLog.query.order_by(MessageLog.id.asc()).all()
        res_msg = verify_message_log_chain(msg_logs, hmac_secret)
        if not res_msg["valid"]:
            broken_at = res_msg.get("broken_at")
            msg = f"Chaîne d'intégrité cryptographique rompue sur 'message_logs' à la ligne id={broken_at}."
            existing = SecurityAlert.query.filter(
                SecurityAlert.alert_type == "LOG_INTEGRITY",
                SecurityAlert.details.like("%message_logs%"),
                SecurityAlert.resolved.is_(False)
            ).first()
            if not existing:
                db.session.add(SecurityAlert(kind="LOG_INTEGRITY", message=msg))

        # 3. Vérification des triggers dans SQLite
        rows = db.session.execute(text("SELECT name FROM sqlite_master WHERE type='trigger'")).fetchall()
        existing_trigs = {r[0] for r in rows}

        for trig in EXPECTED_TRIGGERS:
            if trig not in existing_trigs:
                msg = f"Trigger de sécurité manquant : '{trig}'."
                existing = SecurityAlert.query.filter(
                    SecurityAlert.alert_type == "TRIGGER_MISSING",
                    SecurityAlert.details.like(f"%{trig}%"),
                    SecurityAlert.resolved.is_(False)
                ).first()
                if not existing:
                    db.session.add(SecurityAlert(kind="TRIGGER_MISSING", message=msg))

        db.session.commit()

    if app:
        with app.app_context():
            _verify()
    else:
        _verify()


_background_threads_started = False

def start_tamper_monitoring_background_jobs(app):
    """
    Lance un thread en arrière-plan qui exécute :
    - sync_tamper_attempts() toutes les 60 secondes.
    - verify_database_integrity() toutes les 5 minutes (300s).
    """
    global _background_threads_started
    if _background_threads_started or app.config.get("TESTING"):
        return
    _background_threads_started = True

    def _loop():
        count = 0
        while True:
            time.sleep(60)
            count += 1
            try:
                sync_tamper_attempts(app)
            except Exception as e:
                print(f"[TAMPER JOB ERROR] sync: {e}")

            if count % 5 == 0:
                try:
                    verify_database_integrity(app)
                except Exception as e:
                    print(f"[TAMPER JOB ERROR] verify: {e}")

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()
