from flask import Flask, render_template, redirect, url_for
from flask_login import LoginManager, login_required, current_user

from config import Config
from models import db, User, LoginLog
from auth import auth_bp, bcrypt
from oauth import oauth_bp, init_oauth
from admin import admin_bp
from cabinet import cabinet_bp
from messages import messages_bp, get_or_create_csrf_token


from sqlalchemy.exc import IntegrityError
from tamper_protection import (
    install_tamper_protection_triggers,
    sync_tamper_attempts,
    verify_database_integrity,
    start_tamper_monitoring_background_jobs,
)


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # --- Extensions ---
    db.init_app(app)
    bcrypt.init_app(app)
    init_oauth(app)

    login_manager = LoginManager()
    login_manager.login_view = "index"  # redirige vers la page d'accueil (modal pop-up)
    login_manager.login_message = "Veuillez vous connecter pour accéder à cette page."
    login_manager.login_message_category = "error"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # --- Interception des erreurs de falsification (append-only) ---
    @app.errorhandler(IntegrityError)
    def handle_integrity_error(e):
        db.session.rollback()
        orig_msg = str(e.orig) if hasattr(e, "orig") else str(e)
        if "append-only" in orig_msg or "lecture seule" in orig_msg or "RAISE" in orig_msg:
            try:
                from security_geo import get_client_ip, get_country
                from flask import request
                user_email = current_user.email if current_user and current_user.is_authenticated else "Anonyme"
                ip = get_client_ip()
                country = get_country(ip) or "inconnu"
                route = request.path if request else "N/A"
                method = request.method if request else "N/A"
                user_agent = request.headers.get("User-Agent", "N/A") if request else "N/A"

                alert_msg = (
                    f"Tentative de modification illégale en base par {user_email} depuis {ip} ({country}) "
                    f"sur {method} {route} [Agent: {user_agent}]."
                )
                from models import SecurityAlert
                existing = SecurityAlert.query.filter_by(
                    alert_type="DB_TAMPER_ATTEMPT",
                    details=alert_msg,
                    resolved=False
                ).first()
                if not existing:
                    db.session.add(SecurityAlert(kind="DB_TAMPER_ATTEMPT", message=alert_msg))
                    db.session.commit()
            except Exception:
                pass
        return "Une erreur de sécurité est survenue (tentative de modification non autorisée).", 500

    # --- Context Processors ---
    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=get_or_create_csrf_token)

    @app.context_processor
    def inject_pending_rdv_count():
        """Injecte le nombre de demandes de RDV en attente pour la secrétaire."""
        from flask_login import current_user
        from models import Appointment
        try:
            if current_user.is_authenticated and current_user.role in ('secretaire', 'admin'):
                count = Appointment.query.filter_by(status='en_attente').count()
                return dict(pending_rdv_count=count)
        except Exception:
            pass
        return dict(pending_rdv_count=0)

    # --- Blueprints ---
    app.register_blueprint(auth_bp)
    app.register_blueprint(oauth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(cabinet_bp)
    app.register_blueprint(messages_bp)

    # --- Vérification automatique de l'existence des tables au premier appel ---
    @app.before_request
    def _auto_init_tables():
        if not getattr(app, "_tables_initialized", False):
            try:
                import models
                db.create_all()
                app._tables_initialized = True
            except Exception:
                pass

    # --- Routes principales ---
    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("cabinet.tableau_de_bord"))
        return render_template("index.html")

    # --- Création de la base + compte admin par défaut + installation triggers et vérification ---
    with app.app_context():
        import models
        db.create_all()
        _ensure_default_admin(app)
        install_tamper_protection_triggers()
        verify_database_integrity()

    start_tamper_monitoring_background_jobs(app)

    return app



def _ensure_default_admin(app):
    """Crée un compte admin de démonstration si aucun n'existe."""
    if User.query.filter_by(role="admin").first():
        return

    import secrets

    default_email = "admin@medicabinet.fr"
    default_password = secrets.token_urlsafe(9)
    password_hash = bcrypt.generate_password_hash(default_password).decode("utf-8")

    admin = User(email=default_email, password_hash=password_hash, role="admin")
    db.session.add(admin)
    db.session.commit()

    print("=" * 60)
    print(" Compte administrateur créé automatiquement :")
    print(f"   Email    : {default_email}")
    print(f"   Password : {default_password}")
    print(" (à changer immédiatement après la première connexion)")
    print("=" * 60)


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, host="0.0.0.0", port=5000)

