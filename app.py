from flask import Flask, render_template, redirect, url_for
from flask_login import LoginManager, login_required, current_user

from config import Config
from models import db, User, LoginLog
from auth import auth_bp, bcrypt
from oauth import oauth_bp, init_oauth
from admin import admin_bp
from cabinet import cabinet_bp


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

    # --- Blueprints ---
    app.register_blueprint(auth_bp)
    app.register_blueprint(oauth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(cabinet_bp)

    # --- Routes principales ---
    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("cabinet.tableau_de_bord"))
        return render_template("index.html")

    # --- Création de la base + compte admin par défaut si absent ---
    with app.app_context():
        db.create_all()
        _ensure_default_admin(app)
        _install_tamper_protection_triggers()

    return app


def _install_tamper_protection_triggers():
    """
    Installe des triggers SQLite qui bloquent toute tentative d'UPDATE
    ou de DELETE sur les tables de logs/alertes — même via un accès
    direct à la base de données (ex: sqlite3 app.db) ou une requête SQL
    injectée. Seul un INSERT reste possible : les logs sont "append-only".

    Défense en profondeur : à combiner avec le chaînage cryptographique
    (log_integrity.py) qui, lui, DÉTECTE la falsification si elle a
    quand même lieu (ex: si l'attaquant a un accès root au fichier .db
    et le remplace complètement hors de l'application).
    """
    from sqlalchemy import text

    triggers = [
        """
        CREATE TRIGGER IF NOT EXISTS prevent_login_logs_update
        BEFORE UPDATE ON login_logs
        BEGIN
            SELECT RAISE(ABORT, 'login_logs est en lecture seule (append-only)');
        END;
        """,
        """
        CREATE TRIGGER IF NOT EXISTS prevent_login_logs_delete
        BEFORE DELETE ON login_logs
        BEGIN
            SELECT RAISE(ABORT, 'login_logs est en lecture seule (append-only)');
        END;
        """,
        """
        CREATE TRIGGER IF NOT EXISTS prevent_alerts_delete
        BEFORE DELETE ON security_alerts
        BEGIN
            SELECT RAISE(ABORT, 'security_alerts ne peut pas être supprimé');
        END;
        """,
    ]
    for trigger_sql in triggers:
        db.session.execute(text(trigger_sql))
    db.session.commit()


def _ensure_default_admin(app):
    """Crée un compte admin de démonstration si aucun n'existe.
    Identifiants affichés dans la console au premier lancement."""
    if User.query.filter_by(role="admin").first():
        return

    import secrets

    default_email = "admin@medicabinet.fr"
    default_password = secrets.token_urlsafe(9)  # mot de passe fort généré aléatoirement
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
