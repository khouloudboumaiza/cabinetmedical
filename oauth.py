from flask import Blueprint, url_for, redirect, request, current_app, flash
from flask_login import login_user
from authlib.integrations.flask_client import OAuth

from models import db, User, Patient
from detection import log_login_attempt, get_country_from_ip, run_all_checks

oauth_bp = Blueprint("oauth", __name__)
oauth = OAuth()


def init_oauth(app):
    """À appeler depuis app.py après app.config chargé."""
    oauth.init_app(app)
    if app.config.get("GOOGLE_CLIENT_ID") and app.config.get("GOOGLE_CLIENT_SECRET"):
        oauth.register(
            name="google",
            client_id=app.config["GOOGLE_CLIENT_ID"],
            client_secret=app.config["GOOGLE_CLIENT_SECRET"],
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )


@oauth_bp.route("/auth/google/login")
def google_login():
    if "google" not in oauth._clients:
        flash("La connexion Google n'est pas configurée (voir README.md).", "error")
        return redirect(url_for("auth.login"))
    redirect_uri = url_for("oauth.google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@oauth_bp.route("/auth/google/callback")
def google_callback():
    if "google" not in oauth._clients:
        flash("La connexion Google n'est pas configurée.", "error")
        return redirect(url_for("auth.login"))

    token = oauth.google.authorize_access_token()
    user_info = token.get("userinfo")
    if not user_info or not user_info.get("email"):
        flash("Impossible de récupérer les informations du compte Google.", "error")
        return redirect(url_for("auth.login"))

    email = user_info["email"].strip().lower()
    google_id = user_info["sub"]
    given_name = user_info.get("given_name", "")
    family_name = user_info.get("family_name", "")

    user = User.query.filter_by(email=email).first()
    if not user:
        # Nouveau compte créé via Google — rôle patient par défaut
        user = User(email=email, google_id=google_id, password_hash=None, role="patient")
        db.session.add(user)
        db.session.flush()  # pour avoir user.id

        # Crée automatiquement le profil patient
        patient = Patient(
            user_id=user.id,
            first_name=given_name or email.split("@")[0],
            last_name=family_name or "",
        )
        db.session.add(patient)
        db.session.commit()
    elif not user.google_id:
        # Compte existant (créé via email/mdp) -> on le lie au compte Google
        user.google_id = google_id
        db.session.commit()

    if user.is_locked:
        flash("Ce compte est verrouillé. Contactez un administrateur.", "error")
        return redirect(url_for("auth.login"))

    login_user(user)

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    country = get_country_from_ip(ip)
    log_login_attempt(user.id, ip, request.headers.get("User-Agent", ""), "google", True)
    try:
        run_all_checks(user.id, country)
    except Exception as ex:
        if hasattr(current_app, "logger"):
            current_app.logger.error(f"Erreur run_all_checks google_callback: {ex}")


    flash("Connexion via Google réussie.", "success")
    return redirect(url_for("cabinet.tableau_de_bord"))
