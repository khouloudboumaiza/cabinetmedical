import re
from datetime import date

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt

from models import db, User, Patient
from detection import log_login_attempt, get_country_from_ip, check_brute_force, run_all_checks

auth_bp = Blueprint("auth", __name__)
bcrypt = Bcrypt()

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


PASSWORD_POLICY_MSG = (
    "Le mot de passe doit contenir au moins 12 caractères, "
    "dont au moins une lettre majuscule, une minuscule et un chiffre."
)


def password_is_strong(password: str) -> bool:
    """Politique de mot de passe unique pour toute l'application :
    au moins 12 caractères, une majuscule, une minuscule et un chiffre."""
    if not password or len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    return True


def get_client_ip():
    # X-Forwarded-For si l'app est derrière un proxy/reverse-proxy
    return request.headers.get("X-Forwarded-For", request.remote_addr)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Déconnecter toute session active si l'utilisateur soumet une nouvelle inscription
        if current_user.is_authenticated:
            logout_user()

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        phone = request.form.get("phone", "").strip()

        if not EMAIL_REGEX.match(email):
            flash("Adresse email invalide.", "error")
            return redirect(url_for("index", auth_tab="register"))

        if not password_is_strong(password):
            flash(PASSWORD_POLICY_MSG, "error")
            return redirect(url_for("index", auth_tab="register"))

        if not first_name or not last_name:
            flash("Le prénom et le nom sont obligatoires.", "error")
            return redirect(url_for("index", auth_tab="register"))

        if User.query.filter_by(email=email).first():
            flash("Impossible de créer ce compte avec ces informations.", "error")
            return redirect(url_for("index", auth_tab="register"))

        try:
            password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
            user = User(email=email, password_hash=password_hash, role="patient")
            db.session.add(user)
            db.session.flush()

            patient = Patient(
                user_id=user.id,
                first_name=first_name,
                last_name=last_name,
                phone=phone or None,
            )
            db.session.add(patient)
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("Une erreur est survenue lors de la création du compte.", "error")
            return redirect(url_for("index", auth_tab="register"))

        flash("Compte créé avec succès. Vous pouvez vous connecter.", "success")
        return redirect(url_for("index", auth_tab="login"))

    return redirect(url_for("index", auth_tab="register"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        ip = get_client_ip()
        user_agent = request.headers.get("User-Agent", "")

        user = User.query.filter_by(email=email).first()

        # Vérifie le brute-force AVANT de traiter la tentative
        if check_brute_force(
            user.id if user else None,
            ip,
            max_attempts=current_app.config["BRUTE_FORCE_MAX_ATTEMPTS"],
            window_minutes=current_app.config["BRUTE_FORCE_WINDOW_MINUTES"],
        ):
            flash("Trop de tentatives échouées. Réessayez plus tard.", "error")
            return redirect(url_for("index"))

        # Comparaison en temps constant via bcrypt ; message d'erreur générique
        valid = (
            user is not None
            and user.password_hash is not None
            and bcrypt.check_password_hash(user.password_hash, password)
        )

        if not valid:
            log_login_attempt(user.id if user else None, ip, user_agent, "password", False)
            flash("Email ou mot de passe incorrect.", "error")
            return redirect(url_for("index"))

        if user.is_locked:
            flash("Ce compte est temporairement verrouillé. Contactez un administrateur.", "error")
            return redirect(url_for("index"))

        # Connexion réussie
        login_user(user)
        country = get_country_from_ip(ip)
        log_login_attempt(user.id, ip, user_agent, "password", True)
        run_all_checks(user.id, country)

        flash("Connexion réussie.", "success")
        return redirect(url_for("cabinet.tableau_de_bord"))

    # GET -> redirige vers index, le modal s'ouvre via JavaScript
    return redirect(url_for("index"))


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Vous avez été déconnecté.", "success")
    return redirect(url_for("index"))
