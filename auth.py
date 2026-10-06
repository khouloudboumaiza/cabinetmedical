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

        # Connexion réussie au niveau du mot de passe
        try:
            from security_geo import check_login_anomaly
            suspicious = check_login_anomaly(user)
        except Exception as e:
            current_app.logger.error(f"Erreur lors de la détection d'anomalies de connexion : {e}")
            suspicious = False

        if suspicious:
            import secrets, hashlib, time
            code = f"{secrets.randbelow(10**6):06d}"
            code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()

            from flask import session
            session["geo_user_id"] = user.id
            session["geo_code_hash"] = code_hash
            session["geo_expires"] = int(time.time()) + 300  # 5 minutes
            session["geo_attempts"] = 0
            session["geo_remember"] = request.form.get("remember", "false").lower() in ("true", "1", "on")
            session["geo_next"] = request.args.get("next") or request.form.get("next") or ""

            send_geo_code(user.email, code)
            flash("Connexion inhabituelle détectée. Un code de vérification a été envoyé à votre adresse email.", "warning")
            return redirect(url_for("auth.verify_geo"))

        login_user(user)
        flash("Connexion réussie.", "success")
        return redirect(url_for("cabinet.tableau_de_bord"))

    # GET -> redirige vers index, le modal s'ouvre via JavaScript
    return redirect(url_for("index"))


def send_geo_code(email: str, code: str):
    """Envoie le code de vérification à l'utilisateur.
    En mode démo/développement, affiche le code dans la console/terminal.
    En production, intégrer un service d'envoi d'email (ex: Flask-Mail / SMTP).
    """
    print(f"[OTP] Code de vérification pour {email} : {code}")


@auth_bp.route("/verify-geo", methods=["GET", "POST"])
def verify_geo():
    from flask import session
    from models import SecurityAlert

    geo_user_id = session.get("geo_user_id")
    if not geo_user_id:
        flash("Aucune vérification de connexion en attente.", "error")
        return redirect(url_for("index"))

    user = User.query.get(geo_user_id)
    if not user:
        _clear_geo_session()
        return redirect(url_for("index"))

    if request.method == "POST":
        import secrets, hashlib, time
        code_input = request.form.get("code", "").strip()
        now = int(time.time())
        expires = session.get("geo_expires", 0)
        attempts = session.get("geo_attempts", 0) + 1
        session["geo_attempts"] = attempts

        stored_hash = session.get("geo_code_hash", "")
        input_hash = hashlib.sha256(code_input.encode("utf-8")).hexdigest()

        is_expired = now > expires
        is_correct = secrets.compare_digest(input_hash, stored_hash)

        if not is_expired and is_correct:
            remember = session.get("geo_remember", False)
            next_url = session.get("geo_next", "")
            _clear_geo_session()

            login_user(user, remember=remember)

            # Log de la connexion réussie après validation OTP
            try:
                from security_geo import get_client_ip, get_country, is_tor_ip
                from detection import log_login_attempt
                ip = get_client_ip()
                country = get_country(ip)
                tor = is_tor_ip(ip)
                user_agent = request.headers.get("User-Agent", "") if request else ""
                log_login_attempt(user.id, ip, user_agent, "password_otp", True, country=country, is_tor=tor)
            except Exception:
                pass

            flash("Vérification réussie. Connexion établie.", "success")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("cabinet.tableau_de_bord"))

        # Échec ou expiration
        if attempts >= 3 or is_expired:
            from security_geo import get_client_ip, get_country
            ip = get_client_ip()
            country = get_country(ip) or "inconnu"

            _clear_geo_session()

            alert = SecurityAlert(
                user_id=user.id,
                kind="GEO_BLOCKED",
                message=f"Échec de vérification OTP pour {user.email} depuis {ip} ({country}). 3 essais manqués ou code expiré."
            )
            db.session.add(alert)
            db.session.commit()

            flash("Trop d'essais ou code expiré. Contactez l'administrateur.", "error")
            return redirect(url_for("index"))
        else:
            remaining = 3 - attempts
            flash(f"Code incorrect. Essais restants : {remaining}.", "error")

    return render_template("verify_geo.html", email=user.email)


def _clear_geo_session():
    from flask import session
    session.pop("geo_user_id", None)
    session.pop("geo_code_hash", None)
    session.pop("geo_expires", None)
    session.pop("geo_attempts", None)
    session.pop("geo_remember", None)
    session.pop("geo_next", None)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Vous avez été déconnecté.", "success")
    return redirect(url_for("index"))
