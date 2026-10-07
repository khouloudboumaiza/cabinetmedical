import re
from datetime import date

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, session
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
            if user:
                # Génération et envoi automatique d'un code OTP au propriétaire du compte (1 mail max / 5 min)
                trigger_auto_unlock_code(user, ip)
                session["unlock_user_id"] = user.id

            flash(
                "Compte bloqué. Un code de confirmation a été envoyé au propriétaire du compte.",
                "error",
            )
            return redirect(url_for("auth.unlock_verify"))




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
        try:
            country = get_country_from_ip(ip)
            run_all_checks(user.id, country)
        except Exception as ex:
            current_app.logger.error(f"Erreur run_all_checks login: {ex}")

        flash("Connexion réussie.", "success")
        return redirect(url_for("cabinet.tableau_de_bord"))


    # GET -> redirige vers index, le modal s'ouvre via JavaScript
    return redirect(url_for("index"))


def send_geo_code(email: str, code: str):
    """Envoie le code de vérification géo (durée d'expiration 5 minutes) via mailer.send_email."""
    from mailer import send_email
    subject = "[MediCabinet] Code de vérification de connexion"
    body = (
        "Bonjour,\n\n"
        "Une connexion inhabituelle a été détectée sur votre compte MediCabinet.\n"
        f"Votre code de vérification est : {code}\n\n"
        "Ce code est valable pendant 5 minutes.\n"
        "Si vous n'êtes pas à l'origine de cette demande, veuillez contacter immédiatement l'administrateur.\n\n"
        "Cordialement,\n"
        "L'équipe MediCabinet"
    )
    send_email(email, subject, body)



@auth_bp.route("/verify-geo", methods=["GET", "POST"])
def verify_geo():
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
                from detection import log_login_attempt, run_all_checks
                ip = get_client_ip()
                country = get_country(ip)
                tor = is_tor_ip(ip)
                user_agent = request.headers.get("User-Agent", "") if request else ""
                log_login_attempt(user.id, ip, user_agent, "password_otp", True, country=country, is_tor=tor)
                run_all_checks(user.id, country)
            except Exception as ex:
                current_app.logger.error(f"Erreur run_all_checks verify_geo: {ex}")


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
    session.pop("geo_user_id", None)
    session.pop("geo_code_hash", None)
    session.pop("geo_expires", None)
    session.pop("geo_attempts", None)
    session.pop("geo_remember", None)
    session.pop("geo_next", None)


# ---------------------------------------------------------------------------
# Déblocage brute-force par code OTP envoyé par email
# ---------------------------------------------------------------------------

def send_unlock_code(email: str, code: str):
    """Envoie le code de déblocage brute-force (durée d'expiration 10 minutes) via mailer.send_email."""
    from mailer import send_email
    subject = "[MediCabinet] Code de déblocage de votre compte"
    body = (
        "Bonjour,\n\n"
        "Votre compte MediCabinet a été temporairement bloqué suite à plusieurs tentatives de connexion échouées.\n"
        f"Votre code de déblocage est : {code}\n\n"
        "Ce code est valable pendant 10 minutes.\n"
        "Après avoir vérifié ce code, il vous sera demandé de choisir un nouveau mot de passe pour des raisons de sécurité.\n\n"
        "Cordialement,\n"
        "L'équipe MediCabinet"
    )
    send_email(email, subject, body)



def _hash_code(code: str) -> str:
    """Hash SHA-256 du code (stocké en base, jamais le code brut)."""
    import hashlib
    return hashlib.sha256(code.encode()).hexdigest()


def trigger_auto_unlock_code(user, ip):
    """
    Génère et envoie automatiquement un code OTP au propriétaire du compte lors d'un blocage brute-force.
    Limite : 1 mail max par 5 minutes par compte pour éviter le spam.
    Horodatages stricts en UTC.
    """
    import secrets
    from datetime import datetime, timedelta
    from models import UnlockCode

    five_min_ago = datetime.utcnow() - timedelta(minutes=5)
    recent_code = UnlockCode.query.filter(
        UnlockCode.user_id == user.id,
        UnlockCode.created_at >= five_min_ago
    ).first()

    if not recent_code:
        code = f"{secrets.randbelow(10**6):06d}"
        expires_at = datetime.utcnow() + timedelta(minutes=10)

        entry = UnlockCode(
            user_id=user.id,
            ip_address=ip,
            code_hash=_hash_code(code),
            expires_at=expires_at,
            attempts=0,
            used=False,
        )
        db.session.add(entry)
        db.session.commit()

        send_unlock_code(user.email, code)
        return entry
    return recent_code


@auth_bp.route("/unlock", methods=["GET", "POST"])
def unlock():
    """
    Formulaire /unlock (GET / POST).
    Ne permet pas d'envoyer un code à une adresse saisie librement :
    si l'email correspond à un compte bloqué, déclenche ou renvoie le code
    vers l'email enregistré du compte (limite : 1 mail / 5 min).
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        ip = get_client_ip()

        user = User.query.filter_by(email=email).first()
        if user and check_brute_force(user.id, ip, max_attempts=current_app.config["BRUTE_FORCE_MAX_ATTEMPTS"], window_minutes=current_app.config["BRUTE_FORCE_WINDOW_MINUTES"]):
            trigger_auto_unlock_code(user, ip)
            session["unlock_user_id"] = user.id

        flash("Compte bloqué. Un code de confirmation a été envoyé au propriétaire du compte.", "error")
        return redirect(url_for("auth.unlock_verify"))

    return render_template("unlock.html")


@auth_bp.route("/unlock/verify", methods=["GET", "POST"])
def unlock_verify():
    """
    Saisie du code OTP de déblocage.
    Max 3 essais. En cas de succès : AccountUnlock créé (neutralise les échecs pour user_id ET ip_address en UTC),
    puis changement de mot de passe obligatoire avant connexion.
    En cas d'échec x3 ou expiration (UTC) : SecurityAlert UNLOCK_FAILED, le compte reste bloqué.
    Exclue du blocage brute-force.
    """
    import secrets as secrets_mod
    from datetime import datetime
    from models import UnlockCode, AccountUnlock

    user_id = session.get("unlock_user_id")
    user = db.session.get(User, user_id) if user_id else None
    email_display = user.email if user else ""

    if request.method == "POST":
        submitted = request.form.get("code", "").strip()
        ip = get_client_ip()

        if not user:
            submitted_email = request.form.get("email", "").strip().lower()
            if submitted_email:
                user = User.query.filter_by(email=submitted_email).first()
                if user:
                    user_id = user.id

        if not user:
            flash("Aucun compte correspondant en cours de déblocage.", "error")
            return redirect(url_for("auth.unlock"))

        entry = (
            UnlockCode.query.filter_by(user_id=user.id, used=False)
            .order_by(UnlockCode.created_at.desc())
            .first()
        )

        if not entry:
            flash("Code invalide ou expiré. Recommencez la demande.", "error")
            return redirect(url_for("auth.unlock"))

        now_utc = datetime.utcnow()

        # Vérification expiration (UTC)
        if now_utc > entry.expires_at:
            entry.used = True
            db.session.commit()
            _create_unlock_alert(user, ip, "UNLOCK_FAILED", "Code de déblocage expiré.")
            session.pop("unlock_user_id", None)
            flash("Le code a expiré. Le compte reste bloqué.", "error")
            return redirect(url_for("auth.unlock_verify"))

        entry.attempts += 1
        db.session.commit()

        # Comparaison sécurisée du hash
        if not secrets_mod.compare_digest(_hash_code(submitted), entry.code_hash):
            remaining = 3 - entry.attempts
            if remaining <= 0:
                entry.used = True
                db.session.commit()
                _create_unlock_alert(user, ip, "UNLOCK_FAILED", f"3 essais de code incorrects depuis {ip}.")
                session.pop("unlock_user_id", None)
                flash("Trop d'essais incorrects. Le compte reste bloqué.", "error")
                return redirect(url_for("auth.unlock_verify"))
            flash(f"Code incorrect. Essais restants : {remaining}.", "error")
            return render_template("unlock_verify.html", email=user.email)

        # ✅ Code correct → Marquer utilisé, créer AccountUnlock avec user_id ET ip_address (en UTC)
        entry.used = True
        unlock_obj = AccountUnlock(user_id=user.id, ip_address=ip, unlocked_at=now_utc)
        db.session.add(unlock_obj)
        db.session.commit()

        _create_unlock_alert(user, ip, "ACCOUNT_UNLOCKED", f"Compte {user.email} débloqué via OTP depuis {ip}.")
        session.pop("unlock_user_id", None)
        session["unlock_reset_user_id"] = user.id

        flash("Code correct. Choisissez un nouveau mot de passe pour vous connecter.", "success")
        return redirect(url_for("auth.unlock_reset_password"))

    return render_template("unlock_verify.html", email=email_display)


@auth_bp.route("/unlock/reset-password", methods=["GET", "POST"])
def unlock_reset_password():
    """
    Changement de mot de passe obligatoire après déblocage OTP.
    Vérifie la politique de robustesse, puis connecte l'utilisateur.
    Exclue du blocage brute-force.
    """
    from log_integrity import log_message_event

    user_id = session.get("unlock_reset_user_id")
    if not user_id:
        flash("Session expirée. Recommencez le déblocage.", "error")
        return redirect(url_for("auth.unlock"))

    user = db.session.get(User, user_id)
    if not user:
        session.pop("unlock_reset_user_id", None)
        flash("Utilisateur introuvable.", "error")
        return redirect(url_for("index"))

    if request.method == "POST":
        new_password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if new_password != confirm:
            flash("Les mots de passe ne correspondent pas.", "error")
            return render_template("unlock_reset_password.html")

        if not password_is_strong(new_password):
            flash(PASSWORD_POLICY_MSG, "error")
            return render_template("unlock_reset_password.html")

        user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
        if user.is_locked:
            user.is_locked = False
        db.session.commit()
        session.pop("unlock_reset_user_id", None)

        try:
            log_message_event(
                user_id=user.id,
                action="unlock_password_reset",
                details=f"Mot de passe réinitialisé suite au déblocage OTP depuis {get_client_ip()}"
            )
        except Exception:
            pass

        login_user(user)
        flash("Mot de passe mis à jour. Vous êtes connecté.", "success")
        return redirect(url_for("cabinet.tableau_de_bord"))

    return render_template("unlock_reset_password.html")


def _create_unlock_alert(user, ip, kind, message):
    """Crée une SecurityAlert pour les événements de déblocage en UTC."""
    from models import SecurityAlert
    try:
        from security_geo import get_country
        country = get_country(ip) or "inconnu"
    except Exception:
        country = "inconnu"
    full_message = f"{message} IP: {ip} (Pays: {country}). Compte: {user.email if user else 'inconnu'}."
    alert = SecurityAlert(kind=kind, user_id=user.id if user else None, message=full_message)
    db.session.add(alert)
    db.session.commit()



@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Vous avez été déconnecté.", "success")
    return redirect(url_for("index"))
