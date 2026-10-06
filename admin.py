from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required

from decorators import admin_required
from models import db, SecurityAlert, LoginLog, User, Patient, Appointment, Prescription
from log_integrity import verify_chain
from auth import bcrypt

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

STAFF_ROLES = ["admin", "medecin", "secretaire"]


@admin_bp.route("/")
@login_required
@admin_required
def index():
    from datetime import datetime, timedelta
    from sqlalchemy import func

    since_24h = datetime.utcnow() - timedelta(hours=24)

    total_users = User.query.count()
    logins_24h = LoginLog.query.filter(LoginLog.timestamp >= since_24h).count()
    failed_24h = LoginLog.query.filter(
        LoginLog.timestamp >= since_24h, LoginLog.success.is_(False)
    ).count()
    open_alerts = SecurityAlert.query.filter_by(resolved=False).count()

    # Répartition des alertes par type (pour le graphique)
    alert_counts = (
        db.session.query(SecurityAlert.alert_type, func.count(SecurityAlert.id))
        .group_by(SecurityAlert.alert_type)
        .all()
    )
    alert_labels = [row[0] for row in alert_counts] or ["—"]
    alert_values = [row[1] for row in alert_counts] or [0]

    recent_alerts = SecurityAlert.query.order_by(SecurityAlert.timestamp.desc()).limit(5).all()

    # Statistiques cabinet
    cabinet_stats = {
        "patients": Patient.query.count(),
        "medecins": User.query.filter_by(role="medecin").count(),
        "rdv_actifs": Appointment.query.filter(
            Appointment.status.in_(["planifie", "confirme"])
        ).count(),
        "ordonnances": Prescription.query.count(),
    }

    return render_template(
        "admin_index.html",
        total_users=total_users,
        logins_24h=logins_24h,
        failed_24h=failed_24h,
        open_alerts=open_alerts,
        alert_labels=alert_labels,
        alert_values=alert_values,
        recent_alerts=recent_alerts,
        cabinet_stats=cabinet_stats,
    )


@admin_bp.route("/alerts")
@login_required
@admin_required
def alerts():
    alert_type = request.args.get("type")
    
    unresolved_q = SecurityAlert.query.filter_by(resolved=False).order_by(SecurityAlert.timestamp.desc())
    if alert_type:
        unresolved_q = unresolved_q.filter_by(alert_type=alert_type)
    unresolved_alerts = unresolved_q.all()

    resolved_q = SecurityAlert.query.filter_by(resolved=True).order_by(SecurityAlert.timestamp.desc())
    if alert_type:
        resolved_q = resolved_q.filter_by(alert_type=alert_type)
    resolved_alerts = resolved_q.limit(20).all()

    return render_template(
        "admin_alerts.html",
        unresolved_alerts=unresolved_alerts,
        resolved_alerts=resolved_alerts,
        alerts=unresolved_alerts + resolved_alerts,
        filter_type=alert_type,
    )


@admin_bp.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@login_required
@admin_required
def resolve_alert(alert_id):
    from datetime import datetime
    alert = SecurityAlert.query.get_or_404(alert_id)
    alert.resolved = True
    alert.resolved_at = datetime.utcnow()
    db.session.commit()
    flash("Alerte marquée comme traitée.", "success")
    return redirect(url_for("admin.alerts"))


@admin_bp.route("/logs")
@login_required
@admin_required
def logs():
    recent_logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(200).all()
    return render_template("admin_logs.html", logs=recent_logs)


@admin_bp.route("/logs/verify")
@login_required
@admin_required
def verify_logs():
    """
    Vérifie l'intégrité complète de la chaîne de logs.
    Si un attaquant a modifié ou supprimé une entrée (même en base
    directement), cette vérification le détecte et indique où.
    """
    all_logs = LoginLog.query.order_by(LoginLog.id.asc()).all()
    result = verify_chain(all_logs, current_app.config["HMAC_SECRET"])
    return render_template("admin_verify.html", result=result, total=len(all_logs))


@admin_bp.route("/users")
@login_required
@admin_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin_users.html", users=all_users, staff_roles=STAFF_ROLES)


@admin_bp.route("/users/create", methods=["POST"])
@login_required
@admin_required
def create_user():
    """Crée un compte pour le personnel médical (médecin, secrétaire, admin)."""
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "medecin")

    if role not in STAFF_ROLES:
        flash("Rôle invalide.", "error")
        return redirect(url_for("admin.users"))

    if len(password) < 12:
        flash("Le mot de passe doit contenir au moins 12 caractères.", "error")
        return redirect(url_for("admin.users"))

    if User.query.filter_by(email=email).first():
        flash("Un compte avec cet email existe déjà.", "error")
        return redirect(url_for("admin.users"))

    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    user = User(email=email, password_hash=pw_hash, role=role)
    db.session.add(user)
    db.session.commit()
    flash(f"Compte {role} créé : {email}", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/toggle_lock", methods=["POST"])
@login_required
@admin_required
def toggle_lock(user_id):
    user = User.query.get_or_404(user_id)
    user.is_locked = not user.is_locked
    db.session.commit()
    state = "verrouillé" if user.is_locked else "déverrouillé"
    flash(f"Compte {user.email} {state}.", "success")
    return redirect(url_for("admin.users"))
