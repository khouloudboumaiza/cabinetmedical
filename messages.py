"""
Blueprint Messagerie Sécurisée Patient ↔ Médecin (MediCabinet).
Sécurité :
  - Chiffrement AES-256-GCM de bout en bout avec AAD (conversation_id)
  - Nonce aléatoire unique de 12 octets par message
  - Contrôle d'accès strict (RBAC & anti-IDOR avec réponse 404)
  - Admin et Secrétaire strictement exclus (404 + log sans alerte)
  - Alertes de sécurité (SecurityAlert) sur tentative IDOR
  - Journalisation avec intégrité HMAC chaînée (log_integrity)
  - Protection CSRF (formulaires & en-têtes fetch)
  - Rate limiting (20 messages / min / utilisateur)
  - Validation (strip, non vide, max 2000 caractères)
"""

from datetime import datetime, timedelta
import secrets
import hmac
from functools import wraps

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, current_app, abort, jsonify, session
)
from flask_login import login_required, current_user

from models import db, User, Patient, Appointment, MedicalRecord, Prescription, Conversation, Message
from crypto_utils import aes_encrypt_message, aes_decrypt_message
from log_integrity import log_message_event
from detection import create_alert

messages_bp = Blueprint("messages", __name__, url_prefix="/messages")


# ─────────────────────────────────────────────────────────────
# Fonctions de sécurité et aides
# ─────────────────────────────────────────────────────────────

def get_or_create_csrf_token() -> str:
    """Génère ou récupère le token CSRF stocké en session."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def verify_csrf():
    """Vérifie le token CSRF pour les requêtes POST (formulaire ou en-tête fetch)."""
    token = (
        request.headers.get("X-CSRFToken")
        or request.headers.get("X-CSRF-Token")
        or request.form.get("csrf_token")
    )
    expected = session.get("csrf_token")
    if not token or not expected or not hmac.compare_digest(str(token), str(expected)):
        abort(400, description="Token CSRF manquant ou invalide.")


def allowed_message_roles(f):
    """
    Restreint l'accès aux seuls rôles 'patient' et 'medecin'.
    Les rôles 'admin' et 'secretaire' reçoivent une 404 (sans alerte, mais avec log).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)

        if current_user.role in ("admin", "secretaire"):
            log_message_event(
                user_id=current_user.id,
                action="role_excluded",
                details=f"Accès refusé au rôle '{current_user.role}' sur la messagerie",
            )
            abort(404)

        if current_user.role not in ("patient", "medecin"):
            abort(404)

        return f(*args, **kwargs)

    return decorated


def get_authorized_conversation_or_404(conversation_id: int) -> Conversation:
    """
    Récupère la conversation et vérifie que l'utilisateur courant en est membre.
    En cas de violation IDOR : journalise l'événement, déclenche une SecurityAlert, et renvoie 404.
    """
    conv = Conversation.query.get(conversation_id)
    if not conv:
        abort(404)

    is_authorized = False

    if current_user.role == "patient":
        pat = current_user.patient_profile
        if pat and conv.patient_id == pat.id:
            is_authorized = True
    elif current_user.role == "medecin":
        if conv.doctor_id == current_user.id:
            is_authorized = True

    if not is_authorized:
        log_message_event(
            user_id=current_user.id,
            action="access_denied",
            conversation_id=conversation_id,
            details=f"Tentative IDOR par l'utilisateur {current_user.id} ({current_user.role})",
        )
        create_alert(
            user_id=current_user.id,
            alert_type="idor_message_attempt",
            details=f"Tentative d'accès non autorisé à la conversation #{conversation_id}",
        )
        abort(404)

    return conv


def check_rate_limit(user_id: int, max_per_minute: int = 20) -> bool:
    """Vérifie si l'utilisateur a dépassé le quota de 20 messages par minute."""
    since = datetime.utcnow() - timedelta(minutes=1)
    recent_count = Message.query.filter(
        Message.sender_id == user_id,
        Message.created_at >= since,
    ).count()
    return recent_count < max_per_minute


def can_communicate(doctor_user_id: int, patient_db_id: int) -> bool:
    """
    Vérifie qu'il existe une relation médicale (rendez-vous, dossier ou ordonnance)
    entre le médecin et le patient, et que le patient a un compte actif.
    """
    patient = Patient.query.get(patient_db_id)
    if not patient or patient.user_id is None:
        return False

    doctor = User.query.get(doctor_user_id)
    if not doctor or doctor.role != "medecin":
        return False

    has_appt = Appointment.query.filter_by(
        patient_id=patient_db_id, medecin_id=doctor_user_id
    ).first() is not None
    if has_appt:
        return True

    has_rec = MedicalRecord.query.filter_by(
        patient_id=patient_db_id, medecin_id=doctor_user_id
    ).first() is not None
    if has_rec:
        return True

    has_rx = Prescription.query.filter_by(
        patient_id=patient_db_id, medecin_id=doctor_user_id
    ).first() is not None
    if has_rx:
        return True

    return False


def get_eligible_doctors_for_patient(patient_id: int):
    """Retourne la liste des médecins avec lesquels le patient a une relation."""
    medecin_ids = set()
    for appt in Appointment.query.filter_by(patient_id=patient_id).all():
        medecin_ids.add(appt.medecin_id)
    for rec in MedicalRecord.query.filter_by(patient_id=patient_id).all():
        medecin_ids.add(rec.medecin_id)
    for rx in Prescription.query.filter_by(patient_id=patient_id).all():
        medecin_ids.add(rx.medecin_id)
    if not medecin_ids:
        return []
    return User.query.filter(User.id.in_(medecin_ids), User.role == "medecin").all()


def get_eligible_patients_for_doctor(doctor_id: int):
    """Retourne la liste des patients ayant un compte utilisateur et une relation avec ce médecin."""
    patient_ids = set()
    for appt in Appointment.query.filter_by(medecin_id=doctor_id).all():
        patient_ids.add(appt.patient_id)
    for rec in MedicalRecord.query.filter_by(medecin_id=doctor_id).all():
        patient_ids.add(rec.patient_id)
    for rx in Prescription.query.filter_by(medecin_id=doctor_id).all():
        patient_ids.add(rx.patient_id)
    if not patient_ids:
        return []
    return Patient.query.filter(
        Patient.id.in_(patient_ids),
        Patient.user_id.isnot(None),
    ).all()


# ─────────────────────────────────────────────────────────────
# Routes de la messagerie
# ─────────────────────────────────────────────────────────────

@messages_bp.route("", methods=["GET"])
@login_required
@allowed_message_roles
def index():
    """Liste des conversations avec compteur de non-lus et contacts éligibles."""
    key = current_app.config["ENCRYPTION_KEY"]
    conversations_data = []

    if current_user.role == "patient":
        pat = current_user.patient_profile
        if not pat:
            conversations = []
            eligible_contacts = []
        else:
            conversations = Conversation.query.filter_by(patient_id=pat.id).order_by(
                Conversation.created_at.desc()
            ).all()
            eligible_doctors = get_eligible_doctors_for_patient(pat.id)
            existing_doc_ids = {c.doctor_id for c in conversations}
            eligible_contacts = [d for d in eligible_doctors if d.id not in existing_doc_ids]

    else:  # medecin
        conversations = Conversation.query.filter_by(doctor_id=current_user.id).order_by(
            Conversation.created_at.desc()
        ).all()
        eligible_patients = get_eligible_patients_for_doctor(current_user.id)
        existing_pat_ids = {c.patient_id for c in conversations}
        eligible_contacts = [p for p in eligible_patients if p.id not in existing_pat_ids]

    for conv in conversations:
        unread = conv.unread_count_for(current_user.id)
        last_msg = conv.last_message()
        last_text = ""
        if last_msg:
            try:
                last_text = aes_decrypt_message(key, last_msg.ciphertext, last_msg.nonce, conv.id)
                if len(last_text) > 40:
                    last_text = last_text[:37] + "..."
            except Exception:
                last_text = "[Message chiffré]"

        contact_name = conv.doctor.email if current_user.role == "patient" else conv.patient.full_name
        conversations_data.append({
            "conv": conv,
            "contact_name": contact_name,
            "unread": unread,
            "last_message": last_text,
            "last_time": last_msg.created_at if last_msg else conv.created_at,
        })

    # Trier par heure du dernier message décroissant
    conversations_data.sort(key=lambda x: x["last_time"], reverse=True)

    return render_template(
        "messages.html",
        conversations=conversations_data,
        eligible_contacts=eligible_contacts,
        csrf_token=get_or_create_csrf_token(),
    )


@messages_bp.route("/<int:conversation_id>", methods=["GET"])
@login_required
@allowed_message_roles
def conversation_view(conversation_id):
    """Affiche la conversation et marque les messages reçus comme lus."""
    conv = get_authorized_conversation_or_404(conversation_id)
    key = current_app.config["ENCRYPTION_KEY"]

    # Marquer les messages reçus non lus comme lus
    unread_messages = conv.messages.filter(
        Message.sender_id != current_user.id,
        Message.read_at.is_(None),
    ).all()

    if unread_messages:
        now = datetime.utcnow()
        for m in unread_messages:
            m.read_at = now
        db.session.commit()

    # Déchiffrement de tous les messages
    decrypted_messages = []
    for msg in conv.messages.all():
        try:
            content = aes_decrypt_message(key, msg.ciphertext, msg.nonce, conv.id)
        except Exception:
            content = "[Erreur : message corrompu ou altéré]"

        decrypted_messages.append({
            "id": msg.id,
            "sender_id": msg.sender_id,
            "is_me": (msg.sender_id == current_user.id),
            "content": content,
            "created_at": msg.created_at,
            "read_at": msg.read_at,
        })

    # Journaliser l'ouverture de la conversation
    log_message_event(
        user_id=current_user.id,
        action="open_conversation",
        conversation_id=conv.id,
    )

    contact_name = conv.doctor.email if current_user.role == "patient" else conv.patient.full_name
    contact_role = "Médecin" if current_user.role == "patient" else "Patient"

    return render_template(
        "message_chat.html",
        conversation=conv,
        messages=decrypted_messages,
        contact_name=contact_name,
        contact_role=contact_role,
        csrf_token=get_or_create_csrf_token(),
    )


@messages_bp.route("/<int:conversation_id>/send", methods=["POST"])
@login_required
@allowed_message_roles
def send_message(conversation_id):
    """Envoi d'un message chiffré dans la conversation."""
    verify_csrf()
    conv = get_authorized_conversation_or_404(conversation_id)

    # Rate limiting (20 messages / minute)
    if not check_rate_limit(current_user.id, max_per_minute=20):
        if request.is_json or request.headers.get("Accept") == "application/json":
            return jsonify({"error": "Limite d'envoi dépassée (20 messages / min max)."}), 429
        abort(429, description="Trop de messages envoyés. Limite de 20 messages par minute.")

    # Récupération et validation du contenu
    raw_content = ""
    if request.is_json:
        data = request.get_json(silent=True) or {}
        raw_content = data.get("content", "")
    else:
        raw_content = request.form.get("content", "")

    content = raw_content.strip()

    if not content or len(content) > 2000:
        if request.is_json or request.headers.get("Accept") == "application/json":
            return jsonify({"error": "Le message ne doit pas être vide et faire au plus 2000 caractères."}), 400
        abort(400, description="Le message ne doit pas être vide et faire au plus 2000 caractères.")

    # Vérification que le patient a toujours un compte valide si le médecin envoie
    if current_user.role == "medecin":
        if not conv.patient.user_id:
            abort(400, description="Ce patient n'a pas de compte utilisateur actif.")

    # Chiffrement AES-256-GCM avec AAD = conversation_id
    key = current_app.config["ENCRYPTION_KEY"]
    ciphertext_b64, nonce_b64 = aes_encrypt_message(key, content, conv.id)

    msg = Message(
        conversation_id=conv.id,
        sender_id=current_user.id,
        ciphertext=ciphertext_b64,
        nonce=nonce_b64,
    )
    db.session.add(msg)
    db.session.commit()

    # Journalisation intègre (sans contenu !)
    log_message_event(
        user_id=current_user.id,
        action="send_message",
        conversation_id=conv.id,
    )

    if request.is_json or request.headers.get("Accept") == "application/json":
        return jsonify({
            "status": "success",
            "message": {
                "id": msg.id,
                "sender_id": msg.sender_id,
                "is_me": True,
                "content": content,
                "created_at": msg.created_at.strftime("%H:%M"),
                "read": False,
            }
        }), 201

    return redirect(url_for("messages.conversation_view", conversation_id=conv.id))


@messages_bp.route("/<int:conversation_id>/poll", methods=["GET"])
@login_required
@allowed_message_roles
def poll_messages(conversation_id):
    """Polling AJAX pour récupérer les nouveaux messages arrivés après after_id."""
    conv = get_authorized_conversation_or_404(conversation_id)
    key = current_app.config["ENCRYPTION_KEY"]

    try:
        after_id = int(request.args.get("after", 0))
    except (ValueError, TypeError):
        after_id = 0

    new_msgs = conv.messages.filter(Message.id > after_id).order_by(Message.created_at.asc()).all()

    # Marquer les nouveaux messages reçus comme lus
    now = datetime.utcnow()
    updated = False
    for m in new_msgs:
        if m.sender_id != current_user.id and m.read_at is None:
            m.read_at = now
            updated = True
    if updated:
        db.session.commit()

    result = []
    for m in new_msgs:
        try:
            content = aes_decrypt_message(key, m.ciphertext, m.nonce, conv.id)
        except Exception:
            content = "[Erreur : message altéré]"

        result.append({
            "id": m.id,
            "sender_id": m.sender_id,
            "is_me": (m.sender_id == current_user.id),
            "content": content,
            "created_at": m.created_at.strftime("%H:%M"),
            "read": (m.read_at is not None),
        })

    return jsonify({"messages": result})


@messages_bp.route("/new", methods=["POST"])
@login_required
@allowed_message_roles
def start_conversation():
    """Démarre une nouvelle conversation après validation des droits de communication."""
    verify_csrf()

    if current_user.role == "patient":
        pat = current_user.patient_profile
        if not pat:
            flash("Profil patient introuvable.", "error")
            return redirect(url_for("messages.index"))

        try:
            doctor_id = int(request.form.get("doctor_id", 0))
        except (ValueError, TypeError):
            doctor_id = 0

        if not doctor_id or not can_communicate(doctor_id, pat.id):
            flash("Vous ne pouvez écrire qu'à un médecin avec qui vous avez un dossier ou un rendez-vous.", "error")
            return redirect(url_for("messages.index")), 403

        # Vérifier si la conversation existe déjà
        conv = Conversation.query.filter_by(patient_id=pat.id, doctor_id=doctor_id).first()
        if not conv:
            conv = Conversation(patient_id=pat.id, doctor_id=doctor_id)
            db.session.add(conv)
            db.session.commit()

        return redirect(url_for("messages.conversation_view", conversation_id=conv.id))

    elif current_user.role == "medecin":
        try:
            patient_id = int(request.form.get("patient_id", 0))
        except (ValueError, TypeError):
            patient_id = 0

        patient = Patient.query.get(patient_id)
        if not patient or not patient.user_id:
            flash("Ce patient ne possède pas de compte utilisateur actif sur le portail.", "error")
            return redirect(url_for("messages.index")), 400

        if not can_communicate(current_user.id, patient.id):
            flash("Vous ne pouvez écrire qu'à vos propres patients.", "error")
            return redirect(url_for("messages.index")), 403

        # Vérifier si la conversation existe déjà
        conv = Conversation.query.filter_by(patient_id=patient.id, doctor_id=current_user.id).first()
        if not conv:
            conv = Conversation(patient_id=patient.id, doctor_id=current_user.id)
            db.session.add(conv)
            db.session.commit()

        return redirect(url_for("messages.conversation_view", conversation_id=conv.id))

    abort(404)
