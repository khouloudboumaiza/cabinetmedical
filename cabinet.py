"""
Blueprint Cabinet Médical — routes principales de l'application :
  - Tableau de bord (statistiques selon le rôle)
  - Gestion des patients (CRUD)
  - Rendez-vous (planification, statuts)
  - Dossiers médicaux chiffrés AES-256-GCM
  - Ordonnances chiffrées + impression
"""

from datetime import datetime, timedelta, date

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, current_app, abort
)
from flask_login import login_required, current_user

from models import db, User, Patient, Appointment, MedicalRecord, Prescription
from crypto_utils import aes_encrypt, aes_decrypt
from decorators import staff_required, role_required

cabinet_bp = Blueprint("cabinet", __name__)


# ─────────────────────────────────────────────────────────────
# Tableau de bord
# ─────────────────────────────────────────────────────────────

@cabinet_bp.route("/dashboard")
@login_required
def tableau_de_bord():
    if current_user.role == "admin":
        return redirect(url_for("admin.index"))
    if current_user.role == "medecin":
        return redirect(url_for("cabinet.appointments"))
        
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    week_end = today_start + timedelta(days=7)

    if current_user.role == "patient":
        pat = current_user.patient_profile
        if pat:
            mes_rdv = Appointment.query.filter(
                Appointment.patient_id == pat.id,
                Appointment.scheduled_at >= now,
                Appointment.status.in_(["planifie", "confirme"]),
            ).count()
            mes_dossiers = MedicalRecord.query.filter_by(patient_id=pat.id).count()
            mes_ordonnances = Prescription.query.filter_by(patient_id=pat.id).count()
        else:
            mes_rdv = mes_dossiers = mes_ordonnances = 0

        stats = {"mes_rdv": mes_rdv, "mes_dossiers": mes_dossiers, "mes_ordonnances": mes_ordonnances}

        upcoming_q = Appointment.query.filter(
            Appointment.patient_id == (pat.id if pat else -1),
            Appointment.scheduled_at >= now,
        ).order_by(Appointment.scheduled_at).limit(10).all()

    else:
        patients_count = Patient.query.count()
        rdv_today = Appointment.query.filter(
            Appointment.scheduled_at >= today_start,
            Appointment.scheduled_at < today_end,
        ).count()
        rdv_week = Appointment.query.filter(
            Appointment.scheduled_at >= today_start,
            Appointment.scheduled_at < week_end,
        ).count()
        ordonnances_count = Prescription.query.count()

        stats = {
            "patients": patients_count,
            "rdv_today": rdv_today,
            "rdv_week": rdv_week,
            "ordonnances": ordonnances_count,
            "mes_rdv_today": 0,
        }

        if current_user.role == "medecin":
            stats["mes_rdv_today"] = Appointment.query.filter(
                Appointment.medecin_id == current_user.id,
                Appointment.scheduled_at >= today_start,
                Appointment.scheduled_at < today_end,
            ).count()

        upcoming_q = Appointment.query.filter(
            Appointment.scheduled_at >= now,
        ).order_by(Appointment.scheduled_at).limit(10).all()

    return render_template("dashboard.html", stats=stats, upcoming=upcoming_q)


# ─────────────────────────────────────────────────────────────
# Patients
# ─────────────────────────────────────────────────────────────

@cabinet_bp.route("/patients")
@login_required
@role_required("admin", "secretaire")
def patients():
    q = request.args.get("q", "").strip()
    query = Patient.query
    if q:
        like = f"%{q}%"
        query = query.filter(
            db.or_(
                Patient.first_name.ilike(like),
                Patient.last_name.ilike(like),
                Patient.phone.ilike(like),
            )
        )
    all_patients = query.order_by(Patient.last_name).all()
    return render_template("patients.html", patients=all_patients, q=q)


@cabinet_bp.route("/patients/new", methods=["GET", "POST"])
@login_required
@role_required("admin", "secretaire")
def patient_new():
    if request.method == "POST":
        dob_str = request.form.get("date_of_birth", "").strip()
        dob = None
        if dob_str:
            try:
                dob = date.fromisoformat(dob_str)
            except ValueError:
                pass

        patient = Patient(
            first_name=request.form.get("first_name", "").strip(),
            last_name=request.form.get("last_name", "").strip(),
            date_of_birth=dob,
            gender=request.form.get("gender") or None,
            phone=request.form.get("phone", "").strip() or None,
            address=request.form.get("address", "").strip() or None,
            blood_type=request.form.get("blood_type") or None,
            allergies=request.form.get("allergies", "").strip() or None,
        )

        # Lier à un compte patient existant
        account_email = request.form.get("account_email", "").strip().lower()
        if account_email:
            acc = User.query.filter_by(email=account_email, role="patient").first()
            if acc and not acc.patient_profile:
                patient.user_id = acc.id
            elif acc and acc.patient_profile:
                flash("Ce compte est déjà lié à un patient.", "error")
                return render_template("patient_form.html", patient=None)

        db.session.add(patient)
        db.session.commit()
        flash(f"Patient {patient.full_name} créé avec succès.", "success")
        return redirect(url_for("cabinet.patient_detail", patient_id=patient.id))

    return render_template("patient_form.html", patient=None)


@cabinet_bp.route("/patients/<int:patient_id>")
@login_required
@staff_required
def patient_detail(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    records = MedicalRecord.query.filter_by(patient_id=patient_id).order_by(
        MedicalRecord.created_at.desc()
    ).all()
    ordonnances = Prescription.query.filter_by(patient_id=patient_id).order_by(
        Prescription.created_at.desc()
    ).all()
    rdv = Appointment.query.filter_by(patient_id=patient_id).order_by(
        Appointment.scheduled_at.desc()
    ).limit(10).all()
    return render_template(
        "patient_detail.html",
        patient=patient,
        records=records,
        ordonnances=ordonnances,
        rdv=rdv,
    )


@cabinet_bp.route("/patients/<int:patient_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin", "secretaire")
def patient_edit(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    if request.method == "POST":
        patient.first_name = request.form.get("first_name", "").strip()
        patient.last_name = request.form.get("last_name", "").strip()
        dob_str = request.form.get("date_of_birth", "").strip()
        if dob_str:
            try:
                patient.date_of_birth = date.fromisoformat(dob_str)
            except ValueError:
                pass
        patient.gender = request.form.get("gender") or None
        patient.phone = request.form.get("phone", "").strip() or None
        patient.address = request.form.get("address", "").strip() or None
        patient.blood_type = request.form.get("blood_type") or None
        patient.allergies = request.form.get("allergies", "").strip() or None
        db.session.commit()
        flash("Fiche patient mise à jour.", "success")
        return redirect(url_for("cabinet.patient_detail", patient_id=patient.id))
    return render_template("patient_form.html", patient=patient)


@cabinet_bp.route("/patients/<int:patient_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def patient_delete(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    db.session.delete(patient)
    db.session.commit()
    flash("Patient supprimé.", "success")
    return redirect(url_for("cabinet.patients"))


# ─────────────────────────────────────────────────────────────
# Rendez-vous
# ─────────────────────────────────────────────────────────────

def send_notification(patient_id, sender_id, notif_type, message, appointment_id=None):
    """Utilitaire centralisé — crée une PatientNotification.
    Réutilise le modèle existant sans dupliquer la logique."""
    from models import PatientNotification
    notif = PatientNotification(
        patient_id=patient_id,
        appointment_id=appointment_id,
        sender_id=sender_id,
        notification_type=notif_type,
        message=message,
        is_read=False,
    )
    db.session.add(notif)
    # pas de commit ici : le caller doit commiter en bloc

# ── Notifications secrétaire (internes) ───────────────────────
def _notify_secretariat(rdv, message):
    """Notifie toutes les secrétaires d'un événement patient."""
    secretaires = User.query.filter_by(role='secretaire').all()
    for sec in secretaires:
        # On envoie la notif vers un patient fictif : on log plutôt en alerte
        from detection import create_alert
        create_alert(
            user_id=sec.id,
            alert_type='appointment_request',
            details=message
        )


@cabinet_bp.route("/appointments")
@login_required
def appointments():
    jour_str = request.args.get("jour", "").strip()
    query = Appointment.query

    if current_user.role == "patient":
        pat = current_user.patient_profile
        if pat:
            query = query.filter_by(patient_id=pat.id)
        else:
            query = query.filter(Appointment.id == -1)
    elif current_user.role == "medecin":
        query = query.filter_by(medecin_id=current_user.id)

    if jour_str:
        try:
            jour = date.fromisoformat(jour_str)
            jour_dt = datetime(jour.year, jour.month, jour.day)
            query = query.filter(
                Appointment.scheduled_at >= jour_dt,
                Appointment.scheduled_at < jour_dt + timedelta(days=1),
            )
        except ValueError:
            pass

    # Séparer les demandes en attente pour la secrétaire
    pending_requests = []
    if current_user.role in ['secretaire', 'admin']:
        pending_requests = Appointment.query.filter(
            Appointment.status == 'en_attente'
        ).order_by(Appointment.created_at.desc()).all()

    all_appts = query.filter(
        Appointment.status != 'en_attente'
    ).order_by(Appointment.scheduled_at.desc()).all() if current_user.role in ['secretaire','admin'] else \
        query.order_by(Appointment.scheduled_at.desc()).all()

    return render_template("appointments.html", appointments=all_appts,
                           jour=jour_str, pending_requests=pending_requests)


@cabinet_bp.route("/appointments/new", methods=["GET", "POST"])
@login_required
@role_required("admin", "secretaire")
def appointment_new():
    if request.method == "POST":
        patient_id = int(request.form.get("patient_id", 0))
        medecin_id = int(request.form.get("medecin_id", 0))
        scheduled_str = request.form.get("scheduled_at", "")
        duration = int(request.form.get("duration_minutes", 30))
        motif = request.form.get("motif", "").strip()
        notes = request.form.get("notes", "").strip() or None

        if not patient_id or not medecin_id or not scheduled_str or not motif:
            flash("Tous les champs obligatoires doivent être remplis.", "error")
        else:
            try:
                scheduled_at = datetime.fromisoformat(scheduled_str)
            except ValueError:
                flash("Format de date invalide.", "error")
                scheduled_at = None

            if scheduled_at:
                conflict = Appointment.query.filter(
                    Appointment.medecin_id == medecin_id,
                    Appointment.status.in_(["planifie", "confirme", "en_attente"]),
                    Appointment.scheduled_at == scheduled_at,
                ).first()
                if conflict:
                    flash("Ce médecin a déjà un rendez-vous à cette heure.", "error")
                else:
                    rdv = Appointment(
                        patient_id=patient_id,
                        medecin_id=medecin_id,
                        scheduled_at=scheduled_at,
                        duration_minutes=duration,
                        motif=motif,
                        notes=notes,
                        status="confirme",
                    )
                    db.session.add(rdv)
                    db.session.flush()
                    # Notifier le patient de la confirmation directe
                    medecin = User.query.get(medecin_id)
                    send_notification(
                        patient_id=patient_id,
                        sender_id=current_user.id,
                        notif_type="Confirmation",
                        message=f"Votre rendez-vous avec Dr {medecin.email} est confirmé pour le {scheduled_at.strftime('%d/%m/%Y à %H:%M')}.",
                        appointment_id=rdv.id
                    )
                    db.session.commit()
                    flash("Rendez-vous planifié avec succès.", "success")
                    return redirect(url_for("cabinet.appointments"))

    patients = Patient.query.order_by(Patient.last_name).all()
    medecins = User.query.filter_by(role="medecin").order_by(User.email).all()
    return render_template("appointment_form.html", patients=patients, medecins=medecins)


@cabinet_bp.route("/appointments/request", methods=["GET", "POST"])
@login_required
@role_required("patient")
def appointment_request():
    """Patient soumet une demande de rendez-vous → statut en_attente."""
    if not current_user.patient_profile:
        flash("Vous n'avez pas de profil patient associé.", "error")
        return redirect(url_for("cabinet.dashboard"))

    if request.method == "POST":
        medecin_id = int(request.form.get("medecin_id", 0))
        scheduled_str = request.form.get("scheduled_at", "")
        motif = request.form.get("motif", "").strip() or "Consultation"

        if not medecin_id or not scheduled_str:
            flash("Veuillez sélectionner un médecin et une date.", "error")
        else:
            try:
                scheduled_at = datetime.fromisoformat(scheduled_str)
            except ValueError:
                flash("Format de date invalide.", "error")
                scheduled_at = None

            if scheduled_at:
                rdv = Appointment(
                    patient_id=current_user.patient_profile.id,
                    medecin_id=medecin_id,
                    scheduled_at=scheduled_at,
                    motif=motif,
                    status="en_attente",
                    requested_by=current_user.id,
                )
                db.session.add(rdv)
                db.session.flush()
                # Notifier la secrétaire
                medecin = User.query.get(medecin_id)
                _notify_secretariat(
                    rdv,
                    f"Nouvelle demande de rendez-vous : {current_user.patient_profile.full_name} "
                    f"souhaite voir Dr {medecin.email} le {scheduled_at.strftime('%d/%m/%Y à %H:%M')}."
                )
                db.session.commit()
                flash("Votre demande a été envoyée. La secrétaire vous contactera bientôt.", "success")
                return redirect(url_for("cabinet.appointments"))

    medecins = User.query.filter_by(role="medecin").order_by(User.email).all()
    return render_template("appointment_request_form.html", medecins=medecins)


@cabinet_bp.route("/appointments/<int:rdv_id>/status", methods=["POST"])
@login_required
@staff_required
def appointment_status(rdv_id):
    rdv = Appointment.query.get_or_404(rdv_id)
    new_status = request.form.get("status")
    proposed_str = request.form.get("proposed_at", "").strip()
    reason = request.form.get("reason", "").strip()
    medecin = User.query.get(rdv.medecin_id)

    if new_status == "confirme":
        # Vérifier conflit avant confirmation
        conflict = Appointment.query.filter(
            Appointment.medecin_id == rdv.medecin_id,
            Appointment.status.in_(["planifie", "confirme"]),
            Appointment.scheduled_at == rdv.scheduled_at,
            Appointment.id != rdv.id,
        ).first()
        if conflict:
            flash("Conflit de créneau détecté. Proposez un autre horaire.", "error")
            return redirect(url_for("cabinet.appointments"))
        rdv.status = "confirme"
        send_notification(
            patient_id=rdv.patient_id,
            sender_id=current_user.id,
            notif_type="Confirmation",
            message=f"Votre rendez-vous avec Dr {medecin.email} est confirmé pour le {rdv.scheduled_at.strftime('%d/%m/%Y à %H:%M')}.",
            appointment_id=rdv.id
        )
        flash("Rendez-vous confirmé. Notification envoyée au patient.", "success")

    elif new_status == "propose":
        if not proposed_str:
            flash("Veuillez saisir la date/heure du nouveau créneau proposé.", "error")
            return redirect(url_for("cabinet.appointments"))
        try:
            proposed_at = datetime.fromisoformat(proposed_str)
        except ValueError:
            flash("Format de date invalide.", "error")
            return redirect(url_for("cabinet.appointments"))
        rdv.status = "propose"
        rdv.proposed_at = proposed_at
        send_notification(
            patient_id=rdv.patient_id,
            sender_id=current_user.id,
            notif_type="Proposition",
            message=f"Le créneau demandé n'est pas disponible. Le secrétariat vous propose le {proposed_at.strftime('%d/%m/%Y à %H:%M')} avec Dr {medecin.email}.",
            appointment_id=rdv.id
        )
        flash("Proposition envoyée au patient.", "success")

    elif new_status == "refuse":
        rdv.status = "annule"
        msg = f"Votre demande de rendez-vous du {rdv.scheduled_at.strftime('%d/%m/%Y à %H:%M')} n'a pas pu être acceptée."
        if reason:
            msg += f" Raison : {reason}"
        send_notification(
            patient_id=rdv.patient_id,
            sender_id=current_user.id,
            notif_type="Refus",
            message=msg,
            appointment_id=rdv.id
        )
        flash("Demande refusée. Notification envoyée au patient.", "success")

    elif new_status in {"termine", "annule"}:
        rdv.status = new_status
        if new_status == "annule":
            send_notification(
                patient_id=rdv.patient_id,
                sender_id=current_user.id,
                notif_type="Annulation",
                message=f"Votre rendez-vous du {rdv.scheduled_at.strftime('%d/%m/%Y à %H:%M')} a été annulé.",
                appointment_id=rdv.id
            )
        flash(f"Statut mis à jour : {new_status}.", "success")

    db.session.commit()
    return redirect(url_for("cabinet.appointments"))


@cabinet_bp.route("/appointments/<int:rdv_id>/respond", methods=["POST"])
@login_required
@role_required("patient")
def appointment_respond(rdv_id):
    """Patient accepte ou refuse la proposition de créneau de la secrétaire."""
    rdv = Appointment.query.get_or_404(rdv_id)
    pat = current_user.patient_profile
    if not pat or rdv.patient_id != pat.id:
        abort(403)
    if rdv.status != "propose":
        flash("Cette demande n'est plus en attente de réponse.", "error")
        return redirect(url_for("cabinet.appointments"))

    choice = request.form.get("choice")
    medecin = User.query.get(rdv.medecin_id)

    if choice == "accept":
        rdv.scheduled_at = rdv.proposed_at
        rdv.proposed_at = None
        rdv.status = "confirme"
        # Notifier secrétariat
        _notify_secretariat(rdv, f"{pat.full_name} a accepté le créneau proposé : {rdv.scheduled_at.strftime('%d/%m/%Y à %H:%M')}.")
        # Confirmation patient
        send_notification(
            patient_id=rdv.patient_id,
            sender_id=current_user.id,
            notif_type="Confirmation",
            message=f"Votre rendez-vous avec Dr {medecin.email} est confirmé pour le {rdv.scheduled_at.strftime('%d/%m/%Y à %H:%M')}.",
            appointment_id=rdv.id
        )
        db.session.commit()
        flash("Rendez-vous confirmé avec le nouveau créneau.", "success")
    elif choice == "refuse":
        rdv.status = "annule"
        _notify_secretariat(rdv, f"{pat.full_name} a refusé le créneau proposé. La demande est annulée.")
        db.session.commit()
        flash("Proposition refusée. Vous pouvez effectuer une nouvelle demande.", "info")

    return redirect(url_for("cabinet.appointments"))



# ─────────────────────────────────────────────────────────────
# Dossiers médicaux (chiffrés AES-256-GCM)
# ─────────────────────────────────────────────────────────────

def _check_patient_access(patient_id: int):
    """403 si un patient essaie d'accéder au dossier d'un autre patient."""
    if current_user.role == "patient":
        pat = current_user.patient_profile
        if not pat or pat.id != patient_id:
            abort(403)


@cabinet_bp.route("/patients/<int:patient_id>/records")
@login_required
def records(patient_id):
    _check_patient_access(patient_id)
    patient = Patient.query.get_or_404(patient_id)
    all_records = MedicalRecord.query.filter_by(patient_id=patient_id).order_by(
        MedicalRecord.created_at.desc()
    ).all()
    return render_template("records.html", patient=patient, records=all_records)


@cabinet_bp.route("/patients/<int:patient_id>/records/new", methods=["GET", "POST"])
@login_required
@role_required("admin", "medecin")
def record_new(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if not title or not content:
            flash("Le titre et le contenu sont obligatoires.", "error")
        else:
            key = current_app.config["ENCRYPTION_KEY"]
            encrypted = aes_encrypt(key, content)
            record = MedicalRecord(
                patient_id=patient_id,
                medecin_id=current_user.id,
                title=title,
                content_encrypted=encrypted,
            )
            db.session.add(record)
            db.session.commit()
            flash("Dossier médical enregistré (chiffré AES-256-GCM).", "success")
            return redirect(url_for("cabinet.records", patient_id=patient_id))
    return render_template("record_form.html", patient=patient)


@cabinet_bp.route("/records/<int:record_id>")
@login_required
def record_view(record_id):
    record = MedicalRecord.query.get_or_404(record_id)
    _check_patient_access(record.patient_id)
    key = current_app.config["ENCRYPTION_KEY"]
    try:
        content = aes_decrypt(key, record.content_encrypted)
    except Exception:
        content = "[Erreur de déchiffrement — clé incorrecte ou données corrompues]"
    return render_template("record_view.html", record=record, content=content)


@cabinet_bp.route("/records/<int:record_id>/delete", methods=["POST"])
@login_required
def record_delete(record_id):
    record = MedicalRecord.query.get_or_404(record_id)
    if not current_user.is_admin() and not (
        current_user.role == "medecin" and record.medecin_id == current_user.id
    ):
        abort(403)
    db.session.delete(record)
    db.session.commit()
    flash("Dossier supprimé.", "success")
    return redirect(url_for("cabinet.records", patient_id=record.patient_id))


# ─────────────────────────────────────────────────────────────
# Ordonnances (médicaments chiffrés AES-256-GCM)
# ─────────────────────────────────────────────────────────────

@cabinet_bp.route("/patients/<int:patient_id>/prescriptions")
@login_required
def prescriptions(patient_id):
    _check_patient_access(patient_id)
    patient = Patient.query.get_or_404(patient_id)
    all_rx = Prescription.query.filter_by(patient_id=patient_id).order_by(
        Prescription.created_at.desc()
    ).all()
    return render_template("prescriptions.html", patient=patient, prescriptions=all_rx)


@cabinet_bp.route("/patients/<int:patient_id>/prescriptions/new", methods=["GET", "POST"])
@login_required
@role_required("admin", "medecin")
def prescription_new(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    if request.method == "POST":
        diagnosis = request.form.get("diagnosis", "").strip()
        medications = request.form.get("medications", "").strip()
        if not diagnosis or not medications:
            flash("Le diagnostic et les médicaments sont obligatoires.", "error")
        else:
            key = current_app.config["ENCRYPTION_KEY"]
            encrypted = aes_encrypt(key, medications)
            rx = Prescription(
                patient_id=patient_id,
                medecin_id=current_user.id,
                diagnosis=diagnosis,
                medications_encrypted=encrypted,
            )
            db.session.add(rx)
            db.session.commit()
            flash("Ordonnance créée (médicaments chiffrés AES-256-GCM).", "success")
            return redirect(url_for("cabinet.prescriptions", patient_id=patient_id))
    return render_template("prescription_form.html", patient=patient)


@cabinet_bp.route("/prescriptions/<int:rx_id>")
@login_required
def prescription_view(rx_id):
    rx = Prescription.query.get_or_404(rx_id)
    _check_patient_access(rx.patient_id)
    key = current_app.config["ENCRYPTION_KEY"]
    try:
        medications = aes_decrypt(key, rx.medications_encrypted)
    except Exception:
        medications = "[Erreur de déchiffrement]"
    return render_template("prescription_view.html", rx=rx, medications=medications)


@cabinet_bp.route("/prescriptions/<int:rx_id>/print")
@login_required
def prescription_print(rx_id):
    rx = Prescription.query.get_or_404(rx_id)
    _check_patient_access(rx.patient_id)
    key = current_app.config["ENCRYPTION_KEY"]
    try:
        medications = aes_decrypt(key, rx.medications_encrypted)
    except Exception:
        medications = "[Erreur de déchiffrement]"
    return render_template("prescription_print.html", rx=rx, medications=medications)
from models import PatientNotification
from detection import create_alert

@cabinet_bp.route('/notifications')
@login_required
@role_required('patient')
def notifications():
    if not current_user.patient_profile:
        flash('Vous n\'avez pas de profil patient associé.', 'error')
        return redirect(url_for('cabinet.dashboard'))
    
    notifs = PatientNotification.query.filter_by(patient_id=current_user.patient_profile.id).order_by(PatientNotification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notifs)

@cabinet_bp.route('/notifications/<int:id>/read', methods=['POST'])
@login_required
@role_required('patient')
def notification_read(id):
    if not current_user.patient_profile:
        abort(403)
        
    notif = PatientNotification.query.get_or_404(id)
    if notif.patient_id != current_user.patient_profile.id:
        abort(403)
        
    notif.is_read = True
    db.session.commit()
    return redirect(url_for('cabinet.notifications'))

@cabinet_bp.route('/notifications/new', methods=['GET', 'POST'])
@login_required
@staff_required
def notification_new():
    if current_user.role not in ['admin', 'secretaire']:
        abort(403)
        
    if request.method == 'POST':
        patient_id = request.form.get('patient_id')
        appointment_id = request.form.get('appointment_id') or None
        notif_type = request.form.get('notification_type')
        message = request.form.get('message')
        
        if not patient_id or not notif_type or not message:
            flash('Veuillez remplir tous les champs obligatoires.', 'error')
            return redirect(url_for('cabinet.notification_new'))
            
        notif = PatientNotification(
            patient_id=patient_id,
            appointment_id=appointment_id,
            sender_id=current_user.id,
            notification_type=notif_type,
            message=message
        )
        db.session.add(notif)
        db.session.commit()
        
        create_alert(
            user_id=current_user.id,
            alert_type='info',
            details=f'Notification envoyée au patient {patient_id} ({notif_type})'
        )
        
        flash('Notification envoyée au patient avec succès.', 'success')
        return redirect(url_for('cabinet.notification_new'))
        
    patients = Patient.query.all()
    appointments = Appointment.query.filter(Appointment.status.in_(['planifie', 'confirme'])).all()
    return render_template('notification_form.html', patients=patients, appointments=appointments)

