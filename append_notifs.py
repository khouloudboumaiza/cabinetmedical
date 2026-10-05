from models import PatientNotification
from detection import log_security_event

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
        
        log_security_event(
            user_id=current_user.id,
            alert_type='info',
            details=f'Notification envoyée au patient {patient_id} ({notif_type})'
        )
        
        flash('Notification envoyée au patient avec succès.', 'success')
        return redirect(url_for('cabinet.notification_new'))
        
    patients = Patient.query.all()
    appointments = Appointment.query.filter(Appointment.status.in_(['planifie', 'confirme'])).all()
    return render_template('notification_form.html', patients=patients, appointments=appointments)
