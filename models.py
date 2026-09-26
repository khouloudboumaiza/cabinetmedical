from datetime import datetime, date
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class User(db.Model, UserMixin):
    """Compte utilisateur — supporte le login classique ET Google (OAuth2).
    Rôles : admin, medecin, secretaire, patient."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)

    password_hash = db.Column(db.String(255), nullable=True)
    google_id = db.Column(db.String(255), unique=True, nullable=True)
    role = db.Column(db.String(20), nullable=False, default="patient")

    is_locked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relations sécurité
    login_logs = db.relationship("LoginLog", backref="user", lazy="dynamic")
    alerts = db.relationship("SecurityAlert", backref="user", lazy="dynamic")

    # Profil patient lié (si l'utilisateur est un patient)
    patient_profile = db.relationship("Patient", backref="account", uselist=False,
                                       foreign_keys="Patient.user_id")

    # Rendez-vous en tant que médecin
    appointments_as_medecin = db.relationship("Appointment", backref="medecin",
                                               foreign_keys="Appointment.medecin_id",
                                               lazy="dynamic")

    # Dossiers médicaux créés (médecin)
    records_created = db.relationship("MedicalRecord", backref="medecin",
                                       foreign_keys="MedicalRecord.medecin_id",
                                       lazy="dynamic")

    # Ordonnances créées (médecin)
    prescriptions_created = db.relationship("Prescription", backref="medecin",
                                             foreign_keys="Prescription.medecin_id",
                                             lazy="dynamic")

    def is_admin(self):
        return self.role == "admin"

    def has_role(self, *roles):
        """Vérifie si l'utilisateur a l'un des rôles donnés."""
        return self.role in roles

    def __repr__(self):
        return f"<User {self.email} ({self.role})>"


class Patient(db.Model):
    """Fiche patient — données médicales de base (non-chiffrées sauf allergies)."""

    __tablename__ = "patients"

    id = db.Column(db.Integer, primary_key=True)
    # Lien optionnel vers un compte utilisateur
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, unique=True)

    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=True)
    gender = db.Column(db.String(1), nullable=True)  # M / F
    phone = db.Column(db.String(30), nullable=True)
    address = db.Column(db.Text, nullable=True)
    blood_type = db.Column(db.String(5), nullable=True)
    allergies = db.Column(db.Text, nullable=True)  # stocké en clair (alerte médicale)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relations
    appointments = db.relationship("Appointment", backref="patient",
                                    foreign_keys="Appointment.patient_id",
                                    lazy="dynamic", cascade="all, delete-orphan")
    medical_records = db.relationship("MedicalRecord", backref="patient",
                                       foreign_keys="MedicalRecord.patient_id",
                                       lazy="dynamic", cascade="all, delete-orphan")
    prescriptions = db.relationship("Prescription", backref="patient",
                                     foreign_keys="Prescription.patient_id",
                                     lazy="dynamic", cascade="all, delete-orphan")

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def age(self):
        if not self.date_of_birth:
            return None
        today = date.today()
        dob = self.date_of_birth
        return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

    def __repr__(self):
        return f"<Patient {self.full_name}>"


class Appointment(db.Model):
    """Rendez-vous médical."""

    __tablename__ = "appointments"

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    medecin_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    scheduled_at = db.Column(db.DateTime, nullable=False)
    duration_minutes = db.Column(db.Integer, default=30)
    motif = db.Column(db.String(255), nullable=False)
    notes = db.Column(db.Text, nullable=True)

    # planifie | confirme | termine | annule
    status = db.Column(db.String(20), default="planifie")

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Appointment {self.patient_id} @ {self.scheduled_at}>"


class MedicalRecord(db.Model):
    """Dossier médical — contenu chiffré AES-256-GCM."""

    __tablename__ = "medical_records"

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    medecin_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    title = db.Column(db.String(255), nullable=False)
    content_encrypted = db.Column(db.Text, nullable=False)  # AES-256-GCM base64

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<MedicalRecord {self.title} patient={self.patient_id}>"


class Prescription(db.Model):
    """Ordonnance — médicaments chiffrés AES-256-GCM."""

    __tablename__ = "prescriptions"

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    medecin_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    diagnosis = db.Column(db.String(500), nullable=False)
    medications_encrypted = db.Column(db.Text, nullable=False)  # AES-256-GCM base64

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Prescription #{self.id} patient={self.patient_id}>"


class LoginLog(db.Model):
    """Historique de chaque tentative de connexion (réussie ou échouée)."""

    __tablename__ = "login_logs"

    id = db.Column(db.Integer, primary_key=True)
    log_uid = db.Column(db.String(36), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    ip_address = db.Column(db.String(64))
    user_agent = db.Column(db.String(255))
    country = db.Column(db.String(100))
    login_method = db.Column(db.String(20))
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # --- Intégrité / anti-falsification (voir log_integrity.py) ---
    prev_hash = db.Column(db.String(64))
    entry_hash = db.Column(db.String(64))

    def __repr__(self):
        return f"<LoginLog user={self.user_id} {self.login_method} success={self.success}>"


class SecurityAlert(db.Model):
    """Alerte générée automatiquement par le module de détection d'anomalies."""

    __tablename__ = "security_alerts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    alert_type = db.Column(db.String(50))
    details = db.Column(db.Text)
    resolved = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<SecurityAlert {self.alert_type} user={self.user_id}>"