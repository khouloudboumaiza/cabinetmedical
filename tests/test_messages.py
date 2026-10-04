import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("ENCRYPTION_KEY_HEX", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

import pytest
from datetime import datetime, timedelta
from cryptography.exceptions import InvalidTag

from app import create_app
from models import (
    db, User, Patient, Appointment, MedicalRecord, Prescription,
    Conversation, Message, MessageLog, SecurityAlert
)
from crypto_utils import aes_encrypt_message, aes_decrypt_message
from auth import bcrypt


@pytest.fixture()
def app():
    a = create_app()
    a.config.update(
        TESTING=True,
        SECRET_KEY="test-secret-key",
        HMAC_SECRET="test-hmac-secret",
    )
    with a.app_context():
        db.create_all()
        yield a
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def create_test_user(email, role, password="Password1234"):
    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    u = User(email=email, password_hash=pw_hash, role=role)
    db.session.add(u)
    db.session.commit()
    return u


def create_test_patient_with_user(email, first_name="Jean", last_name="Dupont"):
    user = create_test_user(email, role="patient")
    pat = Patient(user_id=user.id, first_name=first_name, last_name=last_name)
    db.session.add(pat)
    db.session.commit()
    return user, pat


def login(client, email, password="Password1234"):
    return client.post("/login", data={"email": email, "password": password}, follow_redirects=True)


def get_csrf_token(client):
    """Récupère le token CSRF généré dans la session du client."""
    with client.session_transaction() as sess:
        if "csrf_token" not in sess:
            sess["csrf_token"] = "valid_csrf_token_for_tests"
        return sess["csrf_token"]


# ─── 1. Tests Cryptographiques (AES-256-GCM + AAD) ───────────

def test_aes256_gcm_message_encryption_and_decryption(app):
    key = app.config["ENCRYPTION_KEY"]
    plaintext = "Bonjour Docteur, j'ai une question sur mon ordonnance."
    conv_id = 42

    ciphertext_b64, nonce_b64 = aes_encrypt_message(key, plaintext, conv_id)

    # Vérifie que le texte n'apparaît JAMAIS en clair
    assert plaintext not in ciphertext_b64
    assert plaintext not in nonce_b64

    # Déchiffrement correct
    decrypted = aes_decrypt_message(key, ciphertext_b64, nonce_b64, conv_id)
    assert decrypted == plaintext


def test_aes256_gcm_ciphertext_tampered_fails(app):
    key = app.config["ENCRYPTION_KEY"]
    plaintext = "Information médicale confidentielle"
    conv_id = 10

    ciphertext_b64, nonce_b64 = aes_encrypt_message(key, plaintext, conv_id)

    # Altération d'un caractère du ciphertext
    import base64
    raw_ct = bytearray(base64.b64decode(ciphertext_b64))
    raw_ct[0] ^= 0xFF  # Flip bits
    tampered_ct_b64 = base64.b64encode(raw_ct).decode("utf-8")

    with pytest.raises(InvalidTag):
        aes_decrypt_message(key, tampered_ct_b64, nonce_b64, conv_id)


def test_aes256_gcm_wrong_aad_fails(app):
    key = app.config["ENCRYPTION_KEY"]
    plaintext = "Message destiné à la conversation 1"
    conv_1 = 1
    conv_2 = 2

    ciphertext_b64, nonce_b64 = aes_encrypt_message(key, plaintext, conv_1)

    # Tentative de réutilisation du ciphertext dans une autre conversation (AAD mismatch)
    with pytest.raises(InvalidTag):
        aes_decrypt_message(key, ciphertext_b64, nonce_b64, conv_2)


# ─── 2. Tests de Messagerie en Base de Données ────────────────

def test_message_stored_encrypted_in_db(app, client):
    with app.app_context():
        doc = create_test_user("docteur.test@hopital.fr", role="medecin")
        p_user, pat = create_test_patient_with_user("patient.test@gmail.com")

        # Relation médicale
        appt = Appointment(patient_id=pat.id, medecin_id=doc.id, scheduled_at=datetime.utcnow(), motif="Consultation")
        db.session.add(appt)
        conv = Conversation(patient_id=pat.id, doctor_id=doc.id)
        db.session.add(conv)
        db.session.commit()
        conv_id = conv.id

    login(client, "patient.test@gmail.com")
    token = get_csrf_token(client)

    resp = client.post(f"/messages/{conv_id}/send", data={
        "content": "Secret medical tres confidentiel",
        "csrf_token": token,
    }, follow_redirects=True)
    assert resp.status_code == 200

    with app.app_context():
        msg = Message.query.filter_by(conversation_id=conv_id).first()
        assert msg is not None
        assert "Secret" not in msg.ciphertext
        assert "confidentiel" not in msg.ciphertext
        
        # Déchiffrement avec la clé
        key = app.config["ENCRYPTION_KEY"]
        decrypted = aes_decrypt_message(key, msg.ciphertext, msg.nonce, conv_id)
        assert decrypted == "Secret medical tres confidentiel"


# ─── 3. Tests IDOR & Contrôle d'accès ────────────────────────

def test_idor_other_patient_forbidden(app, client):
    with app.app_context():
        doc = create_test_user("doc1@hopital.fr", role="medecin")
        p1_user, p1 = create_test_patient_with_user("p1@test.com")
        p2_user, p2 = create_test_patient_with_user("p2@test.com")

        conv = Conversation(patient_id=p1.id, doctor_id=doc.id)
        db.session.add(conv)
        db.session.commit()
        conv_id = conv.id
        p2_user_id = p2_user.id

    # Patient 2 tente d'accéder à la conversation de Patient 1
    login(client, "p2@test.com")
    resp = client.get(f"/messages/{conv_id}")
    assert resp.status_code == 404

    # Vérifie qu'une SecurityAlert IDOR a été créée
    with app.app_context():
        alert = SecurityAlert.query.filter_by(user_id=p2_user_id, alert_type="idor_message_attempt").first()
        assert alert is not None
        assert str(conv_id) in alert.details


def test_idor_other_doctor_forbidden(app, client):
    with app.app_context():
        doc1 = create_test_user("doc1@cabinet.fr", role="medecin")
        doc2 = create_test_user("doc2@cabinet.fr", role="medecin")
        p_user, pat = create_test_patient_with_user("patient@test.com")

        conv = Conversation(patient_id=pat.id, doctor_id=doc1.id)
        db.session.add(conv)
        db.session.commit()
        conv_id = conv.id
        doc2_id = doc2.id

    # Médecin 2 tente d'accéder à la conversation du Médecin 1
    login(client, "doc2@cabinet.fr")
    resp = client.get(f"/messages/{conv_id}")
    assert resp.status_code == 404

    # Vérifie qu'une SecurityAlert IDOR a été créée
    with app.app_context():
        alert = SecurityAlert.query.filter_by(user_id=doc2_id, alert_type="idor_message_attempt").first()
        assert alert is not None


def test_admin_and_secretaire_excluded_from_messages(app, client):
    with app.app_context():
        admin = create_test_user("admin.secret@cabinet.fr", role="admin")
        secretaire = create_test_user("secretaire@cabinet.fr", role="secretaire")
        doc = create_test_user("doc@cabinet.fr", role="medecin")
        p_user, pat = create_test_patient_with_user("p@cabinet.fr")

        conv = Conversation(patient_id=pat.id, doctor_id=doc.id)
        db.session.add(conv)
        db.session.commit()
        conv_id = conv.id
        admin_id = admin.id
        secretaire_id = secretaire.id

    # Admin -> 404 sans SecurityAlert
    login(client, "admin.secret@cabinet.fr")
    assert client.get("/messages").status_code == 404
    assert client.get(f"/messages/{conv_id}").status_code == 404

    # Secrétaire -> 404 sans SecurityAlert
    login(client, "secretaire@cabinet.fr")
    assert client.get("/messages").status_code == 404
    assert client.get(f"/messages/{conv_id}").status_code == 404

    with app.app_context():
        # Pas d'alerte pour admin ou secrétaire
        assert SecurityAlert.query.filter_by(user_id=admin_id).first() is None
        assert SecurityAlert.query.filter_by(user_id=secretaire_id).first() is None
        # Mais un log d'événement a bien été consigné
        log_admin = MessageLog.query.filter_by(user_id=admin_id, action="role_excluded").first()
        assert log_admin is not None


# ─── 4. Tests Relations Patient ↔ Médecin ─────────────────────

def test_patient_cannot_start_conversation_without_relation(app, client):
    with app.app_context():
        doc = create_test_user("inconnu.doc@cabinet.fr", role="medecin")
        p_user, pat = create_test_patient_with_user("patient.isole@test.com")
        doc_id = doc.id
        pat_id = pat.id

    login(client, "patient.isole@test.com")
    token = get_csrf_token(client)

    resp = client.post("/messages/new", data={
        "doctor_id": doc_id,
        "csrf_token": token,
    })
    # Refusé (403)
    assert resp.status_code in (403, 302)
    with app.app_context():
        assert Conversation.query.filter_by(patient_id=pat_id, doctor_id=doc_id).first() is None


def test_patient_can_start_conversation_with_appointment_or_record(app, client):
    with app.app_context():
        doc = create_test_user("mon.medecin@cabinet.fr", role="medecin")
        p_user, pat = create_test_patient_with_user("patient.suivi@test.com")
        appt = Appointment(patient_id=pat.id, medecin_id=doc.id, scheduled_at=datetime.utcnow(), motif="Suivi")
        db.session.add(appt)
        db.session.commit()
        doc_id = doc.id
        pat_id = pat.id

    login(client, "patient.suivi@test.com")
    token = get_csrf_token(client)

    resp = client.post("/messages/new", data={
        "doctor_id": doc_id,
        "csrf_token": token,
    }, follow_redirects=False)
    assert resp.status_code == 302

    with app.app_context():
        conv = Conversation.query.filter_by(patient_id=pat_id, doctor_id=doc_id).first()
        assert conv is not None



def test_doctor_cannot_contact_patient_without_user_account(app, client):
    with app.app_context():
        doc = create_test_user("dr.smith@cabinet.fr", role="medecin")
        # Patient créé manuellement sans compte User
        pat_sans_compte = Patient(user_id=None, first_name="Sans", last_name="Compte")
        db.session.add(pat_sans_compte)
        db.session.commit()
        pat_id = pat_sans_compte.id

    login(client, "dr.smith@cabinet.fr")
    token = get_csrf_token(client)

    resp = client.post("/messages/new", data={
        "patient_id": pat_id,
        "csrf_token": token,
    })
    # Doit être refusé proprement
    assert resp.status_code in (400, 403, 302)


# ─── 5. Tests CSRF ───────────────────────────────────────────

def test_missing_csrf_token_rejected(app, client):
    with app.app_context():
        doc = create_test_user("doc.csrf@cabinet.fr", role="medecin")
        p_user, pat = create_test_patient_with_user("p.csrf@test.com")
        conv = Conversation(patient_id=pat.id, doctor_id=doc.id)
        db.session.add(conv)
        db.session.commit()
        conv_id = conv.id

    login(client, "p.csrf@test.com")

    # POST sans token CSRF
    resp = client.post(f"/messages/{conv_id}/send", data={
        "content": "Message sans CSRF"
    })
    assert resp.status_code == 400


def test_fetch_with_csrf_header_accepted(app, client):
    with app.app_context():
        doc = create_test_user("doc.fetch@cabinet.fr", role="medecin")
        p_user, pat = create_test_patient_with_user("p.fetch@test.com")
        conv = Conversation(patient_id=pat.id, doctor_id=doc.id)
        db.session.add(conv)
        db.session.commit()
        conv_id = conv.id

    login(client, "p.fetch@test.com")
    token = get_csrf_token(client)

    resp = client.post(
        f"/messages/{conv_id}/send",
        json={"content": "Message via fetch avec header CSRF"},
        headers={"X-CSRFToken": token, "Accept": "application/json"}
    )
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["message"]["content"] == "Message via fetch avec header CSRF"


# ─── 6. Tests Validation & XSS ───────────────────────────────

def test_empty_or_whitespace_message_rejected(app, client):
    with app.app_context():
        doc = create_test_user("doc.val@cabinet.fr", role="medecin")
        p_user, pat = create_test_patient_with_user("p.val@test.com")
        conv = Conversation(patient_id=pat.id, doctor_id=doc.id)
        db.session.add(conv)
        db.session.commit()
        conv_id = conv.id

    login(client, "p.val@test.com")
    token = get_csrf_token(client)

    resp = client.post(f"/messages/{conv_id}/send", data={
        "content": "   ",
        "csrf_token": token,
    })
    assert resp.status_code == 400


def test_overlong_message_rejected(app, client):
    with app.app_context():
        doc = create_test_user("doc.long@cabinet.fr", role="medecin")
        p_user, pat = create_test_patient_with_user("p.long@test.com")
        conv = Conversation(patient_id=pat.id, doctor_id=doc.id)
        db.session.add(conv)
        db.session.commit()
        conv_id = conv.id

    login(client, "p.long@test.com")
    token = get_csrf_token(client)

    resp = client.post(f"/messages/{conv_id}/send", data={
        "content": "A" * 2001,
        "csrf_token": token,
    })
    assert resp.status_code == 400


def test_xss_is_escaped_in_rendered_html(app, client):
    with app.app_context():
        doc = create_test_user("doc.xss@cabinet.fr", role="medecin")
        p_user, pat = create_test_patient_with_user("p.xss@test.com")
        conv = Conversation(patient_id=pat.id, doctor_id=doc.id)
        db.session.add(conv)
        db.session.commit()
        conv_id = conv.id

    login(client, "p.xss@test.com")
    token = get_csrf_token(client)

    xss_payload = "<script>alert('XSS_TEST')</script><b>gras</b>"
    client.post(f"/messages/{conv_id}/send", data={
        "content": xss_payload,
        "csrf_token": token,
    }, follow_redirects=True)

    resp = client.get(f"/messages/{conv_id}")
    html = resp.get_data(as_text=True)

    # Le payload XSS brut ne doit pas être rendu non échappé
    assert xss_payload not in html
    assert "&lt;script&gt;alert(&#39;XSS_TEST&#39;)&lt;/script&gt;&lt;b&gt;gras&lt;/b&gt;" in html




# ─── 7. Tests Rate Limiting ──────────────────────────────────

def test_rate_limiting_enforced(app, client):
    with app.app_context():
        doc = create_test_user("doc.rate@cabinet.fr", role="medecin")
        p_user, pat = create_test_patient_with_user("p.rate@test.com")
        conv = Conversation(patient_id=pat.id, doctor_id=doc.id)
        db.session.add(conv)
        db.session.commit()
        conv_id = conv.id

    login(client, "p.rate@test.com")
    token = get_csrf_token(client)

    # Envoyer 20 messages (quota max autorisé)
    for i in range(20):
        r = client.post(
            f"/messages/{conv_id}/send",
            json={"content": f"Message test #{i}"},
            headers={"X-CSRFToken": token, "Accept": "application/json"}
        )
        assert r.status_code == 201

    # Le 21ème doit être rejeté avec 429
    r21 = client.post(
        f"/messages/{conv_id}/send",
        json={"content": "Message 21 qui depasse la limite"},
        headers={"X-CSRFToken": token, "Accept": "application/json"}
    )
    assert r21.status_code == 429


# ─── 8. Tests Polling & Marquage de Lecture ──────────────────

def test_polling_and_read_status(app, client):
    with app.app_context():
        doc = create_test_user("doc.poll@cabinet.fr", role="medecin")
        p_user, pat = create_test_patient_with_user("p.poll@test.com")
        conv = Conversation(patient_id=pat.id, doctor_id=doc.id)
        db.session.add(conv)
        db.session.commit()
        conv_id = conv.id

    # Patient envoie un message
    login(client, "p.poll@test.com")
    token = get_csrf_token(client)
    client.post(
        f"/messages/{conv_id}/send",
        json={"content": "Message initial"},
        headers={"X-CSRFToken": token, "Accept": "application/json"}
    )

    # Médecin fait un poll
    login(client, "doc.poll@cabinet.fr")
    poll_resp = client.get(f"/messages/{conv_id}/poll?after=0")
    assert poll_resp.status_code == 200
    data = poll_resp.get_json()
    assert len(data["messages"]) == 1
    assert data["messages"][0]["content"] == "Message initial"
    assert data["messages"][0]["is_me"] is False

    # Le message doit maintenant être marqué comme lu en base
    with app.app_context():
        msg = Message.query.filter_by(conversation_id=conv_id).first()
        assert msg.read_at is not None
