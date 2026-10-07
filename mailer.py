"""
Module de gestion et d'envoi d'emails (SMTP avec STARTTLS / Mode Démo).

Propose la fonction send_email(to, subject, body).
Charge les configurations SMTP depuis le fichier .env (python-dotenv).
Si SMTP_HOST est absent ou vide, bascule automatiquement en mode démo (affichage console).
Garantie : aucune exception d'envoi d'email ne remonte vers l'application.
"""

import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Chargement du fichier .env s'il existe
load_dotenv()


def send_email(to: str, subject: str, body: str) -> bool:
    """
    Envoie un email texte au destinataire `to`.
    - Si SMTP_HOST est configuré : utilise smtplib avec STARTTLS.
    - Si SMTP_HOST est absent : bascule en mode démo (print terminal).
    - En cas d'erreur SMTP : intercepte l'exception, log l'erreur et renvoie False (ne plante jamais la requête caller).
    """
    if not to or not isinstance(to, str):
        print("[MAIL-ERROR] Destinataire invalide.")
        return False

    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    smtp_port_str = os.environ.get("SMTP_PORT", "587").strip()
    try:
        smtp_port = int(smtp_port_str)
    except ValueError:
        smtp_port = 587

    smtp_user = os.environ.get("SMTP_USER", "").strip()
    smtp_password = os.environ.get("SMTP_PASSWORD", "").strip()
    mail_from = os.environ.get("MAIL_FROM", "").strip() or smtp_user or "noreply@medicabinet.fr"

    # Mode Démo : si SMTP_HOST n'est pas renseigné
    if not smtp_host:
        print(f"[DEMO-MAIL] À: {to} | Sujet: {subject}\n{body}")
        return True

    # Mode SMTP Réel (STARTTLS)
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = mail_from
        msg["To"] = to

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            server.sendmail(mail_from, [to], msg.as_string())

        print(f"[MAIL-SUCCESS] Email envoyé à {to} (Sujet: {subject})")
        return True
    except Exception as ex:
        print(f"[MAIL-ERROR] Échec de l'envoi d'email à {to} : {ex}")
        return False
