"""
Tests pytest pour le module mailer.py (envoi d'emails SMTP & fallback mode démo).
"""

import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from mailer import send_email


# ---------------------------------------------------------------------------
# Test 1 : Mode démo (SMTP_HOST absent) → affichage console & return True
# ---------------------------------------------------------------------------
def test_mailer_demo_mode_when_smtp_host_absent(capsys):
    with patch.dict(os.environ, {"SMTP_HOST": ""}, clear=False):
        res = send_email("test@patient.fr", "Sujet Test", "Corps du message de test")
        assert res is True

    captured = capsys.readouterr().out
    assert "[DEMO-MAIL]" in captured
    assert "À: test@patient.fr" in captured
    assert "Sujet Test" in captured


# ---------------------------------------------------------------------------
# Test 2 : Mode SMTP réel (mock de smtplib.SMTP) → STARTTLS & sendmail appelés
# ---------------------------------------------------------------------------
def test_mailer_smtp_mode_success():
    env_vars = {
        "SMTP_HOST": "smtp.example.com",
        "SMTP_PORT": "587",
        "SMTP_USER": "user@example.com",
        "SMTP_PASSWORD": "secretpassword",
        "MAIL_FROM": "noreply@medicabinet.fr",
    }

    mock_smtp_instance = MagicMock()
    mock_smtp_class = MagicMock(return_value=mock_smtp_instance)
    mock_smtp_instance.__enter__.return_value = mock_smtp_instance

    with patch.dict(os.environ, env_vars, clear=False), \
         patch("smtplib.SMTP", mock_smtp_class):
        res = send_email("destinataire@test.fr", "Sujet SMTP", "Code OTP: 123456")
        assert res is True

        # Vérifie que smtplib.SMTP a été instancié avec hôte et port
        mock_smtp_class.assert_called_once_with("smtp.example.com", 587, timeout=10)

        # Vérifie l'appel STARTTLS et authentification
        mock_smtp_instance.starttls.assert_called_once()
        mock_smtp_instance.login.assert_called_once_with("user@example.com", "secretpassword")

        # Vérifie l'appel sendmail
        mock_smtp_instance.sendmail.assert_called_once()
        call_args = mock_smtp_instance.sendmail.call_args[0]
        assert call_args[0] == "noreply@medicabinet.fr"
        assert call_args[1] == ["destinataire@test.fr"]
        assert "Sujet SMTP" in call_args[2]



# ---------------------------------------------------------------------------
# Test 3 : Erreur SMTP → interceptée proprement, return False, pas d'exception
# ---------------------------------------------------------------------------
def test_mailer_smtp_error_handled_without_exception(capsys):
    env_vars = {
        "SMTP_HOST": "smtp.failing-server.com",
        "SMTP_PORT": "587",
        "SMTP_USER": "user@example.com",
        "SMTP_PASSWORD": "wrong",
    }

    mock_smtp_class = MagicMock(side_effect=Exception("Connection refused or timeout"))

    with patch.dict(os.environ, env_vars, clear=False), \
         patch("smtplib.SMTP", mock_smtp_class):
        # Ne doit lever AUCUNE exception
        res = send_email("error@test.fr", "Sujet Erreur", "Message")
        assert res is False

    captured = capsys.readouterr().out
    assert "[MAIL-ERROR]" in captured
    assert "error@test.fr" in captured


# ---------------------------------------------------------------------------
# Test 4 : Destinataire invalide → return False sans exception
# ---------------------------------------------------------------------------
def test_mailer_invalid_recipient():
    assert send_email("", "Sujet", "Corps") is False
    assert send_email(None, "Sujet", "Corps") is False
