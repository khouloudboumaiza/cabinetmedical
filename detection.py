"""
Module de détection d'anomalies de connexion.

Trois règles implémentées :
  1. Nouveau pays  : la connexion vient d'un pays jamais vu pour cet utilisateur
  2. Brute-force   : trop de tentatives échouées en peu de temps
  3. Heure inhabituelle : connexion à une heure très différente des habitudes
"""

from datetime import datetime, timedelta

import requests

from models import db, LoginLog, SecurityAlert
from log_integrity import append_chained_hash, GENESIS_HASH


def _get_last_hash():
    last = LoginLog.query.order_by(LoginLog.id.desc()).first()
    return last.entry_hash if last and last.entry_hash else GENESIS_HASH


def get_country_from_ip(ip: str) -> str:
    if not ip or ip in ("127.0.0.1", "localhost", "::1"):
        return "Local"
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = response.json()
        return data.get("country", "Unknown")
    except Exception:
        return "Unknown"


def log_login_attempt(user_id, ip, user_agent, method, success, country=None, is_tor=False):
    from flask import current_app
    import uuid

    if not country:
        country = get_country_from_ip(ip)

    # On récupère le hash précédent AVANT de créer la nouvelle entrée
    last_hash = _get_last_hash()

    log = LoginLog(
        log_uid=str(uuid.uuid4()),  # identifiant généré côté Python, disponible immédiatement
        user_id=user_id,
        ip_address=ip,
        user_agent=user_agent,
        country=country,
        login_method=method,
        success=success,
        is_tor=is_tor,
    )

    # Le hash est calculé AVANT l'insertion : un seul INSERT est nécessaire,
    # donc le trigger anti-UPDATE ne se déclenche jamais pour un log normal.
    append_chained_hash(log, current_app.config["HMAC_SECRET"], last_hash)

    db.session.add(log)
    db.session.commit()
    return log


def create_alert(user_id, alert_type, details):
    alert = SecurityAlert(user_id=user_id, alert_type=alert_type, details=details)
    db.session.add(alert)
    db.session.commit()
    return alert


def check_new_country(user_id, current_country):
    if current_country in ("Local", "Unknown"):
        return None

    previous = (
        LoginLog.query.filter_by(user_id=user_id, success=True)
        .order_by(LoginLog.timestamp.desc())
        .limit(21)
        .all()
    )

    if not previous:
        return None

    # Si la tentative la plus récente correspond à la connexion en cours (moins de 10s),
    # on l'exclut pour évaluer les pays historiquement connus.
    now = datetime.utcnow()
    if (now - previous[0].timestamp).total_seconds() < 10 and previous[0].country == current_country:
        prior_logs = previous[1:]
    else:
        prior_logs = previous

    known_countries = {log.country for log in prior_logs if log.country not in (None, "Local", "Unknown")}

    if known_countries and current_country not in known_countries:
        return create_alert(
            user_id, "new_country", f"Connexion depuis un nouveau pays : {current_country}"
        )
    return None



def check_brute_force(user_id, ip, max_attempts=3, window_minutes=5):
    from models import AccountUnlock  # import local pour éviter les imports circulaires
    from sqlalchemy import or_

    since = datetime.utcnow() - timedelta(minutes=window_minutes)

    # Si le compte ou l'IP a été débloqué récemment, on ignore les échecs antérieurs au déblocage (en UTC).
    # login_logs est append-only (chaîne HMAC) : on ne le modifie jamais.
    unlock_filter = []
    if user_id:
        unlock_filter.append(AccountUnlock.user_id == user_id)
    if ip:
        unlock_filter.append(AccountUnlock.ip_address == ip)

    if unlock_filter:
        last_unlock = (
            AccountUnlock.query
            .filter(or_(*unlock_filter))
            .order_by(AccountUnlock.unlocked_at.desc())
            .first()
        )
        if last_unlock and last_unlock.unlocked_at > since:
            since = last_unlock.unlocked_at

    query = LoginLog.query.filter(
        LoginLog.success.is_(False), LoginLog.timestamp >= since
    )
    if user_id:
        query = query.filter(
            (LoginLog.user_id == user_id) | (LoginLog.ip_address == ip)
        )
    else:
        query = query.filter(LoginLog.ip_address == ip)

    recent_fails = query.count()

    if recent_fails >= max_attempts:
        create_alert(
            user_id,
            "brute_force",
            f"{recent_fails} tentatives de connexion échouées en {window_minutes} min depuis {ip}",
        )
        return True
    return False




def check_unusual_time(user_id):
    current_hour = datetime.utcnow().hour

    previous = (
        LoginLog.query.filter_by(user_id=user_id, success=True)
        .order_by(LoginLog.timestamp.desc())
        .limit(31)
        .all()
    )

    if not previous:
        return None

    now = datetime.utcnow()
    if (now - previous[0].timestamp).total_seconds() < 10:
        prior_logs = previous[1:]
    else:
        prior_logs = previous

    hours = [log.timestamp.hour for log in prior_logs]

    if len(hours) < 5:
        return None

    usual_min, usual_max = min(hours), max(hours)
    if not (usual_min - 2 <= current_hour <= usual_max + 2):
        return create_alert(
            user_id, "unusual_time", f"Connexion à {current_hour}h (heure inhabituelle pour cet utilisateur)"
        )
    return None



def run_all_checks(user_id, country):
    check_new_country(user_id, country)
    check_unusual_time(user_id)