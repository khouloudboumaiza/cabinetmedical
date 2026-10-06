import os
import time
import ipaddress
import requests
import geoip2.database
from flask import request, current_app
from models import db, LoginLog, SecurityAlert


GEO_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "GeoLite2-Country.mmdb")
_reader = None
_tor_cache = {"ips": set(), "ts": 0}


def _get_reader():
    """Gère un lecteur singleton pour la base de données GeoLite2.
    Si le fichier .mmdb n'est pas présent, retourne None sans planter.
    """
    global _reader
    if _reader is None and os.path.exists(GEO_DB_PATH):
        try:
            _reader = geoip2.database.Reader(GEO_DB_PATH)
        except Exception as e:
            if hasattr(current_app, "logger"):
                current_app.logger.warning(f"Erreur d'ouverture GeoIP2: {e}")
            _reader = None
    return _reader


def get_client_ip():
    """Récupère l'adresse IP réelle du client.
    L'en-tête X-Forwarded-For est lu seulement si TRUST_PROXY_HEADERS est activé en config.
    ⚠️ À désactiver en production si l'application n'est pas derrière un proxy de confiance.
    """
    if not request:
        return "127.0.0.1"
    remote = request.remote_addr
    xff = request.headers.get("X-Forwarded-For", "")
    trusted = current_app.config.get("TRUST_PROXY_HEADERS") or remote in ("127.0.0.1", "::1")
    if trusted and xff:
        return xff.split(",")[0].strip()
    return remote if remote else "127.0.0.1"


def get_country(ip):
    """Retourne le code ISO du pays (ex: 'TN', 'FR', 'DE') pour une IP donnée.
    Retourne None si le fichier GeoIP n'est pas présent ou si l'IP n'est pas trouvée.
    """
    reader = _get_reader()
    if not reader or not ip:
        return None
    try:
        return reader.country(ip).country.iso_code
    except Exception:
        return None


def load_tor_exit_ips():
    """Télécharge et met en cache (pendant 1h) la liste des nœuds de sortie Tor depuis torproject.org."""
    if time.time() - _tor_cache["ts"] > 3600:
        try:
            r = requests.get("https://check.torproject.org/torbulkexitlist", timeout=10)
            r.raise_for_status()
            _tor_cache["ips"] = set(r.text.split())
            _tor_cache["ts"] = time.time()
        except Exception as e:
            if hasattr(current_app, "logger"):
                current_app.logger.warning(f"Tor list fetch failed: {e}")
    return _tor_cache["ips"]


def is_tor_ip(ip):
    """Vérifie si l'adresse IP spécifiée est un nœud de sortie Tor.
    Normalise l'IP (IPv4 et IPv6) pour la comparaison.
    """
    if not ip:
        return False
    try:
        target_ip = ipaddress.ip_address(ip)
    except ValueError:
        return False

    tor_list = load_tor_exit_ips()
    for tor_str in tor_list:
        try:
            if ipaddress.ip_address(tor_str) == target_ip:
                return True
        except ValueError:
            continue
    return False


def check_login_anomaly(user):
    """Analyse la connexion pour détecter les anomalies de pays (GEO_ANOMALY) et nœuds Tor (TOR_EXIT).
    Retourne True si la connexion est suspecte (nécessite une vérification OTP), False sinon.
    Ne lève jamais d'exception pour ne pas bloquer le login normal.
    """
    try:
        ip = get_client_ip()
        country = get_country(ip)
        tor = is_tor_ip(ip)

        # Dernière connexion réussie de référence avec un pays valide
        last = (
            LoginLog.query.filter(
                LoginLog.user_id == user.id,
                LoginLog.success.is_(True),
                LoginLog.country.isnot(None),
                LoginLog.country.notin_(["Local", "Unknown"]),
            )
            .order_by(LoginLog.timestamp.desc())
            .first()
        )

        last_country = last.country if last else None
        if current_app and current_app.debug:
            print(f"[GEO] user={user.email} ip={ip} country={country} tor={tor} last_country={last_country}")

        suspicious = False
        is_geo_anomaly = False
        is_tor_exit = False

        if last and last.country and country and last.country != country:
            suspicious = True
            is_geo_anomaly = True

        if tor:
            suspicious = True
            is_tor_exit = True

        # Enregistrement de la tentative :
        # Si suspecte, success=False pour ne pas enregistrer ce pays comme pays de référence tant que l'OTP n'est pas validé.
        from detection import log_login_attempt
        user_agent = request.headers.get("User-Agent", "") if request else ""
        log_login_attempt(user.id, ip, user_agent, "password", not suspicious, country=country, is_tor=tor)

        # Enregistrement des alertes admin
        if is_geo_anomaly:
            db.session.add(
                SecurityAlert(
                    user_id=user.id,
                    kind="GEO_ANOMALY",
                    message=f"{user.email} : connexion depuis {country} ({ip}) alors que la dernière était depuis {last.country}."
                )
            )

        if is_tor_exit:
            db.session.add(
                SecurityAlert(
                    user_id=user.id,
                    kind="TOR_EXIT",
                    message=f"{user.email} : connexion via un nœud de sortie Tor ({ip})."
                )
            )

        db.session.commit()
        return suspicious

    except Exception as e:
        if current_app and hasattr(current_app, "logger"):
            current_app.logger.error(f"Erreur lors de la détection d'anomalie : {e}")
        return False
