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


def parse_ip(ip_str):
    """
    Extrait et normalise une adresse IP (IPv4 ou IPv6) avec le module ipaddress.
    Gère les crochets [2001:db8::1] et les ports host:port.
    Retourne un objet IPv4Address ou IPv6Address, ou None si invalide.
    """
    if not ip_str:
        return None
    s = str(ip_str).strip()
    if s.startswith("["):
        end = s.find("]")
        if end != -1:
            s = s[1:end]
    elif ":" in s and "." in s and s.count(":") == 1:
        # IPv4:port ex: 1.2.3.4:9001
        s = s.split(":")[0]

    try:
        return ipaddress.ip_address(s)
    except ValueError:
        # Si le port est collé à la fin sans crochets
        if ":" in s and not s.startswith("["):
            parts = s.rsplit(":", 1)
            try:
                return ipaddress.ip_address(parts[0])
            except ValueError:
                pass
        return None


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
    """
    Télécharge et met en cache (1h) la liste des nœuds de sortie Tor (IPv4 et IPv6).
    Utilise en priorité Onionoo API, avec fallback sur torbulkexitlist puis sur le cache existant.
    """
    now = time.time()
    if now - _tor_cache["ts"] < 3600 and _tor_cache["ips"]:
        return _tor_cache["ips"]

    new_ips = set()

    # Source 1 : Onionoo API (inclut IPv4 et IPv6)
    try:
        url_onionoo = "https://onionoo.torproject.org/details?flag=Exit&running=true&fields=exit_addresses,or_addresses"
        r = requests.get(url_onionoo, timeout=10)
        if r.status_code == 200:
            data = r.json()
            for relay in data.get("relays", []):
                for addr in relay.get("exit_addresses", []):
                    ip_str = addr.get("ip") if isinstance(addr, dict) else addr
                    parsed = parse_ip(ip_str)
                    if parsed:
                        new_ips.add(parsed)
                for addr in relay.get("or_addresses", []):
                    ip_str = addr.get("ip") if isinstance(addr, dict) else addr
                    parsed = parse_ip(ip_str)
                    if parsed:
                        new_ips.add(parsed)
    except Exception as e:
        if hasattr(current_app, "logger"):
            current_app.logger.warning(f"Onionoo Tor list fetch failed: {e}")

    # Source 2 (Fallback si Onionoo vide) : check.torproject.org
    if not new_ips:
        try:
            r = requests.get("https://check.torproject.org/torbulkexitlist", timeout=10)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    parsed = parse_ip(line.strip())
                    if parsed:
                        new_ips.add(parsed)
        except Exception as e:
            if hasattr(current_app, "logger"):
                current_app.logger.warning(f"Tor bulk exit list fetch failed: {e}")

    if new_ips:
        _tor_cache["ips"] = new_ips
        _tor_cache["ts"] = now

    return _tor_cache["ips"]


def is_tor_ip(ip):
    """
    Vérifie si l'adresse IP spécifiée (IPv4 ou IPv6) est un nœud de sortie Tor.
    Normalise les IP pour la comparaison avec ipaddress.
    Ne lève jamais d'exception.
    """
    if not ip:
        return False

    target_obj = parse_ip(ip)
    if not target_obj:
        return False

    is_found = False
    try:
        tor_set = load_tor_exit_ips()
        # Support sets of ipaddress objects (real loader) AND sets of strings (test mocks)
        is_found = target_obj in tor_set or str(target_obj) in tor_set
    except Exception as e:
        if hasattr(current_app, "logger"):
            current_app.logger.warning(f"Erreur vérification is_tor_ip: {e}")
        is_found = False

    # Debug log uniquement en mode debug
    if current_app and getattr(current_app, "debug", False):
        print(f"[TOR] ip={ip} trouvé={is_found}")

    return is_found


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

        # Enregistrement de la tentative
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
