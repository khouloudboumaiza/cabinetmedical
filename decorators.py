from functools import wraps
from flask import abort
from flask_login import current_user


def admin_required(f):
    """Autorise l'accès uniquement aux utilisateurs avec le rôle 'admin'.
    Le contrôle est fait côté serveur — jamais uniquement côté client."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)

    return decorated


def role_required(*roles):
    """Autorise l'accès aux utilisateurs ayant l'un des rôles spécifiés."""

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated

    return decorator


def staff_required(f):
    """Autorise admin, medecin, secretaire — interdit aux patients."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if current_user.role not in ("admin", "medecin", "secretaire"):
            abort(403)
        return f(*args, **kwargs)

    return decorated


def owner_or_admin_required(get_owner_id):
    """
    Empêche l'IDOR : vérifie que l'utilisateur connecté est soit
    le propriétaire de la ressource, soit un admin.
    `get_owner_id` est une fonction qui extrait l'ID propriétaire
    depuis les arguments de la route (ex: l'ID dans l'URL).
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            owner_id = get_owner_id(*args, **kwargs)
            if current_user.id != owner_id and not current_user.is_admin():
                abort(403)
            return f(*args, **kwargs)

        return decorated

    return decorator
