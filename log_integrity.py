"""
Intégrité des logs — protection contre la falsification/suppression
par un attaquant qui aurait compromis l'application ou la base.
"""

import hashlib
import hmac as hmac_module

GENESIS_HASH = "0" * 64


def _serialize(entry) -> str:
    """Utilise log_uid (généré côté Python AVANT l'insertion) et non l'ID
    auto-incrémenté, qui n'existe qu'après l'INSERT."""
    return "|".join(
        str(x)
        for x in (
            entry.log_uid,
            entry.user_id,
            entry.ip_address,
            entry.user_agent,
            entry.country,
            entry.login_method,
            entry.success,
            entry.timestamp,
        )
    )


def compute_entry_hash(prev_hash: str, entry, secret_key: str) -> str:
    message = f"{prev_hash}|{_serialize(entry)}".encode()
    return hmac_module.new(secret_key.encode(), message, hashlib.sha256).hexdigest()


def append_chained_hash(entry, secret_key: str, last_hash: str):
    entry.prev_hash = last_hash
    entry.entry_hash = compute_entry_hash(last_hash, entry, secret_key)
    return entry.entry_hash


def verify_chain(entries, secret_key: str):
    prev_hash = GENESIS_HASH
    for entry in entries:
        expected = compute_entry_hash(prev_hash, entry, secret_key)
        if entry.entry_hash != expected:
            return {
                "valid": False,
                "broken_at": entry.id,
                "checked": entries.index(entry) + 1,
                "reason": (
                    "Hash incohérent : la ligne a été modifiée, ou une "
                    "ligne précédente a été supprimée/modifiée."
                ),
            }
        prev_hash = entry.entry_hash
    return {"valid": True, "broken_at": None, "checked": len(entries)}


# ---------------------------------------------------------------------------
# Intégrité des logs de messagerie (MessageLog)
# ---------------------------------------------------------------------------

def _serialize_message_log(entry) -> str:
    return "|".join(
        str(x)
        for x in (
            entry.log_uid,
            entry.user_id,
            entry.ip_address,
            entry.action,
            entry.conversation_id,
            entry.details,
            entry.timestamp,
        )
    )


def compute_message_log_hash(prev_hash: str, entry, secret_key: str) -> str:
    message = f"{prev_hash}|{_serialize_message_log(entry)}".encode()
    return hmac_module.new(secret_key.encode(), message, hashlib.sha256).hexdigest()


def append_chained_message_hash(entry, secret_key: str, last_hash: str):
    entry.prev_hash = last_hash
    entry.entry_hash = compute_message_log_hash(last_hash, entry, secret_key)
    return entry.entry_hash


def _get_last_message_log_hash():
    from models import MessageLog
    last = MessageLog.query.order_by(MessageLog.id.desc()).first()
    return last.entry_hash if last and last.entry_hash else GENESIS_HASH


def log_message_event(user_id, action, conversation_id=None, details=None, ip=None):
    """Enregistre un événement de messagerie avec intégrité cryptographique HMAC.
    Ne prend JAMAIS le contenu des messages."""
    import uuid
    from flask import current_app, request
    from models import db, MessageLog

    if ip is None:
        try:
            ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        except Exception:
            ip = "127.0.0.1"

    last_hash = _get_last_message_log_hash()

    entry = MessageLog(
        log_uid=str(uuid.uuid4()),
        user_id=user_id,
        ip_address=ip,
        action=action,
        conversation_id=conversation_id,
        details=details,
    )

    append_chained_message_hash(entry, current_app.config["HMAC_SECRET"], last_hash)
    db.session.add(entry)
    db.session.commit()
    return entry