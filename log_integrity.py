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