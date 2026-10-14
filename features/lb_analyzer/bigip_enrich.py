"""Second extraction pass: security modules, certificate details and (when the input is a UCS) the archive facts.

``bigip_extract.extract`` builds the base model from the TMSH tree; ``enrich`` adds to the same dictionary

``data["extra"]``  security modules, global settings and the configuration inventory (``bigip_security``);
``data["ucs"]``    ``None`` for a plain configuration, otherwise ``{"bundle", "facts", "history"}``;
``data["certs"]``  each certificate gains ``used_by`` (SSL profiles) and, from the archive, ``san``, ``signature``,
                  ``not_before``, ``ca`` and the real validity dates.

It must run before the rules, which read these keys.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any

from . import bigip_gtm, bigip_security, ucs_history
from .bigip_extract import short
from .tmsh_tree import TmshTree


def enrich(tree: TmshTree, data: dict[str, Any], bundle: Any | None, today: date) -> None:
    data["extra"] = bigip_security.extract(tree, data)
    data["gtm"] = bigip_gtm.extract(tree)                           # None unless the capture has gtm stanzas
    used = _certificate_users(tree)
    for cert in data["certs"]:
        cert["used_by"] = sorted(set(used.get(cert["short"], [])))
        cert.update({"san": [], "signature": "", "not_before": None, "ca": None})
    data["ucs"] = None
    if bundle is None:
        return
    for cert in data["certs"]:
        parsed = bundle.certs.get((cert.get("cache_path") or "").rsplit("/", 1)[-1])
        if parsed:
            cert.update({"expires": parsed["not_after"], "key_size": parsed["key_size"], "key_type": parsed["key_type"], "subject": parsed["subject"], "issuer": parsed["issuer"], "self_signed": parsed["self_signed"],
                         "san": parsed["san"], "signature": parsed["signature"], "not_before": parsed["not_before"], "ca": parsed["ca"]})
    data["ucs"] = {"bundle": bundle, "facts": _facts(bundle), "history": ucs_history.summarize(bundle.history, today)}
    if bundle.version.get("Version") and not data["info"]["version"]:
        data["info"]["version"] = bundle.version["Version"]


def _certificate_users(tree: TmshTree) -> dict[str, list[str]]:
    used: dict[str, list[str]] = {}
    for n in tree.root:
        if n.tokens[:3] in (["ltm", "profile", "client-ssl"], ["ltm", "profile", "server-ssl"]) and len(n.tokens) == 4:
            for item in n.walk():
                if item.key in ("cert", "chain", "ca-file", "trusted-ca-file") and item.args:
                    used.setdefault(short(item.args[0]), []).append(short(n.name))
    return used


def _epoch(db: dict[str, dict[str, str]], key: str) -> datetime | None:
    try:
        value = int(db[key]["value"])
    except (KeyError, ValueError):
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc) if value > 0 else None


def _facts(bundle: Any) -> dict[str, datetime | None]:
    """Timestamps that mcpd and the failover daemon keep in ``sys db``."""
    db = bundle.db
    return {"last_config_change": _epoch(db, "LTM.ConfigTime"), "last_sync": _epoch(db, "Configsync.LocalConfigTime"), "last_active": _epoch(db, "Failover.ActiveTime"),
            "last_standby": _epoch(db, "Failover.StandbyTime"), "last_ucs_load": _epoch(db, "UCS.LoadTime")}
