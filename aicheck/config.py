"""Load the engagement config and enforce the authorization gate."""

from __future__ import annotations

import datetime as dt
import os
from urllib.parse import urlparse

import yaml


class AuthorizationError(Exception):
    """Raised when the engagement is not authorized for this run."""


DEFAULTS = {
    "target": {
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "timeout": 60,
        "delay_seconds": 0.5,
        "response_path": "reply",
    },
    "users": {},
    "feature": {"sees": [], "can_do": [], "users": "", "must_never": []},
    "policy": {"must_not": [], "forbidden_strings": []},
    "known_secrets": [],
    "agency": {"action_log_url": None, "dangerous_requests": []},
    "abuse": {"burst": 15, "long_output_chars": 20000, "slow_seconds": 30},
    "judge": {"provider": None, "model": "claude-sonnet-5-5"},
    "confirm_runs": 2,
}

MAX_BURST = 50


def _merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    cfg = _merge(DEFAULTS, raw)
    cfg["_config_dir"] = os.path.dirname(os.path.abspath(path))
    cfg["abuse"]["burst"] = min(int(cfg["abuse"]["burst"]), MAX_BURST)
    if "url" not in cfg["target"]:
        raise ValueError("target.url is required")
    if not cfg["users"]:
        cfg["users"] = {"a": {"headers": {}, "vars": {}}}
    return cfg


def check_authorization(cfg: dict, today: dt.date | None = None) -> dict:
    """Refuse to run unless a signed permission letter covers this target today."""
    auth = cfg.get("authorization") or {}
    required = ["client", "signed_by", "letter_file", "start", "end", "allowed_hosts"]
    missing = [k for k in required if not auth.get(k)]
    if missing:
        raise AuthorizationError(
            "authorization block is incomplete, missing: " + ", ".join(missing)
        )

    letter = auth["letter_file"]
    if not os.path.isabs(letter):
        letter = os.path.join(cfg["_config_dir"], letter)
    if not os.path.isfile(letter):
        raise AuthorizationError(f"signed permission letter not found: {letter}")

    today = today or dt.date.today()
    start = _as_date(auth["start"])
    end = _as_date(auth["end"])
    if not start <= today <= end:
        raise AuthorizationError(
            f"today ({today}) is outside the authorized window {start} to {end}"
        )

    hosts = {h.lower() for h in auth["allowed_hosts"]}
    urls = [cfg["target"]["url"]]
    if cfg["agency"].get("action_log_url"):
        urls.append(cfg["agency"]["action_log_url"])
    for url in urls:
        host = (urlparse(url).hostname or "").lower()
        if host not in hosts:
            raise AuthorizationError(f"host '{host}' is not in authorization.allowed_hosts")

    return {
        "client": auth["client"],
        "signed_by": auth["signed_by"],
        "letter_file": letter,
        "window": f"{start} to {end}",
        "allowed_hosts": sorted(hosts),
    }


def _as_date(value) -> dt.date:
    if isinstance(value, dt.date):
        return value
    return dt.date.fromisoformat(str(value))
