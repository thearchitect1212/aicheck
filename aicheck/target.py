"""Talk to any chat endpoint described in the config."""

from __future__ import annotations

import copy
import time
import uuid
from dataclasses import asdict, dataclass, field

import requests


@dataclass
class Exchange:
    user: str
    message: str
    document: str | None
    status: int
    reply: str
    latency: float
    error: str | None = None
    raw: str = ""
    time: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


def _fill(template, values: dict):
    """Replace {{name}} placeholders anywhere inside a nested structure."""
    if isinstance(template, dict):
        return {k: _fill(v, values) for k, v in template.items()}
    if isinstance(template, list):
        return [_fill(v, values) for v in template]
    if isinstance(template, str):
        for key, val in values.items():
            token = "{{" + key + "}}"
            if template == token:
                return val
            if token in template:
                template = template.replace(token, "" if val is None else str(val))
        return template
    return template


def extract(data, path: str):
    """Follow a dotted path such as 'choices.0.message.content'."""
    cur = data
    for part in path.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


class Target:
    def __init__(self, cfg: dict):
        self.cfg = cfg["target"]
        self.users = cfg["users"]
        self.sessions: dict[str, str] = {}
        self.supports_document = "{{document}}" in str(self.cfg.get("body_template", {}))
        self.request_count = 0

    def new_session(self, user: str) -> str:
        sid = f"aicheck-{user}-{uuid.uuid4().hex[:8]}"
        self.sessions[user] = sid
        return sid

    def send(self, message: str, user: str = "a", document: str | None = None,
             fresh_session: bool = False, delay: bool = True) -> Exchange:
        if user not in self.users:
            raise KeyError(f"user '{user}' is not defined in config.users")
        if fresh_session or user not in self.sessions:
            self.new_session(user)
        ucfg = self.users[user] or {}
        values = {"message": message, "document": document or "",
                  "session": self.sessions[user], "user": user}
        values.update(ucfg.get("vars", {}))

        headers = dict(self.cfg.get("headers", {}))
        headers.update(ucfg.get("headers", {}))
        body = _fill(copy.deepcopy(self.cfg.get("body_template", {"message": "{{message}}"})), values)

        start = time.time()
        try:
            resp = requests.request(self.cfg["method"], self.cfg["url"], json=body,
                                    headers=headers, timeout=self.cfg["timeout"])
            latency = time.time() - start
            raw = resp.text
            reply = raw
            try:
                got = extract(resp.json(), self.cfg["response_path"])
                if got is not None:
                    reply = got if isinstance(got, str) else str(got)
            except ValueError:
                pass
            ex = Exchange(user, message, document, resp.status_code, reply, latency, raw=raw[:20000])
        except requests.RequestException as exc:
            ex = Exchange(user, message, document, 0, "", time.time() - start, error=str(exc))
        self.request_count += 1
        if delay:
            time.sleep(self.cfg.get("delay_seconds", 0))
        return ex
