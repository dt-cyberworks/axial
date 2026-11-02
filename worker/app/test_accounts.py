"""Test accounts on the worker (REQ-TESTACCT-003/005/007/008, GitHub #89, R4).

The model sees the real credentials (decision D1) and writes the login request itself. Everything between the model and the target is then
deterministic: the model's tool call is rewritten here, before anything leaves this process for the control plane (the Scope Gateway, the
audit trail, an approval), so the value is replaced by a placeholder `{{testaccount:<label>}}`; and the real value is put back in exactly
one place, `dispatch._run`, just before the request goes to the tool runner. The gateway's rule (`credential_rule.py`) does not depend on
this rewrite: it recognizes the value as well as the placeholder.

Placeholders carry the encoding the value was found in (`{{testaccount:shop|url}}`), so that putting the value back produces the bytes
the model wrote, not a different encoding of them.

Nothing here is written anywhere: the accounts live in process memory for the duration of one agent phase.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import re
import threading
from urllib.parse import quote, quote_plus

SESSION_RE = re.compile(r"\{\{session:([0-9a-f]{12})\}\}")
MIN_SESSION_LENGTH = 16     # a session id is long; a shorter cookie value (`security=low`) is a setting, and replacing it would hide ordinary words
PLACEHOLDER_RE = re.compile(r"\{\{testaccount:([A-Za-z0-9_-]{1,40})(?:\|([a-z0-9]{1,8}))?\}\}")
MIN_SECRET_LENGTH = 8
LOGIN_KINDS = ("login_form", "login_json")
TOKEN_KEYS = ("access_token", "auth_token", "id_token", "token", "jwt", "sessionid", "session_id", "session")


class UnresolvedPlaceholder(RuntimeError):
    """A placeholder names no account known to this run. The request is NOT sent with the placeholder as the value."""


@dataclasses.dataclass(frozen=True)
class Account:
    label: str
    role: str
    kind: str
    username: str | None
    secret: str = dataclasses.field(repr=False)
    header_name: str | None = None
    login_path: str | None = None
    login_paths: dict = dataclasses.field(default_factory=dict)
    can_use_on: tuple = ()
    cannot_use_on: tuple = ()

    def login_path_on(self, host: str) -> str | None:
        return (self.login_paths or {}).get(host.lower()) or self.login_path


_lock = threading.RLock()
_by_run: dict[str, dict[str, Account]] = {}
_forms_cache: list[tuple[str, str, str]] | None = None
# REQ-TESTACCT-014: the live session values of the runs in this process (run key -> token -> value). A login's session is as sensitive as the
# password that produced it for as long as it lives, so it is treated the same way: a placeholder everywhere but the one request that is sent.
_sessions: dict[str, dict[str, str]] = {}
_session_forms_cache: list[tuple[str, str]] | None = None


def register(run_key: str, accounts: list[dict]) -> dict[str, Account]:
    """The accounts of one run, as the control plane delivered them (with the real value)."""
    global _forms_cache
    parsed: dict[str, Account] = {}
    for item in accounts or []:
        secret = str(item.get("secret") or "")
        if len(secret) < MIN_SECRET_LENGTH:
            continue    # too short to search for safely; the control plane refuses such a secret anyway
        parsed[item["label"]] = Account(
            label=item["label"], role=item.get("role", ""), kind=item.get("kind", ""), username=item.get("username"), secret=secret,
            header_name=item.get("header_name"), login_path=item.get("login_path"),
            login_paths={str(h).lower(): p for h, p in (item.get("login_paths") or {}).items()},
            can_use_on=tuple(str(h).lower() for h in item.get("can_use_on") or ()), cannot_use_on=tuple(item.get("cannot_use_on") or ()),
        )
    with _lock:
        _by_run[run_key] = parsed
        _forms_cache = None
    return parsed


def unregister(run_key: str) -> None:
    global _forms_cache, _session_forms_cache
    with _lock:
        _by_run.pop(run_key, None)
        _sessions.pop(run_key, None)
        _forms_cache = None
        _session_forms_cache = None


def reset() -> None:
    """Forget everything (a test's teardown; the process never needs it)."""
    global _forms_cache, _session_forms_cache
    with _lock:
        _by_run.clear()
        _sessions.clear()
        _forms_cache = None
        _session_forms_cache = None


def active() -> bool:
    return bool(_by_run) or bool(_sessions)


def session_placeholder(value: str) -> str:
    return "{{session:%s}}" % hashlib.sha256(value.encode()).hexdigest()[:12]


def register_session_values(run_key: str, values) -> None:
    """The session values a run was issued (REQ-TESTACCT-014). Anything shorter than MIN_SESSION_LENGTH is not a session id."""
    global _session_forms_cache
    fresh = {session_placeholder(v): v for v in values if isinstance(v, str) and len(v) >= MIN_SESSION_LENGTH}
    if not fresh:
        return
    with _lock:
        _sessions.setdefault(run_key, {}).update(fresh)
        _session_forms_cache = None


def _session_forms() -> list[tuple[str, str]]:
    """(value, placeholder) over every registered session, longest first."""
    global _session_forms_cache
    with _lock:
        if _session_forms_cache is None:
            seen = {v: t for tokens in _sessions.values() for t, v in tokens.items()}
            _session_forms_cache = sorted(seen.items(), key=lambda kv: len(kv[0]), reverse=True)
        return _session_forms_cache


def accounts_of(run_key: str) -> dict[str, Account]:
    with _lock:
        return dict(_by_run.get(run_key, {}))


def _all_accounts() -> list[Account]:
    with _lock:
        return [a for accounts in _by_run.values() for a in accounts.values()]


def _forms_of(account: Account) -> list[tuple[str, str]]:
    """(text, form name) for the value and its recognized encodings."""
    s = account.secret
    forms = [(s, "plain"), (quote(s, safe=""), "url"), (quote_plus(s), "plus"), (json.dumps(s)[1:-1], "json"),
             (base64.b64encode(s.encode()).decode(), "b64"), (base64.urlsafe_b64encode(s.encode()).decode().rstrip("="), "b64u")]
    if account.username:
        raw = f"{account.username}:{s}".encode()
        forms += [(base64.b64encode(raw).decode(), "basic"), (base64.urlsafe_b64encode(raw).decode().rstrip("="), "basicu")]
    return forms


def _forms() -> list[tuple[str, str, str]]:
    """(text, label, form) over every registered account, longest first so a long encoding is replaced whole."""
    global _forms_cache
    with _lock:
        if _forms_cache is None:
            seen: dict[str, tuple[str, str]] = {}
            for account in _all_accounts():
                for text, form in _forms_of(account):
                    if len(text) >= MIN_SECRET_LENGTH and text not in seen:
                        seen[text] = (account.label, form)
            _forms_cache = sorted(((t, l, f) for t, (l, f) in seen.items()), key=lambda x: len(x[0]), reverse=True)
        return _forms_cache


def placeholder(label: str, form: str = "plain") -> str:
    return "{{testaccount:%s}}" % label if form == "plain" else "{{testaccount:%s|%s}}" % (label, form)


def to_placeholders(value):
    """`value` with every known secret, in any recognized form, replaced by its placeholder, and every live session value by its own.
    Strings, and any nesting of dicts, lists and tuples. Cheap when nothing is registered (the common case outside an agent phase)."""
    if not _by_run and not _sessions:
        return value
    forms = _forms()
    sessions = _session_forms()
    if not forms and not sessions:
        return value

    def walk(v):
        if isinstance(v, str):
            for text, label, form in forms:
                if text in v:
                    v = v.replace(text, placeholder(label, form))
            for text, token in sessions:
                if text in v:
                    v = v.replace(text, token)
            return v
        if isinstance(v, dict):
            return {walk(k) if isinstance(k, str) else k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, tuple):
            return tuple(walk(x) for x in v)
        return v

    return walk(value)


def _render(account: Account, form: str) -> str:
    for text, name in _forms_of(account):
        if name == form:
            return text
    return account.secret


def resolve(value, run_key: str | None = None):
    """The inverse, for ONE request, at the last step before it leaves for the target. A placeholder that names no account (or session) of
    this run raises (the request is not sent with the placeholder as its value)."""
    pool = accounts_of(run_key) if run_key is not None else {a.label: a for a in _all_accounts()}
    with _lock:
        sessions = dict(_sessions.get(run_key, {})) if run_key is not None else {t: v for tokens in _sessions.values() for t, v in tokens.items()}

    def sub(match: re.Match) -> str:
        account = pool.get(match.group(1))
        if account is None:
            raise UnresolvedPlaceholder(match.group(1))
        return _render(account, match.group(2) or "plain")

    def sub_session(match: re.Match) -> str:
        found = sessions.get(match.group(0))
        if found is None:
            raise UnresolvedPlaceholder("session")
        return found

    def walk(v):
        if isinstance(v, str):
            if "{{testaccount:" in v:
                v = PLACEHOLDER_RE.sub(sub, v)
            if "{{session:" in v:
                v = SESSION_RE.sub(sub_session, v)
            return v
        if isinstance(v, dict):
            return {walk(k) if isinstance(k, str) else k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, tuple):
            return tuple(walk(x) for x in v)
        return v

    return walk(value)


def mask_forms(value, run_key: str | None = None) -> list[str]:
    """Every recognized form of the secret of each account whose placeholder `value` carries, and the session values it names (REQ-TESTACCT-013,
    -014): what the tool runner is told to mask in its own log for the one request that puts them back."""
    labels = labels_in(value)
    tokens = _session_tokens_in(value)
    if not labels and not tokens:
        return []
    pool = accounts_of(run_key) if run_key is not None else {a.label: a for a in _all_accounts()}
    forms: list[str] = []
    for label in sorted(labels):
        account = pool.get(label)
        if account is None:
            continue
        for text, _name in _forms_of(account):
            if len(text) >= MIN_SECRET_LENGTH and text not in forms:
                forms.append(text)
    if tokens:
        with _lock:
            known = {t: v for run, mapping in _sessions.items() if run_key is None or run == run_key for t, v in mapping.items()}
        forms += [known[t] for t in sorted(tokens) if t in known and known[t] not in forms]
    return forms


def session_values_in(value, run_key: str | None = None) -> list[str]:
    """The registered session values (of this run, or of every run when none is given) that `value` carries, for the runner's log mask."""
    with _lock:
        known = [v for run, mapping in _sessions.items() if run_key is None or run == run_key for v in mapping.values()]
    if not known:
        return []
    text = json.dumps(value, default=str)
    return [v for v in sorted(set(known), key=len, reverse=True) if v in text]


def _session_tokens_in(value) -> set[str]:
    found: set[str] = set()
    if isinstance(value, str):
        found.update(m.group(0) for m in SESSION_RE.finditer(value))
    elif isinstance(value, dict):
        for k, v in value.items():
            found |= _session_tokens_in(k) | _session_tokens_in(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            found |= _session_tokens_in(v)
    return found


def has_placeholder(value) -> bool:
    if isinstance(value, str):
        return "{{testaccount:" in value or "{{session:" in value
    if isinstance(value, dict):
        return any(has_placeholder(k) or has_placeholder(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(has_placeholder(v) for v in value)
    return False


def labels_in(value) -> set[str]:
    found: set[str] = set()
    if isinstance(value, str):
        found.update(m.group(1) for m in PLACEHOLDER_RE.finditer(value))
    elif isinstance(value, dict):
        for k, v in value.items():
            found |= labels_in(k) | labels_in(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            found |= labels_in(v)
    return found


# ------------------------------------------------------------------------------------------------ the agent's view and sessions


def identity_for(raw: str, run_key: str) -> str:
    """'primary' / 'secondary' as before; a test account's label keeps that account's session apart from every other (REQ-TESTACCT-001)."""
    wanted = (raw or "").strip()
    if wanted.lower() in ("primary", "secondary"):
        return wanted.lower()
    for label in accounts_of(run_key):
        if label.lower() == wanted.lower():
            return label
    return "primary"


def login_account_for(run_key: str, host: str, method: str, path: str, args_text) -> Account | None:
    """The account whose declared login this request is (POST to its login path on this host, carrying its placeholder), if any."""
    if method.upper() != "POST":
        return None
    labels = labels_in(args_text)
    for label in labels:
        account = accounts_of(run_key).get(label)
        if account is not None and account.kind in LOGIN_KINDS and path == account.login_path_on(host):
            return account
    return None


_STATUS_RE = re.compile(r"HTTP/\d(?:\.\d)?\s+(\d{3})")
_LOCATION_RE = re.compile(r"^location:\s*(?P<url>\S+)", re.IGNORECASE | re.MULTILINE)
_REDIRECTS = (301, 302, 303, 307, 308)
# Where a target sends a wrong password (or a stale CSRF token, which looks the same from outside): back to the form, or to an error.
_FAILURE_HINTS = ("login", "signin", "sign-in", "logon", "error", "fail", "denied", "invalid")


def classify_login(response_text: str, fresh_cookie_names, had_session: bool = False) -> str:
    """`session_established` or `rejected` for the response to a login (REQ-TESTACCT-007/008). Conservative: when in doubt it says
    `rejected`, because a false 'established' lets an account be tried again and again against a target that is rejecting it.

    Established: a session cookie or a token was issued by the response; or, when the run already held a session for that host and identity
    (`had_session`: the target issued it before the login, as many PHP applications do and keep it), a redirect AWAY from the login page.
    Found live against DVWA: its accepted login answers `302 -> index.php` with no new cookie, and a wrong one `302 -> login.php`."""
    match = _STATUS_RE.search(response_text or "")
    status = int(match.group(1)) if match else 0
    if status in (401, 403) or status >= 400 or status == 0:
        return "rejected"
    redirect = _LOCATION_RE.search(response_text or "")
    target = redirect.group("url").lower() if redirect else ""
    if status in _REDIRECTS and redirect and any(hint in target for hint in _FAILURE_HINTS):
        return "rejected"      # sent back to the login page or an error: the usual answer to a wrong password
    token = any(f'"{key}"' in (response_text or "").lower() for key in TOKEN_KEYS)
    if fresh_cookie_names or token:
        return "session_established"
    if status in _REDIRECTS and redirect and had_session:
        return "session_established"
    return "rejected"


def render_for_agent(accounts: list[dict]) -> str:
    """The block of the agent's first message (REQ-TESTACCT-003): the real value, and where each account can and cannot be used."""
    if not accounts:
        return ""
    lines = [
        "TEST ACCOUNTS — dedicated accounts the owner created for this test. Use them to log in where the target has a login, and to test "
        "what sits behind it. The value below is real; use it ONLY in an http_request to a host listed under \"can be used on\".",
    ]
    for a in accounts:
        who = f"{a.get('label')} (role {a.get('role')}, {a.get('kind')})"
        secret = a.get("secret")
        if a.get("kind") == "header_token":
            lines.append(f"- {who}: token {secret}" + (f" — send it in the header {a['header_name']}" if a.get("header_name") else ""))
        else:
            lines.append(f"- {who}: username {a.get('username')}, password {secret}")
        paths = a.get("login_paths") or {}
        if a.get("kind") in LOGIN_KINDS:
            lines.append("  Log in with POST " + (a.get("login_path") or "(its login path)") + (
                " (other login paths: " + ", ".join(f"{h} → {p}" for h, p in paths.items() if p != a.get("login_path")) + ")"
                if any(p != a.get("login_path") for p in paths.values()) else ""))
        can = ", ".join(a.get("can_use_on") or []) or "(no host: this account cannot be used anywhere yet)"
        lines.append(f"  Can be used on: {can}")
        cannot = a.get("cannot_use_on") or []
        if cannot:
            lines.append("  Cannot be used on: " + "; ".join(f"{c['host']} ({c.get('reason_text') or c.get('reason')})" for c in cannot))
    lines += [
        "Rules: the account goes only into http_request, never into another tool, and never to a host outside the list above (the Scope "
        "Gateway refuses it). A session from one host is not valid on another, so log in on each host you test. At most two login attempts "
        "per host; do not retry a login the target rejected. Pass identity=<label> in http_request to keep this account's session apart from "
        "any other. Confirm that you are really logged in before concluding that functionality is absent, use a second role's account to "
        "prove access-control flaws, and report what you could not reach behind a login as UNTESTED, not as clean. Do not write the "
        "password into your reasons, findings or evidence.",
        "",
    ]
    return "\n".join(lines) + "\n"
