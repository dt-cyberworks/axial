"""The Scope Gateway's rule for test-account credentials (REQ-TESTACCT-004/006/007, GitHub #89, R4).

Deny wins; this module only ever narrows, with ONE exception: the declared login request of a consented monitor on an assigned usable
host is allowed without a per-call approval (R-F). The rule needs no cooperation from the model: it runs on the request as proposed,
with the plaintext the control plane can decrypt, and recognizes the placeholder, the plain value and the encodings of it.

  R-A  a request that carries an account's credential is refused unless the tool is `http_request`        credential_tool_not_allowed
  R-B  ... and the target is an assigned, usable host of that account                                      credential_host_not_usable
  R-C  ... and the account is not erased or suspended                                                       (inside R-B: the verdict says why)
  R-D  a login account's password is allowed only in its declared login request                             credential_wrong_use
  R-E  at most 2 login requests per account and host per run, 20 per account per run                        login_attempt_limit
  R-F  monitoring: POST of the declared login to an assigned usable host under a current consent           allowed (testaccount_login)
"""

from __future__ import annotations

import dataclasses
import uuid

from sqlalchemy.orm import Session

from app import testaccounts
from app.models.engagement import Engagement
from app.models.test_account import TestAccount, TestAccountHost


@dataclasses.dataclass
class CredentialVerdict:
    denial: str | None = None          # a gateway reason code
    detail: str | None = None          # in words, for the agent and the console: the rule, the account label, never the value
    consented_login: bool = False      # R-F
    login_account: TestAccount | None = None
    login_host: str | None = None
    consent_id: uuid.UUID | None = None


def _request_parts(args: dict) -> tuple[str, str, object, object]:
    method = str((args or {}).get("method", "GET")).upper()
    path = str((args or {}).get("path", "") or "")
    return method, path, (args or {}).get("headers"), (args or {}).get("body")


def evaluate(db: Session, eng: Engagement, call, run) -> CredentialVerdict:
    args = call.args if isinstance(call.args, dict) else {}
    # Cheap exit: nothing to look for when the engagement has no account and the request names no placeholder.
    probe = [args, call.path, call.target, call.rationale, call.risk]
    uses, unknown = testaccounts.find_uses(db, eng.id, *probe)
    if not uses and not unknown:
        return CredentialVerdict()
    if unknown:
        return CredentialVerdict("credential_wrong_use", f"the request names a test account that this engagement does not have ({unknown[0]})")
    # R-A
    if call.tool != "http_request":
        return CredentialVerdict("credential_tool_not_allowed",
                                 f"test account {uses[0].label} may only be used in an http_request, never in {call.tool}")
    host = testaccounts.normalize_host(call.target)
    # R-B / R-C
    assignments_cache: dict[uuid.UUID, dict[str, TestAccountHost]] = {}
    for account in uses:
        assignments = assignments_cache.setdefault(
            account.id, {a.host: a for a in testaccounts.assignments_of(db, account)})
        verdict = testaccounts.host_verdict(db, eng, account, host, assignments)
        if not verdict.usable:
            return CredentialVerdict("credential_host_not_usable",
                                     f"test account {account.label} cannot be used on {host}: {verdict.reason_text}")
    method, path, _headers, body = _request_parts(args)
    login_uses = [a for a in uses if a.kind in testaccounts.LOGIN_KINDS]
    # R-D: a login account's password belongs in its login request and nowhere else
    declared: list[tuple[TestAccount, TestAccountHost]] = []
    for account in login_uses:
        assignment = assignments_cache[account.id][host]
        login_path = testaccounts.effective_login_path(account, assignment)
        is_login = method == "POST" and path == login_path
        if not is_login:
            return CredentialVerdict("credential_wrong_use",
                                     f"the password of test account {account.label} is only for its login request (POST {login_path}), not for {method} {path or '/'}")
        declared.append((account, assignment))
    if len(login_uses) > 1:
        return CredentialVerdict("credential_wrong_use", "one request may carry only one account's login")
    if not declared:
        return CredentialVerdict()         # a bearer / API-key / Basic account on a usable host: allowed on any path
    account, assignment = declared[0]
    # R-E
    run_id = run.id if run is not None else None
    per_host, per_run = testaccounts.login_attempts(db, account, host, run_id)
    if per_host >= testaccounts.MAX_LOGINS_PER_HOST_PER_RUN or per_run >= testaccounts.MAX_LOGINS_PER_RUN:
        return CredentialVerdict("login_attempt_limit",
                                 f"test account {account.label} was already tried {per_host} time(s) on {host} in this run; no further attempt")
    # R-F: only a monitor, only the declared login that carries this account's own username, only under a current consent
    consent = None
    if eng.operating_mode == "monitoring" and account.username and _contains(body, account.username):
        consent = testaccounts.consent_covers(db, eng.id, account, host, testaccounts.effective_login_path(account, assignment))
    return CredentialVerdict(consented_login=consent is not None, login_account=account, login_host=host,
                             consent_id=consent.id if consent is not None else None)


def _contains(value, needle: str) -> bool:
    leaves: list[str] = []
    testaccounts._leaves(value, leaves)
    return any(needle in leaf for leaf in leaves)
