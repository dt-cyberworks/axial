"""Test accounts of an engagement (REQ-TESTACCT-001..006, GitHub #89, R4).

Mounted behind the router-wide engagement access check: every signed-in user may read, only the engagement's owner or an administrator
may write (REQ-IAM-022/023), and each write handler checks that again. No response carries a secret."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import testaccounts
from app.db.base import get_db
from app.models.engagement import Engagement
from app.models.user import User
from app.schemas.test_account import HostsIn, SecretIn, TestAccountCreateIn
from app.security import can_manage_engagement, require_user

router = APIRouter(prefix="/engagements", tags=["test-accounts"])


def _engagement(db: Session, engagement_id: uuid.UUID) -> Engagement:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(404, "engagement not found")
    return eng


def _manageable(db: Session, engagement_id: uuid.UUID, user: User) -> Engagement:
    eng = _engagement(db, engagement_id)
    if not can_manage_engagement(user, eng):
        raise HTTPException(403, "only the owner of the engagement or an administrator can change its test accounts")
    return eng


def _account(db: Session, eng: Engagement, account_id: uuid.UUID):
    account = db.get(testaccounts.TestAccount, account_id)
    if account is None or account.engagement_id != eng.id:
        raise HTTPException(404, "test account not found")
    return account


def _fail(exc: testaccounts.TestAccountError):
    # The detail is the code (like the handover endpoints); the console and the manual have a sentence for each.
    raise HTTPException(exc.status, exc.code)


@router.get("/{engagement_id}/test-accounts")
def list_test_accounts(engagement_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(require_user)):
    eng = _engagement(db, engagement_id)
    return {"accounts": [testaccounts.view(db, eng, a) for a in testaccounts.accounts_of(db, eng.id)],
            "can_manage": can_manage_engagement(user, eng),
            "consent": testaccounts.consent_view(db, eng), "cipher_available": _cipher_available()}


@router.get("/{engagement_id}/test-accounts/host-choices")
def host_choices(engagement_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(require_user)):
    return testaccounts.host_choices(db, _engagement(db, engagement_id))


@router.post("/{engagement_id}/test-accounts", status_code=201)
def create_test_account(engagement_id: uuid.UUID, body: TestAccountCreateIn, db: Session = Depends(get_db), user: User = Depends(require_user)):
    eng = _manageable(db, engagement_id, user)
    try:
        account = testaccounts.create(
            db, eng, user, label=body.label, role=body.role, kind=body.kind, username=body.username, secret=body.secret,
            login_path=body.login_path, header_name=body.header_name, hosts=[h.model_dump() for h in body.hosts], attested=body.attested)
    except testaccounts.TestAccountError as exc:
        _fail(exc)
    return testaccounts.view(db, eng, account)


@router.put("/{engagement_id}/test-accounts/{account_id}/hosts")
def set_test_account_hosts(engagement_id: uuid.UUID, account_id: uuid.UUID, body: HostsIn, db: Session = Depends(get_db),
                           user: User = Depends(require_user)):
    eng = _manageable(db, engagement_id, user)
    account = _account(db, eng, account_id)
    try:
        testaccounts.set_hosts(db, eng, user, account, [h.model_dump() for h in body.hosts], attested=body.attested, consent=body.consent)
    except testaccounts.TestAccountError as exc:
        _fail(exc)
    return testaccounts.view(db, eng, account)


@router.put("/{engagement_id}/test-accounts/{account_id}/secret")
def replace_test_account_secret(engagement_id: uuid.UUID, account_id: uuid.UUID, body: SecretIn, db: Session = Depends(get_db),
                                user: User = Depends(require_user)):
    eng = _manageable(db, engagement_id, user)
    account = _account(db, eng, account_id)
    try:
        testaccounts.replace_secret(db, eng, user, account, body.secret)
    except testaccounts.TestAccountError as exc:
        _fail(exc)
    return testaccounts.view(db, eng, account)


@router.post("/{engagement_id}/test-accounts/{account_id}/resume")
def resume_test_account(engagement_id: uuid.UUID, account_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(require_user)):
    eng = _manageable(db, engagement_id, user)
    account = _account(db, eng, account_id)
    try:
        testaccounts.resume(db, eng, user, account)
    except testaccounts.TestAccountError as exc:
        _fail(exc)
    return testaccounts.view(db, eng, account)


@router.delete("/{engagement_id}/test-accounts/{account_id}", status_code=204)
def delete_test_account(engagement_id: uuid.UUID, account_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(require_user)):
    eng = _manageable(db, engagement_id, user)
    testaccounts.delete(db, eng, user, _account(db, eng, account_id))


@router.get("/{engagement_id}/login-consent")
def read_login_consent(engagement_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(require_user)):
    return testaccounts.consent_view(db, _engagement(db, engagement_id))


@router.post("/{engagement_id}/login-consent", status_code=201)
def give_login_consent(engagement_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(require_user)):
    eng = _manageable(db, engagement_id, user)
    try:
        testaccounts.give_consent(db, eng, user)
    except testaccounts.TestAccountError as exc:
        _fail(exc)
    return testaccounts.consent_view(db, eng)


@router.delete("/{engagement_id}/login-consent")
def revoke_login_consent(engagement_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(require_user)):
    eng = _manageable(db, engagement_id, user)
    testaccounts.revoke_consent(db, eng, user)
    return testaccounts.consent_view(db, eng)


def _cipher_available() -> bool:
    try:
        testaccounts._cipher()
        return True
    except testaccounts.CipherUnavailable:
        return False
