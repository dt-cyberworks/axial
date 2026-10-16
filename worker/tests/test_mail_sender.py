"""REQ-MAIL-003/005: the worker's side of outbound e-mail. Nothing here reaches a real
relay: smtplib is replaced by a recording fake."""

from __future__ import annotations

import smtplib

import pytest

from app import mail_sender
from app.tasks import mail_tasks

RELAY = {"host": "smtp.example.org", "port": 587, "security": "starttls", "username": "relay", "password": "pw-secret",
         "from_address": "axial@example.org", "from_name": "Axial"}
PUBLIC = lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 587))]  # noqa: E731


class FakeSmtp:
    def __init__(self):
        self.calls, self.sent = [], []

    def starttls(self, context=None):
        self.calls.append(("starttls", context is not None))

    def login(self, user, password):
        self.calls.append(("login", user))

    def send_message(self, msg):
        self.sent.append(msg)

    def quit(self):
        self.calls.append(("quit",))


def test_a_message_is_built_plain_with_auto_submitted_and_no_extra_headers():
    msg = mail_sender.build_message(sender="axial@example.org", sender_name="Axial", to="user@example.com",
                                    subject="Reset your Axial password", body="link\n")
    assert msg["Auto-Submitted"] == "auto-generated"
    assert msg["To"] == "user@example.com" and msg["From"] == "Axial <axial@example.org>"
    assert msg.get_content_type() == "text/plain" and not msg.is_multipart()
    assert msg["Bcc"] is None and msg["Cc"] is None


@pytest.mark.parametrize("field", ["to", "subject", "sender", "sender_name"])
def test_a_line_break_in_a_header_value_is_refused(field):
    args = dict(sender="axial@example.org", sender_name="Axial", to="user@example.com", subject="s", body="b")
    key = {"sender": "sender", "sender_name": "sender_name", "to": "to", "subject": "subject"}[field]
    args[key] = args[key] + "\r\nBcc: attacker@example.net"
    with pytest.raises(mail_sender.MailRefused):
        mail_sender.build_message(**args)


def test_starttls_is_used_then_login_then_send():
    smtp = FakeSmtp()
    mail_sender.send(RELAY, to="user@example.com", subject="s", body="b", smtp_factory=lambda h, p: smtp, resolve=PUBLIC)
    assert [c[0] for c in smtp.calls] == ["starttls", "login", "quit"]
    assert smtp.calls[0] == ("starttls", True) and smtp.calls[1] == ("login", "relay")
    assert len(smtp.sent) == 1


def test_no_login_without_a_username():
    smtp = FakeSmtp()
    mail_sender.send({**RELAY, "username": ""}, to="user@example.com", subject="s", body="b",
                     smtp_factory=lambda h, p: smtp, resolve=PUBLIC)
    assert ("login", "") not in smtp.calls and all(c[0] != "login" for c in smtp.calls)


@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254", "0.0.0.0", "::1"])
def test_a_relay_that_resolves_to_loopback_or_link_local_is_refused_before_connecting(address):
    connected = []
    with pytest.raises(mail_sender.MailRefused):
        mail_sender.send(RELAY, to="user@example.com", subject="s", body="b",
                         smtp_factory=lambda h, p: connected.append(1) or FakeSmtp(),
                         resolve=lambda *a, **k: [(2, 1, 6, "", (address, 587))])
    assert connected == []


def test_the_connection_is_closed_even_when_sending_fails():
    smtp = FakeSmtp()

    def boom(msg):
        raise smtplib.SMTPRecipientsRefused({"user@example.com": (550, b"no")})

    smtp.send_message = boom
    with pytest.raises(smtplib.SMTPRecipientsRefused):
        mail_sender.send(RELAY, to="user@example.com", subject="s", body="b", smtp_factory=lambda h, p: smtp, resolve=PUBLIC)
    assert ("quit",) in smtp.calls


def test_delivery_reports_each_result_with_a_reason_that_holds_no_recipient_or_body(monkeypatch):
    messages = [
        {"id": "m1", "to": "ok@example.com", "subject": "s", "body": "https://x/reset-password#SECRET1", "attempts": 0},
        {"id": "m2", "to": "bad@example.com", "subject": "s", "body": "https://x/reset-password#SECRET2", "attempts": 0},
        {"id": "m3", "to": "auth@example.com", "subject": "s", "body": "b", "attempts": 0},
    ]
    monkeypatch.setattr(mail_tasks.client, "due_mail", lambda: {"relay": RELAY, "messages": messages})
    results = {}
    monkeypatch.setattr(mail_tasks.client, "report_mail_result",
                        lambda mid, delivered, error=None: results.__setitem__(mid, (delivered, error)))

    def send(relay, *, to, subject, body):
        if to == "bad@example.com":
            raise smtplib.SMTPRecipientsRefused({to: (550, b"mailbox unavailable")})
        if to == "auth@example.com":
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials")

    out = mail_tasks.deliver_due_mail(send=send)
    assert out == {"sent": 1, "failed": 2, "relay": True}
    assert results["m1"] == (True, None)
    assert results["m2"] == (False, "recipient_refused")
    assert results["m3"] == (False, "relay_authentication_failed")
    blob = str(results)
    assert "example.com" not in blob and "SECRET" not in blob and "pw-secret" not in blob


def test_nothing_happens_when_the_control_plane_has_no_relay(monkeypatch):
    monkeypatch.setattr(mail_tasks.client, "due_mail", lambda: {"relay": None, "messages": []})
    assert mail_tasks.deliver_due_mail(send=lambda *a, **k: pytest.fail("must not send")) == {"sent": 0, "failed": 0, "relay": False}
