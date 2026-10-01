"""TC-PIPE-021 (GitHub issue #49): the customer report does not present a safety stop
as something the operator did."""

from app.report_builder import _skip_text


def test_a_safety_stop_is_not_described_as_an_operator_stop():
    text = _skip_text("cancellation_status_unavailable")
    assert "safety" in text and "operator" not in text


def test_a_real_operator_stop_keeps_its_text():
    assert _skip_text("cancelled_by_operator") == "stopped by the operator"
