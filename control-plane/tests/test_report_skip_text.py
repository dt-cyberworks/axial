"""REQ-EXPLAIN-005 (GitHub #59): the customer report says the same thing as the console about a check that
was skipped because the name has no DNS address."""

from app import report_builder


def test_the_report_names_the_cause_of_a_skip_for_lack_of_an_address():
    text = report_builder._skip_text("materialized_ip_missing")
    assert text == "the name has no DNS address, so nothing was sent to it"


def test_negative_other_skip_reasons_keep_their_own_words():
    assert report_builder._skip_text("not_a_tls_service") == "plain HTTP, no TLS layer to test"
    assert report_builder._skip_text("gateway_denied:no_tool_grant") == "refused by the scope gateway (no_tool_grant)"
