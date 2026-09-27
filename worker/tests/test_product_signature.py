from app.product_signature import normalize_product_key, split_tech_entry


def test_split_tech_entry_with_version():
    assert split_tech_entry("WordPress:6.4.2") == ("WordPress", "6.4.2")


def test_split_tech_entry_without_version():
    assert split_tech_entry("nginx") == ("nginx", None)


def test_split_tech_entry_strips_whitespace():
    assert split_tech_entry("  PHP:8.1.2  ") == ("PHP", "8.1.2")


def test_split_tech_entry_empty_version_after_colon_is_none():
    assert split_tech_entry("nginx:") == ("nginx", None)


def test_normalize_product_key_lowercases_and_collapses_whitespace():
    assert normalize_product_key("  OpenSSH   8.9p1 ") == "openssh 8.9p1"
