from app import passwords


def test_hash_and_verify_roundtrip():
    h = passwords.hash_secret("correct horse battery staple")
    assert passwords.verify_secret("correct horse battery staple", h) is True


def test_wrong_secret_fails():
    h = passwords.hash_secret("correct horse battery staple")
    assert passwords.verify_secret("wrong", h) is False


def test_hash_is_never_the_raw_value():
    h = passwords.hash_secret("mysecret")
    assert h != "mysecret"
    assert "mysecret" not in h


def test_malformed_hash_fails_closed_not_raises():
    assert passwords.verify_secret("anything", "not-a-real-argon2-hash") is False


def test_temp_password_meets_minimum_length_and_varies():
    a = passwords.generate_temp_password()
    b = passwords.generate_temp_password()
    assert len(a) >= 16
    assert a != b


def test_backup_codes_are_unique_and_formatted():
    codes = passwords.generate_backup_codes(10)
    assert len(codes) == 10
    assert len(set(codes)) == 10
    for code in codes:
        assert len(code) == 9  # XXXX-XXXX
        assert code[4] == "-"
