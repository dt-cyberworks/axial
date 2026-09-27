from app import sessions


def test_token_is_high_entropy_and_unique():
    a = sessions.generate_token()
    b = sessions.generate_token()
    assert a != b
    assert len(a) >= 32


def test_hash_is_deterministic_and_not_the_raw_token():
    token = sessions.generate_token()
    h1 = sessions.hash_token(token)
    h2 = sessions.hash_token(token)
    assert h1 == h2
    assert h1 != token


def test_different_tokens_hash_differently():
    assert sessions.hash_token(sessions.generate_token()) != sessions.hash_token(sessions.generate_token())
