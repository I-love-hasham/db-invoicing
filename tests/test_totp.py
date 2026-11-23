from app import totp

# RFC 6238 Appendix B, SHA-1, 8 digits, key = "12345678901234567890"
RFC_KEY = b"12345678901234567890"
VECTORS = [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
           (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]


def test_rfc6238_vectors():
    for t, expected in VECTORS:
        assert totp.code_at("", t // 30, digits=8, key=RFC_KEY) == expected


def test_verify_window_and_replay(clock):
    secret = totp.new_secret()
    step = totp.current_step()
    code = totp.code_at(secret, step)
    assert totp.verify(secret, code, last_step=0) == step
    assert totp.verify(secret, code, last_step=step) is None          # reuse blocked
    assert totp.verify(secret, totp.code_at(secret, step - 1), 0) == step - 1   # 30s drift ok
    assert totp.verify(secret, totp.code_at(secret, step + 3), 0) is None       # too far
    assert totp.verify(secret, "12345", 0) is None
    assert totp.verify(secret, "abcdef", 0) is None
