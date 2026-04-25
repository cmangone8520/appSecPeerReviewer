import hashlib
import hmac

from app.webhook import verify_signature


def _sig(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_verify_signature_accepts_valid_signature():
    secret = "abc123"
    body = b'{"hello":"world"}'
    assert verify_signature(secret, body, _sig(secret, body)) is True


def test_verify_signature_rejects_tampered_body():
    secret = "abc123"
    sig = _sig(secret, b'{"hello":"world"}')
    assert verify_signature(secret, b'{"hello":"WORLD"}', sig) is False


def test_verify_signature_rejects_wrong_secret():
    sig = _sig("abc123", b"x")
    assert verify_signature("def456", b"x", sig) is False


def test_verify_signature_rejects_missing_or_malformed_header():
    assert verify_signature("abc", b"x", None) is False
    assert verify_signature("abc", b"x", "sha1=deadbeef") is False
    assert verify_signature("", b"x", "sha256=anything") is False
