from datetime import datetime, timedelta, timezone

from license_manager import generate_license, verify_license, LicenseError


def test_generate_and_verify_roundtrip():
    secret = "top-secret"
    token = generate_license(secret, customer="Acme", product="secure-app")
    payload = verify_license(secret, token)

    assert payload["customer"] == "Acme"
    assert payload["product"] == "secure-app"
    assert "id" in payload


def test_reject_tampered_token():
    secret = "top-secret"
    token = generate_license(secret, customer="Acme", product="secure-app")
    body, sig = token.split(".", 1)
    tampered = body[:-1] + ("A" if body[-1] != "A" else "B") + "." + sig

    try:
        verify_license(secret, tampered)
        assert False, "Expected signature validation to fail"
    except LicenseError as exc:
        assert "Signature mismatch" in str(exc)


def test_expired_license_fails():
    secret = "top-secret"
    expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    token = generate_license(secret, customer="Acme", product="secure-app", expires=expired)

    try:
        verify_license(secret, token)
        assert False, "Expected expiration check to fail"
    except LicenseError as exc:
        assert "expired" in str(exc).lower()
