# SecureKey-Manager

SecureKey Manager is a lightweight and secure license key generation tool for **your own software products**.

> This project is for legitimate licensing workflows only. It does **not** generate keys for third-party software.

## Features
- Generate HMAC-SHA256 signed license tokens.
- Verify authenticity and expiration.
- Simple CLI with no external dependencies.

## Usage

### Generate
```bash
python3 license_manager.py generate \
  --secret "change-me" \
  --customer "Acme Inc" \
  --product "secure-app" \
  --expires "2027-01-01T00:00:00Z"
```

### Verify
```bash
python3 license_manager.py verify \
  --secret "change-me" \
  --token "<TOKEN_FROM_GENERATE>"
```

## Run tests
```bash
python3 -m pytest -q
```
