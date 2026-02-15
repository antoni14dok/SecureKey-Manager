import hashlib
import uuid
import datetime

SECRET_SALT = "MySecretSalt123"

def generate_license(user_name, days_valid=30):
    expire_date = datetime.datetime.now() + datetime.timedelta(days=days_valid)
    raw_string = f"{user_name}{expire_date}{SECRET_SALT}"
    license_hash = hashlib.sha256(raw_string.encode()).hexdigest()
    return f"{license_hash[:16]}-{license_hash[16:32]}"

def validate_license(user_name, license_key, expire_date):
    raw_string = f"{user_name}{expire_date}{SECRET_SALT}"
    expected_hash = hashlib.sha256(raw_string.encode()).hexdigest()
    expected_key = f"{expected_hash[:16]}-{expected_hash[16:32]}"
    return expected_key == license_key


# Пример использования
user = "Anton"
license_key = generate_license(user)
print("Generated license:", license_key)