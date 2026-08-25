import hashlib
import os
from cryptography.fernet import Fernet

_fernet = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        key = os.environ["ENCRYPTION_KEY"]
        _fernet = Fernet(key.encode())
    return _fernet


def encrypt_ip(ip: str) -> str:
    return encrypt_value(ip)


def decrypt_ip(encrypted: str) -> str:
    return decrypt_value(encrypted)


def hash_ip(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()


def encrypt_value(value: str) -> str:
    return _get_fernet().encrypt(value.encode()).decode()


def decrypt_value(encrypted: str) -> str:
    return _get_fernet().decrypt(encrypted.encode()).decode()


def agent_secret_fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()[:12]
