import os
import pytest
from cryptography.fernet import Fernet
from api.crypto import (
    agent_secret_fingerprint, decrypt_ip, decrypt_value,
    encrypt_ip, encrypt_value, hash_ip,
)

@pytest.fixture(autouse=True)
def setup_env():
    # Provide a valid test key
    test_key = Fernet.generate_key().decode()
    os.environ["ENCRYPTION_KEY"] = test_key
    
    # reset global state
    import api.crypto
    api.crypto._fernet = None
    
    yield
    
    # teardown
    api.crypto._fernet = None

def test_encrypt_decrypt_ip():
    ip = "1.2.3.4"
    encrypted = encrypt_ip(ip)
    
    assert encrypted != ip
    assert type(encrypted) == str
    
    decrypted = decrypt_ip(encrypted)
    assert decrypted == ip

def test_hash_ip():
    ip = "1.2.3.4"
    hashed = hash_ip(ip)
    # sha256 of 1.2.3.4
    assert hashed == "6694f83c9f476da31f5df6bcc520034e7e57d421d247b9d34f49edbfc84a764c"


def test_encrypt_decrypt_agent_secret():
    secret = "relay-control-secret"
    encrypted = encrypt_value(secret)

    assert encrypted != secret
    assert decrypt_value(encrypted) == secret
    assert agent_secret_fingerprint(secret) == "1e48fa53e210"

    from api.database import _decrypt_relay
    relay = _decrypt_relay({"id": 1, "agent_secret": "", "agent_secret_enc": encrypted})
    assert relay["agent_secret"] == secret
    assert "agent_secret_enc" not in relay

def test_decrypt_error_on_invalid_key():
    ip = "192.168.1.1"
    encrypted = encrypt_ip(ip)
    
    # change key
    os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    import api.crypto
    api.crypto._fernet = None
    
    with pytest.raises(Exception):
        decrypt_ip(encrypted)
