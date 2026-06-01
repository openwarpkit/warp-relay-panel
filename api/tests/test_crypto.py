import os
import pytest
from cryptography.fernet import Fernet
from api.crypto import encrypt_ip, decrypt_ip, hash_ip

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

def test_decrypt_error_on_invalid_key():
    ip = "192.168.1.1"
    encrypted = encrypt_ip(ip)
    
    # change key
    os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    import api.crypto
    api.crypto._fernet = None
    
    with pytest.raises(Exception):
        decrypt_ip(encrypted)
