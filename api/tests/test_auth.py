import os
import pytest
from fastapi import HTTPException
from api.index import require_api_key

def test_require_api_key_success():
    os.environ["API_KEY"] = "my_secret_key"
    # Should not raise any exception
    require_api_key("my_secret_key")

def test_require_api_key_invalid():
    os.environ["API_KEY"] = "my_secret_key"
    with pytest.raises(HTTPException) as exc:
        require_api_key("wrong_key")
    assert exc.value.status_code == 403
    assert exc.value.detail == "Invalid API key"

def test_require_api_key_empty_server_key():
    # When the server is not configured with an API_KEY
    os.environ["API_KEY"] = ""
    
    # Requesting with an empty key should fail
    with pytest.raises(HTTPException) as exc:
        require_api_key("")
    assert exc.value.status_code == 403

    # Requesting with any key should fail
    with pytest.raises(HTTPException) as exc:
        require_api_key("some_key")
    assert exc.value.status_code == 403
