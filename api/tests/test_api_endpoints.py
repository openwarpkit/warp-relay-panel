import os
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from api.index import app

@pytest.fixture(autouse=True)
def setup_env():
    os.environ["API_KEY"] = "test_key"
    os.environ["ENCRYPTION_KEY"] = "dGVzdF9rZXlfdGVzdF9rZXlfdGVzdF9rZXlfdGVzdF8=" # Valid fernet key (must be 32 url-safe base64)
    os.environ["SUPABASE_URL"] = "http://localhost"
    os.environ["SUPABASE_KEY"] = "dummy.dummy.dummy"
    yield

@pytest.fixture
def client():
    return TestClient(app)

def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

@patch("api.index.create_client_record")
def test_create_client(mock_create, client):
    mock_create.return_value = {"id": 1, "token": "test_token"}
    
    response = client.post(
        "/api/clients",
        headers={"X-API-Key": "test_key"},
        json={"label": "test_user"}
    )
    
    assert response.status_code == 200
    assert response.json()["token"] == "test_token"

@patch("api.index.get_active_relays", return_value=[])
@patch("api.index.get_client_by_token")
def test_activate_client_banned_bot(mock_get, mock_relays, client):
    # Test bot rejection
    response = client.get(
        "/activate/some_token",
        headers={"User-Agent": "TelegramBot"}
    )
    assert response.status_code == 200
    assert "og:title" in response.text # Bot returns html with og-tags

@patch("api.index.relay_client.remove_ip")
@patch("api.index.add_ip_ban")
def test_add_blacklist(mock_ban, mock_remove, client):
    mock_ban.return_value = {"id": 1, "ip": "1.2.3.4", "reason": "test"}
    
    response = client.post(
        "/api/blacklist",
        headers={"X-API-Key": "test_key"},
        json={"ip": "1.2.3.4", "reason": "test"}
    )
    assert response.status_code == 200
    assert response.json()["ip"] == "1.2.3.4"
