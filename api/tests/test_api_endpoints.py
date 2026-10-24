import os
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
from api.index import app

@pytest.fixture(autouse=True)
def setup_env():
    os.environ["API_KEY"] = "test_key"
    os.environ["ENCRYPTION_KEY"] = "dGVzdF9rZXlfdGVzdF9rZXlfdGVzdF9rZXlfdGVzdF8=" # Valid fernet key (must be 32 url-safe base64)
    os.environ["DATABASE_URL"] = "postgresql://test:test@127.0.0.1:5432/test"
    yield

@pytest.fixture
def client():
    return TestClient(app)

def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@patch("api.index.relay_client.reset_traffic_all_relays", new_callable=AsyncMock)
def test_reset_traffic_ip_requires_api_key(mock_reset, client):
    response = client.post("/api/traffic/203.0.113.7/reset", headers={"X-API-Key": "wrong"})
    assert response.status_code == 403
    mock_reset.assert_not_awaited()


@patch("api.index.relay_client.reset_traffic_all_relays", new_callable=AsyncMock)
def test_reset_traffic_ip_returns_per_relay_results(mock_reset, client):
    mock_reset.return_value = {"r1": {"ok": True, "reset": True}, "r2": {"ok": False, "error": "timeout"}}
    response = client.post("/api/traffic/203.0.113.7/reset", headers={"X-API-Key": "test_key"})
    assert response.status_code == 200
    assert response.json() == mock_reset.return_value
    mock_reset.assert_awaited_once_with("203.0.113.7")


@pytest.mark.parametrize("ip", ["invalid", "::1", "999.1.2.3"])
@patch("api.index.relay_client.reset_traffic_all_relays", new_callable=AsyncMock)
def test_reset_traffic_ip_rejects_invalid_address(mock_reset, ip, client):
    response = client.post(f"/api/traffic/{ip}/reset", headers={"X-API-Key": "test_key"})
    assert response.status_code == 400
    mock_reset.assert_not_awaited()

@patch("api.index.get_sync_payload", new_callable=AsyncMock)
def test_whitelist_payload_is_compressed(mock_payload, client):
    mock_payload.return_value = {
        "clients": [
            {"ip": f"198.51.100.{index % 250 + 1}", "client_id": index}
            for index in range(1000)
        ],
        "rate_limits": [],
    }
    response = client.get(
        "/api/relays/1/whitelist-payload",
        headers={"X-API-Key": "test_key", "Accept-Encoding": "gzip"},
    )
    assert response.status_code == 200
    assert response.headers["content-encoding"] == "gzip"
    assert len(response.json()["clients"]) == 1000

@patch("api.index.create_client_record", new_callable=AsyncMock)
def test_create_client(mock_create, client):
    mock_create.return_value = {"id": 1, "token": "test_token"}

    response = client.post(
        "/api/clients",
        headers={"X-API-Key": "test_key"},
        json={"label": "test_user"}
    )

    assert response.status_code == 200
    assert response.json()["token"] == "test_token"

@patch("api.index.get_active_relays", new_callable=AsyncMock, return_value=[])
@patch("api.index.get_client_by_token", new_callable=AsyncMock)
def test_activate_client_banned_bot(mock_get, mock_relays, client):
    # Test bot rejection
    response = client.get(
        "/activate/some_token",
        headers={"User-Agent": "TelegramBot"}
    )
    assert response.status_code == 200
    assert "og:title" in response.text # Bot returns html with og-tags

@patch("api.index.relay_client.remove_ip", new_callable=AsyncMock)
@patch("api.index.add_ip_ban", new_callable=AsyncMock)
def test_add_blacklist(mock_ban, mock_remove, client):
    mock_ban.return_value = {"id": 1, "ip": "1.2.3.4", "reason": "test"}

    response = client.post(
        "/api/blacklist",
        headers={"X-API-Key": "test_key"},
        json={"ip": "1.2.3.4", "reason": "test"}
    )
    assert response.status_code == 200
    assert response.json()["ip"] == "1.2.3.4"
