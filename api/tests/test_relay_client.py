import pytest
import respx
import httpx
from unittest.mock import patch, AsyncMock
import api.relay_client as rc
from api.relay_client import (
    _state_hashes, add_ip, remove_ip, full_sync,
    get_traffic_all_relays, reconcile_full_relays,
)

@pytest.fixture
def mock_db_relays():
    relays = [{"id": 1, "host": "1.2.3.4", "agent_port": 7580, "agent_secret": "sec", "name": "r1", "agent_type": "full"}]
    with patch("api.database.get_active_relays", new_callable=AsyncMock) as m1, \
         patch("api.database.list_relays", new_callable=AsyncMock) as m2:
        m1.return_value = relays
        m2.return_value = relays
        yield m1

@pytest.fixture
def mock_db_mark():
    with patch("api.database.mark_relay_synced", new_callable=AsyncMock) as m:
        yield m

@pytest.mark.asyncio
@respx.mock
async def test_add_ip_success(mock_db_relays, mock_db_mark):
    respx.post("http://1.2.3.4:7580/whitelist/update").mock(
        return_value=httpx.Response(200, json={"ok": True, "added": "10.0.0.1"})
    )
    result = await add_ip("10.0.0.1", "10.0.0.2", 1)

    assert "r1" in result
    assert result["r1"]["ok"] is True
    assert result["r1"]["added"] == "10.0.0.1"
    mock_db_mark.assert_called_once_with(1, True)

@pytest.mark.asyncio
@respx.mock
async def test_add_ip_timeout(mock_db_relays, mock_db_mark):
    respx.post("http://1.2.3.4:7580/whitelist/update").mock(
        side_effect=httpx.TimeoutException("Timeout")
    )
    result = await add_ip("10.0.0.1", "10.0.0.2", 1)
    assert result["r1"]["ok"] is False
    assert "timeout" in result["r1"]["error"]

@pytest.mark.asyncio
@respx.mock
async def test_remove_ip(mock_db_relays, mock_db_mark):
    respx.post("http://1.2.3.4:7580/whitelist/remove").mock(
        return_value=httpx.Response(200, json={"ok": True, "removed": "10.0.0.1"})
    )
    result = await remove_ip("10.0.0.1")
    assert result["r1"]["ok"] is True
    assert result["r1"]["removed"] == "10.0.0.1"

@pytest.mark.asyncio
@respx.mock
@patch("api.database.get_sync_payload", new_callable=AsyncMock)
async def test_full_sync(m_payload, mock_db_relays, mock_db_mark):
    m_payload.return_value = {"clients": [{"ip": "10.0.0.1", "client_id": 1}], "rate_limits": []}
    respx.post("http://1.2.3.4:7580/whitelist/sync").mock(
        return_value=httpx.Response(200, json={"ok": True, "accepted": True, "received": 1})
    )
    result = await full_sync(relay_id=1)
    assert result["total_clients"] == 1
    assert result["relays"]["r1"]["ok"] is True
    assert result["relays"]["r1"]["accepted"] is True


def test_state_hashes_match_agent_format():
    state_hash, whitelist_hash = _state_hashes({
        "clients": [
            {"ip": "203.0.113.2", "client_id": 8},
            {"ip": "203.0.113.2", "client_id": 7},
            {"ip": "203.0.113.1", "client_id": 3},
        ],
        "rate_limits": [
            {"ip": "203.0.113.2", "mbps": 5, "expires_at": None, "client_id": 7},
        ],
    })
    assert state_hash == "c20e72f5cbc44e49acd5f50f249d1fc22bd7608be22c911c867a932de5c580cd"
    assert whitelist_hash == "22819dc99b331ec12e7d48f36347489718292e838f9e709ad78f7011f2b2f744"


@pytest.mark.asyncio
@respx.mock
@patch("api.database.get_sync_payload", new_callable=AsyncMock)
async def test_reconcile_skips_matching_state(m_payload, mock_db_relays, mock_db_mark):
    payload = {"clients": [{"ip": "10.0.0.1", "client_id": 1}], "rate_limits": []}
    m_payload.return_value = payload
    state_hash, whitelist_hash = _state_hashes(payload)
    respx.get("http://1.2.3.4:7580/state").mock(return_value=httpx.Response(200, json={
        "ok": True, "state_hash": state_hash, "whitelist_hash": whitelist_hash,
    }))

    result = await reconcile_full_relays()

    assert result["relays"]["r1"]["ok"] is True
    assert result["relays"]["r1"]["changed"] is False
    mock_db_mark.assert_called_once_with(1, True)


@pytest.mark.asyncio
@respx.mock
@patch("api.database.get_sync_payload", new_callable=AsyncMock)
async def test_reconcile_repairs_drift(m_payload, mock_db_relays, mock_db_mark):
    payload = {"clients": [{"ip": "10.0.0.1", "client_id": 1}], "rate_limits": []}
    m_payload.return_value = payload
    state_hash, whitelist_hash = _state_hashes(payload)
    respx.get("http://1.2.3.4:7580/state").mock(return_value=httpx.Response(200, json={
        "ok": True, "state_hash": "stale", "whitelist_hash": "stale",
    }))
    respx.post("http://1.2.3.4:7580/whitelist/sync").mock(return_value=httpx.Response(200, json={
        "ok": True, "state_hash": state_hash, "whitelist_hash": whitelist_hash,
    }))

    result = await reconcile_full_relays()

    assert result["relays"]["r1"]["ok"] is True
    assert result["relays"]["r1"]["changed"] is True
    mock_db_mark.assert_called_once_with(1, True)

@pytest.mark.asyncio
@respx.mock
async def test_get_traffic_all_relays():
    with patch("api.database.get_active_relays", new_callable=AsyncMock) as m:
        m.return_value = [
            {"id": 1, "host": "1.2.3.4", "agent_port": 7580, "agent_secret": "s1", "name": "r1"},
            {"id": 2, "host": "2.3.4.5", "agent_port": 7580, "agent_secret": "s2", "name": "r2"}
        ]

        respx.get("http://1.2.3.4:7580/traffic").mock(
            return_value=httpx.Response(200, json={"ips": {"10.0.0.1": {"tx_bytes": 100, "rx_bytes": 200}}})
        )
        respx.get("http://2.3.4.5:7580/traffic").mock(
            side_effect=httpx.ConnectError("Connection Refused")
        )

        result = await get_traffic_all_relays()

        assert "r1" in result
        assert result["r1"]["ips"]["10.0.0.1"]["tx_bytes"] == 100
        assert "r2" in result
        assert result["r2"]["ok"] is False


@pytest.mark.asyncio
@respx.mock
async def test_get_relay_traffic_min_returns_totals():
    from api.relay_client import get_relay_traffic
    relay = {"id": 3, "host": "9.9.9.9", "agent_port": 7580,
             "agent_secret": "s", "name": "mr", "agent_type": "min"}
    respx.get("http://9.9.9.9:7580/traffic").mock(
        return_value=httpx.Response(200, json={
            "ips": {}, "ip_count": 0,
            "total_bytes": 123456, "total": "120.6 KB",
            "total_tx": "60 KB", "total_rx": "60.6 KB"})
    )
    result = await get_relay_traffic(relay)
    assert result["ok"] is True
    assert result["ips"] == {}
    assert result["ip_count"] == 0
    assert result["total_bytes"] == 123456
    assert result["total"] == "120.6 KB"


@pytest.mark.asyncio
@respx.mock
async def test_pool_timeout_recycles_client(mock_db_relays, mock_db_mark):
    rc._consecutive_timeouts = 0
    before = await rc._get_client()
    respx.post("http://1.2.3.4:7580/whitelist/update").mock(
        side_effect=httpx.PoolTimeout("pool exhausted")
    )
    result = await add_ip("10.0.0.1", "10.0.0.2", 1)
    assert result["r1"]["ok"] is False
    assert "timeout" in result["r1"]["error"]
    assert rc._http_client is not before


@pytest.mark.asyncio
@respx.mock
async def test_consecutive_timeouts_recycle(mock_db_relays, mock_db_mark, monkeypatch):
    monkeypatch.setattr(rc, "_RECYCLE_AFTER", 2)
    rc._consecutive_timeouts = 0
    before = await rc._get_client()
    respx.post("http://1.2.3.4:7580/whitelist/update").mock(
        side_effect=httpx.ReadTimeout("read")
    )
    await add_ip("10.0.0.1", None, 1)
    assert rc._http_client is before
    await add_ip("10.0.0.1", None, 1)
    assert rc._http_client is not before


@pytest.mark.asyncio
@respx.mock
async def test_success_resets_timeout_counter(mock_db_relays, mock_db_mark):
    rc._consecutive_timeouts = 5
    respx.post("http://1.2.3.4:7580/whitelist/update").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    await add_ip("10.0.0.1", None, 1)
    assert rc._consecutive_timeouts == 0
