import pytest
import respx
import httpx
from unittest.mock import patch
import api.relay_client as rc
from api.relay_client import add_ip, remove_ip, full_sync, get_traffic_all_relays

@pytest.fixture
def mock_db_relays():
    with patch("api.database.get_active_relays") as m1, patch("api.database.list_relays") as m2:
        relays = [{"id": 1, "host": "1.2.3.4", "agent_port": 7580, "agent_secret": "sec", "name": "r1", "agent_type": "full"}]
        m1.return_value = relays
        m2.return_value = relays
        yield m1

@pytest.fixture
def mock_db_mark():
    with patch("api.database.mark_relay_synced") as m:
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
@patch("api.database.get_sync_payload",
       return_value={"clients": [{"ip": "10.0.0.1", "client_id": 1}], "rate_limits": []})
async def test_full_sync(m_payload, mock_db_relays, mock_db_mark):
    respx.post("http://1.2.3.4:7580/whitelist/sync").mock(
        return_value=httpx.Response(200, json={"ok": True, "accepted": True, "received": 1})
    )
    result = await full_sync(relay_id=1)
    assert result["total_clients"] == 1
    assert result["relays"]["r1"]["ok"] is True
    assert result["relays"]["r1"]["accepted"] is True

@pytest.mark.asyncio
@respx.mock
async def test_get_traffic_all_relays():
    with patch("api.database.get_active_relays") as m:
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
async def test_get_relay_traffic_min_skips_agent():
    from api.relay_client import get_relay_traffic
    relay = {"id": 3, "host": "9.9.9.9", "agent_port": 7580,
             "agent_secret": "s", "name": "mr", "agent_type": "min"}
    # No respx route registered: any HTTP attempt would raise. The short-circuit must not call the agent.
    result = await get_relay_traffic(relay)
    assert result["ok"] is True
    assert result["skipped"] == "min"
    assert result["ips"] == {}
    assert result["ip_count"] == 0


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
