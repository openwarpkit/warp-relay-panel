import asyncio

import httpx
import pytest
import pytest_asyncio

from api import relay_client as rc


@pytest_asyncio.fixture
async def client_state(monkeypatch):
    clients = []

    def new_client():
        client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
        clients.append(client)
        return client

    async def respond(request):
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr(rc, "_new_client", new_client)
    monkeypatch.setattr(rc, "_http_client", None)
    monkeypatch.setattr(rc, "_client_lock", asyncio.Lock())
    monkeypatch.setattr(rc, "_client_requests", {}, raising=False)
    monkeypatch.setattr(rc, "_consecutive_timeouts", 0)
    yield clients
    for client in clients:
        await client.aclose()


def relay(name):
    return {"name": name, "host": "8.8.8.8", "agent_port": 7580}


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [httpx.PoolTimeout, httpx.ReadTimeout])
async def test_recycle_preserves_inflight_http_request(client_state, monkeypatch, failure):
    started = asyncio.Event()
    resume = asyncio.Event()
    finished = asyncio.Event()

    async def handle(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            started.set()
            await resume.wait()
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{"ok":true}')
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            finished.set()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    class LocalTransport(httpx.AsyncHTTPTransport):
        async def handle_async_request(self, request):
            request.url = request.url.copy_with(host="127.0.0.1", port=port)
            return await super().handle_async_request(request)

    old = httpx.AsyncClient(transport=LocalTransport())
    client_state.append(old)
    monkeypatch.setattr(rc, "_http_client", old)
    monkeypatch.setattr(rc, "_RECYCLE_AFTER", 1)
    request = asyncio.create_task(rc._agent_request(relay("healthy"), "GET", "/health"))
    try:
        await asyncio.wait_for(started.wait(), 2)
        original_request = old.request

        async def fail(*args, **kwargs):
            raise failure("timeout")

        monkeypatch.setattr(old, "request", fail)
        ok, data = await rc._agent_request(relay("unreachable"), "GET", "/health")
        monkeypatch.setattr(old, "request", original_request)
        assert not ok
        assert "timeout" in data["error"]
        assert rc._http_client is not old
        assert not old.is_closed
        ok, _ = await rc._agent_request(relay("new-client"), "GET", "/health")
        assert ok
        resume.set()
        assert await asyncio.wait_for(request, 2) == (True, {"ok": True})
        assert old.is_closed
        assert not rc._client_requests
    finally:
        resume.set()
        await asyncio.gather(request, return_exceptions=True)
        await asyncio.wait_for(finished.wait(), 2)
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["success", "timeout", "cancel"])
async def test_retired_request_does_not_change_current_generation(client_state, monkeypatch, outcome):
    started = asyncio.Event()
    resume = asyncio.Event()

    async def respond(request):
        started.set()
        await resume.wait()
        if outcome == "timeout":
            raise httpx.ReadTimeout("timeout")
        return httpx.Response(200, json={"ok": True})

    old = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    client_state.append(old)
    monkeypatch.setattr(rc, "_http_client", old)
    monkeypatch.setattr(rc, "_RECYCLE_AFTER", 2)
    task = asyncio.create_task(rc._agent_request(relay("old-client"), "GET", "/health"))
    try:
        await asyncio.wait_for(started.wait(), 2)
        await rc._recycle_client(old)
        current = rc._http_client
        rc._consecutive_timeouts = 1
        if outcome == "cancel":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            resume.set()
            await asyncio.wait_for(task, 2)
        assert rc._http_client is current
        assert rc._consecutive_timeouts == 1
        assert old.is_closed
        assert not rc._client_requests
    finally:
        resume.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_retired_client_closes_after_last_request(client_state, monkeypatch):
    started = {path: asyncio.Event() for path in ("/one", "/two")}
    resume = {path: asyncio.Event() for path in started}

    async def respond(request):
        path = request.url.path
        started[path].set()
        await resume[path].wait()
        return httpx.Response(200, json={"ok": True})

    old = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    client_state.append(old)
    monkeypatch.setattr(rc, "_http_client", old)
    tasks = {
        path: asyncio.create_task(rc._agent_request(relay(path), "GET", path))
        for path in started
    }
    try:
        for event in started.values():
            await asyncio.wait_for(event.wait(), 2)
        await rc._recycle_client(old)
        current = rc._http_client
        await rc._recycle_client(old)
        assert rc._http_client is current
        resume["/one"].set()
        assert await asyncio.wait_for(tasks["/one"], 2) == (True, {"ok": True})
        assert not old.is_closed
        resume["/two"].set()
        assert await asyncio.wait_for(tasks["/two"], 2) == (True, {"ok": True})
        assert old.is_closed
        assert not rc._client_requests
    finally:
        for event in resume.values():
            event.set()
        await asyncio.gather(*tasks.values(), return_exceptions=True)
