import pytest
from pytest_httpx import HTTPXMock
from phantompilot.adapters.rest import RESTAdapter
from phantompilot.adapters.base import AdapterConnectionError

@pytest.fixture
def adapter(): return RESTAdapter(base_url="https://agent.test", auth_type="bearer", auth_value="tok", endpoints={"send_message": "/chat", "get_state": "/state", "get_memory": "/memory", "health": "/health"})

class TestSend:
    @pytest.mark.asyncio
    async def test_ok(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://agent.test/chat", json={"response": "Hello!", "tool_calls": []})
        r = await adapter.send_message("Hi"); assert r.content == "Hello!"
    @pytest.mark.asyncio
    async def test_tools(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://agent.test/chat", json={"response": "Found.", "tool_calls": [{"name": "search", "arguments": {"q": "t"}, "result": "d"}]})
        assert len((await adapter.send_message("Find")).tool_calls) == 1
    @pytest.mark.asyncio
    async def test_500(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://agent.test/chat", status_code=500, text="Error")
        with pytest.raises(AdapterConnectionError): await adapter.send_message("Hi")

class TestHealth:
    @pytest.mark.asyncio
    async def test_ok(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://agent.test/health", json={"ok": True}); assert await adapter.health_check() is True
    @pytest.mark.asyncio
    async def test_fail(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://agent.test/health", status_code=503); assert await adapter.health_check() is False

class TestAuth:
    @pytest.mark.asyncio
    async def test_bearer(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://agent.test/health", json={}); await adapter.health_check()
        assert httpx_mock.get_request().headers["authorization"] == "Bearer tok"
    @pytest.mark.asyncio
    async def test_apikey(self, httpx_mock: HTTPXMock):
        a = RESTAdapter(base_url="https://agent.test", auth_type="api_key", auth_value="k")
        httpx_mock.add_response(url="https://agent.test/health", json={}); await a.health_check()
        assert httpx_mock.get_request().headers["x-api-key"] == "k"

class TestState:
    @pytest.mark.asyncio
    async def test_ok(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://agent.test/state", json={"tools": [{"name": "search"}], "system_prompt": "Be helpful.", "model": "gpt"})
        assert "search" in (await adapter.get_agent_state()).available_tools
