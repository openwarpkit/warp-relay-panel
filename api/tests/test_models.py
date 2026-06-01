import pytest
from pydantic import ValidationError
from api.index import RelayCreate

def test_relay_create_defaults():
    relay = RelayCreate(name="Test", host="1.2.3.4")
    assert relay.name == "Test"
    assert relay.host == "1.2.3.4"
    assert relay.agent_port == 7580
    assert relay.agent_secret == ""
    assert relay.agent_type == "full"

def test_relay_create_custom_agent_type():
    relay = RelayCreate(name="Min-Relay", host="1.1.1.1", agent_type="min")
    assert relay.agent_type == "min"

def test_relay_create_invalid():
    with pytest.raises(ValidationError):
        RelayCreate(name="Test") # missing host
