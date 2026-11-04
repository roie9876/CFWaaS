import json
import time
from types import SimpleNamespace
from unittest.mock import Mock, call
from urllib.parse import urlsplit

import pytest
from azure.core.exceptions import HttpResponseError

from service.checkpoint_prerequisites import (
    REQUIRED_PROVIDERS, CheckpointPrerequisiteError, CheckpointProviderRegistration,
)
from service.store import LostLease

SUBSCRIPTION = "00000000-0000-0000-0000-000000000001"


@pytest.fixture
def provider_check(monkeypatch):
    client = Mock()
    client.providers.get.side_effect = lambda name: SimpleNamespace(
        namespace=name, registration_state="Registered")
    factory = Mock(return_value=client)
    monkeypatch.setattr("service.checkpoint_prerequisites.ResourceManagementClient", factory)
    return CheckpointProviderRegistration(SUBSCRIPTION, Mock()), client, factory


def test_registration_preflight_is_read_only_and_subscription_bound(provider_check):
    preflight, client, factory = provider_check
    check = Mock()
    preflight.verify(check)
    assert client.providers.get.call_args_list == [call(name) for name in REQUIRED_PROVIDERS]
    assert check.call_count == len(REQUIRED_PROVIDERS) + 1
    assert factory.call_args.args[1] == SUBSCRIPTION
    assert factory.call_args.kwargs["logging_enable"] is False
    client.providers.register.assert_not_called()
    preflight.close()
    client.close.assert_called_once_with()


@pytest.mark.parametrize("state", ["NotRegistered", "Registering", "Unregistering"])
def test_registration_preflight_reports_unregistered_provider_without_changing_it(provider_check, state):
    preflight, client, _ = provider_check
    client.providers.get.side_effect = lambda name: SimpleNamespace(namespace=name, registration_state=state)
    with pytest.raises(CheckpointPrerequisiteError) as error:
        preflight.verify(lambda: None)
    assert error.value.code == "ProviderNotRegistered"
    assert error.value.provider == REQUIRED_PROVIDERS[0]
    client.providers.register.assert_not_called()


@pytest.mark.parametrize("response", [
    None, SimpleNamespace(namespace="foreign", registration_state="Registered"),
    SimpleNamespace(namespace="Microsoft.Compute", registration_state=None),
])
def test_registration_preflight_rejects_malformed_results(provider_check, response):
    preflight, client, _ = provider_check
    client.providers.get.side_effect = None
    client.providers.get.return_value = response
    with pytest.raises(CheckpointPrerequisiteError) as error:
        preflight.verify(lambda: None)
    assert error.value.code == "ProviderRegistrationInvalid"
    client.providers.register.assert_not_called()


def test_registration_preflight_redacts_azure_errors(provider_check):
    preflight, client, _ = provider_check
    client.providers.get.side_effect = HttpResponseError("PRIVATE-VALUE")
    with pytest.raises(CheckpointPrerequisiteError) as error:
        preflight.verify(lambda: None)
    assert error.value.code == "ProviderRegistrationUnavailable"
    assert "PRIVATE-VALUE" not in str(error.value)
    client.providers.register.assert_not_called()


def test_registration_preflight_stops_after_lease_loss(provider_check):
    preflight, client, _ = provider_check
    with pytest.raises(LostLease):
        preflight.verify(Mock(side_effect=[None, LostLease()]))
    assert client.providers.get.call_count == 1
    client.providers.register.assert_not_called()


def test_registration_preflight_rejects_invalid_subscription(monkeypatch):
    factory = Mock()
    monkeypatch.setattr("service.checkpoint_prerequisites.ResourceManagementClient", factory)
    with pytest.raises(ValueError):
        CheckpointProviderRegistration("PRIVATE-VALUE", Mock())
    factory.assert_not_called()


def test_registration_preflight_uses_actual_arm_sdk_response_shape(monkeypatch):
    from azure.core.credentials import AccessToken
    from azure.core.pipeline.transport import HttpResponse, HttpTransport
    from azure.mgmt.resource import ResourceManagementClient

    class Response(HttpResponse):
        def __init__(self, request):
            super().__init__(request, None)
            self.status_code = 200
            self.headers = {"Content-Type": "application/json"}
            self.content_type = "application/json"
            self.namespace = urlsplit(request.url).path.rsplit("/", 1)[-1]

        def body(self):
            return json.dumps({"namespace": self.namespace, "registrationState": "Registered"}).encode()

    class Transport(HttpTransport):
        def __init__(self):
            self.requests = []

        def open(self):
            pass

        def close(self):
            pass

        def __exit__(self, *args):
            self.close()

        def send(self, request, **kwargs):
            self.requests.append((request.method, urlsplit(request.url).path))
            return Response(request)

    transport = Transport()
    credential = Mock(spec=["get_token"])
    credential.get_token.return_value = AccessToken("fixture-token", int(time.time()) + 3600)
    def factory(identity, subscription, **kwargs):
        return ResourceManagementClient(identity, subscription, transport=transport, **kwargs)
    monkeypatch.setattr("service.checkpoint_prerequisites.ResourceManagementClient", factory)
    preflight = CheckpointProviderRegistration(SUBSCRIPTION, credential)
    try:
        preflight.verify(lambda: None)
        assert len(transport.requests) == len(REQUIRED_PROVIDERS)
        assert all(method == "GET" and path.startswith(f"/subscriptions/{SUBSCRIPTION}/providers/")
                   for method, path in transport.requests)
    finally:
        preflight.close()
