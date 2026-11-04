import time
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from service.provider_bootstrap import BootstrapError
from service.provider_bootstrap_auth import GRAPH_SCOPES
from service.provider_device_auth import DevicePending, ProviderDeviceAuth


def uid(number):
    return str(UUID(int=number))


TENANT, CLIENT, ADMIN = uid(1), uid(2), uid(3)
TOKEN = "fixture-" + uuid4().hex


class OAuth:
    def __init__(self, signing, claims=None, scopes=None):
        self.signing, self.claims = signing, claims or {}
        self.scopes = scopes if scopes is not None else list(GRAPH_SCOPES)
        self.pending = False
        self.polls = 0
        self.url = "https://microsoft.com/devicelogin"

    def initiate_device_flow(self, scopes):
        assert scopes == list(GRAPH_SCOPES)
        return {"verification_uri": self.url, "user_code": "ABCDEFGH",
                "device_code": "fixture-device-code", "expires_in": 900, "interval": 5}

    def acquire_token_by_device_flow(self, flow, **kwargs):
        self.polls += 1
        assert kwargs["exit_condition"](flow)
        if self.pending:
            return {"error": "authorization_pending"}
        now = int(time.time())
        claims = {"iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
                  "aud": CLIENT, "tid": TENANT, "oid": ADMIN,
                  "exp": now + 300, "nbf": now - 1, "iat": now - 1}
        claims.update(self.claims)
        return {"id_token": jwt.encode(claims, self.signing, algorithm="RS256", headers={"kid": "unit"}),
                "access_token": TOKEN, "scope": self.scopes}


@pytest.fixture(scope="module")
def signing():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, SimpleNamespace(get=lambda kid: SimpleNamespace(key=private.public_key()))


@pytest.fixture
def auth(signing):
    client = OAuth(signing[0])
    return ProviderDeviceAuth(TENANT, CLIENT, lambda: client, signing[1]), client


def test_device_signin_is_scoped_single_use_and_secret_safe(auth):
    broker, client = auth
    challenge = broker.begin()
    assert challenge.verification_uri == "https://microsoft.com/devicelogin"
    assert challenge.user_code == "ABCDEFGH"
    assert challenge.user_code not in repr(challenge)
    assert challenge.session_id not in repr(challenge)
    result = broker.poll(challenge.session_id)
    assert result.object_id == ADMIN and result.tenant_id == TENANT
    assert TOKEN not in repr(result)
    with pytest.raises(BootstrapError) as error:
        broker.poll(challenge.session_id)
    assert error.value.code == "BootstrapSignInExpired"


@pytest.mark.parametrize("url", [
    "https://microsoft.com/devicelogin",
    "https://login.microsoft.com/device",
])
def test_microsoft_device_verification_urls_are_accepted(auth, url):
    broker, client = auth
    client.url = url
    assert broker.begin().verification_uri == url


@pytest.mark.parametrize("url", [
    "http://login.microsoft.com/device",
    "https://login.microsoft.com/device?redirect=https://attacker.example",
    "https://login.microsoft.com/device#fragment",
    "https://login.microsoft.com.attacker.example/device",
    "https://attacker.example" + "@" + "group.login.microsoft.com/device",
    "https://login.microsoft.com:444/device",
    "https://login.microsoft.com/devicelogin",
])
def test_other_device_verification_urls_are_rejected(auth, url):
    broker, client = auth
    client.url = url
    with pytest.raises(BootstrapError) as error:
        broker.begin()
    assert error.value.code == "BootstrapSignInUnavailable"


def test_pending_is_explicit_rate_limited_and_only_polls_once(auth):
    broker, client = auth
    client.pending = True
    challenge = broker.begin()
    assert broker.poll(challenge.session_id) == DevicePending(5)
    assert isinstance(broker.poll(challenge.session_id), DevicePending)
    assert client.polls == 1


@pytest.mark.parametrize("claims", [
    {"tid": uid(4)}, {"oid": uid(0)}, {"aud": uid(4)},
    {"iss": "https://issuer.example"}, {"exp": 1}, {"idtyp": "app"},
])
def test_invalid_identity_is_not_accepted(signing, claims):
    client = OAuth(signing[0], claims=claims)
    broker = ProviderDeviceAuth(TENANT, CLIENT, lambda: client, signing[1])
    challenge = broker.begin()
    with pytest.raises(BootstrapError):
        broker.poll(challenge.session_id)


def test_missing_permissions_and_untrusted_verification_url_fail_closed(signing):
    client = OAuth(signing[0], scopes=["User.Read"])
    broker = ProviderDeviceAuth(TENANT, CLIENT, lambda: client, signing[1])
    with pytest.raises(BootstrapError):
        broker.poll(broker.begin().session_id)
    client.url = "https://attacker.example/devicelogin"
    with pytest.raises(BootstrapError):
        broker.begin()


def test_expired_session_is_removed(auth):
    broker, client = auth
    challenge = broker.begin()
    with patch("service.provider_device_auth.time.monotonic", return_value=time.monotonic() + 1000):
        with pytest.raises(BootstrapError) as error:
            broker.poll(challenge.session_id)
    assert error.value.code == "BootstrapSignInExpired"
    assert client.polls == 0
