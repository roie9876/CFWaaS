import base64
import hashlib
import time
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import urlencode
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from service.provider_bootstrap import BootstrapError
from service.provider_bootstrap_auth import GRAPH_SCOPES, ProviderBrowserAuth, msal_public_client_factory


def uid(number):
    return str(UUID(int=number))


TENANT, CLIENT, ADMIN = uid(1), uid(2), uid(3)
ORIGIN = "https://unit-admin.azurewebsites.net"
FAKE_TOKEN = "fixture-" + uuid4().hex


@pytest.fixture(scope="module")
def signing():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, SimpleNamespace(get=lambda kid: SimpleNamespace(key=private.public_key()))


class OAuth:
    def __init__(self, signing, claims=None, scopes=None):
        self.signing, self.overrides = signing, claims or {}
        self.scopes = scopes if scopes is not None else list(GRAPH_SCOPES)
        self.calls = []
        self.nonce = "unit-nonce"
        self.state = "unit-state-that-is-long-enough"
        self.verifier = "unit-verifier"
        self.result = None

    def initiate_auth_code_flow(self, scopes, **kwargs):
        self.calls.append(("begin", scopes, kwargs))
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(self.verifier.encode()).digest()).rstrip(b"=").decode()
        query = urlencode({
            "state": self.state, "redirect_uri": kwargs["redirect_uri"], "client_id": CLIENT,
            "nonce": hashlib.sha256(self.nonce.encode()).hexdigest(),
            "code_challenge": challenge, "code_challenge_method": "S256",
        })
        return {"state": self.state, "nonce": self.nonce, "code_verifier": self.verifier,
                "auth_uri": f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize?{query}"}

    def acquire_token_by_auth_code_flow(self, flow, response):
        self.calls.append(("complete", response))
        if self.result is not None:
            return self.result
        now = int(time.time())
        claims = {
            "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
            "aud": CLIENT, "tid": TENANT, "oid": ADMIN,
            "exp": now + 300, "nbf": now - 1, "iat": now - 1,
            "nonce": hashlib.sha256(flow["nonce"].encode()).hexdigest(),
        }
        claims.update(self.overrides)
        return {
            "id_token": jwt.encode(claims, self.signing, algorithm="RS256", headers={"kid": "unit"}),
            "access_token": FAKE_TOKEN, "scope": self.scopes,
        }


@pytest.fixture
def auth(signing):
    instances = []
    def factory():
        client = OAuth(signing[0])
        instances.append(client)
        return client
    return ProviderBrowserAuth(TENANT, CLIENT, ORIGIN, factory, signing[1]), instances


def test_msal_flow_is_browser_bound_single_use_and_token_is_not_returned_to_browser(auth):
    broker, instances = auth
    challenge = broker.begin()
    assert challenge.session_id not in repr(challenge)
    assert "unit-state" not in repr(challenge)
    assert instances[0].calls[0][1] == list(GRAPH_SCOPES)
    assert instances[0].calls[0][2]["prompt"] == "consent"
    result = broker.complete(challenge.session_id, {"state": instances[0].state, "code": "unit-code"})
    assert result.object_id == ADMIN and result.tenant_id == TENANT
    assert FAKE_TOKEN not in repr(result)
    assert not broker._flows
    with pytest.raises(BootstrapError) as error:
        broker.complete(challenge.session_id, {"state": instances[0].state, "code": "unit-code"})
    assert error.value.code == "BootstrapSignInExpired"


def test_wrong_state_is_rejected_without_consuming_correct_flow(auth):
    broker, instances = auth
    challenge = broker.begin()
    with pytest.raises(BootstrapError) as error:
        broker.complete(challenge.session_id, {"state": "wrong", "code": "unit-code"})
    assert error.value.code == "BootstrapSignInStateMismatch"
    assert len(instances[0].calls) == 1
    assert broker.complete(challenge.session_id, {"state": instances[0].state, "code": "unit-code"}).object_id == ADMIN


@pytest.mark.parametrize("claims", [
    {"tid": uid(4)}, {"oid": uid(0)}, {"aud": uid(4)},
    {"iss": "https://issuer.example"}, {"exp": 1}, {"nonce": "not-the-original"},
    {"idtyp": "app"},
])
def test_invalid_signed_administrator_claims_fail_closed(signing, claims):
    client = OAuth(signing[0], claims=claims)
    broker = ProviderBrowserAuth(TENANT, CLIENT, ORIGIN, lambda: client, signing[1])
    challenge = broker.begin()
    with pytest.raises(BootstrapError) as error:
        broker.complete(challenge.session_id, {"state": client.state, "code": "unit-code"})
    assert error.value.code == "BootstrapSignInInvalid"


def test_wrong_signing_key_and_missing_scopes_are_rejected(signing):
    for bad_signer, scopes in ((rsa.generate_private_key(public_exponent=65537, key_size=2048), None),
                               (signing[0], ["User.Read"])):
        client = OAuth(bad_signer, scopes=scopes)
        broker = ProviderBrowserAuth(TENANT, CLIENT, ORIGIN, lambda: client, signing[1])
        challenge = broker.begin()
        with pytest.raises(BootstrapError):
            broker.complete(challenge.session_id, {"state": client.state, "code": "unit-code"})


def test_flow_is_invalidated_on_denial_and_expiry(auth):
    broker, instances = auth
    challenge = broker.begin()
    with pytest.raises(BootstrapError) as error:
        broker.complete(challenge.session_id, {"state": instances[0].state, "error": "access_denied"})
    assert error.value.code == "BootstrapSignInOrConsentDenied"
    with pytest.raises(BootstrapError):
        broker.complete(challenge.session_id, {"state": instances[0].state, "code": "unit-code"})
    challenge = broker.begin()
    with patch("service.provider_bootstrap_auth.time.monotonic", return_value=time.monotonic() + 1000):
        with pytest.raises(BootstrapError) as expired:
            broker.complete(challenge.session_id, {"state": instances[-1].state, "code": "unit-code"})
    assert expired.value.code == "BootstrapSignInExpired"


def test_session_capacity_and_redirect_authority_are_bounded(signing):
    client = OAuth(signing[0])
    broker = ProviderBrowserAuth(TENANT, CLIENT, ORIGIN, lambda: client, signing[1], max_sessions=1)
    broker.begin()
    with pytest.raises(BootstrapError) as error:
        broker.begin()
    assert error.value.code == "BootstrapSignInCapacityExceeded"
    malicious = OAuth(signing[0])
    original = malicious.initiate_auth_code_flow
    def bad_flow(*args, **kwargs):
        flow = original(*args, **kwargs)
        flow["auth_uri"] = flow["auth_uri"].replace("login.microsoftonline.com", "attacker.example")
        return flow
    malicious.initiate_auth_code_flow = bad_flow
    broker = ProviderBrowserAuth(TENANT, CLIENT, ORIGIN, lambda: malicious, signing[1])
    with pytest.raises(BootstrapError):
        broker.begin()


def test_msal_errors_are_redacted_and_tokens_never_logged(auth, caplog):
    broker, instances = auth
    challenge = broker.begin()
    instances[0].result = {"error": "access_denied", "error_description": FAKE_TOKEN}
    with pytest.raises(BootstrapError) as error:
        broker.complete(challenge.session_id, {"state": instances[0].state, "code": "unit-code"})
    assert error.value.code == "BootstrapSignInOrConsentDenied"
    assert FAKE_TOKEN not in str(error.value)
    assert FAKE_TOKEN not in caplog.text


def test_real_msal_client_is_tenant_pinned_and_does_not_request_offline_access():
    with patch("msal.PublicClientApplication") as client:
        msal_public_client_factory(TENANT, CLIENT)()
    client.assert_called_once_with(
        CLIENT, authority=f"https://login.microsoftonline.com/{TENANT}",
        exclude_scopes=["offline_access"], enable_pii_log=False,
    )
