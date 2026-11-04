"""Short-lived, browser-bound provider administrator authorization.

This component is not exposed by the deployed application yet. A hosting layer
must use a Secure, HttpOnly, SameSite=Lax, host-only cookie for the session ID
and must not log callback URLs or tokens. Graph writes remain a separate step.
"""
import base64
import hashlib
import hmac
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol
from urllib.parse import parse_qs, urlsplit

import jwt

from .auth import TrustedKeys
from .config import endpoint
from .provider_bootstrap import BootstrapError, canonical_guid

GRAPH_SCOPES = (
    "https://graph.microsoft.com/User.Read",
    "https://graph.microsoft.com/Application.ReadWrite.All",
    "https://graph.microsoft.com/Application.Read.All",
    "https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All",
)
logger = logging.getLogger("faas.provider-bootstrap-auth")


class OAuthClient(Protocol):
    def initiate_auth_code_flow(self, scopes: list[str], **kwargs) -> dict: ...
    def acquire_token_by_auth_code_flow(self, auth_code_flow: dict, auth_response: dict) -> dict: ...


def msal_public_client_factory(tenant_id: str, client_id: str) -> Callable[[], OAuthClient]:
    import msal
    tenant_id, client_id = canonical_guid(tenant_id), canonical_guid(client_id)

    def create() -> OAuthClient:
        return msal.PublicClientApplication(
            client_id, authority=f"https://login.microsoftonline.com/{tenant_id}",
            exclude_scopes=["offline_access"], enable_pii_log=False,
        )
    return create


@dataclass(frozen=True)
class BrowserChallenge:
    session_id: str = field(repr=False)
    authorization_url: str = field(repr=False)


@dataclass(frozen=True)
class VerifiedAdministrator:
    tenant_id: str
    object_id: str
    graph_access_token: str = field(repr=False)


class ProviderBrowserAuth:
    """Single-process, bounded one-time MSAL flows; never persists a token."""

    def __init__(self, tenant_id: str, client_id: str, origin: str,
                 client_factory: Callable[[], OAuthClient],
                 keys: TrustedKeys, *, ttl_seconds: int = 600, max_sessions: int = 100) -> None:
        self.tenant_id = canonical_guid(tenant_id)
        self.client_id = canonical_guid(client_id)
        self.origin = endpoint(origin, ".azurewebsites.net")
        if not 60 <= ttl_seconds <= 900 or not 1 <= max_sessions <= 1000:
            raise ValueError("Invalid browser session limits")
        self.redirect_uri = self.origin + "/bootstrap/callback"
        self.client_factory, self.keys = client_factory, keys
        self.ttl_seconds, self.max_sessions = ttl_seconds, max_sessions
        self._flows: dict[str, tuple[float, dict, OAuthClient]] = {}
        self._lock = threading.Lock()

    def begin(self) -> BrowserChallenge:
        try:
            client = self.client_factory()
            flow = client.initiate_auth_code_flow(
                list(GRAPH_SCOPES), redirect_uri=self.redirect_uri, prompt="consent")
            state, auth_url = flow["state"], flow["auth_uri"]
            parsed = urlsplit(auth_url)
            query = parse_qs(parsed.query)
            verifier, nonce = flow["code_verifier"], flow["nonce"]
            if not isinstance(verifier, str) or not isinstance(nonce, str):
                raise ValueError("Invalid MSAL verifier or nonce")
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
            nonce_hash = hashlib.sha256(nonce.encode("ascii")).hexdigest()
            if (not isinstance(state, str) or len(state) < 20
                    or parsed.scheme != "https" or parsed.hostname != "login.microsoftonline.com"
                    or parsed.path != f"/{self.tenant_id}/oauth2/v2.0/authorize"
                    or parsed.username or parsed.password or parsed.fragment
                    or parsed.port not in (None, 443) or not parsed.query
                    or query.get("state") != [state]
                    or query.get("redirect_uri") != [self.redirect_uri]
                    or query.get("client_id") != [self.client_id]
                    or query.get("code_challenge_method") != ["S256"]
                    or query.get("code_challenge") != [challenge]
                    or query.get("nonce") != [nonce_hash]):
                raise ValueError("Invalid MSAL authorization flow")
        except (KeyError, TypeError, ValueError):
            raise BootstrapError(503, "BootstrapSignInUnavailable") from None
        except Exception as error:
            logger.warning("code=BootstrapSignInUnavailable type=%s", type(error).__name__)
            raise BootstrapError(503, "BootstrapSignInUnavailable") from None
        session_id = secrets.token_urlsafe(32)
        now = time.monotonic()
        with self._lock:
            self._flows = {key: value for key, value in self._flows.items() if value[0] > now}
            if len(self._flows) >= self.max_sessions:
                raise BootstrapError(429, "BootstrapSignInCapacityExceeded")
            self._flows[session_id] = (now + self.ttl_seconds, flow, client)
        return BrowserChallenge(session_id, auth_url)

    def complete(self, session_id: str, response: dict[str, str]) -> VerifiedAdministrator:
        if (not isinstance(session_id, str) or len(session_id) > 128
                or not isinstance(response, dict) or set(response) - {"state", "code", "session_state", "error"}
                or not all(isinstance(value, str) and len(value) <= 8192 for value in response.values())):
            raise BootstrapError(400, "BootstrapInvalidCallback")
        with self._lock:
            entry = self._flows.get(session_id)
            if entry is None:
                raise BootstrapError(401, "BootstrapSignInExpired")
            expires, flow, client = entry
            if expires <= time.monotonic():
                del self._flows[session_id]
                raise BootstrapError(401, "BootstrapSignInExpired")
            if not hmac.compare_digest(response.get("state", ""), flow["state"]):
                raise BootstrapError(403, "BootstrapSignInStateMismatch")
            del self._flows[session_id]
        if response.get("error"):
            raise BootstrapError(403, "BootstrapSignInOrConsentDenied")
        if not response.get("code"):
            raise BootstrapError(400, "BootstrapInvalidCallback")
        try:
            result = client.acquire_token_by_auth_code_flow(flow, response)
            if result.get("error"):
                raise BootstrapError(403, "BootstrapSignInOrConsentDenied")
            raw_id, token = result["id_token"], result["access_token"]
            if (not isinstance(raw_id, str) or len(raw_id) > 16384
                    or not isinstance(token, str) or not token or len(token) > 16384):
                raise ValueError("Invalid token response")
            header = jwt.get_unverified_header(raw_id)
            kid = header.get("kid")
            if (header.get("alg") != "RS256" or header.get("crit")
                    or not isinstance(kid, str) or not 1 <= len(kid) <= 256):
                raise ValueError("Invalid ID token header")
            claims = jwt.decode(
                raw_id, self.keys.get(kid).key, algorithms=["RS256"], audience=self.client_id,
                issuer=f"https://login.microsoftonline.com/{self.tenant_id}/v2.0",
                options={"require": ["iss", "aud", "exp", "nbf", "iat", "tid", "oid"],
                         "strict_aud": True}, leeway=0,
            )
            nonce_hash = hashlib.sha256(flow["nonce"].encode("ascii")).hexdigest()
            if (claims.get("tid") != self.tenant_id or claims.get("idtyp") == "app"
                    or not isinstance(claims.get("nonce"), str)
                    or not hmac.compare_digest(claims["nonce"], nonce_hash)):
                raise ValueError("Invalid administrator identity")
            object_id = canonical_guid(claims["oid"])
            scope = result.get("scope")
            if isinstance(scope, str):
                granted = {item.rsplit("/", 1)[-1] for item in scope.split()}
            elif isinstance(scope, list) and all(isinstance(item, str) for item in scope):
                granted = {item.rsplit("/", 1)[-1] for item in scope}
            else:
                raise ValueError("Missing delegated Graph scopes")
            if not {item.rsplit("/", 1)[-1] for item in GRAPH_SCOPES}.issubset(granted):
                raise ValueError("Missing delegated Graph scopes")
        except BootstrapError:
            raise
        except (KeyError, TypeError, ValueError, jwt.PyJWTError):
            raise BootstrapError(401, "BootstrapSignInInvalid") from None
        except Exception as error:
            logger.warning("code=BootstrapSignInUnavailable type=%s", type(error).__name__)
            raise BootstrapError(503, "BootstrapSignInUnavailable") from None
        return VerifiedAdministrator(self.tenant_id, object_id, token)
