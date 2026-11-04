"""Provider-only device-code sign-in for an Azure-hosted setup flow.

The Entra public-client registration must be publisher-owned and explicitly
consented in the provider tenant. Tokens stay in memory and are never returned
by the HTTP surface. This module is not a deployed setup service by itself.
"""
import logging
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol
from urllib.parse import urlsplit

import jwt

from .auth import TrustedKeys
from .provider_bootstrap import BootstrapError, canonical_guid
from .provider_bootstrap_auth import GRAPH_SCOPES, VerifiedAdministrator

logger = logging.getLogger("faas.provider-device-auth")


class DeviceClient(Protocol):
    def initiate_device_flow(self, scopes: list[str]) -> dict: ...
    def acquire_token_by_device_flow(self, flow: dict, **kwargs) -> dict: ...


@dataclass(frozen=True)
class DeviceChallenge:
    session_id: str = field(repr=False)
    user_code: str = field(repr=False)
    verification_uri: str
    expires_in: int


@dataclass(frozen=True)
class DevicePending:
    retry_after: int


class ProviderDeviceAuth:
    """Bounded process-local sign-ins; the device code and tokens stay on the server."""

    def __init__(self, tenant_id: str, client_id: str,
                 client_factory: Callable[[], DeviceClient], keys: TrustedKeys,
                 *, max_sessions: int = 100) -> None:
        self.tenant_id, self.client_id = canonical_guid(tenant_id), canonical_guid(client_id)
        if not 1 <= max_sessions <= 1000:
            raise ValueError("Invalid device session limit")
        self.client_factory, self.keys, self.max_sessions = client_factory, keys, max_sessions
        self._sessions: dict[str, dict] = {}
        self._lock = threading.Lock()

    def begin(self) -> DeviceChallenge:
        session_id = secrets.token_urlsafe(32)
        now = time.monotonic()
        with self._lock:
            self._sessions = {key: value for key, value in self._sessions.items()
                              if value["deadline"] > now}
            if len(self._sessions) >= self.max_sessions:
                raise BootstrapError(429, "BootstrapSignInCapacityExceeded")
            self._sessions[session_id] = {"deadline": now + 30, "initializing": True}
        try:
            client = self.client_factory()
            flow = client.initiate_device_flow(list(GRAPH_SCOPES))
            verification = urlsplit(flow["verification_uri"])
            code, device_code = flow["user_code"], flow["device_code"]
            duration, interval = int(flow["expires_in"]), int(flow.get("interval", 5))
            if (verification.scheme != "https"
                    or (verification.hostname, verification.path) not in {
                        ("microsoft.com", "/devicelogin"), ("login.microsoft.com", "/device")
                    } or verification.query
                    or verification.fragment or verification.username or verification.password
                    or verification.port not in (None, 443)
                    or not isinstance(code, str) or not re.fullmatch(r"[A-Z0-9]{6,16}", code)
                    or not isinstance(device_code, str) or not device_code
                    or not 1 <= duration <= 1800 or not 1 <= interval <= 60):
                raise ValueError("Invalid Microsoft device authorization response")
        except Exception as error:
            with self._lock:
                self._sessions.pop(session_id, None)
            logger.warning("code=BootstrapSignInUnavailable type=%s", type(error).__name__)
            raise BootstrapError(503, "BootstrapSignInUnavailable") from None
        with self._lock:
            if session_id not in self._sessions:
                raise BootstrapError(401, "BootstrapSignInExpired")
            self._sessions[session_id] = {
                "deadline": time.monotonic() + duration, "flow": flow, "client": client,
                "nextPoll": time.monotonic(), "inFlight": False,
            }
        return DeviceChallenge(session_id, code, flow["verification_uri"], duration)

    def poll(self, session_id: str) -> DevicePending | VerifiedAdministrator:
        if not isinstance(session_id, str) or len(session_id) > 128:
            raise BootstrapError(400, "BootstrapInvalidDeviceSession")
        now = time.monotonic()
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise BootstrapError(401, "BootstrapSignInExpired")
            if session["deadline"] <= now:
                del self._sessions[session_id]
                raise BootstrapError(401, "BootstrapSignInExpired")
            if session.get("initializing"):
                raise BootstrapError(409, "BootstrapSignInPending")
            if session["inFlight"]:
                raise BootstrapError(409, "BootstrapSignInAlreadyPolling")
            if session["nextPoll"] > now:
                return DevicePending(max(1, int(session["nextPoll"] - now + 0.999)))
            session["inFlight"] = True
        try:
            result = session["client"].acquire_token_by_device_flow(
                session["flow"], exit_condition=lambda flow: True)
            if result.get("error") in ("authorization_pending", "slow_down"):
                interval = int(session["flow"].get("interval", 5))
                if not 1 <= interval <= 120:
                    raise ValueError("Unexpected polling interval")
                with self._lock:
                    session["inFlight"] = False
                    session["nextPoll"] = time.monotonic() + interval
                return DevicePending(interval)
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
            if claims.get("tid") != self.tenant_id or claims.get("idtyp") == "app":
                raise ValueError("Invalid administrator identity")
            object_id = canonical_guid(claims["oid"])
            scope = result.get("scope")
            if isinstance(scope, str):
                scopes = scope.split()
            elif isinstance(scope, list) and all(isinstance(item, str) for item in scope):
                scopes = scope
            else:
                raise ValueError("Missing delegated Graph scopes")
            if not {item.rsplit("/", 1)[-1] for item in GRAPH_SCOPES}.issubset(
                    {item.rsplit("/", 1)[-1] for item in scopes}):
                raise ValueError("Missing delegated Graph scopes")
            return VerifiedAdministrator(self.tenant_id, object_id, token)
        except BootstrapError:
            raise
        except Exception as error:
            logger.warning("code=BootstrapSignInInvalid type=%s", type(error).__name__)
            raise BootstrapError(401, "BootstrapSignInInvalid") from None
        finally:
            with self._lock:
                if session.get("inFlight"):
                    self._sessions.pop(session_id, None)
