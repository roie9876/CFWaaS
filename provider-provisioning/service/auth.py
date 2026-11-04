import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

import httpx
import jwt
from fastapi import HTTPException
from jwt import PyJWK

from .config import Customer, Settings
if TYPE_CHECKING:
    from .enrollment import CustomerBinding


class CallerRegistry(Protocol):
    def lookup(self, client_id: str, principal_id: str) -> "CustomerBinding | None": ...


@dataclass(frozen=True)
class Owner:
    tenant: str
    principal: str
    client: str

    @property
    def key(self) -> str:
        return f"{self.principal}:{self.client}"


class TrustedKeys:
    """Bounded tenant-pinned cache; no token-controlled discovery or network URL."""

    def __init__(self, tenant: str, client: httpx.Client | None = None) -> None:
        self.issuer = f"https://login.microsoftonline.com/{tenant}/v2.0"
        self.metadata = f"{self.issuer}/.well-known/openid-configuration"
        self.allowed_jwks = {
            f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys",
            "https://login.microsoftonline.com/common/discovery/v2.0/keys",
        }
        self.client = client or httpx.Client(timeout=5, follow_redirects=False, trust_env=False)
        self.keys: dict[str, PyJWK] = {}
        self.expires = 0.0
        self.last_attempt = float("-inf")
        self.lock = threading.Lock()

    def get(self, kid: str) -> PyJWK:
        with self.lock:
            now = time.monotonic()
            if kid in self.keys and now < self.expires:
                return self.keys[kid]
            if now - self.last_attempt < 30:
                raise ValueError("Signing key unavailable")
            self.last_attempt = now
            metadata = self._json(self.metadata)
            if metadata.get("issuer") != self.issuer:
                raise ValueError("Untrusted metadata issuer")
            uri = metadata.get("jwks_uri")
            if uri not in self.allowed_jwks:
                raise ValueError("Untrusted key endpoint")
            document = self._json(str(uri))
            raw_keys = document.get("keys")
            if not isinstance(raw_keys, list) or not 1 <= len(raw_keys) <= 32:
                raise ValueError("Invalid key set")
            keys = {}
            for raw in raw_keys:
                if not isinstance(raw, dict):
                    raise ValueError("Invalid signing key")
                if raw.get("kty") == "RSA" and raw.get("use", "sig") == "sig":
                    key_id = raw.get("kid")
                    if isinstance(key_id, str) and len(key_id) <= 256:
                        keys[key_id] = PyJWK(raw, algorithm="RS256")
            self.keys = keys
            self.expires = now + 3600
            return self.keys[kid]

    def _json(self, url: str) -> dict:
        # Streaming caps metadata/JWKS memory even if Content-Length is absent.
        with self.client.stream("GET", url) as response:
            response.raise_for_status()
            data = bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data) > 131072:
                    raise ValueError("Metadata too large")
        import json
        document = json.loads(data)
        if not isinstance(document, dict):
            raise ValueError("Invalid metadata")
        return document

    def close(self) -> None:
        self.client.close()


class Authenticator:
    def __init__(self, settings: Settings, keys: TrustedKeys,
                 registry: CallerRegistry | None = None) -> None:
        self.settings = settings
        self.keys = keys
        self.registry = registry
        if settings.auth_mode == "provider-api-registry" and registry is None:
            raise ValueError("Registry authentication requires a customer registry")

    def authenticate(self, authorization: str | None) -> Owner:
        try:
            if not authorization or len(authorization) > 16384:
                raise ValueError("Missing token")
            scheme, token = authorization.split(" ", 1)
            if scheme.lower() != "bearer" or not token or " " in token:
                raise ValueError("Invalid bearer")
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if (header.get("alg") != "RS256" or not isinstance(kid, str)
                    or not 1 <= len(kid) <= 256 or header.get("crit")):
                raise ValueError("Invalid signing header")
            claims = jwt.decode(
                token, self.keys.get(kid).key, algorithms=["RS256"],
                audience=self.settings.audience,
                issuer=f"https://login.microsoftonline.com/{self.settings.authority_tenant}/v2.0",
                options={"require": ["exp", "nbf", "iat", "iss", "aud", "tid", "oid",
                                     "ver", "idtyp"], "strict_aud": True},
                leeway=0,
            )
            if claims.get("ver") != "2.0" or claims.get("tid") != self.settings.authority_tenant:
                raise ValueError("Invalid tenant/version")
        except Exception:
            raise HTTPException(401, "Invalid access token",
                                headers={"WWW-Authenticate": "Bearer"}) from None
        roles = claims.get("roles")
        azp, appid = claims.get("azp"), claims.get("appid")
        client = azp or appid
        if (
            claims.get("idtyp") != "app"
            or "scp" in claims
            or not isinstance(roles, list)
            or self.settings.required_role not in roles
            or not isinstance(client, str) or not client
            or not isinstance(claims.get("oid"), str)
            or (azp is not None and appid is not None and azp != appid)
        ):
            raise HTTPException(403, "Caller is not authorized")
        if self.settings.auth_mode == "provider-api-registry":
            if self.registry is None:
                raise HTTPException(503, "Customer registry unavailable")
            binding = self.registry.lookup(client, claims["oid"])
            if (binding is None or binding.client != client
                    or binding.principal != claims["oid"]):
                raise HTTPException(403, "Caller is not authorized")
            customer = Customer(binding.tenant, binding.principal, binding.client)
        else:
            customer = self.settings.customer
            if (customer is None or claims["oid"] != customer.principal
                    or client != customer.client):
                raise HTTPException(403, "Caller is not authorized")
        return Owner(customer.tenant, customer.principal, customer.client)
