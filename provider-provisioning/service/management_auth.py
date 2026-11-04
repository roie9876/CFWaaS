from dataclasses import dataclass
import re
from uuid import UUID

import jwt
from fastapi import HTTPException, Request

from .auth import TrustedKeys
from .config import endpoint, uuid_text


@dataclass(frozen=True)
class Administrator:
    oid: str
    name: str


class ManagementAuthenticator:
    def __init__(self, tenant: str, client_id: str, administrators: set[str],
                 origin: str, keys: TrustedKeys) -> None:
        self.tenant, self.client_id = uuid_text(tenant), uuid_text(client_id)
        if not administrators or len(administrators) > 50:
            raise ValueError("An explicit administrator allowlist is required")
        self.administrators = {uuid_text(value) for value in administrators}
        self.origin = endpoint(origin, ".azurewebsites.net")
        self.keys = keys

    def authenticate(self, request: Request) -> Administrator:
        token = request.headers.get("x-ms-token-aad-id-token", "")
        try:
            if not token or len(token) > 16384:
                raise ValueError("Missing platform identity")
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if (header.get("alg") != "RS256" or header.get("crit")
                    or not isinstance(kid, str) or not 1 <= len(kid) <= 256):
                raise ValueError("Invalid identity header")
            claims = jwt.decode(
                token, self.keys.get(kid).key, algorithms=["RS256"],
                issuer=f"https://login.microsoftonline.com/{self.tenant}/v2.0",
                audience=self.client_id,
                options={"require": ["iss", "aud", "exp", "nbf", "iat", "tid", "oid"],
                         "strict_aud": True}, leeway=0,
            )
            if claims.get("tid") != self.tenant or claims.get("idtyp") == "app":
                raise ValueError("Invalid administrator identity")
            oid = str(UUID(claims["oid"]))
        except (ValueError, KeyError, TypeError, jwt.PyJWTError):
            raise HTTPException(401, "AdministratorSignInRequired") from None
        if oid not in self.administrators:
            raise HTTPException(403, "AdministratorNotAuthorized")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            if request.headers.get("origin") != self.origin:
                raise HTTPException(403, "InvalidRequestOrigin")
            if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
                raise HTTPException(415, "JsonRequired")
        name = claims.get("name")
        return Administrator(oid, name if isinstance(name, str) else oid)


class ProviderRelayAuthenticator:
    """Only the exact provider managed identity may publish private connection details."""
    def __init__(self, tenant: str, audience: str, client_id: str, principal_id: str,
                 identity_id: str, keys: TrustedKeys) -> None:
        self.tenant, self.audience = uuid_text(tenant), uuid_text(audience)
        self.client, self.principal = uuid_text(client_id), uuid_text(principal_id)
        if not re.fullmatch(
            r"/subscriptions/[0-9a-f-]{36}/resourceGroups/rg-faas-cp-control-[0-9a-f-]{36}"
            r"/providers/Microsoft.ManagedIdentity/userAssignedIdentities/faas-cp-publisher-[a-z0-9]{8}",
            identity_id,
        ):
            raise ValueError("Invalid Check Point relay identity")
        self.identity_id, self.keys = identity_id, keys

    def authenticate(self, request: Request) -> str:
        authorization = request.headers.get("authorization", "")
        try:
            if not authorization.startswith("Bearer ") or len(authorization) > 16400:
                raise ValueError()
            token = authorization[7:]
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if (header.get("alg") != "RS256" or header.get("crit")
                    or not isinstance(kid, str) or not 1 <= len(kid) <= 256):
                raise ValueError()
            claims = jwt.decode(
                token, self.keys.get(kid).key, algorithms=["RS256"], audience=self.audience,
                issuer=f"https://login.microsoftonline.com/{self.tenant}/v2.0",
                options={"require": ["iss", "aud", "exp", "nbf", "iat", "tid", "oid"],
                         "strict_aud": True}, leeway=0,
            )
            # V2 MI tokens can omit mirid; the signed tenant/object/client binding is mandatory.
            mirid = claims.get("xms_mirid")
            if (claims["tid"] != self.tenant or claims["oid"] != self.principal
                    or claims.get("azp", claims.get("appid")) != self.client
                    or claims.get("idtyp", "app") != "app" or "scp" in claims
                    or ("xms_mirid" in claims
                        and (not isinstance(mirid, str) or mirid.lower() != self.identity_id.lower()))):
                raise ValueError()
        except (ValueError, KeyError, TypeError, jwt.PyJWTError):
            raise HTTPException(401, "ProviderRelayNotAuthorized") from None
        if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            raise HTTPException(415, "JsonRequired")
        return self.principal
