"""Owner-authorized, restart-resumable peering labs, separate from VPN onboarding."""
import json
import logging
import os
import re
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import NAMESPACE_URL, uuid5

import httpx
import jwt
import msal
from azure.core.exceptions import AzureError, ClientAuthenticationError, ResourceNotFoundError
from pydantic import Field, field_validator

from .admin_access import normalize_admin_sources
from .auth import TrustedKeys
from .checkpoint_foundation import validate_checkpoint_foundation
from .checkpoint_plan import validate_checkpoint_public_key
from .checkpoint_private_data import validate_checkpoint_private_data_outputs
from .checkpoint_provisioner import CheckpointSettings, load_checkpoint_settings
from .checkpoint_runner import (
    build_checkpoint_runner_request, validate_checkpoint_runner_observation,
    validate_checkpoint_runner_request,
)
from .config import CheckpointWorkerSettings, uuid_text
from .enrollment import EnrollmentError
from .managed_environment_groups import CHECKPOINT_PUBLISHER_ROLES
from .models import StrictModel
from .peering_templates import peering_foundation
from .store import Change, Conflict

logger = logging.getLogger("faas.peering-lab")
PARTITION = "peering-labs"
ARM = "https://management.azure.com"
ARM_API = "2025-04-01"
NETWORK_API = "2025-05-01"
SCOPES = ["https://management.azure.com/user_impersonation"]
NETWORK_CONTRIBUTOR = "4d97b98b-1d4f-4787-a291-c67834d212e7"
# Role assignments can take several minutes to reach ARM; peering 403s inside this window are retried.
ROLE_PROPAGATION_SECONDS = 900
# Failed labs that can be reopened: earlier stages are reused, only the runner is rerun.
RUNNER_RETRYABLE_FAILURES = frozenset({"PeeringCheckpointRunnerFailed", "PeeringEvidenceInvalid"})
PHASES = (
    "Creating dedicated resource groups", "Deploying Check Point security network",
    "Deploying private state and vault", "Authorizing the provider-only runner",
    "Deploying two customer VNets", "Connecting four peering directions",
    "Deploying and configuring Check Point VMSS and management",
    "Deploying two accelerated workload VMs", "Verifying MANA, original IPs and Internet egress",
    "Retiring temporary authorization", "Complete",
)

class PeeringAuthorizationRequired(EnrollmentError):
    def __init__(self, side: str):
        super().__init__(401, "PeeringReauthorizationRequired")
        self.side = side


def managed_identity_network_tokens(identity_client_id: str, application_client_id: str):
    """Exchange the management app's user-assigned identity for the peering app's ARM token in a tenant.

    ARM rejects primary/auxiliary user tokens from different identities, so all four peerings use
    one multitenant application provisioned in both tenants. It has no secret or certificate.
    """
    from azure.identity import ClientAssertionCredential, ManagedIdentityCredential

    identity = ManagedIdentityCredential(client_id=identity_client_id, logging_enable=False)

    def assertion() -> str:
        return identity.get_token("api://AzureADTokenExchange/.default").token

    def token(tenant: str) -> str:
        credential = ClientAssertionCredential(tenant, application_client_id, assertion, logging_enable=False)
        try:
            return credential.get_token("https://management.azure.com/.default").token
        finally:
            credential.close()
    return token


class PeeringLabRequest(StrictModel):
    customerId: str
    workloadSshPublicKey: str
    adminAllowedSources: list[str] = Field(min_length=1, max_length=16)
    approveLabCosts: Literal[True]
    approveCrossTenantPeering: Literal[True]

    @field_validator("approveLabCosts", "approveCrossTenantPeering", mode="before")
    @classmethod
    def approval(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("Explicit boolean approval is required")
        return True

    @field_validator("customerId")
    @classmethod
    def guid(cls, value: str) -> str:
        return uuid_text(value)

    @field_validator("workloadSshPublicKey")
    @classmethod
    def public_key(cls, value: str) -> str:
        return validate_checkpoint_public_key(value).decode("ascii")

    @field_validator("adminAllowedSources", mode="before")
    @classmethod
    def sources(cls, value: object) -> list[str]:
        return normalize_admin_sources(value)


@dataclass(frozen=True)
class PeeringLabSettings:
    provider_tenant: str
    provider_subscription: str
    oauth_client_id: str
    checkpoint: CheckpointSettings
    customer_template: dict
    network_client_id: str = ""
    network_identity_client_id: str = ""

    @classmethod
    def from_env(cls, tenant: str) -> "PeeringLabSettings":
        subscription = uuid_text(os.environ["FAAS_PROVIDER_SUBSCRIPTION_ID"])
        config = CheckpointWorkerSettings.from_env(
            provider_subscription=subscription, ssh_public_key=os.environ["FAAS_NVA_SSH_PUBLIC_KEY"])
        if config is None:
            raise ValueError("Peering requires a pinned Check Point VMSS release")
        checkpoint = load_checkpoint_settings(config)
        # The VPN operation registry/credential relay does not own these separate lab jobs.
        checkpoint = replace(checkpoint, runner=replace(
            checkpoint.runner, management_relay_url="", management_relay_client_id=""))
        path = Path(__file__).parent / "templates/peering-customer.json"
        network = os.getenv("FAAS_PEERING_NETWORK_CLIENT_ID", "").strip()
        identity = os.getenv("FAAS_PEERING_NETWORK_IDENTITY_CLIENT_ID", "").strip()
        if bool(network) != bool(identity):
            raise ValueError("Incomplete peering network identity configuration")
        return cls(uuid_text(tenant), subscription,
                   uuid_text(os.environ["FAAS_PEERING_OAUTH_CLIENT_ID"]),
                   checkpoint, json.loads(path.read_text()),
                   uuid_text(network) if network else "", uuid_text(identity) if identity else "")


class PeeringLabs:
    def __init__(self, settings: PeeringLabSettings, registry, vault, *,
                 http=None, msal_factory=None, keys_factory=TrustedKeys, network_token_factory=None):
        self.settings, self.registry, self.backend, self.vault = settings, registry, registry.backend, vault
        self.http = http or httpx.Client(timeout=30, follow_redirects=False, trust_env=False)
        self.msal_factory = msal_factory or self._msal
        self.keys_factory = keys_factory
        if network_token_factory is None and settings.network_client_id:
            network_token_factory = managed_identity_network_tokens(
                settings.network_identity_client_id, settings.network_client_id)
        self.network_token_factory = network_token_factory
        self.foundation_template = peering_foundation(settings.checkpoint.foundation_template)

    def _msal(self, tenant: str, cache):
        return msal.PublicClientApplication(
            self.settings.oauth_client_id, authority=f"https://login.microsoftonline.com/{tenant}",
            token_cache=cache)

    @staticmethod
    def public(row: dict) -> dict:
        result = {key: row[key] for key in (
            "environmentId", "customerId", "status", "phase", "providerAuthorized", "customerAuthorized",
            "providerGroupId", "customerGroupId", "errorCode", "expiresAt")}
        result["retryable"] = (row["status"] == "Failed" and row.get("stage") == 6
                               and row.get("errorCode") in RUNNER_RETRYABLE_FAILURES)
        return result

    def _row(self, environment: str, owner: str) -> dict:
        uuid_text(environment)
        row = self.backend.get(PARTITION, "lab:" + environment)
        if not row or row["owner"] != owner:
            raise EnrollmentError(404, "PeeringLabNotFound")
        return row

    def _save(self, row: dict) -> None:
        changes = [Change(row, row.get("_etag"))]
        if not row.get("_etag") or row["status"] in ("Ready", "Failed"):
            quota = self.backend.get(PARTITION, "quota:" + row["owner"]) or {
                "PartitionKey": PARTITION, "RowKey": "quota:" + row["owner"], "active": "[]"}
            active = json.loads(quota["active"])
            if not row.get("_etag"):
                retained = []
                for environment in active:
                    existing = self.backend.get(PARTITION, "lab:" + environment)
                    if existing and existing["status"] not in ("Ready", "Failed") and existing["expiresAt"] > time.time():
                        retained.append(environment)
                if len(retained) >= 3:
                    raise EnrollmentError(429, "PeeringLabActiveLimit")
                active = [*retained, row["environmentId"]]
            elif row["environmentId"] in active:
                active.remove(row["environmentId"])
            quota["active"] = json.dumps(active)
            changes.append(Change(quota, quota.get("_etag")))
        self.backend.transact(changes)

    def list(self, owner: str) -> list[dict]:
        rows = self.backend.list_rows(PARTITION, "lab:", 101)
        if len(rows) > 100:
            raise EnrollmentError(503, "PeeringLabListLimit")
        return [self.public(row) for row in rows if row["owner"] == owner and not row.get("removed")]

    def create(self, request: PeeringLabRequest, owner: str, key: str) -> dict:
        binding = self.registry.binding(request.customerId)
        if binding is None or binding.status != "Ready":
            raise EnrollmentError(409, "PeeringCustomerNotReady")
        if (binding.tenant == self.settings.provider_tenant
                or binding.subscription == self.settings.provider_subscription):
            raise EnrollmentError(422, "PeeringRequiresSeparateTenantsAndSubscriptions")
        text = request.model_dump_json()
        environment = str(uuid5(NAMESPACE_URL, "faas-peering:" + owner + ":" + key))
        existing = self.backend.get(PARTITION, "lab:" + environment)
        if existing:
            if existing["owner"] != owner or existing["request"] != text:
                raise EnrollmentError(409, "IdempotencyConflict")
            return self.public(existing)
        if sum(row["status"] not in ("Ready", "Failed") and row["expiresAt"] > time.time()
               for row in self.list(owner)) >= 3:
            raise EnrollmentError(429, "PeeringLabActiveLimit")
        row = {
            "PartitionKey": PARTITION, "RowKey": "lab:" + environment,
            "environmentId": environment, "customerId": binding.customer_id, "owner": owner,
            "customerTenant": binding.tenant, "customerSubscription": binding.subscription,
            "providerGroupId": f"/subscriptions/{self.settings.provider_subscription}/resourceGroups/rg-faas-env-{environment}",
            "customerGroupId": f"/subscriptions/{binding.subscription}/resourceGroups/rg-faas-peering-{environment}",
            "status": "AwaitingAuthorization", "phase": PHASES[0], "stage": 0,
            "providerAuthorized": False, "customerAuthorized": False, "errorCode": "",
            "request": text, "evidence": "{}", "busyUntil": 0, "authRetired": False,
            "expiresAt": int(time.time()) + 6 * 3600,
        }
        try:
            self._save(row)
        except Conflict:
            existing = self.backend.get(PARTITION, "lab:" + environment)
            if existing is None:
                raise EnrollmentError(503, "PeeringReservationContention") from None
            if existing["owner"] != owner or existing["request"] != text:
                raise EnrollmentError(409, "IdempotencyConflict") from None
            return self.public(existing)
        return self.public(row)

    def _tenant(self, row: dict, side: str) -> str:
        if side not in ("provider", "customer"):
            raise EnrollmentError(422, "InvalidPeeringSide")
        return self.settings.provider_tenant if side == "provider" else row["customerTenant"]

    @staticmethod
    def _secret(row: dict, side: str) -> str:
        return "faas-peering-" + row["environmentId"] + "-" + side

    def _write_auth(self, row: dict, side: str, value: dict) -> None:
        text = json.dumps(value, separators=(",", ":"))
        if len(text.encode("utf-8")) > 25000:
            raise EnrollmentError(503, "PeeringAuthorizationCacheTooLarge")
        self.vault.set_secret(
            self._secret(row, side), text,
            expires_on=datetime.fromtimestamp(row["expiresAt"], timezone.utc),
            content_type="application/vnd.faas.peering-oauth-cache+json", logging_enable=False)

    def _auth(self, row: dict, side: str) -> dict:
        value = self.vault.get_secret(self._secret(row, side), logging_enable=False).value
        if not isinstance(value, str) or len(value) > 25000:
            raise EnrollmentError(503, "PeeringAuthorizationUnavailable")
        return json.loads(value)

    def _claim(self, row: dict) -> dict:
        if row["busyUntil"] > time.time():
            raise EnrollmentError(409, "PeeringLabBusy")
        row["busyUntil"] = int(time.time()) + 180
        try:
            self._save(row)
        except Conflict:
            raise EnrollmentError(409, "PeeringLabBusy") from None
        return self._row(row["environmentId"], row["owner"])

    def signin(self, environment: str, owner: str, side: str) -> dict:
        row = self._row(environment, owner)
        if row["expiresAt"] <= time.time() or row["status"] in ("Ready", "Failed"):
            raise EnrollmentError(409, "PeeringLabNotAuthorizable")
        tenant = self._tenant(row, side)
        row = self._claim(row)
        try:
            cache = msal.SerializableTokenCache()
            client = self.msal_factory(tenant, cache)
            flow = client.initiate_device_flow(SCOPES)
            if (not isinstance(flow, dict) or not isinstance(flow.get("device_code"), str)
                    or flow.get("verification_uri") not in (
                        "https://microsoft.com/devicelogin", "https://login.microsoft.com/device")
                    or not isinstance(flow.get("user_code"), str)
                    or not re.fullmatch(r"[A-Z0-9]{6,16}", flow["user_code"])
                    or type(flow.get("expires_in")) is not int or not 1 <= flow["expires_in"] <= 1800):
                raise EnrollmentError(503, "PeeringSignInUnavailable")
            self._write_auth(row, side, {"flow": flow, "cache": cache.serialize(),
                                        "deadline": int(time.time()) + flow["expires_in"]})
            row[side + "Authorized"] = False
            return {"userCode": flow["user_code"], "verificationUri": flow["verification_uri"],
                    "expiresIn": flow["expires_in"]}
        finally:
            row["busyUntil"] = 0
            self._save(row)

    def poll_signin(self, environment: str, owner: str, side: str) -> dict:
        row = self._row(environment, owner)
        tenant = self._tenant(row, side)
        if row["expiresAt"] <= time.time():
            raise EnrollmentError(401, "PeeringSignInExpired")
        if row[side + "Authorized"]:
            return {"status": "authorized"}
        row = self._claim(row)
        try:
            return self._poll_signin(row, side, tenant, owner)
        finally:
            row["busyUntil"] = 0
            self._save(row)

    def _poll_signin(self, row: dict, side: str, tenant: str, owner: str) -> dict:
        if row.get(side + "NextPoll", 0) > time.time():
            return {"status": "pending"}
        saved = self._auth(row, side)
        if saved.get("deadline", 0) <= time.time():
            raise EnrollmentError(401, "PeeringSignInExpired")
        cache = msal.SerializableTokenCache()
        cache.deserialize(saved["cache"])
        client = self.msal_factory(tenant, cache)
        result = client.acquire_token_by_device_flow(saved["flow"], exit_condition=lambda flow: True)
        if result.get("error") in ("authorization_pending", "slow_down"):
            row[side + "NextPoll"] = time.time() + 5
            return {"status": "pending"}
        if result.get("error"):
            raise EnrollmentError(403, "PeeringSignInOrConsentDenied")
        if not isinstance(result.get("access_token"), str) or not result["access_token"]:
            raise EnrollmentError(401, "PeeringSignInInvalidToken")
        raw = result.get("id_token")
        try:
            header = jwt.get_unverified_header(raw)
            if (header.get("alg") != "RS256" or header.get("crit")
                    or not isinstance(header.get("kid"), str) or not 1 <= len(header["kid"]) <= 256):
                raise ValueError()
            keys = self.keys_factory(tenant)
            try:
                claims = jwt.decode(raw, keys.get(header["kid"]).key, algorithms=["RS256"],
                                    audience=self.settings.oauth_client_id,
                                    issuer=f"https://login.microsoftonline.com/{tenant}/v2.0",
                                    options={"require": ["iss", "aud", "tid", "oid", "exp", "nbf", "iat"],
                                             "strict_aud": True})
            finally:
                keys.close()
            if (claims["tid"] != tenant or claims.get("idtyp") == "app"
                    or side == "provider" and claims["oid"] != owner):
                raise ValueError()
            accounts = client.get_accounts()
            if len(accounts) != 1 or not accounts[0].get("home_account_id"):
                raise ValueError()
        except (jwt.PyJWTError, KeyError, TypeError, ValueError):
            raise EnrollmentError(401, "PeeringSignInIdentityMismatch") from None
        self._write_auth(row, side, {"cache": cache.serialize(), "account": accounts[0],
                                    "homeAccount": accounts[0]["home_account_id"]})
        row[side + "Authorized"], row["errorCode"] = True, ""
        return {"status": "authorized"}

    def _tokens(self, row: dict, *, force_refresh: bool = False) -> dict[str, str]:
        tokens, required = {}, []
        for side in ("provider", "customer"):
            try:
                saved = self._auth(row, side)
            except ResourceNotFoundError:
                row[side + "Authorized"] = False
                required.append(side)
                continue
            if not isinstance(saved, dict) or not isinstance(saved.get("account"), dict):
                row[side + "Authorized"] = False
                required.append(side)
                continue
            cache = msal.SerializableTokenCache()
            cache.deserialize(saved["cache"])
            result = self.msal_factory(self._tenant(row, side), cache).acquire_token_silent(
                SCOPES, account=saved["account"], force_refresh=force_refresh)
            if not result or not isinstance(result.get("access_token"), str) or not result["access_token"]:
                row[side + "Authorized"] = False
                required.append(side)
                continue
            row[side + "Authorized"] = True
            tokens[side] = result["access_token"]
            if cache.has_state_changed:
                self._write_auth(row, side, {**saved, "cache": cache.serialize()})
        if required:
            raise PeeringAuthorizationRequired(required[0])
        return tokens

    def resume(self, environment: str, owner: str) -> dict:
        row = self._row(environment, owner)
        if row["status"] == "Failed" and row.get("errorCode") in RUNNER_RETRYABLE_FAILURES:
            return self._reopen_runner_failure(row)
        if row["status"] in ("Ready", "Failed") or row["expiresAt"] <= time.time():
            raise EnrollmentError(409, "PeeringLabNotResumable")
        row = self._claim(row)
        try:
            # A resumed lab gets a fresh deployment window; the runner alone can take hours.
            if row["expiresAt"] - time.time() < 4 * 3600:
                saved = {}
                for side in ("provider", "customer"):
                    try:
                        saved[side] = self._auth(row, side)
                    except ResourceNotFoundError:
                        pass
                row["expiresAt"] = int(time.time()) + 6 * 3600
                for side, value in saved.items():
                    self._write_auth(row, side, value)
            self._tokens(row, force_refresh=True)
            row.update(status="Deploying", errorCode="", providerAuthorized=True, customerAuthorized=True)
        except PeeringAuthorizationRequired as error:
            row.update(status="AwaitingAuthorization", errorCode=error.code)
            logger.warning("environment=%s code=%s side=%s", environment, error.code, error.side)
        finally:
            row["busyUntil"] = 0
            self._save(row)
        return self.public(row)

    def _reopen_runner_failure(self, row: dict) -> dict:
        """Reopen a lab that failed only in the Check Point runner; its earlier stages are reused.

        Failure retired the authorization caches, so both tenants must sign in again. The stopped
        runner container is replaced on the next runner stage and the pinned image is used.
        """
        if row["stage"] != 6:
            raise EnrollmentError(409, "PeeringLabNotResumable")
        row = self._claim(row)
        evidence = json.loads(row["evidence"])
        evidence["runnerRetry"] = True
        row.update(status="AwaitingAuthorization", errorCode="", evidence=json.dumps(evidence, separators=(",", ":")),
                   providerAuthorized=False, customerAuthorized=False, authRetired=False,
                   expiresAt=int(time.time()) + 6 * 3600, busyUntil=0)
        self._save(row)
        logger.info("environment=%s code=PeeringRunnerRetryRequested", row["environmentId"])
        return self.public(row)

    def remove(self, environment: str, owner: str) -> dict:
        """Hide a failed lab's record from the portal; Azure resources are never touched here."""
        row = self._row(environment, owner)
        if row["status"] != "Failed":
            raise EnrollmentError(409, "PeeringLabNotRemovable")
        row = self._claim(row)
        if not row.get("authRetired"):
            self._retire_auth(row)
        row.update(removed=True, authRetired=True, busyUntil=0)
        self._save(row)
        logger.info("environment=%s code=PeeringLabRemoved", environment)
        return {"environmentId": environment, "removed": True}

    def cancel(self, environment: str, owner: str) -> dict:
        row = self._row(environment, owner)
        if row["status"] in ("Ready", "Failed"):
            return self.public(row)
        row = self._claim(row)
        row.update(status="Failed", errorCode="PeeringLabCancelled", busyUntil=0,
                   providerAuthorized=False, customerAuthorized=False)
        self._save(row)
        logger.info("environment=%s code=PeeringLabCancelled", environment)
        return self.public(row)

    def _arm(self, method: str, resource: str, version: str, token: str, body=None, auxiliary=None, *,
             expand: str = ""):
        if (not resource.startswith("/subscriptions/") or "?" in resource
                or "#" in resource or ".." in resource):
            raise ValueError("Invalid peering ARM resource")
        headers = {"Authorization": "Bearer " + token}
        if auxiliary:
            headers["x-ms-authorization-auxiliary"] = "Bearer " + auxiliary
        parameters = {"api-version": version}
        if expand:
            if expand != "instanceView":
                raise ValueError("Unsupported ARM expansion")
            parameters["$expand"] = expand
        response = self.http.request(method, ARM + resource, params=parameters,
                                     headers=headers, json=body)
        if response.status_code == 404 and method == "GET":
            return None
        if response.status_code == 401:
            raise EnrollmentError(401, "PeeringArmAuthenticationExpired")
        if response.status_code == 403:
            raise EnrollmentError(403, "PeeringArmPermissionRequired")
        if response.status_code in (408, 409, 429, 500, 502, 503, 504):
            raise EnrollmentError(503, "PeeringArmTemporarilyUnavailable")
        if response.status_code not in (200, 201, 202, 204):
            raise EnrollmentError(502, "PeeringArmDeploymentRejected")
        if not response.content:
            return {}
        return response.json()

    def _groups(self, row: dict, tokens: dict, evidence: dict) -> bool:
        index = evidence.get("groupIndex", 0)
        for side in (("provider", "customer")[index],):
            subscription = (self.settings.provider_subscription if side == "provider"
                            else row["customerSubscription"])
            account = self._arm("GET", "/subscriptions/" + subscription, "2022-12-01", tokens[side])
            if (not isinstance(account, dict) or account.get("tenantId") != self._tenant(row, side)
                    or account.get("state") != "Enabled"):
                raise EnrollmentError(403, "PeeringSubscriptionTenantMismatch")
            scope = row[side + "GroupId"]
            group = self._arm("GET", scope, "2022-09-01", tokens[side])
            tags = {"purpose": "faas-peering-lab", "faasEnvironmentId": row["environmentId"],
                    "faasCustomerId": row["customerId"]}
            if group is None:
                self._arm("PUT", scope, "2022-09-01", tokens[side], {"location": "eastus2", "tags": tags})
            elif (group.get("id", "").lower() != scope.lower() or group.get("location") != "eastus2"
                  or any(group.get("tags", {}).get(key) != value for key, value in tags.items())
                  or group.get("managedBy")):
                raise EnrollmentError(409, "PeeringResourceGroupOwnershipMismatch")
        evidence["groupIndex"] = index + 1
        return evidence["groupIndex"] == 2

    def _deployment(self, row: dict, side: str, name: str, template: dict, parameters: dict,
                    tokens: dict) -> dict | None:
        path = row[side + "GroupId"] + "/providers/Microsoft.Resources/deployments/" + name
        current = self._arm("GET", path, "2022-09-01", tokens[side])
        if current is None:
            self._arm("PUT", path, "2022-09-01", tokens[side], {"properties": {
                "mode": "Incremental", "template": template,
                "parameters": {key: {"value": value} for key, value in parameters.items()},
            }})
            return None
        properties = current["properties"]
        actual = properties.get("parameters")
        if (not isinstance(actual, dict) or set(actual) != set(parameters)
                or any(not isinstance(actual[key], dict) or actual[key].get("value") != value
                       for key, value in parameters.items())):
            raise EnrollmentError(409, "PeeringDeploymentParametersConflict")
        if properties["provisioningState"] in ("Failed", "Canceled", "Cancelled"):
            raise EnrollmentError(422, "PeeringDeploymentFailed")
        return properties.get("outputs", {}) if properties["provisioningState"] == "Succeeded" else None

    def _lab_vnets(self, row: dict) -> dict:
        return {
            "provider": [row["providerGroupId"] + "/providers/Microsoft.Network/virtualNetworks/"
                         "vnet-cp-security-" + row["environmentId"][:8]],
            "customer": [row["customerGroupId"] + f"/providers/Microsoft.Network/virtualNetworks/vnet-peering-workload-{i}"
                         for i in range(2)],
        }

    def _network_tokens(self, row: dict) -> dict[str, dict]:
        if self.network_token_factory is None:
            raise EnrollmentError(409, "PeeringNetworkIdentityNotConfigured")
        result = {}
        for side in ("provider", "customer"):
            tenant = self._tenant(row, side)
            try:
                token = self.network_token_factory(tenant)
            except ClientAuthenticationError as error:
                # Typically the tenant has not yet provisioned (consented to) the peering application.
                # Only the public AADSTS number is surfaced; never token or assertion content.
                code = "PeeringCustomerTenantConsentRequired" if side == "customer" else "PeeringProviderTenantConsentRequired"
                detail = re.search(r"AADSTS\d{4,8}", str(getattr(error, "message", "") or error))
                logger.warning("environment=%s side=%s code=%s entra=%s", row["environmentId"], side, code,
                               detail.group() if detail else "none")
                raise EnrollmentError(403, code + (":" + detail.group() if detail else "")) from None
            try:
                claims = jwt.decode(token, options={"verify_signature": False})
                if (claims.get("tid") != tenant or claims.get("idtyp") != "app"
                        or self.settings.network_client_id not in (claims.get("appid"), claims.get("azp"))):
                    raise ValueError()
                principal = uuid_text(claims["oid"])
            except (jwt.PyJWTError, KeyError, TypeError, ValueError):
                raise EnrollmentError(403, "PeeringNetworkIdentityInvalid") from None
            result[side] = {"token": token, "principal": principal}
        return result

    def _network_roles(self, row: dict, tokens: dict, network: dict, evidence: dict) -> None:
        """Each tenant's administrator grants the peering app Network Contributor on its own lab VNets only."""
        for side, scopes in self._lab_vnets(row).items():
            principal = network[side]["principal"]
            subscription = scopes[0].split("/")[2]
            definition = f"/subscriptions/{subscription}/providers/Microsoft.Authorization/roleDefinitions/{NETWORK_CONTRIBUTOR}"
            for scope in scopes:
                name = str(uuid5(NAMESPACE_URL, "faas-peering-network:" + scope.lower() + ":" + principal))
                path = scope + "/providers/Microsoft.Authorization/roleAssignments/" + name
                current = self._arm("GET", path, "2022-04-01", tokens[side])
                if current is None:
                    self._arm("PUT", path, "2022-04-01", tokens[side], {"properties": {
                        "principalId": principal, "principalType": "ServicePrincipal",
                        "roleDefinitionId": definition}})
                elif (current["properties"]["principalId"].lower() != principal
                      or current["properties"]["roleDefinitionId"].lower() != definition.lower()
                      or current["properties"]["scope"].lower() != scope.lower()):
                    raise EnrollmentError(409, "PeeringNetworkRoleConflict")
        evidence["networkRolesAt"] = int(time.time())

    def _peerings(self, row: dict, tokens: dict, evidence: dict) -> bool:
        provider = (row["providerGroupId"] + "/providers/Microsoft.Network/virtualNetworks/"
                    "vnet-cp-security-" + row["environmentId"][:8])
        index = evidence.get("peeringIndex", 0)
        verifying = index >= 4
        selected = index % 4
        for i in (selected // 2,):
            customer = row["customerGroupId"] + f"/providers/Microsoft.Network/virtualNetworks/vnet-peering-workload-{i}"
            for side, local, remote, name in (
                ("customer", customer, provider, "checkpoint"),
                ("provider", provider, customer, f"customer-workload-{i}"),
            ):
                if side != ("customer" if selected % 2 == 0 else "provider"):
                    continue
                path = local + "/virtualNetworkPeerings/" + name
                auxiliary = tokens["provider" if side == "customer" else "customer"]
                properties = {
                    "remoteVirtualNetwork": {"id": remote}, "allowVirtualNetworkAccess": True,
                    "allowForwardedTraffic": True, "allowGatewayTransit": False, "useRemoteGateways": False,
                }
                existing = self._arm("GET", path, NETWORK_API, tokens[side])
                if existing is None:
                    self._arm("PUT", path, NETWORK_API, tokens[side], {"properties": properties}, auxiliary)
                    if not verifying:
                        evidence["peeringIndex"] = index + 1
                else:
                    actual = existing.get("properties", {})
                    if (actual.get("remoteVirtualNetwork", {}).get("id", "").lower() != remote.lower()
                            or any(actual.get(key) is not value for key, value in properties.items()
                                   if key != "remoteVirtualNetwork")):
                        raise EnrollmentError(409, "PeeringConfigurationConflict")
                    if not verifying or actual.get("peeringState") == "Connected":
                        evidence["peeringIndex"] = index + 1
        return evidence.get("peeringIndex") == 8

    def _verify_workload(self, row: dict, tokens: dict, evidence: dict) -> bool:
        index = evidence.get("verifiedWorkloads", 0)
        path = (row["customerGroupId"] + "/providers/Microsoft.Compute/virtualMachines/"
                f"vm-peering-workload-{index}/runCommands/verify-peering-lab")
        resource = self._arm("GET", path, ARM_API, tokens["customer"], expand="instanceView")
        view = resource.get("properties", {}).get("instanceView") if isinstance(resource, dict) else None
        if not isinstance(view, dict):
            raise EnrollmentError(503, "PeeringVerificationEvidenceUnavailable")
        if view.get("executionState") in ("Pending", "Running"):
            return False
        output = view.get("output")
        if (view.get("executionState") != "Succeeded" or type(view.get("exitCode")) is not int
                or view["exitCode"] != 0 or not isinstance(output, str)
                or not {"FAAS_MANA_VERIFIED", "FAAS_ORIGINAL_SOURCE_AND_EGRESS_VERIFIED"} <= set(output.splitlines())):
            raise EnrollmentError(422, "PeeringWorkloadVerificationFailed")
        evidence["verifiedWorkloads"] = index + 1
        return evidence["verifiedWorkloads"] == 2

    def _runner_spec(self, row: dict, evidence: dict, tokens: dict):
        config = self.settings.checkpoint
        identity = self._arm("GET", config.identity_id, "2023-01-31", tokens["provider"])
        return build_checkpoint_runner_request(
            evidence["foundation"], evidence["private"], self.settings.provider_subscription,
            self.settings.provider_tenant, row["providerGroupId"].rsplit("/", 1)[1],
            row["environmentId"], config.control_group, identity, config.registry_server,
            config.image_sha256, config.runner,
            json.loads(row["request"])["adminAllowedSources"], "vmss", "peering")
    def _runner(self, row: dict, evidence: dict, tokens: dict) -> bool:
        spec, body = self._runner_spec(row, evidence, tokens)
        current = self._arm("GET", spec.job_id, "2023-05-01", tokens["provider"])
        if evidence.get("runnerRetry"):
            # Replace only a runner that has already stopped; Terraform state makes the rerun idempotent.
            if current is not None:
                properties = current.get("properties", {}) if isinstance(current, dict) else {}
                containers = properties.get("containers") or [{}]
                state = (((containers[0].get("properties") or {}).get("instanceView") or {})
                         .get("currentState") or {}).get("state")
                if properties.get("provisioningState") == "Failed" or state == "Terminated":
                    self._arm("DELETE", spec.job_id, "2023-05-01", tokens["provider"])
                elif properties.get("provisioningState") != "Deleting":
                    raise EnrollmentError(409, "PeeringRunnerStillActive")
                return False
            evidence.pop("runnerRetry")
        if current is None:
            validate_checkpoint_runner_request(spec, body)
            self._arm("PUT", spec.job_id, "2023-05-01", tokens["provider"], json.loads(body))
            return False
        observation = validate_checkpoint_runner_observation(current, spec)
        if observation.state == "provisioning_failed" or (
                observation.state == "completed" and observation.exit_code != 0):
            raise EnrollmentError(422, "PeeringCheckpointRunnerFailed")
        return observation.state == "completed"

    def _roles(self, row: dict, tokens: dict, evidence: dict) -> bool:
        spec, _ = self._runner_spec(row, evidence, tokens)
        principal = spec.identity_principal_id
        index = evidence.get("roleIndex", 0)
        for role in (CHECKPOINT_PUBLISHER_ROLES[index],):
            scope = row["providerGroupId"]
            name = str(uuid5(NAMESPACE_URL, scope.lower() + ":" + principal + ":" + role))
            path = scope + "/providers/Microsoft.Authorization/roleAssignments/" + name
            definition = f"/subscriptions/{self.settings.provider_subscription}/providers/Microsoft.Authorization/roleDefinitions/{role}"
            current = self._arm("GET", path, "2022-04-01", tokens["provider"])
            if current is None:
                self._arm("PUT", path, "2022-04-01", tokens["provider"], {"properties": {
                    "principalId": principal, "principalType": "ServicePrincipal", "roleDefinitionId": definition,
                }})
            elif (current["properties"]["principalId"].lower() != principal
                  or current["properties"]["roleDefinitionId"].lower() != definition.lower()
                  or current["properties"]["scope"].lower() != scope.lower()):
                raise EnrollmentError(409, "PeeringRunnerRoleConflict")
        evidence["roleIndex"] = index + 1
        return evidence["roleIndex"] == len(CHECKPOINT_PUBLISHER_ROLES)

    def _step(self, row: dict, tokens: dict, evidence: dict) -> bool:
        stage = row["stage"]
        config = self.settings.checkpoint
        request = PeeringLabRequest.model_validate_json(row["request"])
        parameters = {"location": "eastus2", "environmentId": row["environmentId"]}
        if stage == 0:
            return self._groups(row, tokens, evidence)
        elif stage == 1:
            result = self._deployment(row, "provider", "peering-foundation", self.foundation_template,
                                      {**parameters, "adminAllowedSources": request.adminAllowedSources,
                                       "firewallTopology": "vmss"}, tokens)
            if result is None:
                return False
            validate_checkpoint_foundation(result, self.settings.provider_subscription,
                                           row["providerGroupId"].rsplit("/", 1)[1],
                                           row["environmentId"], "vmss", "peering")
            evidence["foundation"] = result
        elif stage == 2:
            result = self._deployment(row, "provider", "peering-private", config.private_template, parameters, tokens)
            if result is None:
                return False
            validate_checkpoint_private_data_outputs(result, self.settings.provider_subscription,
                                                       row["providerGroupId"].rsplit("/", 1)[1], row["environmentId"])
            evidence["private"] = result
        elif stage == 3:
            return self._roles(row, tokens, evidence)
        elif stage == 5:
            network = self._network_tokens(row)
            if "networkRolesAt" not in evidence:
                self._network_roles(row, tokens, network, evidence)
                return False
            try:
                return self._peerings(row, {side: value["token"] for side, value in network.items()}, evidence)
            except EnrollmentError as error:
                if error.status in (401, 403) and time.time() - evidence["networkRolesAt"] < ROLE_PROPAGATION_SECONDS:
                    raise EnrollmentError(503, "PeeringRolePropagationPending") from None
                raise
        elif stage == 6:
            return self._runner(row, evidence, tokens)
        elif stage in (4, 7, 8):
            result = self._deployment(
                row, "customer", ("peering-networks" if stage == 4 else "peering-workloads" if stage == 7
                                  else "peering-verification"), self.settings.customer_template,
                {**parameters, "sshPublicKey": request.workloadSshPublicKey,
                 "deployWorkloads": stage >= 7, "verifyWorkloads": stage == 8}, tokens)
            if result is None:
                return False
            return self._verify_workload(row, tokens, evidence) if stage == 8 else True
        else:
            raise ValueError("Invalid peering deployment stage")
        return True

    def _retire_auth(self, row: dict) -> None:
        for side in ("provider", "customer"):
            name = self._secret(row, side)
            try:
                versions = list(self.vault.list_properties_of_secret_versions(name, logging_enable=False))
            except ResourceNotFoundError:
                continue
            if len(versions) > 64:
                raise EnrollmentError(503, "PeeringAuthorizationCleanupRequired")
            for version in versions:
                if version.enabled:
                    self.vault.update_secret_properties(name, version.version, enabled=False, logging_enable=False)

    def advance(self, environment: str, owner: str) -> dict:
        row = self._row(environment, owner)
        if row["status"] in ("Ready", "Failed"):
            if row["status"] == "Failed" and not row.get("authRetired"):
                self._retire_auth(row)
                row["authRetired"] = True
                self._save(row)
            return self.public(row)
        if row["busyUntil"] > time.time():
            return self.public(row)
        if row["expiresAt"] <= time.time():
            row.update(status="Failed", errorCode="PeeringLabTimedOut")
            self._save(row)
            return self.public(row)
        if row["status"] == "NeedsAttention":
            return self.public(row)
        if not row["providerAuthorized"] or not row["customerAuthorized"]:
            return self.public(row)
        row["busyUntil"] = int(time.time()) + 180
        try:
            self._save(row)
        except Conflict:
            return self.public(self._row(environment, owner))
        row = self._row(environment, owner)
        try:
            evidence = json.loads(row["evidence"])
            if row["stage"] == 9:
                self._retire_auth(row)
                row["authRetired"] = True
                row["stage"] += 1
            elif self._step(row, self._tokens(row), evidence):
                row["stage"] += 1
            row.update(evidence=json.dumps(evidence, separators=(",", ":")),
                       phase=PHASES[row["stage"]], status="Ready" if row["stage"] == 10 else "Deploying",
                       errorCode="")
        except EnrollmentError as error:
            row["errorCode"] = error.code
            if isinstance(error, PeeringAuthorizationRequired):
                row["status"] = "AwaitingAuthorization"
            elif error.status in (401, 403):
                row["status"] = "NeedsAttention"
            elif error.status in (502, 503):
                row["status"] = "Retrying"
            else:
                row["status"] = "Failed"
            logger.warning("environment=%s code=%s", environment, error.code)
        except (AzureError, httpx.HTTPError):
            row.update(status="Retrying", errorCode="PeeringDependencyUnavailable")
            logger.warning("environment=%s code=PeeringDependencyUnavailable", environment)
        except (KeyError, TypeError, ValueError):
            row.update(status="Failed", errorCode="PeeringEvidenceInvalid")
            logger.warning("environment=%s code=PeeringEvidenceInvalid", environment)
        row["busyUntil"] = 0
        self._save(row)
        return self.public(row)

    def run(self, stop) -> None:
        while not stop.is_set():
            try:
                rows = self.backend.list_rows(PARTITION, "lab:", 101)
                if len(rows) > 100:
                    raise EnrollmentError(503, "PeeringLabListLimit")
                for row in rows:
                    if stop.is_set():
                        return
                    if (row["status"] == "Failed" and not row.get("authRetired")
                            or row["status"] not in ("Ready", "Failed") and (
                                row["expiresAt"] <= time.time()
                                or row["status"] != "NeedsAttention"
                                and row["providerAuthorized"] and row["customerAuthorized"])):
                        self.advance(row["environmentId"], row["owner"])
            except (AzureError, httpx.HTTPError, Conflict, EnrollmentError, KeyError, TypeError, ValueError) as error:
                logger.warning("code=PeeringPollUnavailable type=%s", type(error).__name__)
            stop.wait(10)

    def close(self) -> None:
        self.http.close()
