import json
import time
from types import SimpleNamespace
from unittest.mock import Mock

import jwt
import pytest
from azure.core.exceptions import ResourceNotFoundError
from fastapi.testclient import TestClient

from service.auth import Owner
from service.connection_details import CheckpointAccess, ConnectionDetails
from service.enrollment import EnrollmentError, PARTITION
from service.management import create_app
from service.management_auth import ProviderRelayAuthenticator
from service.models import RoutingAddress
from service.store import Change, DomainError

from test_decommission import (AUTHORITY, CLIENT, CUSTOMER, OTHER_CUSTOMER, PRINCIPAL, TENANT,
                              world)  # noqa: F401
from test_management import (ADMIN, ORIGIN, authentication, identity, signing, uid)  # noqa: F401

RELAY_CLIENT, RELAY_PRINCIPAL = uid(91), uid(92)
RELAY_ID = ("/subscriptions/" + uid(93) + "/resourceGroups/rg-faas-cp-control-" + uid(94)
            + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/faas-cp-publisher-12345678")
PASSWORD = "Aa1!unit-private-password"


@pytest.fixture
def access(world):
    operation = world.operations.rows[(world.store.partition, "op:" + world.environment_id)]
    request = json.loads(operation["request"])
    request["firewallType"] = "checkpoint-byol"
    operation["request"] = json.dumps(request)
    world.customers.transact([Change({
        "PartitionKey": PARTITION, "RowKey": "client:" + CLIENT, "customerId": CUSTOMER,
    })])
    stored = {}
    secrets = Mock()

    def write(name, value, **options):
        stored[name] = SimpleNamespace(
            value=value, properties=SimpleNamespace(
                enabled=True, content_type=options["content_type"], tags=options["tags"]),
        )

    def read(name, **options):
        if name not in stored:
            raise ResourceNotFoundError()
        return stored[name]

    secrets.set_secret.side_effect = write
    secrets.get_secret.side_effect = read
    service = ConnectionDetails(world.service, secrets)
    payload = CheckpointAccess(
        environmentId=world.environment_id, providerGroupName=world.group,
        managementPublicIp="8.8.8.8", gatewayPublicIp="1.1.1.1", managementPassword=PASSWORD,
    )
    return SimpleNamespace(service=service, payload=payload, secrets=secrets, stored=stored, world=world)


def test_reveal_reports_missing_details_explicitly_without_guessing_addresses(access):
    result = access.service.reveal(CUSTOMER, ADMIN)
    assert result[0]["credentialStatus"] == "PrivateConnectionDetailsNotPublished"
    assert result[0]["routing"]["nextHopIp"] is None
    assert "management" not in result[0]
    assert PASSWORD not in repr(access.world.customers.rows)


def test_publish_and_reveal_bind_credentials_and_separate_customer_next_hop(access):
    assert access.service.publish(access.payload, RELAY_PRINCIPAL) == {"status": "stored"}
    access.world.store.register_routing(
        Owner(TENANT, PRINCIPAL, CLIENT), access.world.environment_id, "172.18.10.7")
    details = access.service.reveal(CUSTOMER, ADMIN)[0]
    assert details["routing"]["nextHopIp"] == "172.18.10.7"
    assert details["routing"]["nextHopType"] == "VirtualAppliance"
    assert details["management"]["username"] == "admin"
    assert details["management"]["password"] == PASSWORD
    assert details["management"]["httpsUrl"] == "https://8.8.8.8"
    assert details["gateway"]["backendPrivateIp"] == "172.22.20.4"
    assert "SSH key" in details["gateway"]["authentication"]
    assert "password" not in details["gateway"]
    assert "sic" not in json.dumps(details).lower()
    assert PASSWORD not in repr(access.world.customers.rows)
    assert PASSWORD not in repr(access.world.operations.rows)
    assert PASSWORD not in repr(access.payload)
    assert all(call.kwargs["logging_enable"] is False
               for call in access.secrets.get_secret.call_args_list)


def test_another_customer_cannot_reveal_or_register_environment_details(access):
    access.service.publish(access.payload, RELAY_PRINCIPAL)
    assert access.service.reveal(OTHER_CUSTOMER, ADMIN) == []
    with pytest.raises(EnrollmentError) as error:
        access.service.register_routing(OTHER_CUSTOMER, access.world.environment_id,
                                       RoutingAddress(routingApplianceIp="172.18.10.7"), ADMIN)
    assert error.value.status == 404


def test_metadata_registration_preserves_request_and_checks_owner(access):
    world = access.world
    before = world.store.owned(Owner(TENANT, PRINCIPAL, CLIENT), world.environment_id)["request"]
    world.store.register_routing(Owner(TENANT, PRINCIPAL, CLIENT), world.environment_id, "172.18.10.7")
    assert world.store.owned(Owner(TENANT, PRINCIPAL, CLIENT), world.environment_id)["request"] == before
    with pytest.raises(DomainError) as error:
        world.store.register_routing(Owner(TENANT, PRINCIPAL, uid(99)), world.environment_id, "172.18.10.7")
    assert error.value.status == 404
    access.service.register_routing(CUSTOMER, world.environment_id,
                                   RoutingAddress(routingApplianceIp="172.18.10.8"), ADMIN)
    assert PASSWORD not in repr(world.customers.rows)


@pytest.mark.parametrize("value", ["8.8.8.8", "169.254.1.1", "::1", "invalid"])
def test_invalid_customer_routing_addresses_are_rejected(value):
    with pytest.raises(ValueError):
        RoutingAddress(routingApplianceIp=value)


@pytest.mark.parametrize("change", ["wrong-group", "wrong-binding", "decommissioned", "revoked"])
def test_reveal_never_uses_unbound_or_retired_credentials(access, change):
    access.service.publish(access.payload, RELAY_PRINCIPAL)
    secret = access.stored["cp-access-" + access.world.environment_id]
    if change == "wrong-group":
        value = json.loads(secret.value)
        value["providerGroupName"] = "another-group"
        secret.value = json.dumps(value)
    elif change == "wrong-binding":
        secret.properties.tags["customerId"] = OTHER_CUSTOMER
    elif change == "decommissioned":
        access.world.operations.rows[
            (access.world.store.partition, "op:" + access.world.environment_id)
        ]["decommissionState"] = "Deleting"
        assert access.service.reveal(CUSTOMER, ADMIN) == []
        return
    else:
        access.world.customers.rows[(PARTITION, "customer:" + CUSTOMER)]["status"] = "Revoked"
    with pytest.raises(EnrollmentError):
        access.service.reveal(CUSTOMER, ADMIN)


def relay_token(signing, **overrides):
    now = int(time.time())
    claims = {
        "iss": f"https://login.microsoftonline.com/{uid(1)}/v2.0", "aud": uid(3),
        "exp": now + 300, "nbf": now - 1, "iat": now - 1, "tid": uid(1),
        "oid": RELAY_PRINCIPAL, "azp": RELAY_CLIENT, "idtyp": "app", "xms_mirid": RELAY_ID,
    }
    claims.update(overrides)
    return jwt.encode(claims, signing[0], algorithm="RS256", headers={"kid": "unit"})


@pytest.fixture
def relay_app(signing, access):
    enrollment = Mock()
    enrollment.reveal.return_value = {"secret": "unit-api-credential", "expiresAt": "2099-01-01"}
    auth = ProviderRelayAuthenticator(uid(1), uid(3), RELAY_CLIENT, RELAY_PRINCIPAL, RELAY_ID, signing[1])
    app = create_app(enrollment, authentication(signing), connection_details=access.service,
                     relay_authenticator=auth)
    with TestClient(app, base_url=ORIGIN) as client:
        yield client


def test_relay_requires_exact_provider_identity_and_does_not_grant_admin_access(relay_app, signing, access):
    headers = {"Authorization": "Bearer " + relay_token(signing)}
    response = relay_app.post("/internal/checkpoint-access", headers=headers,
                              json=access.payload.model_dump())
    assert response.status_code == 200 and response.json() == {"status": "stored"}
    assert PASSWORD not in response.text
    assert relay_app.get("/admin/customers", headers=headers).status_code == 401
    assert relay_app.post("/internal/checkpoint-access",
                          headers={"x-ms-token-aad-id-token": identity(signing)},
                          json=access.payload.model_dump()).status_code == 401


def test_real_v2_token_without_optional_mirid_still_requires_exact_oid_and_client(relay_app, signing, access):
    encoded = relay_token(signing)
    claims = jwt.decode(encoded, options={"verify_signature": False})
    claims.pop("xms_mirid")
    token = jwt.encode(claims, signing[0], algorithm="RS256", headers={"kid": "unit"})
    assert relay_app.post("/internal/checkpoint-access",
                          headers={"Authorization": "Bearer " + token},
                          json=access.payload.model_dump()).status_code == 200
    claims["oid"] = uid(99)
    token = jwt.encode(claims, signing[0], algorithm="RS256", headers={"kid": "unit"})
    assert relay_app.post("/internal/checkpoint-access",
                          headers={"Authorization": "Bearer " + token},
                          json=access.payload.model_dump()).status_code == 401


@pytest.mark.parametrize("override", [
    {"oid": uid(99)}, {"azp": uid(99)}, {"tid": uid(99)}, {"aud": uid(99)},
    {"xms_mirid": RELAY_ID + "-other"}, {"idtyp": "user"}, {"scp": "user_impersonation"},
    {"iss": "https://issuer.example"}, {"exp": 1},
    {"xms_mirid": None}, {"iss": f"https://sts.windows.net/{uid(1)}/"},
])
def test_relay_rejects_other_identities_and_delegated_tokens(relay_app, signing, access, override):
    response = relay_app.post(
        "/internal/checkpoint-access",
        headers={"Authorization": "Bearer " + relay_token(signing, **override)},
        json=access.payload.model_dump(),
    )
    assert response.status_code == 401
    access.secrets.set_secret.assert_not_called()
    assert PASSWORD not in response.text


def test_existing_reveal_endpoint_includes_details_only_for_provider_administrators(relay_app, access, signing):
    access.service.publish(access.payload, RELAY_PRINCIPAL)
    headers = {"x-ms-token-aad-id-token": identity(signing), "Origin": ORIGIN}
    response = relay_app.post("/admin/customers/" + CUSTOMER + "/reveal", headers=headers, json={})
    assert response.status_code == 200
    assert response.json()["connectionDetails"][0]["management"]["password"] == PASSWORD
    assert response.headers["Cache-Control"] == "no-store"
    assert relay_app.post("/admin/customers/" + CUSTOMER + "/reveal", json={}).status_code == 401
