"""Transfer only administrator access details between provider-owned services over authenticated TLS."""
import time

import httpx
from azure.core.exceptions import AzureError
from azure.mgmt.resource import ResourceManagementClient

from .checkpoint_gaia import CheckpointGaiaError
from .checkpoint_runner_config import CheckpointRuntimeInputs
from .connection_details import CheckpointAccess


def publish_checkpoint_access(inputs: CheckpointRuntimeInputs, identity) -> None:
    config = inputs.config
    if not config.managementRelayUrl:
        return
    try:
        with ResourceManagementClient(identity, config.providerSubscriptionId) as resources:
            addresses = {}
            for name in ("management", "gateway"):
                resource_id = (config.providerGroupId + "/providers/Microsoft.Network/publicIPAddresses/"
                               + "cp-" + name + "-" + config.environmentId[:8])
                resource = resources.resources.get_by_id(resource_id, "2024-05-01")
                if (str(resource.id).lower() != resource_id.lower()
                        or not isinstance(resource.properties, dict)
                        or resource.properties.get("provisioningState") != "Succeeded"):
                    raise CheckpointGaiaError("Check Point public address is not ready")
                addresses[name] = resource.properties.get("ipAddress")
        body = CheckpointAccess(
            environmentId=config.environmentId, providerGroupName=config.group_name,
            managementPublicIp=addresses["management"], gatewayPublicIp=addresses["gateway"],
            managementPassword=inputs.credentials.management_password,
        )
        token = identity.get_token(config.managementRelayClientId + "/.default").token
        with httpx.Client(timeout=30, follow_redirects=False, trust_env=False) as client:
            for attempt in range(4):
                try:
                    response = client.post(
                        config.managementRelayUrl + "/internal/checkpoint-access",
                        headers={"Authorization": "Bearer " + token},
                        json=body.model_dump(),
                    )
                except httpx.RequestError:
                    if attempt == 3:
                        raise CheckpointGaiaError("Private management access publication failed") from None
                else:
                    if response.status_code == 200:
                        try:
                            valid = response.json() == {"status": "stored"}
                        except ValueError:
                            valid = False
                        if valid:
                            return
                        raise CheckpointGaiaError("Private management access publication response invalid")
                    if response.status_code not in (408, 429, 500, 502, 503, 504) or attempt == 3:
                        raise CheckpointGaiaError("Private management access publication rejected")
                time.sleep(10)
    except (AzureError, ValueError):
        raise CheckpointGaiaError("Private management access publication failed") from None
