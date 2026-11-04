"""Provider-only ARM evidence for the experimental private Terraform state."""
from typing import Callable

from azure.core.exceptions import AzureError
from azure.mgmt.resource import ResourceManagementClient

from .checkpoint_private_data import (
    CheckpointPrivateDataReferences, validate_checkpoint_private_data_outputs,
    validate_checkpoint_state_evidence,
)


class CheckpointStateEvidenceError(Exception):
    pass


def verify_checkpoint_state(
        outputs: dict, provider_subscription: str, group_name: str, environment_id: str,
        resources: ResourceManagementClient, check: Callable[[], None]) -> CheckpointPrivateDataReferences:
    check()
    references = validate_checkpoint_private_data_outputs(
        outputs, provider_subscription, group_name, environment_id)
    queries = (
        (references.storage_id, "2023-05-01"),
        (references.storage_id + "/blobServices/default", "2023-05-01"),
        (references.storage_id + "/blobServices/default/containers/terraform-state", "2023-05-01"),
        (references.storage_endpoint_id, "2025-05-01"),
    )
    evidence = []
    for resource_id, api_version in queries:
        check()
        try:
            response = resources.resources.get_by_id(resource_id, api_version)
        except AzureError:
            raise CheckpointStateEvidenceError("Check Point private state evidence is unavailable") from None
        evidence.append(response.as_dict())
    check()
    return validate_checkpoint_state_evidence(
        outputs, provider_subscription, group_name, environment_id,
        evidence[0], evidence[1], evidence[2], evidence[3])
