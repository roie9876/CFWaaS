"""Provider-only, audited connection details backed by the private management vault."""
import json
import time
from uuid import uuid4

from azure.core.exceptions import AzureError, ResourceNotFoundError
from pydantic import Field, field_validator

from .decommission import EnvironmentDecommissions
from .enrollment import EnrollmentError, PARTITION
from .models import (
    CHECKPOINT_TOPOLOGIES, Endpoint, RoutingAddress, StrictModel, parse_stored_environment_request,
)
from .store import Change, Conflict
from .config import uuid_text

CONTENT_TYPE = "application/vnd.faas.checkpoint-access+json"


class CheckpointAccess(StrictModel):
    environmentId: str
    providerGroupName: str
    managementPublicIp: str
    gatewayPublicIp: str
    managementPassword: str = Field(min_length=16, max_length=72, repr=False)

    @field_validator("environmentId")
    @classmethod
    def environment_id(cls, value: str) -> str:
        return uuid_text(value)

    @field_validator("managementPublicIp", "gatewayPublicIp")
    @classmethod
    def public_ip(cls, value: str) -> str:
        return Endpoint.global_ip(value)


class ConnectionDetails:
    def __init__(self, environments: EnvironmentDecommissions, secrets) -> None:
        self.environments, self.secrets = environments, secrets
        self.registry, self.operations = environments.registry, environments.operations

    def _operation(self, customer_id: str, environment_id: str) -> dict:
        customer = self.registry._customer(customer_id)
        if customer.get("status") != "Ready":
            raise EnrollmentError(409, "EnrollmentNotReady")
        identity = self.environments._identity(customer)
        try:
            row = self.operations.get(self.environments.partition, "op:" + environment_id)
        except Exception:
            raise EnrollmentError(503, "OperationsStoreUnavailable") from None
        if not self.environments._owned(row, identity):
            raise EnrollmentError(404, "EnvironmentNotFound")
        if row.get("decommissionState") in ("Deleting", "Decommissioned"):
            raise EnrollmentError(409, "EnvironmentDecommissioned")
        return row

    def _audit(self, customer_id: str, actor: str, event: str, environment_id: str = "") -> None:
        self.registry._transact([Change({
            "PartitionKey": PARTITION, "RowKey": "audit:" + str(uuid4()),
            "customerId": customer_id, "actorOid": uuid_text(actor), "event": event,
            "environmentId": environment_id, "timestamp": time.time(),
        })])

    def publish(self, body: CheckpointAccess, actor: str) -> dict:
        try:
            operation = self.operations.get(self.environments.partition, "op:" + body.environmentId)
        except Exception:
            raise EnrollmentError(503, "OperationsStoreUnavailable") from None
        index = self.registry._get("client:" + str((operation or {}).get("client", "")))
        if not index:
            raise EnrollmentError(404, "EnvironmentNotFound")
        customer_id = str(index["customerId"])
        operation = self._operation(customer_id, body.environmentId)
        customer = self.registry._customer(customer_id)
        request, _, _ = parse_stored_environment_request(operation["request"])
        if (customer.get("status") != "Ready" or request.firewallType not in CHECKPOINT_TOPOLOGIES
                or operation["providerGroupName"] != body.providerGroupName
                or operation.get("status") not in ("Running", "Ready")):
            raise EnrollmentError(409, "ConnectionDetailsPublicationRejected")
        tags = {"environmentId": body.environmentId, "customerId": customer_id,
                "purpose": "checkpoint-admin-access"}
        self._audit(customer_id, actor, "ConnectionDetailsPublishClaimed", body.environmentId)
        try:
            self.secrets.set_secret("cp-access-" + body.environmentId, body.model_dump_json(),
                                    content_type=CONTENT_TYPE, tags=tags, logging_enable=False)
        except AzureError:
            raise EnrollmentError(503, "ConnectionDetailsVaultWriteFailed") from None
        return {"status": "stored"}

    def register_routing(self, customer_id: str, environment_id: str,
                         address: RoutingAddress, actor: str) -> dict:
        self._operation(customer_id, environment_id)
        self._audit(customer_id, actor, "CustomerRoutingAddressRegistered", environment_id)
        for _ in range(8):
            previous = self.registry._get("routing:" + environment_id)
            if previous and previous.get("customerId") != customer_id:
                raise EnrollmentError(404, "EnvironmentNotFound")
            row = {
                "PartitionKey": PARTITION, "RowKey": "routing:" + environment_id,
                "customerId": customer_id, "routingApplianceIp": address.routingApplianceIp,
            }
            try:
                self.registry._transact([Change(row, str(previous["_etag"]) if previous else None)])
                return {"status": "registered"}
            except Conflict:
                continue
        raise EnrollmentError(409, "RoutingRegistrationContention")

    def reveal(self, customer_id: str, actor: str) -> list[dict]:
        self._audit(customer_id, actor, "ConnectionDetailsRevealClaimed")
        result = []
        for view in self.environments.environments(customer_id):
            if view.get("decommissionState") in ("Deleting", "Decommissioned"):
                continue
            row = self._operation(customer_id, view["environmentId"])
            request, _, _ = parse_stored_environment_request(row["request"])
            if request.firewallType not in CHECKPOINT_TOPOLOGIES:
                continue
            routing = row.get("customerRoutingApplianceIp")
            if not routing:
                previous = self.registry._get("routing:" + view["environmentId"])
                if previous and previous.get("customerId") == customer_id:
                    routing = previous.get("routingApplianceIp")
            if routing:
                routing = RoutingAddress(routingApplianceIp=routing).routingApplianceIp
            item = {
                "environmentId": view["environmentId"], "status": view["status"],
                "routing": {
                    "nextHopType": "VirtualAppliance", "nextHopIp": routing,
                    "status": "registered" if routing else "CustomerRoutingAddressNotRegistered",
                    "instructions": (
                        "On customer workload subnets, route remote workload prefixes and 0.0.0.0/0 "
                        "to the customer Routing Appliance IP. Keep BGP route propagation enabled. "
                        "Configure customer-side peering/gateway transit for new VNets; "
                        "a default route alone does not override more-specific peering routes. "
                        "Do not use the provider firewall IP as the customer UDR next hop. "
                        "Customer VNet changes must not require provider-side route or NAT changes."
                    ),
                },
                "credentialStatus": "EnvironmentNotReady",
            }
            if view["status"] == "Ready":
                try:
                    secret = self.secrets.get_secret("cp-access-" + view["environmentId"],
                                                     logging_enable=False)
                except ResourceNotFoundError:
                    item["credentialStatus"] = "PrivateConnectionDetailsNotPublished"
                except AzureError:
                    raise EnrollmentError(503, "ConnectionDetailsVaultReadFailed") from None
                else:
                    properties = secret.properties
                    if (properties.enabled is not True or properties.content_type != CONTENT_TYPE
                            or properties.tags != {
                                "environmentId": view["environmentId"], "customerId": customer_id,
                                "purpose": "checkpoint-admin-access"}):
                        raise EnrollmentError(503, "ConnectionDetailsBindingInvalid")
                    try:
                        access = CheckpointAccess.model_validate_json(secret.value)
                    except ValueError:
                        raise EnrollmentError(503, "ConnectionDetailsInvalid") from None
                    if (access.environmentId != view["environmentId"]
                            or access.providerGroupName != row["providerGroupName"]):
                        raise EnrollmentError(503, "ConnectionDetailsBindingInvalid")
                    self._operation(customer_id, view["environmentId"])
                    gateway = {
                        "username": "admin", "publicIp": access.gatewayPublicIp,
                        "frontendPrivateIp": "172.22.10.4", "backendPrivateIp": "172.22.20.4",
                        "httpsUrl": "https://" + access.gatewayPublicIp,
                        "ssh": "ssh -i <provider-private-key> admin@" + access.gatewayPublicIp,
                        "authentication": (
                            "Deployment uses the provider SSH key; no gateway password is managed. "
                            "Any manually configured web password is unchanged and is not recoverable here."
                        ),
                    }
                    if CHECKPOINT_TOPOLOGIES[request.firewallType] == "vmss":
                        gateway = {
                            "username": "admin", "topology": "Two-instance scale set",
                            "publicLoadBalancerIp": access.gatewayPublicIp,
                            "internalLoadBalancerIp": "172.22.20.4",
                            "instanceFrontendPrivateIps": ["172.22.10.4", "172.22.10.5"],
                            "ssh": "ssh -i <provider-private-key> admin@<instance public IP>",
                            "authentication": gateway["authentication"] + (
                                " Each instance has its own public IP, shown on the scale set's "
                                "Instances > Networking page; the public load balancer forwards TCP 80 only."),
                        }
                    item.update(credentialStatus="available", management={
                        "username": "admin", "publicIp": access.managementPublicIp,
                        "privateIp": "172.22.30.4", "httpsUrl": "https://" + access.managementPublicIp,
                        "ssh": "ssh admin@" + access.managementPublicIp,
                        "password": access.managementPassword,
                    }, gateway=gateway)
            result.append(item)
        return result
