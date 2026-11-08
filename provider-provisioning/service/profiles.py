import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

from azure.core.exceptions import ResourceExistsError
from azure.storage.blob import BlobServiceClient, ContentSettings, generate_blob_sas, BlobSasPermissions

from .config import endpoint, uuid_text
from .enrollment import CustomerBinding
from .admin_access import normalize_admin_sources
from .deployment_scope import ProviderScope, ScopeSelectionError, bind_scope

ADMIN_SOURCES_FORM_OUTPUT = (
    "[if(or(equals(steps('basics').firewallType, 'ubuntu'), "
    "empty(replace(coalesce(steps('basics').adminAllowedSources, ''), ' ', ''))), parse('[]'), "
    "split(replace(coalesce(steps('basics').adminAllowedSources, ''), ' ', ''), ','))]")
FIREWALL_TYPES = ["ubuntu", "checkpoint-byol", "checkpoint-vmss"]


class ProfilePublisher:
    def __init__(self, credential, account_url: str, api_url: str, api_resource: str,
                 authority_tenant: str, template_directory: Path | None = None,
                 admin_allowed_sources: list[str] | None = None,
                 provider_scope: ProviderScope | None = None) -> None:
        self.provider_scope = provider_scope
        self.admin_sources = normalize_admin_sources([] if admin_allowed_sources is None else admin_allowed_sources)
        self.api_url = endpoint(api_url, ".azurewebsites.net")
        self.authority = uuid_text(authority_tenant)
        if provider_scope is not None and provider_scope.tenant != self.authority:
            raise ValueError("Provider scope authority does not match the provider tenant")
        if not api_resource.startswith("api://"):
            raise ValueError("Invalid API resource")
        uuid_text(api_resource.removeprefix("api://"))
        self.api_resource = api_resource
        self.directory = template_directory or Path(__file__).parent / "templates"
        if not all((self.directory / name).is_file()
                   for name in ("customer.json", "customer-connections.json", "customer-form.json")):
            raise ValueError("Compiled customer release assets are missing")
        account_url = endpoint(account_url, ".blob.core.windows.net")
        self.account = urlsplit(account_url).hostname.split(".")[0]
        self.blobs = BlobServiceClient(account_url, credential=credential, logging_enable=False,
                                       retry_total=2, connection_timeout=5, read_timeout=20)

    def documents(self, customer: CustomerBinding) -> tuple[dict, dict]:
        template = copy.deepcopy(json.loads((self.directory / "customer.json").read_text()))
        connections = json.loads((self.directory / "customer-connections.json").read_text())
        form = copy.deepcopy(json.loads((self.directory / "customer-form.json").read_text()))
        network = [resource for resource in template.get("resources", [])
                   if resource.get("type") == "Microsoft.Resources/deployments"
                   and resource.get("name") == "customer-provider-connection"]
        if len(network) != 1:
            raise ValueError("Customer network template is missing")
        nested = network[0].get("properties", {}).get("template", {})
        variables = nested.get("variables", {})
        if (not isinstance(variables, dict)
                or not any(isinstance(value, str) and "/retry-group" in value
                           and "GroupOwnershipError" in value for value in variables.values())
                or form.get("view", {}).get("properties", {}).get("title") !=
                "FaaS customer deployment - recovery-enabled release"):
            raise ValueError("Customer recovery release is incomplete")
        parameters = template["parameters"]
        secret = parameters["apiClientSecret"]
        if secret.get("type", "").lower() != "securestring" or "defaultValue" in secret:
            raise ValueError("Customer secret must not have a template default")
        import base64
        defaults = {
            "runId": "cust-" + customer.customer_id.replace("-", "")[:18],
            "deploymentMode": "network",
            "expectedCustomerTenantId": customer.tenant,
            "expectedCustomerSubscriptionId": customer.subscription,
            "enrolledCustomerResourceGroupId": "",
            "apiUrl": self.api_url,
            "apiResource": self.api_resource,
            "apiAuthorityTenantId": self.authority,
            "apiClientId": customer.client,
            "customerConnectionsTemplateBase64": base64.b64encode(
                json.dumps(connections, separators=(",", ":")).encode()).decode(),
        }
        for key, value in defaults.items():
            parameters[key]["defaultValue"] = value
        fields = {item["name"]: item for step in form["view"]["properties"]["steps"]
                  for item in step["elements"]}
        proof = [resource for resource in template.get("resources", [])
                 if resource.get("type") == "Microsoft.Resources/deployments"
                 and resource.get("name") == "customer-authorization-proof"]
        firewall = parameters.get("firewallType", {})
        firewall_field = fields.get("firewallType", {})
        choices = firewall_field.get("constraints", {}).get("allowedValues", [])

        def firewall_preflight(resource: dict) -> bool:
            properties = resource.get("properties", {})
            nested = properties.get("template", {})
            variables = nested.get("variables", {})
            resources = nested.get("resources", [])
            if not isinstance(resources, list) or not all(isinstance(item, dict) for item in resources):
                return False
            scripts = [item for item in resources if item.get("type") == "Microsoft.Resources/deploymentScripts"]
            if len(scripts) != 1:
                return False
            environment = scripts[0].get("properties", {}).get("environmentVariables", [])
            if not isinstance(environment, list) or not all(isinstance(item, dict) for item in environment):
                return False
            selection = [item for item in environment
                         if item.get("name") == "FAAS_FIREWALL_TYPE"]
            return (properties.get("parameters", {}).get("firewallType", {}).get("value")
                    == "[parameters('firewallType')]"
                    and selection == [{"name": "FAAS_FIREWALL_TYPE", "value": "[parameters('firewallType')]"}]
                    and isinstance(variables, dict)
                    and any(isinstance(value, str)
                            and "/v1/firewall-types/checkpoint-byol/readiness" in value
                            and "FirewallUnavailable" in value for value in variables.values()))

        if (len(proof) != 1
                or firewall.get("defaultValue") != "ubuntu"
                or firewall.get("allowedValues") != FIREWALL_TYPES
                or not isinstance(choices, list)
                or not all(isinstance(item, dict) for item in choices)
                or [item.get("value") for item in choices] != FIREWALL_TYPES
                or firewall_field.get("defaultValue") != next(
                    (item.get("label") for item in choices if item.get("value") == "checkpoint-vmss"), None)
                or form.get("view", {}).get("outputs", {}).get("parameters", {}).get("firewallType")
                != "[steps('basics').firewallType]"
                or not all(firewall_preflight(resource) for resource in (proof[0], network[0]))):
            raise ValueError("Customer firewall selection release is incomplete")
        if self.admin_sources or "adminAllowedSources" in parameters:
            admin = parameters.get("adminAllowedSources", {})
            admin_field = fields.get("adminAllowedSources", {})
            complete = (
                admin.get("type") == "array" and admin.get("defaultValue") == []
                and admin.get("maxLength") == 16
                and admin_field.get("type") == "Microsoft.Common.TextBox"
                and admin_field.get("visible") == "[not(equals(steps('basics').firewallType, 'ubuntu'))]"
                and form["view"]["outputs"]["parameters"].get("adminAllowedSources") == ADMIN_SOURCES_FORM_OUTPUT)
            for resource in (proof[0], network[0]):
                properties = resource["properties"]
                scripts = [item for item in properties["template"]["resources"]
                           if item.get("type") == "Microsoft.Resources/deploymentScripts"]
                environment = scripts[0]["properties"]["environmentVariables"]
                complete = complete and (
                    properties.get("parameters", {}).get("adminAllowedSources", {}).get("value")
                    == "[parameters('adminAllowedSources')]"
                    and [item for item in environment if item.get("name") == "FAAS_ADMIN_ALLOWED_SOURCES"]
                    == [{"name": "FAAS_ADMIN_ALLOWED_SOURCES",
                         "value": "[string(parameters('adminAllowedSources'))]"}])
            if not complete:
                raise ValueError("Customer admin access release is incomplete")
            parameters["adminAllowedSources"]["defaultValue"] = self.admin_sources
            fields["adminAllowedSources"]["defaultValue"] = ", ".join(self.admin_sources)
        if (fields["apiClientSecret"].get("type") != "Microsoft.Common.PasswordBox"
                or "defaultValue" in fields["apiClientSecret"]
                or fields["apiClientSecret"].get("visible") is False
                or not fields["apiClientSecret"].get("constraints", {}).get("required")):
            raise ValueError("Customer secret must be a required empty UI field")
        fields["apiClientId"]["defaultValue"] = customer.client
        fields["runId"].update(defaultValue=defaults["runId"], visible=False)
        if self.provider_scope is not None:
            try:
                self.provider_scope.validate(customer.scope_mode, customer.provider_lab_acknowledged,
                                             customer.tenant, customer.subscription)
            except ScopeSelectionError as error:
                raise ValueError("Provider lab enrollment scope is invalid") from error
        if customer.scope_mode == "provider-lab":
            if self.provider_scope is None:
                raise ValueError("Provider scope is not configured")
        bind_scope(parameters, fields, customer.scope_mode, customer.tenant, customer.subscription,
                   self.provider_scope.protected_groups if self.provider_scope is not None else ())
        return template, form

    def publish(self, customer: CustomerBinding) -> dict:
        container = self.blobs.get_container_client("deployment-artifacts")
        properties = container.get_container_properties()
        if properties.public_access:
            raise ValueError("Artifact container must not allow anonymous access")
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(hours=4)
        delegation = self.blobs.get_user_delegation_key(now - timedelta(minutes=5), expiry)
        uris = []
        for name, document in zip(("azuredeploy.json", "uiFormDefinition.json"),
                                  self.documents(customer), strict=True):
            data = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
            digest = hashlib.sha256(data).hexdigest()
            blob = container.get_blob_client(f"customers/{customer.customer_id}/{digest}/{name}")
            try:
                blob.upload_blob(data, overwrite=False, metadata={"sha256": digest},
                                 content_settings=ContentSettings(content_type="application/json"))
            except ResourceExistsError:
                if blob.get_blob_properties().metadata.get("sha256") != digest:
                    raise ValueError("Existing customer artifact hash mismatch") from None
            signature = generate_blob_sas(
                self.account, container.container_name, blob.blob_name,
                user_delegation_key=delegation, permission=BlobSasPermissions(read=True),
                start=now - timedelta(minutes=5), expiry=expiry, protocol="https",
            )
            uris.append(blob.url + "?" + signature)
        return {
            "portalUrl": "https://portal.azure.com/#create/Microsoft.Template/uri/"
                         + quote(uris[0], safe="") + "/uiFormDefinitionUri/"
                         + quote(uris[1], safe=""),
            "expiresAt": expiry.isoformat(),
        }

    def close(self) -> None:
        self.blobs.close()
