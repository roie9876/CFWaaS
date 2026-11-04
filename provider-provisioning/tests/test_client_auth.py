import io
import json
from pathlib import Path
import sys
import time
import tempfile
import unittest
import urllib.error
import urllib.parse
from unittest.mock import MagicMock, patch
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import customer_connector as connector


def uid(value):
    return str(UUID(int=value))


def response(value):
    result = MagicMock()
    result.__enter__.return_value = io.BytesIO(json.dumps(value).encode())
    return result


class ClientAuthTests(unittest.TestCase):
    def test_selected_customer_region_reaches_reciprocal_connections(self):
        operation = {
            "operationId": uid(5), "environmentId": uid(5), "status": "Ready",
            "connectionManifest": {
                "providerIngress": {"publicIp": "192.0.2.10", "bgpAddress": "172.20.255.30", "asn": 65030},
                "providerDelivery": {"publicIp": "192.0.2.11", "bgpAddress": "172.21.255.30", "asn": 65031}},
        }
        material = {"environmentId": uid(5), "ingressSharedKey": "unit-ingress-material",
                    "deliverySharedKey": "unit-delivery-material"}
        writes = {}
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(Path, "cwd", return_value=Path(temporary)), \
                patch.object(connector, "validate_connection_template"), \
                patch.object(connector, "private_json",
                             side_effect=lambda path, value: writes.update({path.name: value})), \
                patch.object(connector, "configure_default_site") as default_site, \
                patch.object(connector, "az"):
            connector.deploy_connections(
                {"FAAS_RUN_ID": "unit-run", "FAAS_CUSTOMER_LOCATION": "northeurope"},
                operation, material, {}, uid(3), "my-customer-lab", time.monotonic() + 60)
        self.assertEqual(writes["parameters.json"]["parameters"]["location"]["value"], "northeurope")
        default_site.assert_called_once()

    def test_customer_can_select_dedicated_rg_but_not_foreign_resources(self):
        env = {
            "FAAS_CUSTOMER_SUBSCRIPTION_ID": uid(3), "FAAS_EXPECTED_CUSTOMER_SUBSCRIPTION_ID": uid(3),
            "FAAS_CUSTOMER_TENANT_ID": uid(4), "FAAS_EXPECTED_CUSTOMER_TENANT_ID": uid(4),
            "FAAS_CUSTOMER_RESOURCE_GROUP": "my-customer-lab",
            "FAAS_ENROLL_CUSTOMER_SCOPE": "true", "FAAS_RUN_ID": "unit-run",
        }
        account = {"id": uid(3), "tenantId": uid(4), "state": "Enabled"}
        group = {"id": f"/subscriptions/{uid(3)}/resourceGroups/my-customer-lab", "tags": {}}
        with patch.object(connector, "az", side_effect=[account, group, []]):
            self.assertEqual(connector.customer_scope(env, time.monotonic() + 60), (uid(3), "my-customer-lab"))
        with patch.object(connector, "az", side_effect=[
                account, group, [{"type": "Microsoft.Network/virtualNetworks", "tags": {}}]]):
            with self.assertRaisesRegex(ValueError, "dedicated RG"):
                connector.customer_scope(env, time.monotonic() + 60)
        env["FAAS_EXPECTED_CUSTOMER_SUBSCRIPTION_ID"] = uid(5)
        with patch.object(connector, "az") as azure:
            with self.assertRaisesRegex(ValueError, "subscription"):
                connector.customer_scope(env, time.monotonic() + 60)
            azure.assert_not_called()

    def credential(self):
        return connector.ApiCredential(uid(1), uid(2), "unit-only-api-credential")

    def test_oauth_secret_only_in_https_body_and_token_is_cached(self):
        opener = MagicMock()
        opener.open.return_value = response({
            "access_token": "unit-api-token", "token_type": "Bearer", "expires_in": 3600})
        auth = self.credential()
        with patch.object(connector.urllib.request, "build_opener", return_value=opener), \
                patch.object(connector, "az", side_effect=AssertionError("API auth must not change ARM login")):
            self.assertEqual(auth.token("api://" + uid(3), time.monotonic() + 60), "unit-api-token")
            self.assertEqual(auth.token("api://" + uid(3), time.monotonic() + 60), "unit-api-token")
        opener.open.assert_called_once()
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, f"https://login.microsoftonline.com/{uid(1)}/oauth2/v2.0/token")
        self.assertEqual(request.get_method(), "POST")
        body = urllib.parse.parse_qs(request.data.decode())
        self.assertEqual(body["client_secret"], [auth.secret])
        self.assertEqual(body["client_id"], [uid(2)])
        self.assertEqual(body["grant_type"], ["client_credentials"])
        self.assertEqual(body["scope"], ["api://" + uid(3) + "/.default"])
        self.assertNotIn(auth.secret, request.full_url)
        self.assertNotIn(auth.secret, str(request.headers))
        self.assertNotIn(auth.secret, repr(auth))

    def test_cached_token_cannot_be_requested_for_arm_or_another_api(self):
        auth = self.credential()
        auth._token, auth._expires, auth._resource = "cached-token", time.monotonic() + 600, "api://" + uid(3)
        with patch.object(connector.urllib.request, "build_opener") as network:
            for resource in ("https://management.azure.com", "api://" + uid(4)):
                with self.subTest(resource=resource), self.assertRaises(ValueError):
                    auth.token(resource, time.monotonic() + 60)
            network.assert_not_called()

    def test_invalid_oauth_responses_are_rejected(self):
        for value in (
            {"access_token": "unit-token", "token_type": "Bearer"},
            {"access_token": "", "token_type": "Bearer", "expires_in": 3600},
            {"access_token": "unit-token", "token_type": "Basic", "expires_in": 3600},
            {"access_token": "unit-token", "token_type": "Bearer", "expires_in": True},
        ):
            opener = MagicMock()
            opener.open.return_value = response(value)
            with self.subTest(value=value), patch.object(connector.urllib.request, "build_opener", return_value=opener):
                with self.assertRaises(ValueError):
                    self.credential().token("api://" + uid(3), time.monotonic() + 60)

    def test_provider_credential_failure_has_no_identity_fallback(self):
        for code in (401, 403, 302):
            opener = MagicMock()
            opener.open.side_effect = urllib.error.HTTPError("https://login.microsoftonline.com", code, "", {}, None)
            with self.subTest(code=code), patch.object(connector.urllib.request, "build_opener", return_value=opener), \
                    patch.object(connector, "az") as az:
                with self.assertRaises(RuntimeError):
                    connector.request("https://unit.azurewebsites.net", "api://" + uid(3),
                                      "/v1/environments", time.monotonic() + 60, {"mode": "proof"},
                                      "unit-proof", auth=self.credential())
                az.assert_not_called()
                opener.open.assert_called_once()

    def test_api_receives_access_token_not_client_secret(self):
        opener = MagicMock()
        opener.open.side_effect = [
            response({"access_token": "unit-api-token", "token_type": "Bearer", "expires_in": 3600}),
            response({"status": "Ready"}),
        ]
        auth = self.credential()
        with patch.object(connector.urllib.request, "build_opener", return_value=opener), \
                patch.object(connector, "az", side_effect=AssertionError("must not use ARM login for API")):
            connector.request("https://unit.azurewebsites.net", "api://" + uid(3),
                              "/v1/environments", time.monotonic() + 60, {"mode": "proof"},
                              "unit-proof", auth=auth)
        request = opener.open.call_args_list[1].args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer unit-api-token")
        self.assertNotIn(auth.secret, request.data.decode())
        self.assertNotIn(auth.secret, str(request.headers))

    def test_provider_mode_requires_complete_credentials_before_arm_login(self):
        env = {
            "FAAS_BACKING_APPROVED": "true", "FAAS_CONNECTOR_MODE": "proof",
            "FAAS_RUN_ID": "unit-run", "FAAS_WAIT_SECONDS": "600",
            "FAAS_API_URL": "https://unit.azurewebsites.net", "FAAS_API_RESOURCE": "api://" + uid(3),
            "FAAS_CUSTOMER_CLIENT_ID": uid(4), "FAAS_AUTH_MODE": "provider-api-client",
            "FAAS_API_AUTHORITY_TENANT_ID": uid(1), "FAAS_API_CLIENT_ID": uid(2),
        }
        with patch.object(connector, "az") as az:
            with self.assertRaises(KeyError):
                connector.run(env)
            az.assert_not_called()

    def test_customer_arm_login_stays_managed_identity(self):
        env = {
            "FAAS_BACKING_APPROVED": "true", "FAAS_CONNECTOR_MODE": "proof",
            "FAAS_RUN_ID": "unit-run", "FAAS_WAIT_SECONDS": "600",
            "FAAS_API_URL": "https://unit.azurewebsites.net", "FAAS_API_RESOURCE": "api://" + uid(3),
            "FAAS_CUSTOMER_CLIENT_ID": uid(4), "FAAS_AUTH_MODE": "provider-api-client",
            "FAAS_API_AUTHORITY_TENANT_ID": uid(1), "FAAS_API_CLIENT_ID": uid(2),
            "FAAS_API_CLIENT_SECRET": self.credential().secret,
        }
        result = {"operationId": uid(5), "environmentId": uid(5), "status": "Ready"}
        with patch.object(connector, "az") as az, patch.object(connector, "request", return_value=result) as api:
            connector.run(env)
        az.assert_called_once()
        arguments = az.call_args.args[0]
        self.assertEqual(arguments[:4], ["login", "--identity", "--client-id", uid(4)])
        self.assertNotIn(uid(2), arguments)
        self.assertNotIn(env["FAAS_API_CLIENT_SECRET"], arguments)
        self.assertIsInstance(api.call_args.kwargs["auth"], connector.ApiCredential)
