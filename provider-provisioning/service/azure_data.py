from azure.core import MatchConditions
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.data.tables import TableClient, UpdateMode
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from dataclasses import dataclass
from typing import Callable

from .store import Change, Conflict, Row


class TableBackend:
    def __init__(self, endpoint: str, credential: ManagedIdentityCredential,
                 table_name: str = "Operations") -> None:
        if table_name not in {"Operations", "Customers", "Bootstrap"}:
            raise ValueError("Unsupported state table")
        self.client = TableClient(endpoint, table_name, credential=credential,
                                  logging_enable=False, retry_total=0,
                                  connection_timeout=5, read_timeout=20)

    @staticmethod
    def _row(entity) -> Row:
        row = dict(entity)
        row["_etag"] = entity.metadata["etag"]
        return row

    def get(self, partition: str, key: str) -> Row | None:
        try:
            return self._row(self.client.get_entity(partition, key))
        except ResourceNotFoundError:
            return None

    def transact(self, changes: list[Change]) -> None:
        operations = []
        for change in changes:
            entity = {key: value for key, value in change.row.items() if key != "_etag"}
            if change.etag:
                operations.append(("update", entity, {
                    "mode": UpdateMode.REPLACE, "etag": change.etag,
                    "match_condition": MatchConditions.IfNotModified,
                }))
            else:
                operations.append(("create", entity))
        try:
            self.client.submit_transaction(operations)
        except HttpResponseError as exc:
            if exc.status_code in (409, 412):
                raise Conflict() from None
            raise

    def jobs(self, partition: str) -> list[Row]:
        # Partition values are server configuration, and still use SDK escaping.
        query = ("PartitionKey eq @partition and "
                 "(status eq 'pending' or status eq 'retry' or status eq 'busy')")
        result = []
        for entity in self.client.query_entities(query, parameters={"partition": partition},
                                                 results_per_page=100):
            if str(entity["RowKey"]).startswith("job:"):
                result.append(self._row(entity))
            if len(result) >= 100:
                break
        return result

    def list_rows(self, partition: str, prefix: str = "", limit: int = 100) -> list[Row]:
        if not 1 <= limit <= 1001:
            raise ValueError("Invalid row limit")
        query = "PartitionKey eq @partition"
        parameters = {"partition": partition}
        if prefix:
            if not prefix.isascii() or not all(32 <= ord(char) < 127 for char in prefix):
                raise ValueError("Invalid row prefix")
            query += " and RowKey ge @prefix and RowKey lt @end"
            parameters.update(prefix=prefix, end=prefix[:-1] + chr(ord(prefix[-1]) + 1))
        rows = []
        for entity in self.client.query_entities(
                query, parameters=parameters,
                results_per_page=100):
            if str(entity["RowKey"]).startswith(prefix):
                rows.append(self._row(entity))
                if len(rows) == limit:
                    break
        return rows

    def close(self) -> None:
        self.client.close()


def secret_names(environment_id: str) -> tuple[str, str]:
    from uuid import UUID
    if str(UUID(environment_id)) != environment_id:
        raise ValueError("Invalid environment ID")
    return f"env-{environment_id}-ingress", f"env-{environment_id}-delivery"


class Vault:
    def __init__(self, url: str, credential: ManagedIdentityCredential) -> None:
        self.client = SecretClient(url, credential, logging_enable=False, retry_total=2,
                                   connection_timeout=5, read_timeout=20)

    def read(self, name: str, version: str | None = None) -> str:
        value = self.client.get_secret(name, version).value
        if not value:
            raise ValueError("Empty exchange secret")
        return value

    def ensure(self, name: str, check_lease: Callable[[], None]) -> "SecretMaterial":
        import secrets
        check_lease()
        try:
            secret = self.client.get_secret(name)
        except ResourceNotFoundError:
            check_lease()
            value = secrets.token_urlsafe(32)
            secret = self.client.set_secret(name, value, content_type="application/ipsec-psk")
        check_lease()
        if not secret.value or not secret.properties.version:
            raise ValueError("Invalid exchange secret")
        return SecretMaterial(secret.value, secret.properties.version)

    def close(self) -> None:
        self.client.close()


@dataclass(frozen=True, repr=False)
class SecretMaterial:
    value: str
    version: str
