import secrets
from dataclasses import dataclass


@dataclass(frozen=True, repr=False)
class CheckpointCredentials:
    management_password: str
    sic_key: str


def generate_checkpoint_credentials() -> CheckpointCredentials:
    return CheckpointCredentials(
        management_password="Aa1!" + secrets.token_urlsafe(32),
        sic_key=secrets.token_hex(24),
    )
