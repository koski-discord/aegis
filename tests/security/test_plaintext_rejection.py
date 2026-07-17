import pytest
from pydantic import ValidationError

from apps.api.schemas.vault import EncryptedRecordIn, VaultCreate


def encrypted_record_payload() -> dict[str, object]:
    return {
        "ciphertext": "ciphertext",
        "nonce": "nonce-value-with-length",
        "encrypted_metadata": "metadata",
        "metadata_nonce": "metadata-nonce-value",
        "algorithm_version": "AES-256-GCM-v1",
        "kdf_version": 1,
    }


@pytest.mark.parametrize("field", ["password", "secret", "plaintext", "recovery_key", "username"])
def test_record_schema_rejects_plaintext_like_fields(field: str) -> None:
    payload = encrypted_record_payload()
    payload[field] = "should-not-arrive-at-api"

    with pytest.raises(ValidationError):
        EncryptedRecordIn.model_validate(payload)


def test_vault_schema_rejects_plaintext_metadata() -> None:
    with pytest.raises(ValidationError):
        VaultCreate.model_validate(
            {
                "kdf_salt": "long-enough-random-salt",
                "kdf_params": {"algorithm": "argon2id"},
                "encrypted_vault_metadata": "ciphertext",
                "metadata_nonce": "metadata-nonce-value",
                "password": "not allowed",
            }
        )
