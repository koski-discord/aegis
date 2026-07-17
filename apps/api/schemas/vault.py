from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from apps.api.schemas.common import StrictEncryptedModel


class VaultCreate(StrictEncryptedModel):
    kdf_salt: str = Field(min_length=16, max_length=128)
    kdf_params: dict[str, int | str] = Field(default_factory=dict)
    encrypted_vault_metadata: str = Field(min_length=1, max_length=65536)
    metadata_nonce: str = Field(min_length=16, max_length=64)
    kdf_version: int = 1


class VaultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    kdf_salt: str
    kdf_params: dict[str, int | str]
    kdf_version: int
    encrypted_vault_metadata: str
    metadata_nonce: str
    version: int
    created_at: datetime
    updated_at: datetime


class EncryptedRecordIn(StrictEncryptedModel):
    ciphertext: str = Field(min_length=1, max_length=131072)
    nonce: str = Field(min_length=16, max_length=64)
    encrypted_metadata: str = Field(min_length=1, max_length=65536)
    metadata_nonce: str = Field(min_length=16, max_length=64)
    algorithm_version: str = Field(pattern=r"^(AES-256-GCM|XCHACHA20-POLY1305)-v[0-9]+$")
    kdf_version: int = Field(ge=1)
    schema_version: int = Field(default=1, ge=1)


class EncryptedRecordUpdate(EncryptedRecordIn):
    expected_version: int = Field(ge=1)


class EncryptedRecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    vault_id: UUID
    ciphertext: str
    nonce: str
    encrypted_metadata: str
    metadata_nonce: str
    algorithm_version: str
    kdf_version: int
    record_version: int
    schema_version: int
    created_at: datetime
    updated_at: datetime


class BackupOut(BaseModel):
    vault: VaultOut
    records: list[EncryptedRecordOut]
