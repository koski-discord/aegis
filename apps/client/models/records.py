from pydantic import BaseModel, ConfigDict, Field


class PlainRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=256)
    username: str = Field(default="", max_length=1024)
    password: str = Field(min_length=1, max_length=8192)
    url: str = Field(default="", max_length=2048)
    notes: str = Field(default="", max_length=8192)


class EncryptedPayload(BaseModel):
    ciphertext: str
    nonce: str
    encrypted_metadata: str
    metadata_nonce: str
    algorithm_version: str = "AES-256-GCM-v1"
    kdf_version: int = 1
    schema_version: int = 1


class LocalProfile(BaseModel):
    api_base_url: str
    access_token: str
    kdf_salt: str | None = None
    kdf_params: dict[str, int | str] | None = None
