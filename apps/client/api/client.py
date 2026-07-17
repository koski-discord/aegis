from typing import Any

import httpx

from apps.client.models.records import EncryptedPayload


class AegisApiClient:
    def __init__(self, base_url: str, access_token: str, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.access_token = access_token
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}

    async def create_vault(
        self, *, salt: str, params: dict[str, int | str], metadata: EncryptedPayload
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/api/v1/vault",
                headers=self._headers(),
                json={
                    "kdf_salt": salt,
                    "kdf_params": params,
                    "encrypted_vault_metadata": metadata.encrypted_metadata,
                    "metadata_nonce": metadata.metadata_nonce,
                    "kdf_version": 1,
                },
            )
            response.raise_for_status()
            return dict(response.json())

    async def get_vault(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(f"{self.base_url}/api/v1/vault", headers=self._headers())
            response.raise_for_status()
            return dict(response.json())

    async def create_record(self, payload: EncryptedPayload) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/api/v1/vault/records",
                headers=self._headers(),
                json=payload.model_dump(),
            )
            response.raise_for_status()
            return dict(response.json())

    async def list_records(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(f"{self.base_url}/api/v1/vault/records", headers=self._headers())
            response.raise_for_status()
            return list(response.json())

    async def get_record(self, record_id: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(f"{self.base_url}/api/v1/vault/records/{record_id}", headers=self._headers())
            response.raise_for_status()
            return dict(response.json())

    async def update_record(self, record_id: str, payload: EncryptedPayload, expected_version: int) -> dict[str, Any]:
        data = payload.model_dump()
        data["expected_version"] = expected_version
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.put(
                f"{self.base_url}/api/v1/vault/records/{record_id}",
                headers=self._headers(),
                json=data,
            )
            response.raise_for_status()
            return dict(response.json())

    async def delete_record(self, record_id: str) -> None:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.delete(f"{self.base_url}/api/v1/vault/records/{record_id}", headers=self._headers())
            response.raise_for_status()

    async def export_backup(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(f"{self.base_url}/api/v1/vault/backup", headers=self._headers())
            response.raise_for_status()
            return dict(response.json())


def encrypted_payload_from_api(data: dict[str, Any]) -> EncryptedPayload:
    fields = [
        "ciphertext",
        "nonce",
        "encrypted_metadata",
        "metadata_nonce",
        "algorithm_version",
        "kdf_version",
        "schema_version",
    ]
    return EncryptedPayload.model_validate({key: data[key] for key in fields})
