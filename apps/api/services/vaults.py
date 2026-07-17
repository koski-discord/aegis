from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_core.exceptions import ConflictError, NotFoundError
from aegis_core.models import EncryptedRecord, User, Vault
from aegis_core.security.tokens import utcnow
from apps.api.schemas.vault import EncryptedRecordIn, EncryptedRecordUpdate, VaultCreate


async def create_vault(db: AsyncSession, owner: User, payload: VaultCreate) -> Vault:
    existing = await db.execute(select(Vault).where(Vault.owner_id == owner.id, Vault.deleted_at.is_(None)))
    if existing.scalar_one_or_none() is not None:
        raise ConflictError("vault already exists")
    vault = Vault(owner_id=owner.id, **payload.model_dump())
    db.add(vault)
    await db.flush()
    return vault


async def get_vault(db: AsyncSession, owner: User) -> Vault:
    result = await db.execute(select(Vault).where(Vault.owner_id == owner.id, Vault.deleted_at.is_(None)))
    vault = result.scalar_one_or_none()
    if vault is None:
        raise NotFoundError("vault not found")
    return vault


async def create_record(db: AsyncSession, owner: User, vault: Vault, payload: EncryptedRecordIn) -> EncryptedRecord:
    record = EncryptedRecord(owner_id=owner.id, vault_id=vault.id, **payload.model_dump())
    db.add(record)
    await db.flush()
    return record


async def list_records(db: AsyncSession, owner: User, vault: Vault) -> list[EncryptedRecord]:
    result = await db.execute(
        select(EncryptedRecord)
        .where(
            EncryptedRecord.owner_id == owner.id,
            EncryptedRecord.vault_id == vault.id,
            EncryptedRecord.deleted_at.is_(None),
        )
        .order_by(EncryptedRecord.created_at.desc())
    )
    return list(result.scalars())


async def get_record(db: AsyncSession, owner: User, record_id: UUID) -> EncryptedRecord:
    result = await db.execute(
        select(EncryptedRecord).where(
            EncryptedRecord.id == record_id,
            EncryptedRecord.owner_id == owner.id,
            EncryptedRecord.deleted_at.is_(None),
        )
    )
    record = result.scalar_one_or_none()
    if record is None:
        raise NotFoundError("record not found")
    return record


async def update_record(
    db: AsyncSession, owner: User, record_id: UUID, payload: EncryptedRecordUpdate
) -> EncryptedRecord:
    record = await get_record(db, owner, record_id)
    if record.record_version != payload.expected_version:
        raise ConflictError("record version conflict")
    data = payload.model_dump(exclude={"expected_version"})
    for key, value in data.items():
        setattr(record, key, value)
    record.record_version += 1
    await db.flush()
    return record


async def delete_record(db: AsyncSession, owner: User, record_id: UUID) -> None:
    record = await get_record(db, owner, record_id)
    record.deleted_at = utcnow()
