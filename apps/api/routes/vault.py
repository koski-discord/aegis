from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_core.exceptions import ConflictError, NotFoundError
from aegis_core.models import User
from apps.api.dependencies.context import current_user, get_db, request_id
from apps.api.schemas.vault import (
    BackupOut,
    EncryptedRecordIn,
    EncryptedRecordOut,
    EncryptedRecordUpdate,
    VaultCreate,
    VaultOut,
)
from apps.api.services.security_events import record_security_event
from apps.api.services.vaults import (
    create_record,
    create_vault,
    delete_record,
    get_record,
    get_vault,
    list_records,
    update_record,
)

router = APIRouter(prefix="/vault", tags=["vault"])


def map_domain_error(exc: Exception) -> HTTPException:
    if isinstance(exc, NotFoundError):
        return HTTPException(status_code=404, detail="not found")
    if isinstance(exc, ConflictError):
        return HTTPException(status_code=409, detail="conflict")
    return HTTPException(status_code=400, detail="request failed")


@router.post("", response_model=VaultOut, status_code=201)
async def create(
    payload: VaultCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> VaultOut:
    try:
        vault = await create_vault(db, user, payload)
        await record_security_event(db, owner_id=user.id, event_type="vault_creation")
        await db.commit()
        return VaultOut.model_validate(vault)
    except (ConflictError, NotFoundError) as exc:
        raise map_domain_error(exc) from exc


@router.get("", response_model=VaultOut)
async def retrieve(db: AsyncSession = Depends(get_db), user: User = Depends(current_user)) -> VaultOut:
    try:
        return VaultOut.model_validate(await get_vault(db, user))
    except NotFoundError as exc:
        raise map_domain_error(exc) from exc


@router.post("/records", response_model=EncryptedRecordOut, status_code=201)
async def add_record(
    payload: EncryptedRecordIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> EncryptedRecordOut:
    try:
        vault = await get_vault(db, user)
        record = await create_record(db, user, vault, payload)
        await db.commit()
        return EncryptedRecordOut.model_validate(record)
    except (ConflictError, NotFoundError) as exc:
        raise map_domain_error(exc) from exc


@router.get("/records", response_model=list[EncryptedRecordOut])
async def records(db: AsyncSession = Depends(get_db), user: User = Depends(current_user)) -> list[EncryptedRecordOut]:
    try:
        vault = await get_vault(db, user)
        return [EncryptedRecordOut.model_validate(record) for record in await list_records(db, user, vault)]
    except NotFoundError as exc:
        raise map_domain_error(exc) from exc


@router.get("/records/{record_id}", response_model=EncryptedRecordOut)
async def record(
    record_id: UUID, db: AsyncSession = Depends(get_db), user: User = Depends(current_user)
) -> EncryptedRecordOut:
    try:
        return EncryptedRecordOut.model_validate(await get_record(db, user, record_id))
    except NotFoundError as exc:
        raise map_domain_error(exc) from exc


@router.put("/records/{record_id}", response_model=EncryptedRecordOut)
async def replace_record(
    record_id: UUID,
    payload: EncryptedRecordUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> EncryptedRecordOut:
    try:
        updated = await update_record(db, user, record_id, payload)
        await db.commit()
        return EncryptedRecordOut.model_validate(updated)
    except (ConflictError, NotFoundError) as exc:
        raise map_domain_error(exc) from exc


@router.delete("/records/{record_id}", status_code=204)
async def remove_record(
    record_id: UUID, db: AsyncSession = Depends(get_db), user: User = Depends(current_user)
) -> None:
    try:
        await delete_record(db, user, record_id)
        await db.commit()
    except NotFoundError as exc:
        raise map_domain_error(exc) from exc


@router.get("/backup", response_model=BackupOut)
async def export_backup(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    rid: str = Depends(request_id),
) -> BackupOut:
    try:
        vault = await get_vault(db, user)
        records = await list_records(db, user, vault)
        await record_security_event(db, owner_id=user.id, event_type="backup_export", request_id=rid)
        await db.commit()
        return BackupOut(
            vault=VaultOut.model_validate(vault),
            records=[EncryptedRecordOut.model_validate(record) for record in records],
        )
    except NotFoundError as exc:
        raise map_domain_error(exc) from exc


@router.post("/backup", status_code=204)
async def import_backup(_: BackupOut, response: Response) -> None:
    response.status_code = status.HTTP_204_NO_CONTENT
