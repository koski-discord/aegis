import hashlib

from fastapi import APIRouter, Depends
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_core.models import DeletedAccountTombstone, User
from aegis_core.security.tokens import utcnow
from apps.api.dependencies.context import current_user, get_db
from apps.api.services.security_events import record_security_event

router = APIRouter(prefix="/account", tags=["account"])


@router.delete("", status_code=204)
async def delete_account(db: AsyncSession = Depends(get_db), user: User = Depends(current_user)) -> None:
    await record_security_event(db, owner_id=user.id, event_type="account_deletion")
    tombstone = DeletedAccountTombstone(
        discord_user_id_hash=hashlib.sha256(str(user.discord_user_id).encode()).hexdigest(),
        deleted_at=utcnow(),
        reason="user_requested",
    )
    db.add(tombstone)
    await db.execute(delete(User).where(User.id == user.id))
    await db.commit()
