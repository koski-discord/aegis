from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_core.models import SecurityEvent, User
from apps.api.dependencies.context import current_user, get_db

router = APIRouter(prefix="/security", tags=["security"])


@router.get("/events")
async def events(db: AsyncSession = Depends(get_db), user: User = Depends(current_user)) -> list[dict[str, object]]:
    result = await db.execute(
        select(SecurityEvent)
        .where(SecurityEvent.owner_id == user.id)
        .order_by(SecurityEvent.created_at.desc())
        .limit(100)
    )
    return [
        {
            "id": str(event.id),
            "event_type": event.event_type,
            "created_at": event.created_at.isoformat(),
            "metadata": event.metadata_,
        }
        for event in result.scalars()
    ]
