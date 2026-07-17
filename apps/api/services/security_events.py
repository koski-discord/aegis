from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from aegis_core.models import SecurityEvent


async def record_security_event(
    db: AsyncSession,
    *,
    owner_id: UUID | None,
    event_type: str,
    request_id: str | None = None,
    metadata: dict[str, str | int | bool] | None = None,
) -> None:
    db.add(
        SecurityEvent(
            owner_id=owner_id,
            event_type=event_type,
            request_id=request_id,
            metadata_=metadata or {},
        )
    )
