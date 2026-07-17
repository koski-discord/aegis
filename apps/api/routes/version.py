from fastapi import APIRouter

from apps.api.schemas.common import VersionInfo

router = APIRouter(tags=["version"])


@router.get("/version", response_model=VersionInfo)
async def version() -> VersionInfo:
    return VersionInfo()
