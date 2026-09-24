from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database.session import get_db
from app.files.models import File as FileModel, ActivityLog
from app.security.jwt_handler import get_current_user, CurrentUser
from app.security.rate_limit import redis_client
import json

router = APIRouter(prefix="/analytics", tags=["Analytics"])
settings = get_settings()

DASHBOARD_CACHE_SECONDS = 60


@router.get("/dashboard")
def my_dashboard(db: Session = Depends(get_db), cu: CurrentUser = Depends(get_current_user)):

    cache_key = f"dashboard:{cu.id}"
    cached = redis_client.get(cache_key)
    if cached:
        return json.loads(cached)

    # SQL-side aggregation instead of `.all()` + Python sum/Counter - the
    # old version pulled every one of the user's file rows into memory on
    # every dashboard view just to add up their sizes and count mime types.
    base_filter = (FileModel.owner_id == cu.id, FileModel.is_deleted.is_(False))

    totals = (
        db.query(func.count(FileModel.id), func.coalesce(func.sum(FileModel.size_bytes), 0))
        .filter(*base_filter)
        .one()
    )
    total_files, total_size = totals

    type_counts = (
        db.query(FileModel.mime_type, func.count(FileModel.id))
        .filter(*base_filter)
        .group_by(FileModel.mime_type)
        .all()
    )

    upload_count = (
        db.query(func.count(ActivityLog.id))
        .filter(ActivityLog.user_id == cu.id, ActivityLog.action == "UPLOAD")
        .scalar()
    )
    download_count = (
        db.query(func.count(ActivityLog.id))
        .filter(ActivityLog.user_id == cu.id, ActivityLog.action == "DOWNLOAD")
        .scalar()
    )

    result = {
        "total_files": total_files,
        "total_storage_bytes": int(total_size),
        "files_by_type": {mime: count for mime, count in type_counts},
        "upload_count": upload_count,
        "download_count": download_count,
    }

    # file set changes meaningfully within a minute, and this is a
    # per-user cache key so one user's stale count never leaks to another.
    redis_client.setex(cache_key, DASHBOARD_CACHE_SECONDS, json.dumps(result))
    return result
