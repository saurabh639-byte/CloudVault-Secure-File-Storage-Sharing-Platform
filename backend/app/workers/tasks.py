import json
import smtplib
from datetime import datetime
from email.message import EmailMessage

from app.workers.celery_app import celery_app


# ============================================================
# FILE PROCESSING
# ============================================================

@celery_app.task(
    name="app.workers.tasks.process_uploaded_file",
    bind=True,
    max_retries=3,
)
def process_uploaded_file(self, file_id: str, version_id: str):
    """
    Runs background processing after a file upload.

    Tasks:
    - Generate thumbnail
    - Scan file for malware
    - Create upload activity log
    """

    from app.database.session import SessionLocal
    from app.files.models import File, ActivityLog

    db = SessionLocal()

    try:
        file_row = (
            db.query(File)
            .filter(File.id == file_id)
            .first()
        )

        if not file_row:
            return {
                "status": "skipped",
                "reason": "file not found",
            }

        generate_thumbnail.delay(file_id, version_id)
        scan_for_malware.delay(file_id, version_id)

        db.add(
            ActivityLog(
                user_id=file_row.owner_id,
                action="UPLOAD",
                resource_type="FILE",
                resource_id=file_id,
                metadata_json=json.dumps(
                    {
                        "version_id": version_id,
                    }
                ),
            )
        )

        db.commit()

        return {
            "status": "processed",
            "file_id": file_id,
        }

    finally:
        db.close()


# ============================================================
# THUMBNAIL GENERATION
# ============================================================

@celery_app.task(
    name="app.workers.tasks.generate_thumbnail"
)
def generate_thumbnail(file_id: str, version_id: str):
    return {
        "status": "stub",
        "file_id": file_id,
        "version_id": version_id,
        "note": "Pillow/ffmpeg thumbnail pipeline goes here",
    }


# ============================================================
# MALWARE SCAN
# ============================================================

@celery_app.task(
    name="app.workers.tasks.scan_for_malware"
)
def scan_for_malware(file_id: str, version_id: str):
    return {
        "status": "stub",
        "file_id": file_id,
        "version_id": version_id,
        "note": "ClamAV/clamd integration goes here",
    }


# ============================================================
# EMAIL OTP
# ============================================================

@celery_app.task(
    name="app.workers.tasks.send_email_otp",
    bind=True,
    max_retries=3,
)
def send_email_otp(
    self,
    email: str,
    otp: str,
    purpose: str,
):
    """
    Send CloudVault OTP email through SMTP.

    Supported purposes:
    - email_verification
    - password_reset
    """

    from app.config import get_settings

    settings = get_settings()

    if purpose == "email_verification":
        subject = "CloudVault - Email Verification OTP"
        message = (
            "Hello,\n\n"
            "Your CloudVault email verification OTP is:\n\n"
            f"{otp}\n\n"
            "This OTP will expire in 10 minutes.\n\n"
            "If you did not create this account, please ignore this email.\n\n"
            "CloudVault"
        )

    elif purpose == "password_reset":
        subject = "CloudVault - Password Reset OTP"
        message = (
            "Hello,\n\n"
            "Your CloudVault password reset OTP is:\n\n"
            f"{otp}\n\n"
            "This OTP will expire in 10 minutes.\n\n"
            "If you did not request a password reset, please ignore this email.\n\n"
            "CloudVault"
        )

    else:
        raise ValueError(
            f"Unsupported OTP purpose: {purpose}"
        )

    smtp_host = settings.SMTP_HOST
    smtp_port = settings.SMTP_PORT
    smtp_username = settings.SMTP_USERNAME
    smtp_password = settings.SMTP_PASSWORD
    smtp_from_email = (
        settings.SMTP_FROM_EMAIL
        or smtp_username
    )

    # --------------------------------------------------------
    # SMTP configuration check
    # --------------------------------------------------------

    if not smtp_host:
        print(
            "OTP email not sent: SMTP_HOST is not configured"
        )
        print(f"OTP recipient: {email}")
        print(f"OTP purpose: {purpose}")
        print(f"OTP: {otp}")

        return {
            "status": "smtp_not_configured",
            "email": email,
            "purpose": purpose,
        }

    if not smtp_username:
        raise RuntimeError(
            "SMTP_USERNAME is not configured"
        )

    if not smtp_password:
        raise RuntimeError(
            "SMTP_PASSWORD is not configured"
        )

    if not smtp_from_email:
        raise RuntimeError(
            "SMTP_FROM_EMAIL is not configured"
        )

    # --------------------------------------------------------
    # Create email
    # --------------------------------------------------------

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_from_email
    msg["To"] = email
    msg.set_content(message)

    # --------------------------------------------------------
    # Send email
    # --------------------------------------------------------

    try:
        with smtplib.SMTP(
            smtp_host,
            smtp_port,
            timeout=30,
        ) as server:

            server.ehlo()

            if settings.SMTP_USE_TLS:
                server.starttls()
                server.ehlo()

            server.login(
                smtp_username,
                smtp_password,
            )

            server.send_message(msg)

        print(
            f"OTP email successfully sent to {email}"
        )

        return {
            "status": "sent",
            "email": email,
            "purpose": purpose,
        }

    except Exception as exc:
        print(
            f"Failed to send OTP email to {email}: {exc}"
        )

        # Retry transient SMTP failures.
        raise self.retry(
            exc=exc,
            countdown=60,
            max_retries=3,
        )


# ============================================================
# ANALYTICS
# ============================================================

@celery_app.task(
    name="app.workers.tasks.recompute_analytics"
)
def recompute_analytics():
    from sqlalchemy import func

    from app.database.session import SessionLocal
    from app.users.models import User
    from app.files.models import File
    from app.analytics.models import StorageUsageSnapshot

    db = SessionLocal()

    try:
        users = db.query(User).all()

        for user in users:
            file_count = (
                db.query(func.count(File.id))
                .filter(
                    File.owner_id == user.id,
                    File.is_deleted.is_(False),
                )
                .scalar()
            )

            db.add(
                StorageUsageSnapshot(
                    user_id=user.id,
                    used_bytes=user.storage_used_bytes,
                    file_count=file_count,
                    snapshot_date=datetime.utcnow(),
                )
            )

        db.commit()

        return {
            "status": "ok",
            "users_processed": len(users),
        }

    finally:
        db.close()


# ============================================================
# PURGE EXPIRED TRASH
# ============================================================

@celery_app.task(
    name="app.workers.tasks.purge_expired_trash"
)
def purge_expired_trash():
    from datetime import timedelta

    from app.config import get_settings
    from app.database.session import SessionLocal
    from app.files.models import File
    from app.files.service import _hard_delete_file

    settings = get_settings()

    cutoff = (
        datetime.utcnow()
        - timedelta(
            days=settings.TRASH_RETENTION_DAYS
        )
    )

    db = SessionLocal()

    try:
        expired = (
            db.query(File)
            .filter(
                File.is_deleted.is_(True),
                File.updated_at < cutoff,
            )
            .all()
        )

        for file_row in expired:
            _hard_delete_file(
                db,
                file_row,
                action="AUTO_PURGE",
            )

        return {
            "status": "ok",
            "purged": len(expired),
        }

    finally:
        db.close()