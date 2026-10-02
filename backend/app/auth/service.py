import hashlib
import secrets
from datetime import datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.auth.models import RefreshToken, OTPCode
from app.config import get_settings
from app.security.jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.security.password import hash_password, verify_password
from app.security.rate_limit import (
    check_and_increment,
    reset,
    RateLimitExceeded,
)
from app.users.models import User
from app.utils.activity_log import log_activity
from app.workers.tasks import send_email_otp

settings = get_settings()

#Register users

def register_user(
    db: Session,
    email: str,
    password: str,
    full_name: str,
) -> User:
    rate_key = f"register:{email}"

    try:
        check_and_increment(
            rate_key,
            settings.RATE_LIMIT_REGISTER_ATTEMPTS,
            settings.RATE_LIMIT_REGISTER_WINDOW_SECONDS,
        )
    except RateLimitExceeded as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
        )

    existing = db.query(User).filter(User.email == email).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    user = User(
        email=email,
        hashed_password=hash_password(password),
        full_name=full_name,
        role="USER",
        storage_quota_bytes=settings.DEFAULT_USER_QUOTA_BYTES,
        is_email_verified=False,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    # Generate and send email verification OTP.
    _issue_otp(
        db,
        user,
        purpose="email_verification",
    )

    return user


def _issue_otp(
    db: Session,
    user: User,
    purpose: str,
) -> str:
    """Generate OTP, store its hash, and send OTP through Celery."""

    code = f"{secrets.randbelow(1_000_000):06d}"

    otp = OTPCode(
        user_id=user.id,
        code_hash=hashlib.sha256(code.encode()).hexdigest(),
        purpose=purpose,
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )

    db.add(otp)
    db.commit()

    # Send OTP asynchronously through Celery.
    send_email_otp.delay(
        user.email,
        code,
        purpose,
    )

    return code


def verify_otp(
    db: Session,
    email: str,
    code: str,
    purpose: str,
) -> None:
    rate_key = f"otp:{purpose}:{email}"

    try:
        check_and_increment(
            rate_key,
            settings.RATE_LIMIT_OTP_ATTEMPTS,
            settings.RATE_LIMIT_OTP_WINDOW_SECONDS,
        )
    except RateLimitExceeded as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
        )

    user = db.query(User).filter(User.email == email).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    otp = (
        db.query(OTPCode)
        .filter(
            OTPCode.user_id == user.id,
            OTPCode.purpose == purpose,
            OTPCode.is_used.is_(False),
        )
        .order_by(OTPCode.created_at.desc())
        .first()
    )

    if not otp or otp.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP expired or not found",
        )

    expected_hash = hashlib.sha256(code.encode()).hexdigest()

    if otp.code_hash != expected_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP",
        )

    otp.is_used = True

    if purpose == "email_verification":
        user.is_email_verified = True

    db.commit()

    # Correct OTP clears rate-limit counter.
    reset(rate_key)


def authenticate_and_issue_tokens(
    db: Session,
    email: str,
    password: str,
    device_info: str,
    ip_address: str | None = None,
) -> tuple[str, str]:

    rate_key = f"login:{email}"

    try:
        check_and_increment(
            rate_key,
            settings.RATE_LIMIT_LOGIN_ATTEMPTS,
            settings.RATE_LIMIT_LOGIN_WINDOW_SECONDS,
        )
    except RateLimitExceeded as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
        )

    user = db.query(User).filter(User.email == email).first()

    if user and user.locked_until and user.locked_until > datetime.utcnow():
        log_activity(
            db,
            user.id,
            "LOGIN_BLOCKED_LOCKED",
            "AUTH",
            ip_address=ip_address,
        )
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=(
                f"Account locked until "
                f"{user.locked_until.isoformat()}Z "
                f"due to repeated failed logins"
            ),
        )

    if not user or not verify_password(
        password,
        user.hashed_password,
    ):
        if user:
            user.failed_login_attempts += 1

            if (
                user.failed_login_attempts
                >= settings.ACCOUNT_LOCKOUT_THRESHOLD
            ):
                user.locked_until = (
                    datetime.utcnow()
                    + timedelta(
                        minutes=settings.ACCOUNT_LOCKOUT_DURATION_MINUTES
                    )
                )

            log_activity(
                db,
                user.id,
                "LOGIN_FAILED",
                "AUTH",
                ip_address=ip_address,
            )

            db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    reset(rate_key)

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.utcnow()

    access_token = create_access_token(
        user.id,
        user.role,
    )

    refresh_token, jti, expires_at = create_refresh_token(
        user.id
    )

    db.add(
        RefreshToken(
            user_id=user.id,
            jti=jti,
            device_info=device_info,
            expires_at=expires_at,
        )
    )

    log_activity(
        db,
        user.id,
        "LOGIN",
        "AUTH",
        metadata={"device_info": device_info},
        ip_address=ip_address,
    )

    db.commit()

    return access_token, refresh_token


def rotate_refresh_token(
    db: Session,
    refresh_token: str,
) -> tuple[str, str]:

    payload = decode_token(
        refresh_token,
        expected_type="refresh",
    )

    jti = payload["jti"]
    user_id = payload["sub"]

    stored = (
        db.query(RefreshToken)
        .filter(RefreshToken.jti == jti)
        .first()
    )

    if not stored or stored.is_revoked:

        if stored:
            db.query(RefreshToken).filter(
                RefreshToken.user_id == user_id
            ).update(
                {"is_revoked": True}
            )
            db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token invalid, all sessions revoked",
        )

    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    stored.is_revoked = True

    new_access = create_access_token(
        user.id,
        user.role,
    )

    new_refresh, new_jti, expires_at = create_refresh_token(
        user.id
    )

    db.add(
        RefreshToken(
            user_id=user.id,
            jti=new_jti,
            device_info=stored.device_info,
            expires_at=expires_at,
        )
    )

    db.commit()

    return new_access, new_refresh


def logout(
    db: Session,
    refresh_token: str,
    ip_address: str | None = None,
) -> None:

    payload = decode_token(
        refresh_token,
        expected_type="refresh",
    )

    db.query(RefreshToken).filter(
        RefreshToken.jti == payload["jti"]
    ).update(
        {"is_revoked": True}
    )

    log_activity(
        db,
        payload["sub"],
        "LOGOUT",
        "AUTH",
        ip_address=ip_address,
    )

    db.commit()


def logout_all_devices(
    db: Session,
    user_id: str,
    ip_address: str | None = None,
) -> None:

    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id
    ).update(
        {"is_revoked": True}
    )

    log_activity(
        db,
        user_id,
        "LOGOUT_ALL",
        "AUTH",
        ip_address=ip_address,
    )

    db.commit()


def forgot_password(
    db: Session,
    email: str,
) -> None:

    rate_key = f"forgot-password:{email}"

    try:
        check_and_increment(
            rate_key,
            settings.RATE_LIMIT_REGISTER_ATTEMPTS,
            settings.RATE_LIMIT_REGISTER_WINDOW_SECONDS,
        )
    except RateLimitExceeded as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
        )

    user = (
        db.query(User)
        .filter(User.email == email)
        .first()
    )

    if not user:
        return

    _issue_otp(
        db,
        user,
        purpose="password_reset",
    )


def reset_password(
    db: Session,
    email: str,
    code: str,
    new_password: str,
) -> None:

    verify_otp(
        db,
        email,
        code,
        purpose="password_reset",
    )

    user = (
        db.query(User)
        .filter(User.email == email)
        .first()
    )

    user.hashed_password = hash_password(new_password)

    db.commit()

    logout_all_devices(
        db,
        user.id,
    )