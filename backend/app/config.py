"""
Central application configuration, loaded from environment variables.
All defaults are safe for local docker-compose development only -
override every secret in production via real env vars / a secrets manager.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- App ---
    APP_NAME: str = "CloudVault"
    ENV: str = "development"

    # for mail
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""
    SMTP_USE_TLS: bool = True
    # --- Monitoring ---
    # Empty by default: Sentry stays fully inactive until a real DSN is set.
    # No code changes needed to turn it on later - just set the env var.
    SENTRY_DSN: str = ""
    SENTRY_TRACES_SAMPLE_RATE: float = 0.1
    PROMETHEUS_ENABLED: bool = True
    DEBUG: bool = True

    # --- Database ---
    DATABASE_URL: str = "mysql+pymysql://cloudvault:cloudvault@mysql:3306/cloudvault"

    # --- Redis / Celery ---
    REDIS_URL: str = "redis://redis:6379/0"
    CELERY_BROKER_URL: str = "redis://redis:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/2"

    # --- JWT ---
    JWT_SECRET_KEY: str = "CHANGE_ME_SUPER_SECRET"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # --- Encryption ---
    # 32-byte urlsafe base64 key for Fernet/AES-256. Generate with
    # `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key())"`
    FILE_ENCRYPTION_KEY: str = "0" * 44  # placeholder, MUST override in production

    # --- Storage ---
    STORAGE_BACKEND: str = "local"  # "local" or "s3"
    LOCAL_STORAGE_ROOT: str = "/data/storage"
    CHUNK_SIZE_BYTES: int = 5 * 1024 * 1024  # 5MB per chunk
    MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024 * 1024  # 10GB

    # S3-compatible (optional, used only if STORAGE_BACKEND == "s3")
    S3_ENDPOINT_URL: str | None = None
    S3_BUCKET: str = "cloudvault"
    S3_ACCESS_KEY: str | None = None
    S3_SECRET_KEY: str | None = None
    S3_REGION: str = "us-east-1"

    # --- Rate limiting ---
    RATE_LIMIT_LOGIN_ATTEMPTS: int = 5
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: int = 300  # 5 minutes

    # Applies to /auth/register and /auth/forgot-password - separate from
    # login limiting since these have different abuse profiles (spam /
    # enumeration rather than credential stuffing).
    RATE_LIMIT_REGISTER_ATTEMPTS: int = 5
    RATE_LIMIT_REGISTER_WINDOW_SECONDS: int = 3600  # 1 hour

    # OTPs are 6-digit numeric (1,000,000 possibilities). Without a tight
    # per-identity limit here, a 10-minute-lived OTP is guessable well
    # within its expiry window by an unthrottled attacker.
    RATE_LIMIT_OTP_ATTEMPTS: int = 5
    RATE_LIMIT_OTP_WINDOW_SECONDS: int = 600  # 10 minutes

    # --- Account lockout ---
    # Persisted on the User row (failed_login_attempts / locked_until) in
    # addition to the Redis-backed login rate limit above: this survives a
    # Redis restart/flush, is queryable for admin/support tooling, and is
    # the mechanism an admin "unlock account" action clears.
    ACCOUNT_LOCKOUT_THRESHOLD: int = 5
    ACCOUNT_LOCKOUT_DURATION_MINUTES: int = 15

    # --- Password policy ---
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_MAX_LENGTH: int = 128
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True

    # --- Default quotas ---
    DEFAULT_USER_QUOTA_BYTES: int = 15 * 1024 * 1024 * 1024  # 15GB

    # --- Trash ---
    TRASH_RETENTION_DAYS: int = 30

    # --- CORS ---
    # 5173 = Vite dev server default; 3000 = kept for parity with the
    # frontend's own docker-compose (frontend container mapped to :3000).
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
