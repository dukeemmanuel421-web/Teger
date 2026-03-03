from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Settings:
    app_name: str = os.getenv("APP_NAME", "teger-guardrails-backend")
    app_env: str = os.getenv("APP_ENV", "development")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    database_url: str | None = os.getenv("DATABASE_URL")
    sqlite_path: Path = Path(__file__).resolve().parent / "data" / "app.db"

    allow_origins_raw: str = os.getenv("ALLOW_ORIGINS", "*")

    gemini_api_key: str | None = os.getenv("GEMINI_API_KEY")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    gemini_timeout_seconds: int = int(os.getenv("GEMINI_TIMEOUT_SECONDS", "10"))

    rate_limit_requests: int = int(os.getenv("RATE_LIMIT_REQUESTS", "30"))
    rate_limit_window_seconds: int = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

    interswitch_mode: str = os.getenv("INTERSWITCH_MODE", "mock").lower()
    interswitch_client_id: str | None = os.getenv("INTERSWITCH_CLIENT_ID")
    interswitch_secret_key: str | None = os.getenv("INTERSWITCH_SECRET_KEY")
    interswitch_token_url: str | None = os.getenv("INTERSWITCH_TOKEN_URL")
    interswitch_base_url: str | None = os.getenv("INTERSWITCH_BASE_URL")
    interswitch_credit_inquiry_path: str = os.getenv(
        "INTERSWITCH_CREDIT_INQUIRY_PATH", "/transfer/credit-inquiry"
    )

    max_content_chars: int = 15000

    @property
    def allow_origins(self) -> list[str]:
        if self.allow_origins_raw.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.allow_origins_raw.split(",") if o.strip()]

    @property
    def effective_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{self.sqlite_path}"


settings = Settings()
