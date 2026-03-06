import secrets
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── 필수 환경변수 (미설정 시 서버 시작 불가) ─────────────
    SECRET_KEY: str
    DATABASE_URL: str

    # ── 선택 환경변수 (기본값 있음) ──────────────────────────
    # CORS 허용 origin (콤마로 구분, 예: https://app.example.com,https://www.example.com)
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"

    # Access token 만료: 60분 (기존 7일에서 단축)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # 로그인 실패 허용 횟수 (초과 시 계정 잠금)
    MAX_LOGIN_ATTEMPTS: int = 5

    # 계정 잠금 지속 시간 (분)
    LOGIN_LOCKOUT_MINUTES: int = 15

    # Railway/Production 환경 여부
    IS_PRODUCTION: bool = False

    # ── 이메일 (Gmail SMTP) — 비밀번호 재설정용 ──────────────
    # Gmail 앱 비밀번호: https://myaccount.google.com/apppasswords
    MAIL_USERNAME: str = ""        # 발신 Gmail 주소
    MAIL_PASSWORD: str = ""        # Gmail 앱 비밀번호 (16자리)
    MAIL_FROM: str = ""            # 발신자 이메일 (보통 MAIL_USERNAME과 동일)
    MAIL_FROM_NAME: str = "StageMate"
    MAIL_SERVER: str = "smtp.gmail.com"
    MAIL_PORT: int = 587

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
