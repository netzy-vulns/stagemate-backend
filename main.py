import logging
import os
import secrets
import string
import json
import base64
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy import desc, nulls_last, text, func
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from database import engine, get_db
import db_models
from config import settings
from auth import (
    hash_password, verify_password, create_access_token,
    validate_password_strength,
    check_account_lock, handle_failed_login, reset_login_attempts,
    get_current_user, get_club_member,
    require_super_admin, require_admin, require_team_leader, require_any_member,
    generate_invite_code,
)
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from models import (
    PerformanceConfig, RoomBooking,
    RegisterRequest, ClubCreateRequest, ClubJoinRequest,
    RoleUpdateRequest, NoticeRequest, SlotRequest,
    ChangePasswordRequest, ForgotPasswordRequest,
    KakaoLoginRequest, CommentRequest,
    DeleteAccountRequest, PostRequest, PostCommentRequest, NicknameRequest,
    PostEditRequest, ReportRequest,
    ClubProfileUpdate,
    SubscriptionVerifyRequest,
    BoostRequest,
    PerformanceCreateRequest, AudioSubmissionRequest,
    FcmTokenRequest,
    PerformanceArchiveRequest,
)
from scheduler import calculate_schedule
from group_schedule import find_common_slots_from_db
from room_booking_db import add_booking_db, get_bookings_db, delete_booking_db
from datetime import datetime, timedelta

# ── 로깅 설정 ──────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("performance-manager")

# ── 구독 플랜 매핑 ────────────────────────────────────
PLAN_MAP = {
    "stagemate_standard_monthly": "standard",
    "stagemate_standard_early":   "standard",
    "stagemate_pro_monthly":      "pro",
    "stagemate_pro_early":        "pro",
    "stagemate_personal_monthly": "personal",  # Phase 2에서 사용
}
BOOST_CREDITS_MAP = {"standard": 5, "pro": 20, "free": 0}


# DB 테이블 자동 생성
db_models.Base.metadata.create_all(bind=engine)


def _run_migrations() -> None:
    """기존 테이블에 새 컬럼을 안전하게 추가 (ADD COLUMN IF NOT EXISTS).
    Alembic 없이 Railway 재배포 시 스키마 변경을 자동 적용한다."""
    migrations = [
        # posts 테이블 — boost 기능 (Tasks 12-13)
        "ALTER TABLE posts ADD COLUMN IF NOT EXISTS is_boosted BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE posts ADD COLUMN IF NOT EXISTS boost_expires_at TIMESTAMP",
        # users 테이블 — 로그인 잠금 (보안 강화)
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP",
        # users 테이블 — 닉네임, 아바타, 소프트삭제
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS nickname VARCHAR UNIQUE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url VARCHAR",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS reregister_allowed_at TIMESTAMP",
        # users 테이블 — 카카오 소셜 로그인
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS kakao_id VARCHAR UNIQUE",
        # clubs 테이블 — 구독/플랜 (Tasks 9-11)
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS logo_url VARCHAR",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS banner_url VARCHAR",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS theme_color VARCHAR(7)",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS plan VARCHAR(20) NOT NULL DEFAULT 'free'",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS plan_expires_at TIMESTAMP",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS storage_used_mb BIGINT NOT NULL DEFAULT 0",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS storage_quota_extra_mb BIGINT NOT NULL DEFAULT 0",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS boost_credits INTEGER NOT NULL DEFAULT 0",
        # users 테이블 — FCM 푸시 토큰
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS fcm_token VARCHAR",
        # notices 테이블 — 미디어 첨부 (이미지/영상)
        "ALTER TABLE notices ADD COLUMN IF NOT EXISTS media_urls JSON DEFAULT '[]'",
        # clubs 테이블 — SNS 링크
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS instagram_url VARCHAR",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS youtube_url VARCHAR",
        # --- 공연 플랫폼 마이그레이션 ---
        """
CREATE TABLE IF NOT EXISTS performance_archives (
    id               SERIAL PRIMARY KEY,
    club_id          INTEGER NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    title            VARCHAR NOT NULL,
    description      TEXT,
    performance_date VARCHAR(10) NOT NULL,
    youtube_url      VARCHAR(500),
    native_video_url VARCHAR,
    view_count       INTEGER NOT NULL DEFAULT 0,
    created_at       TIMESTAMP DEFAULT NOW()
)
""",
        """
CREATE TABLE IF NOT EXISTS performance_archive_likes (
    id         SERIAL PRIMARY KEY,
    archive_id INTEGER NOT NULL REFERENCES performance_archives(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_archive_like UNIQUE (archive_id, user_id)
)
""",
        """
CREATE TABLE IF NOT EXISTS challenges (
    id         SERIAL PRIMARY KEY,
    year_month VARCHAR(7) NOT NULL,
    is_active  BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_challenge_month UNIQUE (year_month)
)
""",
        """
CREATE TABLE IF NOT EXISTS challenge_entries (
    id           SERIAL PRIMARY KEY,
    challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    club_id      INTEGER NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    archive_id   INTEGER NOT NULL REFERENCES performance_archives(id) ON DELETE CASCADE,
    created_at   TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_challenge_entry UNIQUE (challenge_id, club_id)
)
""",
        """
CREATE TABLE IF NOT EXISTS challenge_entry_likes (
    id         SERIAL PRIMARY KEY,
    entry_id   INTEGER NOT NULL REFERENCES challenge_entries(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_entry_like UNIQUE (entry_id, user_id)
)
""",
        "ALTER TABLE posts ADD COLUMN IF NOT EXISTS youtube_url VARCHAR(500)",
    ]
    with engine.connect() as conn:
        for sql in migrations:
            try:
                conn.execute(text(sql))
            except Exception as exc:
                logging.warning("Migration skipped (%s): %s", sql[:60], exc)
        conn.commit()
    logging.info("DB migrations applied.")


_run_migrations()

# ── Rate Limiter 설정 ──────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── Firebase Admin SDK 초기화 ──────────────────────────
import firebase_admin
from firebase_admin import credentials as fb_credentials, messaging as fb_messaging
import json

_firebase_app = None
_firebase_creds_json = os.getenv("FIREBASE_CREDENTIALS_JSON")
if _firebase_creds_json:
    try:
        _cred = fb_credentials.Certificate(json.loads(_firebase_creds_json))
        _firebase_app = firebase_admin.initialize_app(_cred)
        logging.info("Firebase Admin SDK initialized.")
    except Exception as _fb_err:
        logging.warning("Firebase init failed: %s", _fb_err)
else:
    logging.info("FIREBASE_CREDENTIALS_JSON not set — push notifications disabled.")


def _send_push(token: str, title: str, body: str, post_id: int) -> None:
    """Fire-and-forget FCM push. Errors are logged, never raised."""
    if not _firebase_app or not token:
        return
    try:
        fb_messaging.send(fb_messaging.Message(
            notification=fb_messaging.Notification(title=title, body=body),
            data={"post_id": str(post_id)},
            token=token,
        ))
        logging.info("FCM push sent to token %s...", token[:10])
    except Exception as e:
        logging.warning("FCM send failed (token=%s...): %s", token[:10], e)


def _send_new_member_push(tokens: list, club_name: str, new_member_name: str) -> None:
    for token in tokens:
        try:
            fb_messaging.send(fb_messaging.Message(
                notification=fb_messaging.Notification(
                    title=f"[{club_name}] 새 멤버 가입",
                    body=f"{new_member_name}님이 가입했습니다.",
                ),
                data={"type": "new_member"},
                token=token,
            ))
        except Exception as e:
            logger.error(f"New member push failed: {e}")


def _send_announcement_push(tokens: list, club_name: str, notice_title: str, notice_id: int) -> None:
    """공지사항 생성 시 동아리 전체 멤버에게 FCM 푸시 발송. 논블로킹 백그라운드 태스크."""
    if not _firebase_app or not tokens:
        return
    title = f"[{club_name}] 새 공지사항"
    body = notice_title[:50]
    for token in tokens:
        if not token:
            continue
        try:
            fb_messaging.send(fb_messaging.Message(
                notification=fb_messaging.Notification(title=title, body=body),
                data={"notice_id": str(notice_id)},
                token=token,
            ))
            logging.info("Announcement FCM push sent to token %s...", token[:10])
        except Exception as e:
            logging.warning("Announcement FCM send failed (token=%s...): %s", token[:10], e)


def _send_audio_submitted_push(tokens: list, club_name: str, team_name: str, song_title: str) -> None:
    """새 음원 제출 시 해당 동아리 admin/super_admin에게 FCM 푸시 발송."""
    for token in tokens:
        try:
            fb_messaging.send(fb_messaging.Message(
                notification=fb_messaging.Notification(
                    title=f"[{club_name}] 새 음원 제출",
                    body=f"{team_name}팀이 '{song_title}' 음원을 제출했습니다.",
                ),
                data={"type": "audio_submitted"},
                token=token,
            ))
        except Exception as e:
            logger.error(f"Audio submitted push failed: {e}")


app = FastAPI(
    title="StageMate API 🎭",
    # 프로덕션에서 자동 문서 노출 제한
    docs_url="/docs" if not settings.IS_PRODUCTION else None,
    redoc_url="/redoc" if not settings.IS_PRODUCTION else None,
)

# Rate limit 초과 핸들러 등록
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS 설정 ─────────────────────────────────────────
# 개발: 모든 로컬 출처 허용 / 프로덕션: 환경변수 지정 origin만 허용
_origins = ["*"] if not settings.IS_PRODUCTION else settings.ALLOWED_ORIGINS.split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=False,   # JWT 헤더 방식이므로 불필요 (쿠키 X)
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Club-Id"],
)


# ── 보안 헤더 미들웨어 ────────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if settings.IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ── 전역 예외 핸들러 (스택 트레이스 노출 방지) ────────────
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "서버 오류가 발생했습니다. 잠시 후 다시 시도해주세요."},
    )


# ── DB 마이그레이션 (startup 시 누락 컬럼 자동 추가) ─────
@app.on_event("startup")
async def run_migrations():
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN kakao_id VARCHAR UNIQUE"))
            conn.commit()
            logger.info("Migration: kakao_id column added")
    except Exception:
        pass  # 이미 존재하면 무시

    # 추가 컬럼 마이그레이션
    for col_def in [
        "ALTER TABLE users ADD COLUMN deleted_at TIMESTAMP",
        "ALTER TABLE users ADD COLUMN reregister_allowed_at TIMESTAMP",
        "ALTER TABLE users ADD COLUMN nickname VARCHAR UNIQUE",
        "ALTER TABLE users ADD COLUMN avatar_url VARCHAR",
        "ALTER TABLE posts ADD COLUMN view_count INTEGER DEFAULT 0",
        "ALTER TABLE posts ADD COLUMN post_author_name VARCHAR",
        "ALTER TABLE posts ADD COLUMN is_anonymous BOOLEAN DEFAULT FALSE",
        """CREATE TABLE IF NOT EXISTS reports (
            id SERIAL PRIMARY KEY,
            reporter_id INTEGER NOT NULL REFERENCES users(id),
            post_id INTEGER REFERENCES posts(id),
            comment_id INTEGER REFERENCES post_comments(id),
            reason VARCHAR NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            actor_id INTEGER REFERENCES users(id),
            post_id INTEGER REFERENCES posts(id),
            message VARCHAR NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        )""",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS logo_url VARCHAR",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS banner_url VARCHAR",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS theme_color VARCHAR(7)",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS plan VARCHAR(20) DEFAULT 'free' NOT NULL",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS plan_expires_at TIMESTAMP",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS storage_used_mb BIGINT DEFAULT 0",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS storage_quota_extra_mb BIGINT DEFAULT 0",
        "ALTER TABLE clubs ADD COLUMN IF NOT EXISTS boost_credits INTEGER DEFAULT 0",
        "ALTER TABLE posts ADD COLUMN IF NOT EXISTS is_boosted BOOLEAN DEFAULT FALSE",
        "ALTER TABLE posts ADD COLUMN IF NOT EXISTS boost_expires_at TIMESTAMP",
        "ALTER TABLE post_comments ADD COLUMN IF NOT EXISTS parent_id INTEGER REFERENCES post_comments(id)",
        """CREATE TABLE IF NOT EXISTS subscription_transactions (
            id SERIAL PRIMARY KEY,
            club_id INTEGER REFERENCES clubs(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            product_id VARCHAR NOT NULL,
            transaction_id VARCHAR UNIQUE NOT NULL,
            platform VARCHAR(20) NOT NULL,
            purchased_at TIMESTAMP NOT NULL,
            expires_at TIMESTAMP,
            status VARCHAR(20) DEFAULT 'active' NOT NULL,
            raw_payload TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS presign_requests (
            key VARCHAR PRIMARY KEY,
            club_id INTEGER REFERENCES clubs(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            file_size_mb INTEGER NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        )""",
    ]:
        try:
            with engine.connect() as conn:
                conn.execute(text(col_def))
                conn.commit()
        except Exception:
            pass  # 이미 존재하면 무시


# ════════════════════════════════════════════════
#  인증 (Auth)
# ════════════════════════════════════════════════

@app.get("/auth/check-username")
@limiter.limit("20/minute")
def check_username(request: Request, username: str, db: Session = Depends(get_db)):
    """아이디 중복 확인"""
    exists = db.query(db_models.User).filter(db_models.User.username == username).first()
    return {"available": exists is None}


@app.get("/auth/check-displayname")
@limiter.limit("20/minute")
def check_displayname(request: Request, display_name: str, db: Session = Depends(get_db)):
    """닉네임 중복 확인"""
    exists = db.query(db_models.User).filter(db_models.User.display_name == display_name).first()
    return {"available": exists is None}


@app.get("/auth/check-nickname")
@limiter.limit("20/minute")
def check_nickname(request: Request, nickname: str, db: Session = Depends(get_db)):
    """커뮤니티 닉네임 중복 확인"""
    exists = db.query(db_models.User).filter(db_models.User.nickname == nickname).first()
    return {"available": exists is None}


@app.get("/auth/check-email")
@limiter.limit("20/minute")
def check_email(request: Request, email: str, db: Session = Depends(get_db)):
    """이메일 중복 확인"""
    exists = db.query(db_models.User).filter(db_models.User.email == email).first()
    return {"available": exists is None}


@app.post("/auth/register")
@limiter.limit("5/minute")
def register(request: Request, req: RegisterRequest, db: Session = Depends(get_db)):
    """회원가입 (동아리 가입은 별도 /clubs/join)"""
    # 비밀번호 강도 검증 (서버 측 이중 확인)
    if not validate_password_strength(req.password):
        raise HTTPException(
            status_code=400,
            detail="비밀번호는 최소 8자 이상, 대문자·소문자·숫자를 각 1개 이상 포함해야 합니다.",
        )

    existing = db.query(db_models.User).filter(
        db_models.User.username == req.username
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="이미 존재하는 아이디입니다.")

    if db.query(db_models.User).filter(
        db_models.User.email == req.email,
        db_models.User.deleted_at == None,
    ).first():
        raise HTTPException(status_code=400, detail="이미 사용 중인 이메일입니다.")

    # 탈퇴 후 7일 재가입 쿨다운 체크
    deleted_user = db.query(db_models.User).filter(
        db_models.User.email == req.email,
        db_models.User.deleted_at != None,
    ).first()
    if deleted_user and deleted_user.reregister_allowed_at:
        now = datetime.utcnow()
        if deleted_user.reregister_allowed_at > now:
            days_left = (deleted_user.reregister_allowed_at - now).days + 1
            raise HTTPException(
                status_code=400,
                detail=f"탈퇴 후 {days_left}일 후에 재가입할 수 있습니다.",
            )

    if db.query(db_models.User).filter(db_models.User.display_name == req.display_name).first():
        raise HTTPException(status_code=400, detail="이미 사용 중인 닉네임입니다.")

    if db.query(db_models.User).filter(
        db_models.User.nickname == req.nickname
    ).first():
        raise HTTPException(status_code=400, detail="이미 사용 중인 닉네임입니다.")

    user = db_models.User(
        username=req.username,
        display_name=req.display_name,
        nickname=req.nickname,
        email=req.email,
        hashed_password=hash_password(req.password),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="이미 사용 중인 아이디, 닉네임 또는 이메일입니다.")
    db.refresh(user)
    logger.info(f"New user registered: {user.username}")
    return {
        "message": f"회원가입 완료! 환영해요, {user.display_name}님 🎉",
        "user_id": user.id,
    }


@app.post("/auth/kakao")
@limiter.limit("10/minute")
async def kakao_login(request: Request, req: KakaoLoginRequest, db: Session = Depends(get_db)):
    """카카오 소셜 로그인 — 카카오 액세스 토큰으로 사용자 인증"""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://kapi.kakao.com/v2/user/me",
            headers={"Authorization": f"Bearer {req.access_token}"},
            timeout=10.0,
        )
    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail="카카오 인증에 실패했습니다.")

    kakao_data = resp.json()
    kakao_id = str(kakao_data["id"])
    profile = kakao_data.get("kakao_account", {}).get("profile", {})
    nickname = profile.get("nickname") or f"user_{kakao_id[:6]}"

    user = db.query(db_models.User).filter(db_models.User.kakao_id == kakao_id).first()
    if not user:
        username = f"kakao_{kakao_id}"
        display_name = nickname
        counter = 1
        temp = display_name
        while db.query(db_models.User).filter(db_models.User.display_name == temp).first():
            temp = f"{display_name}_{counter}"
            counter += 1
        display_name = temp

        user = db_models.User(
            username=username,
            display_name=display_name,
            kakao_id=kakao_id,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info(f"New kakao user: {user.username}")

    token = create_access_token({"sub": user.username, "uid": user.id})
    return {
        "access_token": token,
        "token_type": "bearer",
        "display_name": user.display_name,
        "user_id": user.id,
    }


@app.post("/auth/login")
@limiter.limit("10/minute")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """로그인 → JWT 토큰 반환"""
    user = db.query(db_models.User).filter(
        db_models.User.username == form_data.username
    ).first()

    # 사용자 미존재 → 동일 오류 메시지 (사용자 열거 공격 방지)
    if not user:
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 틀렸습니다.")

    # 탈퇴된 계정 확인
    if user.deleted_at is not None:
        raise HTTPException(status_code=401, detail="탈퇴된 계정입니다.")

    # 계정 잠금 확인 (5회 실패 시 15분 잠금)
    check_account_lock(user)

    # 비밀번호 검증
    if not verify_password(form_data.password, user.hashed_password):
        handle_failed_login(user, db)
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 틀렸습니다.")

    # 로그인 성공 — 실패 카운터 초기화
    reset_login_attempts(user, db)
    logger.info(f"User logged in: {user.username}")

    # JWT payload에 uid 포함 → get_current_user에서 PK 조회로 속도 개선
    token = create_access_token({"sub": user.username, "uid": user.id})
    return {
        "access_token": token,
        "token_type": "bearer",
        "display_name": user.display_name,
        "user_id": user.id,
    }


@app.get("/auth/me")
def get_me(current_user: db_models.User = Depends(get_current_user)):
    """토큰 유효성 확인 + 현재 사용자 정보 반환"""
    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "display_name": current_user.display_name,
        "nickname": current_user.nickname or "",
        "avatar_url": current_user.avatar_url or "",
    }


@app.patch("/auth/avatar")
@limiter.limit("10/minute")
def update_avatar(
    request: Request,
    body: dict,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """프로필 사진 URL 업데이트 (http/https 스킴만 허용)"""
    from urllib.parse import urlparse
    avatar_url = body.get("avatar_url", "").strip()
    if avatar_url:
        parsed = urlparse(avatar_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise HTTPException(status_code=400, detail="올바르지 않은 이미지 URL입니다.")
    current_user.avatar_url = avatar_url if avatar_url else None
    db.commit()
    return {"message": "프로필 사진이 업데이트됐어요."}


@app.patch("/auth/nickname")
@limiter.limit("10/minute")
def update_nickname(
    request: Request,
    req: NicknameRequest,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    """닉네임 설정/변경 (전체 커뮤니티용)"""
    # 중복 확인
    existing = db.query(db_models.User).filter(
        db_models.User.nickname == req.nickname,
        db_models.User.id != current_user.id,
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="이미 사용 중인 닉네임입니다.")
    current_user.nickname = req.nickname
    db.commit()
    logger.info(f"Nickname updated: {current_user.username} → {req.nickname}")
    return {"message": "닉네임이 설정됐습니다.", "nickname": req.nickname}


@app.patch("/auth/change-password")
@limiter.limit("5/minute")
def change_password(
    request: Request,
    req: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    """비밀번호 변경 (현재 비밀번호 확인 후 변경)"""
    if not verify_password(req.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="현재 비밀번호가 일치하지 않습니다.")
    current_user.hashed_password = hash_password(req.new_password)
    db.commit()
    logger.info(f"Password changed: {current_user.username}")
    return {"message": "비밀번호가 변경됐습니다."}


def _get_mail_config() -> ConnectionConfig:
    """SMTP 설정 객체 반환 (MAIL_USERNAME 미설정 시 예외)"""
    if not settings.MAIL_USERNAME:
        raise HTTPException(
            status_code=503,
            detail="이메일 서비스가 설정되지 않았습니다. 동아리 관리자에게 문의하세요.",
        )
    return ConnectionConfig(
        MAIL_USERNAME=settings.MAIL_USERNAME,
        MAIL_PASSWORD=settings.MAIL_PASSWORD,
        MAIL_FROM=settings.MAIL_FROM or settings.MAIL_USERNAME,
        MAIL_FROM_NAME=settings.MAIL_FROM_NAME,
        MAIL_PORT=settings.MAIL_PORT,
        MAIL_SERVER=settings.MAIL_SERVER,
        MAIL_STARTTLS=True,
        MAIL_SSL_TLS=False,
        USE_CREDENTIALS=True,
    )


@app.post("/auth/forgot-password")
@limiter.limit("3/minute")
async def forgot_password(
    request: Request,
    req: ForgotPasswordRequest,
    db: Session = Depends(get_db),
):
    """비밀번호 분실 → 이메일로 임시 비밀번호 발송 (사용자 열거 공격 방지)"""
    mail_config = _get_mail_config()

    user = db.query(db_models.User).filter(
        db_models.User.email == req.email
    ).first()

    if user:
        # 임시 비밀번호 생성
        chars = string.ascii_letters + string.digits
        while True:
            temp_password = ''.join(secrets.choice(chars) for _ in range(8))
            if (any(c.isupper() for c in temp_password)
                    and any(c.islower() for c in temp_password)
                    and any(c.isdigit() for c in temp_password)):
                break

        user.hashed_password = hash_password(temp_password)
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()

        message = MessageSchema(
            subject="[StageMate] 임시 비밀번호 발급",
            recipients=[req.email],
            body=(
                f"안녕하세요, {user.display_name}님!\n\n"
                f"StageMate 임시 비밀번호가 발급됐습니다.\n\n"
                f"  임시 비밀번호: {temp_password}\n\n"
                f"로그인 후 반드시 비밀번호를 변경해 주세요.\n"
                f"(설정 → 계정 관리 → 비밀번호 변경)\n\n"
                f"감사합니다.\nStageMate 팀"
            ),
            subtype=MessageType.plain,
        )
        try:
            await FastMail(mail_config).send_message(message)
            logger.info(f"Password reset email sent: {user.username}")
        except Exception as e:
            logger.error(f"Email send failed: {e}")
            raise HTTPException(
                status_code=500,
                detail="이메일 발송에 실패했습니다. 잠시 후 다시 시도해주세요.",
            )

    # 이메일 존재 여부 노출 방지 — 항상 동일 응답
    return {"message": "이메일 주소가 등록되어 있다면 임시 비밀번호를 발송했습니다."}


@app.post("/auth/find-id")
@limiter.limit("3/minute")
async def find_id(
    request: Request,
    req: ForgotPasswordRequest,
    db: Session = Depends(get_db),
):
    """아이디 찾기 → 가입 이메일로 아이디(마스킹) 발송"""
    mail_config = _get_mail_config()

    user = db.query(db_models.User).filter(
        db_models.User.email == req.email,
        db_models.User.deleted_at.is_(None),
    ).first()

    if user:
        # 아이디 앞 2자리만 노출, 나머지는 * 처리
        uid = user.username
        masked = uid[:2] + "*" * max(len(uid) - 2, 0)
        message = MessageSchema(
            subject="[StageMate] 아이디 찾기",
            recipients=[req.email],
            body=(
                f"안녕하세요, {user.display_name}님!\n\n"
                f"요청하신 StageMate 아이디를 안내해 드립니다.\n\n"
                f"  아이디: {masked}\n\n"
                f"보안을 위해 일부 글자는 *로 표시됩니다.\n"
                f"아이디가 기억나지 않으시면 고객센터에 문의해 주세요.\n\n"
                f"감사합니다.\nStageMate 팀"
            ),
            subtype=MessageType.plain,
        )
        try:
            await FastMail(mail_config).send_message(message)
            logger.info(f"Find-ID email sent: {user.username}")
        except Exception as e:
            logger.error(f"Email send failed: {e}")
            raise HTTPException(
                status_code=500,
                detail="이메일 발송에 실패했습니다. 잠시 후 다시 시도해주세요.",
            )

    # 이메일 존재 여부 노출 방지
    return {"message": "등록된 이메일이라면 아이디를 발송했습니다."}


@app.delete("/auth/me")
def delete_account(
    req: DeleteAccountRequest,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    """회원 탈퇴 - 비밀번호 확인 후 소프트 삭제, 7일 재가입 쿨다운"""
    is_kakao_user = current_user.kakao_id is not None and current_user.hashed_password is None

    if is_kakao_user:
        if req.confirm_text != "탈퇴합니다":
            raise HTTPException(status_code=400, detail="'탈퇴합니다'를 정확히 입력해주세요.")
    else:
        if not req.password:
            raise HTTPException(status_code=400, detail="비밀번호를 입력해주세요.")
        if not verify_password(req.password, current_user.hashed_password):
            raise HTTPException(status_code=400, detail="비밀번호가 일치하지 않습니다.")

    now = datetime.utcnow()
    current_user.deleted_at = now
    current_user.reregister_allowed_at = now + timedelta(days=7)
    db.commit()
    logger.info(f"User soft-deleted: {current_user.username}")
    return {"message": "탈퇴가 완료됐습니다. 7일 후 재가입이 가능합니다."}


# ════════════════════════════════════════════════
#  동아리 (Club)
# ════════════════════════════════════════════════

@app.post("/clubs")
@limiter.limit("5/minute")
def create_club(
    request: Request,
    req: ClubCreateRequest,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user)
):
    """동아리 생성 → 생성자가 자동으로 super_admin"""
    existing = db.query(db_models.Club).filter(
        db_models.Club.name == req.name
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="이미 존재하는 동아리 이름입니다.")

    code, expires_at = generate_invite_code()
    club = db_models.Club(
        name=req.name,
        invite_code=code,
        invite_code_expires_at=expires_at,
    )
    db.add(club)
    db.flush()  # club.id 생성

    member = db_models.ClubMember(
        club_id=club.id,
        user_id=current_user.id,
        role="super_admin",
    )
    db.add(member)
    db.commit()
    db.refresh(club)

    return {
        "message": f"'{club.name}' 동아리가 생성됐습니다! 🎉",
        "club_id": club.id,
        "club_name": club.name,
        "role": "super_admin",
        "invite_code": club.invite_code,
        "invite_code_expires_at": club.invite_code_expires_at.isoformat(),
    }


@app.post("/clubs/join")
@limiter.limit("10/minute")  # 초대코드 브루트포스 방어
def join_club(
    request: Request,
    background_tasks: BackgroundTasks,
    req: ClubJoinRequest,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user)
):
    """초대 코드로 동아리 가입"""
    club = db.query(db_models.Club).filter(
        db_models.Club.invite_code == req.invite_code.upper()
    ).first()
    if not club:
        raise HTTPException(status_code=404, detail="유효하지 않은 초대 코드입니다.")

    # 만료 확인
    if club.invite_code_expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=400,
            detail="초대 코드가 만료됐습니다. 동아리장에게 새 코드를 요청하세요."
        )

    # 이미 가입된 멤버 확인
    existing = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club.id,
        db_models.ClubMember.user_id == current_user.id
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="이미 해당 동아리의 멤버입니다.")

    member = db_models.ClubMember(
        club_id=club.id,
        user_id=current_user.id,
        role="user",
    )
    db.add(member)
    db.commit()

    # Push to admins
    admins = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club.id,
        db_models.ClubMember.role.in_(["admin", "super_admin"])
    ).all()
    admin_tokens = [m.user.fcm_token for m in admins if m.user and m.user.fcm_token]
    if admin_tokens:
        background_tasks.add_task(
            _send_new_member_push,
            admin_tokens,
            club.name,
            current_user.display_name or current_user.email,
        )

    return {
        "message": f"'{club.name}' 동아리에 가입됐습니다! 🎊",
        "club_id": club.id,
        "club_name": club.name,
        "role": "user",
    }


@app.get("/clubs/my")
def get_my_clubs(
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """내가 속한 동아리 목록 (X-Club-Id 헤더 불필요)"""
    memberships = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.user_id == current_user.id
    ).all()

    return [
        {
            "club_id": m.club_id,
            "club_name": m.club.name,
            "role": m.role,
        }
        for m in memberships
    ]


@app.get("/clubs/{club_id}/invite-code")
def get_invite_code(
    club_id: int,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user)
):
    """초대 코드 조회 (만료 시 자동 재발급) — 회장 전용"""
    # 직접 권한 체크 (path param과 Header 충돌 우회)
    me = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id,
        db_models.ClubMember.user_id == current_user.id
    ).first()
    if not me or me.role != "super_admin":
        raise HTTPException(status_code=403, detail="회장만 접근할 수 있습니다.")

    club = db.query(db_models.Club).filter(db_models.Club.id == club_id).first()
    if not club:
        raise HTTPException(status_code=404, detail="동아리를 찾을 수 없습니다.")

    # 만료됐으면 새 코드 발급
    if club.invite_code_expires_at < datetime.utcnow():
        code, expires_at = generate_invite_code()
        club.invite_code = code
        club.invite_code_expires_at = expires_at
        db.commit()
        db.refresh(club)

    return {
        "invite_code": club.invite_code,
        "expires_at": club.invite_code_expires_at.isoformat(),
    }


@app.post("/clubs/{club_id}/invite-code/regenerate")
def regenerate_invite_code(
    club_id: int,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user)
):
    """초대 코드 강제 재발급 — 회장 전용"""
    me = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id,
        db_models.ClubMember.user_id == current_user.id
    ).first()
    if not me or me.role != "super_admin":
        raise HTTPException(status_code=403, detail="회장만 접근할 수 있습니다.")

    club = db.query(db_models.Club).filter(db_models.Club.id == club_id).first()
    if not club:
        raise HTTPException(status_code=404, detail="동아리를 찾을 수 없습니다.")

    code, expires_at = generate_invite_code()
    club.invite_code = code
    club.invite_code_expires_at = expires_at
    db.commit()
    db.refresh(club)

    return {
        "invite_code": club.invite_code,
        "expires_at": club.invite_code_expires_at.isoformat(),
    }


@app.get("/clubs/{club_id}/members")
def get_members(
    club_id: int,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user)
):
    """멤버 목록 조회"""
    # 해당 동아리 멤버인지 확인
    me = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id,
        db_models.ClubMember.user_id == current_user.id
    ).first()
    if not me:
        raise HTTPException(status_code=403, detail="해당 동아리의 멤버가 아닙니다.")

    members = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id
    ).all()

    return [
        {
            "user_id": m.user_id,
            "display_name": m.user.display_name,
            "username": m.user.username,
            "role": m.role,
            "joined_at": m.joined_at.strftime("%Y-%m-%d"),
        }
        for m in members
    ]


@app.delete("/clubs/{club_id}/members/{user_id}")
@limiter.limit("10/minute")
def kick_member(
    request: Request,
    club_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user)
):
    """멤버 강제 탈퇴 — 회장 전용"""
    me = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id,
        db_models.ClubMember.user_id == current_user.id
    ).first()
    if not me or me.role != "super_admin":
        raise HTTPException(status_code=403, detail="회장만 접근할 수 있습니다.")

    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="자기 자신을 내보낼 수 없습니다.")

    target = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id,
        db_models.ClubMember.user_id == user_id
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="해당 멤버를 찾을 수 없습니다.")
    if target.role == "super_admin":
        raise HTTPException(status_code=400, detail="다른 회장을 내보낼 수 없습니다.")

    db.delete(target)
    db.commit()
    return {"message": "멤버를 내보냈습니다."}


@app.patch("/clubs/{club_id}/members/{user_id}/role")
@limiter.limit("10/minute")
def update_member_role(
    request: Request,
    club_id: int,
    user_id: int,
    req: RoleUpdateRequest,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user)
):
    """역할 변경 — 회장 전용 (super_admin 부여 불가 — Literal 타입으로 강제)"""
    me = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id,
        db_models.ClubMember.user_id == current_user.id
    ).first()
    if not me or me.role != "super_admin":
        raise HTTPException(status_code=403, detail="회장만 접근할 수 있습니다.")

    target = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id,
        db_models.ClubMember.user_id == user_id
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="해당 멤버를 찾을 수 없습니다.")
    if target.role == "super_admin":
        raise HTTPException(status_code=400, detail="회장의 역할은 변경할 수 없습니다.")

    target.role = req.role
    db.commit()

    role_labels = {"admin": "임원진", "user": "일반 멤버"}
    return {
        "message": f"역할이 '{role_labels[req.role]}'(으)로 변경됐습니다.",
        "user_id": user_id,
        "role": req.role,
    }


@app.post("/clubs/{club_id}/members/{user_id}/reset-password")
@limiter.limit("5/minute")
async def reset_member_password(
    request: Request,
    club_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    """멤버 임시 비밀번호 발급 — 회장(super_admin) 전용"""
    me = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id,
        db_models.ClubMember.user_id == current_user.id
    ).first()
    if not me or me.role != "super_admin":
        raise HTTPException(status_code=403, detail="회장만 접근할 수 있습니다.")

    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="자기 자신의 비밀번호는 변경할 수 없습니다.")

    target_member = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id,
        db_models.ClubMember.user_id == user_id
    ).first()
    if not target_member:
        raise HTTPException(status_code=404, detail="해당 멤버를 찾을 수 없습니다.")

    target_user = db.query(db_models.User).filter(db_models.User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    # 임시 비밀번호 생성 (8자, 대/소문자/숫자 각 1개 이상)
    chars = string.ascii_letters + string.digits
    while True:
        temp_password = ''.join(secrets.choice(chars) for _ in range(8))
        if (any(c.isupper() for c in temp_password)
                and any(c.islower() for c in temp_password)
                and any(c.isdigit() for c in temp_password)):
            break

    target_user.hashed_password = hash_password(temp_password)
    target_user.failed_login_attempts = 0
    target_user.locked_until = None
    db.commit()
    logger.info(f"Password reset by {current_user.username} for user {target_user.username}")

    # 이메일이 있으면 본인에게 직접 발송 (응답에 비밀번호 미포함)
    if target_user.email and settings.MAIL_USERNAME:
        try:
            mail_config = _get_mail_config()
            message = MessageSchema(
                subject="[StageMate] 임시 비밀번호 발급",
                recipients=[target_user.email],
                body=(
                    f"안녕하세요, {target_user.display_name}님!\n\n"
                    f"동아리 관리자가 임시 비밀번호를 발급했습니다.\n\n"
                    f"  임시 비밀번호: {temp_password}\n\n"
                    f"로그인 후 반드시 비밀번호를 변경해 주세요.\n"
                    f"(설정 → 계정 관리 → 비밀번호 변경)\n\n"
                    f"감사합니다.\nStageMate 팀"
                ),
                subtype=MessageType.plain,
            )
            await FastMail(mail_config).send_message(message)
            logger.info(f"Temp password emailed to {target_user.username}")
            return {
                "message": f"'{target_user.display_name}' 임시 비밀번호가 이메일로 발송됐습니다.",
                "display_name": target_user.display_name,
                "sent_to_email": True,
            }
        except Exception as e:
            logger.error(f"Failed to email temp password: {e}")
            # 이메일 발송 실패 시 응답에 포함 (fallback)

    # 이메일 없음 또는 SMTP 미설정 — 응답에 포함 (관리자가 직접 전달)
    return {
        "message": f"'{target_user.display_name}' 임시 비밀번호가 발급됐습니다.",
        "temp_password": temp_password,
        "display_name": target_user.display_name,
        "sent_to_email": False,
    }


# ════════════════════════════════════════════════
#  공지사항 (Notice)
# ════════════════════════════════════════════════

@app.get("/notices")
def get_notices(
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member)
):
    notices = db.query(db_models.Notice).filter(
        db_models.Notice.club_id == member.club_id
    ).order_by(db_models.Notice.created_at.desc()).all()

    return [
        {
            "id": n.id,
            "title": n.title,
            "content": n.content,
            "media_urls": n.media_urls or [],
            "author": n.author.display_name,
            "author_id": n.author_id,
            "created_at": n.created_at.strftime("%Y-%m-%d %H:%M"),
        }
        for n in notices
    ]


@app.post("/notices")
def create_notice(
    req: NoticeRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_admin)
):
    notice = db_models.Notice(
        club_id=member.club_id,
        title=req.title,
        content=req.content,
        media_urls=req.media_urls,
        author_id=member.user_id,
    )
    db.add(notice)
    db.commit()
    db.refresh(notice)

    # 동아리 전체 멤버에게 FCM 푸시 발송 (백그라운드, 논블로킹)
    club = db.query(db_models.Club).filter(db_models.Club.id == member.club_id).first()
    club_name = club.name if club else "동아리"
    members = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == member.club_id
    ).all()
    tokens = [
        m.user.fcm_token
        for m in members
        if m.user and m.user.fcm_token
    ]
    background_tasks.add_task(
        _send_announcement_push,
        tokens,
        club_name,
        req.title,
        notice.id,
    )

    return {"message": "공지사항이 등록됐습니다!", "id": notice.id}


@app.get("/notices/{notice_id}")
def get_notice(
    notice_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member)
):
    notice = db.query(db_models.Notice).filter(
        db_models.Notice.id == notice_id,
        db_models.Notice.club_id == member.club_id
    ).first()
    if not notice:
        raise HTTPException(status_code=404, detail="공지사항을 찾을 수 없습니다.")
    return {
        "id": notice.id,
        "title": notice.title,
        "content": notice.content,
        "media_urls": notice.media_urls or [],
        "author": notice.author.display_name,
        "author_id": notice.author_id,
        "created_at": notice.created_at.strftime("%Y-%m-%d %H:%M"),
    }


@app.patch("/notices/{notice_id}")
def update_notice(
    notice_id: int,
    req: NoticeRequest,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_admin)
):
    notice = db.query(db_models.Notice).filter(
        db_models.Notice.id == notice_id,
        db_models.Notice.club_id == member.club_id
    ).first()
    if not notice:
        raise HTTPException(status_code=404, detail="공지사항을 찾을 수 없습니다.")
    # 작성자 본인만 수정 가능
    if notice.author_id != member.user_id:
        raise HTTPException(status_code=403, detail="본인이 작성한 공지사항만 수정할 수 있습니다.")
    notice.title = req.title
    notice.content = req.content
    db.commit()
    return {"message": "수정되었습니다."}


@app.delete("/notices/{notice_id}")
def delete_notice(
    notice_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_admin)
):
    notice = db.query(db_models.Notice).filter(
        db_models.Notice.id == notice_id,
        db_models.Notice.club_id == member.club_id
    ).first()
    if not notice:
        raise HTTPException(status_code=404, detail="공지사항을 찾을 수 없습니다.")
    # 임원진(admin)은 본인 작성 공지만 삭제 가능 / 회장(super_admin)은 모두 삭제 가능
    if member.role == "admin" and notice.author_id != member.user_id:
        raise HTTPException(status_code=403, detail="본인이 작성한 공지사항만 삭제할 수 있습니다.")
    db.delete(notice)
    db.commit()
    return {"message": "삭제 완료!"}


# ── 공지사항 댓글 ─────────────────────────────────
@app.get("/notices/{notice_id}/comments")
def get_comments(
    notice_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member)
):
    notice = db.query(db_models.Notice).filter(
        db_models.Notice.id == notice_id,
        db_models.Notice.club_id == member.club_id
    ).first()
    if not notice:
        raise HTTPException(status_code=404, detail="공지사항을 찾을 수 없습니다.")
    return [
        {
            "id": c.id,
            "author": c.author.display_name,
            "author_id": c.author_id,
            "content": c.content,
            "created_at": c.created_at.strftime("%Y-%m-%d %H:%M"),
        }
        for c in notice.comments
    ]


@app.post("/notices/{notice_id}/comments")
def create_comment(
    notice_id: int,
    req: CommentRequest,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member)
):
    notice = db.query(db_models.Notice).filter(
        db_models.Notice.id == notice_id,
        db_models.Notice.club_id == member.club_id
    ).first()
    if not notice:
        raise HTTPException(status_code=404, detail="공지사항을 찾을 수 없습니다.")
    comment = db_models.NoticeComment(
        notice_id=notice_id,
        author_id=member.user_id,
        content=req.content,
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return {
        "id": comment.id,
        "author": comment.author.display_name,
        "author_id": comment.author_id,
        "content": comment.content,
        "created_at": comment.created_at.strftime("%Y-%m-%d %H:%M"),
    }


@app.delete("/notices/{notice_id}/comments/{comment_id}")
def delete_comment(
    notice_id: int,
    comment_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member)
):
    # 공지가 같은 클럽 소속인지 먼저 확인 (H-1: IDOR 방어)
    notice = db.query(db_models.Notice).filter(
        db_models.Notice.id == notice_id,
        db_models.Notice.club_id == member.club_id,
    ).first()
    if not notice:
        raise HTTPException(status_code=404, detail="공지사항을 찾을 수 없습니다.")

    comment = db.query(db_models.NoticeComment).filter(
        db_models.NoticeComment.id == comment_id,
        db_models.NoticeComment.notice_id == notice_id,
    ).first()
    if not comment:
        raise HTTPException(status_code=404, detail="댓글을 찾을 수 없습니다.")
    # 본인 댓글 또는 회장/임원진만 삭제 가능
    if comment.author_id != member.user_id and member.role not in ("admin", "super_admin"):
        raise HTTPException(status_code=403, detail="삭제 권한이 없습니다.")
    db.delete(comment)
    db.commit()
    return {"message": "댓글이 삭제됐습니다."}


# ════════════════════════════════════════════════
#  무대 순서 최적화
# ════════════════════════════════════════════════

@app.post("/schedule")
def create_schedule(
    config: PerformanceConfig,
    member: db_models.ClubMember = Depends(require_admin)
):
    return calculate_schedule(config)


# ════════════════════════════════════════════════
#  그룹 스케줄 조율
# ════════════════════════════════════════════════

@app.post("/availability")
def save_availability(
    req: SlotRequest,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member)
):
    slot = db_models.AvailabilitySlot(
        user_id=member.user_id,
        club_id=member.club_id,
        room_code=req.room_code,
        day=req.day,
        start_time=req.start_time,
        end_time=req.end_time,
    )
    db.add(slot)
    db.commit()
    return {"message": f"{req.day} {req.start_time}~{req.end_time} 저장 완료!"}


@app.delete("/availability/{slot_id}")
def delete_availability(
    slot_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member)
):
    slot = db.query(db_models.AvailabilitySlot).filter(
        db_models.AvailabilitySlot.id == slot_id,
        db_models.AvailabilitySlot.user_id == member.user_id,
        db_models.AvailabilitySlot.club_id == member.club_id,
    ).first()
    if not slot:
        raise HTTPException(status_code=404, detail="슬롯을 찾을 수 없습니다.")
    db.delete(slot)
    db.commit()
    return {"message": "삭제 완료!"}


@app.get("/availability/{room_code}")
def get_availability(
    room_code: str,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member)
):
    slots = db.query(db_models.AvailabilitySlot).filter(
        db_models.AvailabilitySlot.room_code == room_code,
        db_models.AvailabilitySlot.club_id == member.club_id,
    ).all()

    members_dict = {}
    for slot in slots:
        name = slot.user.display_name
        if name not in members_dict:
            members_dict[name] = []
        members_dict[name].append({
            "id": slot.id,
            "day": slot.day,
            "start": slot.start_time,
            "end": slot.end_time,
        })
    return {"room_code": room_code, "members": members_dict}


@app.post("/group-schedule/{room_code}")
def group_schedule(
    room_code: str,
    duration_needed: float = 2.0,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member)
):
    return find_common_slots_from_db(room_code, duration_needed, db, member.club_id)


# ════════════════════════════════════════════════
#  연습실 예약
# ════════════════════════════════════════════════

@app.post("/booking")
def create_booking(
    booking: RoomBooking,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member)
):
    return add_booking_db(booking, member.user_id, member.club_id, db)


@app.get("/booking/{date}")
def get_booking_list(
    date: str,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member)
):
    return get_bookings_db(date, member.club_id, db)


@app.delete("/booking/{booking_id}")
def cancel_booking(
    booking_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member)
):
    return delete_booking_db(booking_id, member.user_id, member.club_id, db)


# ════════════════════════════════════════════════
#  게시판 (Posts)
# ════════════════════════════════════════════════

@app.post("/posts")
@limiter.limit("20/minute")
def create_post(
    request: Request,
    req: PostRequest,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """게시글 작성 (동아리 피드 or 전체 채널)"""
    author = db.query(db_models.User).filter(db_models.User.id == member.user_id).first()
    # 전체 커뮤니티: 익명 or 닉네임 / 동아리: 항상 실명
    if req.is_global:
        if req.is_anonymous:
            post_author_name = "익명"
        else:
            post_author_name = (author.nickname if author and author.nickname else None)
    else:
        post_author_name = None  # 실명 사용 (author.display_name)

    post = db_models.Post(
        club_id=member.club_id if not req.is_global else None,
        author_id=member.user_id,
        content=req.content,
        media_urls=req.media_urls,
        is_global=req.is_global,
        is_anonymous=req.is_anonymous,
        post_author_name=post_author_name,
        view_count=0,
        youtube_url=req.youtube_url,
    )
    db.add(post)
    db.commit()
    db.refresh(post)
    return {"id": post.id, "message": "게시글이 등록됐습니다."}


@app.get("/posts")
@limiter.limit("60/minute")
def get_posts(
    request: Request,
    is_global: bool = False,
    offset: int = 0,
    limit: int = 20,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """게시글 목록 조회 (동아리 피드 or 전체 채널, 최신순)"""
    limit = min(limit, 50)  # L-1: 최대 50개 제한 (DoS 방어)
    query = db.query(db_models.Post)
    if is_global:
        query = query.filter(db_models.Post.is_global == True)
    else:
        query = query.filter(
            db_models.Post.club_id == member.club_id,
            db_models.Post.is_global == False,
        )
    posts = query.order_by(
        desc(db_models.Post.is_boosted),
        nulls_last(desc(db_models.Post.boost_expires_at)),
        desc(db_models.Post.created_at),
    ).offset(offset).limit(limit).all()

    result = []
    for p in posts:
        author = db.query(db_models.User).filter(db_models.User.id == p.author_id).first()
        like_count = db.query(db_models.PostLike).filter(db_models.PostLike.post_id == p.id).count()
        comment_count = db.query(db_models.PostComment).filter(db_models.PostComment.post_id == p.id).count()
        my_liked = db.query(db_models.PostLike).filter(
            db_models.PostLike.post_id == p.id,
            db_models.PostLike.user_id == member.user_id,
        ).first() is not None
        # 표시 이름: 전체 채널은 닉네임/익명만 사용, 동아리 내부는 실명 사용
        if p.is_global:
            # 전체 채널: post_author_name(닉네임 or "익명")만 사용, display_name 폴백 금지
            display_author = p.post_author_name or "알 수 없음"
        else:
            # 동아리 내부: 실명 사용
            display_author = p.post_author_name or (author.display_name if author else "탈퇴한 사용자")
        # 익명 글이면 아바타 노출 안 함
        author_avatar = (
            None if (p.is_anonymous)
            else (author.avatar_url if author else None)
        )
        result.append({
            "id": p.id,
            "author": display_author,
            "author_id": p.author_id,
            "author_avatar": author_avatar or "",
            "is_anonymous": p.is_anonymous or False,
            "content": p.content,
            "media_urls": p.media_urls or [],
            "youtube_url": p.youtube_url,
            "like_count": like_count,
            "comment_count": comment_count,
            "view_count": p.view_count or 0,
            "my_liked": my_liked,
            "is_global": p.is_global,
            "is_boosted": p.is_boosted or False,
            "created_at": p.created_at.strftime("%Y.%m.%d %H:%M") if p.created_at else "",
        })
    return result


@app.get("/posts/search")
@limiter.limit("30/minute")
def search_posts(
    request: Request,
    q: str = "",
    is_global: bool = False,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """게시글 검색 (content ILIKE, 우리동아리/전체동아리)"""
    q_stripped = q.strip()
    if len(q_stripped) < 2:
        return []

    # % 와 _ 와일드카드 이스케이프 (사용자 입력 보호)
    q_safe = q_stripped.replace('%', r'\%').replace('_', r'\_')
    q_like = f"%{q_safe}%"

    query = db.query(db_models.Post).filter(
        db_models.Post.content.ilike(q_like)
    )

    if is_global:
        # 전체 동아리: is_global=True인 게시글은 모든 인증 멤버에게 공개 (의도된 동작)
        query = query.filter(db_models.Post.is_global == True)
    else:
        # 우리 동아리: 요청자의 club_id로 필터
        query = query.filter(
            db_models.Post.is_global == False,
            db_models.Post.club_id == member.club_id,
        )

    posts = query.order_by(desc(db_models.Post.created_at)).limit(20).all()

    result = []
    for p in posts:
        author = db.query(db_models.User).filter(db_models.User.id == p.author_id).first()
        like_count = db.query(db_models.PostLike).filter(db_models.PostLike.post_id == p.id).count()
        comment_count = db.query(db_models.PostComment).filter(db_models.PostComment.post_id == p.id).count()
        my_liked = db.query(db_models.PostLike).filter(
            db_models.PostLike.post_id == p.id,
            db_models.PostLike.user_id == member.user_id,
        ).first() is not None

        if p.is_global:
            display_author = p.post_author_name or "알 수 없음"
        else:
            display_author = p.post_author_name or (author.display_name if author else "탈퇴한 사용자")

        # 익명 글이면 author 이름/아바타 null (author_id는 항상 반환 — "내 글" 판단에 필요)
        author_name = None if p.is_anonymous else display_author
        author_avatar = None if p.is_anonymous else (author.avatar_url if author else None)

        result.append({
            "id": p.id,
            "author": author_name,
            "author_id": p.author_id,
            "author_avatar": author_avatar or "",
            "is_anonymous": p.is_anonymous or False,
            "content": p.content,
            "media_urls": p.media_urls or [],
            "youtube_url": p.youtube_url,
            "like_count": like_count,
            "comment_count": comment_count,
            "view_count": p.view_count or 0,
            "my_liked": my_liked,
            "is_boosted": p.is_boosted or False,
            "is_global": p.is_global,
            "club_id": p.club_id,
            "created_at": p.created_at.strftime("%Y.%m.%d %H:%M") if p.created_at else "",
        })
    return result


@app.get("/posts/{post_id}")
@limiter.limit("60/minute")
def get_post(
    request: Request,
    post_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """게시글 단건 조회 (푸시 알림 딥링크용)"""
    p = db.query(db_models.Post).filter(db_models.Post.id == post_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    # 권한 확인: 전체 채널이 아니면 같은 동아리만
    if not p.is_global and p.club_id != member.club_id:
        raise HTTPException(status_code=403, detail="접근 권한이 없습니다.")

    author = db.query(db_models.User).filter(db_models.User.id == p.author_id).first()
    like_count = db.query(db_models.PostLike).filter(db_models.PostLike.post_id == p.id).count()
    comment_count = db.query(db_models.PostComment).filter(db_models.PostComment.post_id == p.id).count()
    my_liked = db.query(db_models.PostLike).filter(
        db_models.PostLike.post_id == p.id,
        db_models.PostLike.user_id == member.user_id,
    ).first() is not None

    if p.is_global:
        display_author = p.post_author_name or "알 수 없음"
    else:
        display_author = p.post_author_name or (author.display_name if author else "탈퇴한 사용자")
    author_avatar = (
        None if (p.is_anonymous)
        else (author.avatar_url if author else None)
    )
    return {
        "id": p.id,
        "author": display_author,
        "author_id": p.author_id,
        "author_avatar": author_avatar or "",
        "is_anonymous": p.is_anonymous or False,
        "content": p.content,
        "media_urls": p.media_urls or [],
        "youtube_url": p.youtube_url,
        "like_count": like_count,
        "comment_count": comment_count,
        "view_count": p.view_count or 0,
        "my_liked": my_liked,
        "is_global": p.is_global,
        "is_boosted": p.is_boosted or False,
        "created_at": p.created_at.strftime("%Y.%m.%d %H:%M") if p.created_at else "",
    }


@app.delete("/posts/{post_id}")
def delete_post(
    post_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """게시글 삭제 (작성자 본인만, 클럽 경계 검증 포함)"""
    post = db.query(db_models.Post).filter(db_models.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    # 전체 공개 게시글이 아닌 경우, 같은 클럽 소속인지 확인
    if not post.is_global and post.club_id != member.club_id:
        raise HTTPException(status_code=403, detail="삭제 권한이 없습니다.")
    if post.author_id != member.user_id:
        raise HTTPException(status_code=403, detail="삭제 권한이 없습니다.")
    db.delete(post)
    db.commit()
    return {"message": "삭제됐습니다."}


@app.post("/posts/{post_id}/boost")
@limiter.limit("10/minute")
def boost_post(
    request: Request,
    post_id: int,
    db:      Session = Depends(get_db),
    member:  db_models.ClubMember = Depends(require_any_member),
):
    """게시글 홍보 부스트 — 크레딧 차감, 24시간 상단 고정 (super_admin만)"""
    if member.role != "super_admin":
        raise HTTPException(status_code=403, detail="동아리장만 홍보 부스트를 사용할 수 있습니다.")

    post = db.query(db_models.Post).filter(db_models.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    if post.club_id != member.club_id:
        raise HTTPException(status_code=403, detail="해당 동아리의 게시글이 아닙니다.")
    if not post.is_global:
        raise HTTPException(status_code=400, detail="전체 채널 게시글만 홍보 부스트할 수 있습니다.")
    if post.is_boosted:
        raise HTTPException(status_code=409, detail="이미 부스트 중인 게시글입니다.")

    # with_for_update: 동시 부스트 레이스 컨디션 방어
    club = db.query(db_models.Club).filter(
        db_models.Club.id == member.club_id
    ).with_for_update().first()
    if not club or (club.boost_credits or 0) <= 0:
        raise HTTPException(status_code=402, detail="홍보 부스트 크레딧이 없습니다. STANDARD 이상 구독이 필요합니다.")

    post.is_boosted = True
    post.boost_expires_at = datetime.utcnow() + timedelta(hours=24)
    club.boost_credits -= 1
    db.commit()
    return {
        "message": "홍보 부스트가 적용됐습니다. 24시간 동안 상단에 노출됩니다.",
        "credits_remaining": club.boost_credits,
    }


@app.post("/posts/{post_id}/likes")
def toggle_like(
    post_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """좋아요 토글 (없으면 추가, 있으면 취소)"""
    post = db.query(db_models.Post).filter(db_models.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    # 비공개 클럽 게시글은 같은 클럽 멤버만 좋아요 가능 (M-2: 클럽 경계)
    if not post.is_global and post.club_id != member.club_id:
        raise HTTPException(status_code=403, detail="접근 권한이 없습니다.")
    existing = db.query(db_models.PostLike).filter(
        db_models.PostLike.post_id == post_id,
        db_models.PostLike.user_id == member.user_id,
    ).first()
    if existing:
        db.delete(existing)
        db.commit()
        liked = False
    else:
        db.add(db_models.PostLike(post_id=post_id, user_id=member.user_id))
        db.commit()
        liked = True
    like_count = db.query(db_models.PostLike).filter(db_models.PostLike.post_id == post_id).count()
    return {"liked": liked, "like_count": like_count}


@app.get("/posts/{post_id}/comments")
def get_post_comments(
    post_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """게시글 댓글 목록 (조회 시 view_count +1)"""
    post = db.query(db_models.Post).filter(db_models.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    # 비공개 클럽 게시글은 같은 클럽 멤버만 조회 가능 (M-1: 클럽 경계)
    if not post.is_global and post.club_id != member.club_id:
        raise HTTPException(status_code=403, detail="접근 권한이 없습니다.")
    post.view_count = (post.view_count or 0) + 1
    db.commit()
    comments = db.query(db_models.PostComment).filter(
        db_models.PostComment.post_id == post_id
    ).order_by(db_models.PostComment.created_at.asc()).all()

    # ── 좋아요 집계 (N+1 방지: 한 번에 조회) ──────────────
    comment_ids = [c.id for c in comments]
    if comment_ids:
        like_counts = dict(
            db.query(db_models.CommentLike.comment_id, func.count(db_models.CommentLike.id))
            .filter(db_models.CommentLike.comment_id.in_(comment_ids))
            .group_by(db_models.CommentLike.comment_id)
            .all()
        )
        my_likes = set(
            row[0] for row in
            db.query(db_models.CommentLike.comment_id)
            .filter(
                db_models.CommentLike.comment_id.in_(comment_ids),
                db_models.CommentLike.user_id == member.user_id,
            )
            .all()
        )
    else:
        like_counts, my_likes = {}, set()

    # ── 베스트 댓글 결정 (좋아요 최다, 최소 1개, 동점 시 먼저 작성된 댓글) ──
    best_comment_id = None
    max_likes = 0
    for c in comments:  # already ordered by created_at asc → first encountered wins ties
        count = like_counts.get(c.id, 0)
        if count > max_likes:
            max_likes = count
            best_comment_id = c.id

    result = []
    for c in comments:
        author = db.query(db_models.User).filter(db_models.User.id == c.author_id).first()
        if post and post.is_global:
            author_name = (author.nickname if author and author.nickname else "알 수 없음")
        else:
            author_name = (author.display_name if author else "탈퇴한 사용자")
        result.append({
            "id": c.id,
            "author": author_name,
            "author_id": c.author_id,
            "author_avatar": (author.avatar_url or "") if author else "",
            "content": c.content,
            "parent_id": c.parent_id,
            "created_at": c.created_at.strftime("%Y.%m.%d %H:%M") if c.created_at else "",
            "like_count": like_counts.get(c.id, 0),
            "is_liked_by_me": c.id in my_likes,
            "is_best": c.id == best_comment_id and max_likes > 0,
        })
    return result


@app.post("/posts/{post_id}/comments")
@limiter.limit("30/minute")
def create_post_comment(
    request: Request,
    background_tasks: BackgroundTasks,
    post_id: int,
    req: PostCommentRequest,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """게시글 댓글 작성"""
    post = db.query(db_models.Post).filter(db_models.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")

    # parent_id 검증: 존재 여부, 같은 게시글 소속, 1단계 깊이 제한
    if req.parent_id is not None:
        parent_comment = db.query(db_models.PostComment).filter(
            db_models.PostComment.id == req.parent_id
        ).first()
        if not parent_comment:
            raise HTTPException(status_code=404, detail="원 댓글을 찾을 수 없습니다.")
        if parent_comment.post_id != post_id:
            raise HTTPException(status_code=400, detail="다른 게시글의 댓글에는 대댓글을 달 수 없습니다.")
        if parent_comment.parent_id is not None:
            raise HTTPException(status_code=400, detail="대댓글에는 댓글을 달 수 없습니다.")

    comment = db_models.PostComment(
        post_id=post_id,
        author_id=member.user_id,
        content=req.content,
        parent_id=req.parent_id,
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    author = db.query(db_models.User).filter(db_models.User.id == member.user_id).first()

    # ── 게시글 작성자에게 알림 생성 (본인 댓글 제외) ──────
    actor_name = (author.nickname if author and author.nickname else "알 수 없음") if post and post.is_global else (author.display_name if author else "알 수 없음")
    preview = req.content[:30] + ("..." if len(req.content) > 30 else "")

    if post.author_id != member.user_id:
        notif = db_models.Notification(
            user_id=post.author_id,
            actor_id=member.user_id,
            post_id=post_id,
            message=f"{actor_name}님이 내 게시글에 댓글을 남겼어요: {preview}",
        )
        db.add(notif)
        db.commit()
        background_tasks.add_task(
            _send_push,
            post.author.fcm_token or "",
            "💬 새 댓글",
            f"{actor_name}: {preview}",
            post_id,
        )

    # ── 대댓글인 경우: 원 댓글 작성자에게도 알림 ──────
    if req.parent_id:
        parent = db.query(db_models.PostComment).filter(
            db_models.PostComment.id == req.parent_id
        ).first()
        if parent and parent.author_id != member.user_id and parent.author_id != post.author_id:
            parent_author = db.query(db_models.User).filter(db_models.User.id == parent.author_id).first()
            if parent_author and parent_author.fcm_token:
                background_tasks.add_task(
                    _send_push,
                    parent_author.fcm_token,
                    "↩️ 새 대댓글",
                    f"{actor_name}: {preview}",
                    post_id,
                )

    return {
        "id": comment.id,
        "author": (author.nickname if author and author.nickname else "알 수 없음") if post and post.is_global else (author.display_name if author else "탈퇴한 사용자"),
        "content": comment.content,
        "created_at": comment.created_at.strftime("%Y.%m.%d %H:%M") if comment.created_at else "",
    }


@app.delete("/posts/{post_id}/comments/{comment_id}")
def delete_post_comment(
    post_id: int,
    comment_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """게시글 댓글 삭제 (작성자 본인만, 클럽 경계 검증 포함)"""
    comment = db.query(db_models.PostComment).filter(
        db_models.PostComment.id == comment_id,
        db_models.PostComment.post_id == post_id,
    ).first()
    if not comment:
        raise HTTPException(status_code=404, detail="댓글을 찾을 수 없습니다.")
    # 해당 댓글이 속한 게시글의 클럽 경계 확인
    post = db.query(db_models.Post).filter(db_models.Post.id == post_id).first()
    if post and not post.is_global and post.club_id != member.club_id:
        raise HTTPException(status_code=403, detail="삭제 권한이 없습니다.")
    if comment.author_id != member.user_id:
        raise HTTPException(status_code=403, detail="삭제 권한이 없습니다.")
    db.delete(comment)
    db.commit()
    return {"message": "삭제됐습니다."}


@app.post("/posts/{post_id}/comments/{comment_id}/like")
@limiter.limit("60/minute")
def toggle_comment_like(
    request: Request,
    post_id: int,
    comment_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """댓글 좋아요 토글 (like ↔ unlike)"""
    comment = db.query(db_models.PostComment).filter(
        db_models.PostComment.id == comment_id,
        db_models.PostComment.post_id == post_id,
    ).first()
    if not comment:
        raise HTTPException(status_code=404, detail="댓글을 찾을 수 없습니다.")

    post = db.query(db_models.Post).filter(db_models.Post.id == post_id).first()
    if not post or (not post.is_global and post.club_id != member.club_id):
        raise HTTPException(status_code=403, detail="접근 권한이 없습니다.")

    existing = db.query(db_models.CommentLike).filter(
        db_models.CommentLike.comment_id == comment_id,
        db_models.CommentLike.user_id == member.user_id,
    ).first()

    if existing:
        db.delete(existing)
        db.commit()
        liked = False
    else:
        db.add(db_models.CommentLike(comment_id=comment_id, user_id=member.user_id))
        db.commit()
        liked = True

    like_count = db.query(db_models.CommentLike).filter(
        db_models.CommentLike.comment_id == comment_id
    ).count()

    return {"liked": liked, "like_count": like_count}


# ── 게시글 수정 ──────────────────────────────────────
@app.patch("/posts/{post_id}")
@limiter.limit("20/minute")
def update_post(
    request: Request,
    post_id: int,
    req: PostEditRequest,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """게시글 수정 (작성자 본인만, 클럽 경계 검증 포함)"""
    post = db.query(db_models.Post).filter(db_models.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    if not post.is_global and post.club_id != member.club_id:
        raise HTTPException(status_code=403, detail="수정 권한이 없습니다.")
    if post.author_id != member.user_id:
        raise HTTPException(status_code=403, detail="수정 권한이 없습니다.")
    post.content = req.content
    db.commit()
    return {"message": "수정됐습니다."}


# ── 댓글 수정 ─────────────────────────────────────────
@app.patch("/posts/{post_id}/comments/{comment_id}")
@limiter.limit("20/minute")
def update_post_comment(
    request: Request,
    post_id: int,
    comment_id: int,
    req: PostCommentRequest,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """댓글 수정 (작성자 본인만, 클럽 경계 검증 포함)"""
    comment = db.query(db_models.PostComment).filter(
        db_models.PostComment.id == comment_id,
        db_models.PostComment.post_id == post_id,
    ).first()
    if not comment:
        raise HTTPException(status_code=404, detail="댓글을 찾을 수 없습니다.")
    post = db.query(db_models.Post).filter(db_models.Post.id == post_id).first()
    if post and not post.is_global and post.club_id != member.club_id:
        raise HTTPException(status_code=403, detail="수정 권한이 없습니다.")
    if comment.author_id != member.user_id:
        raise HTTPException(status_code=403, detail="수정 권한이 없습니다.")
    comment.content = req.content
    db.commit()
    return {"message": "수정됐습니다."}


# ── 게시글 신고 ──────────────────────────────────────
@app.post("/posts/{post_id}/report")
@limiter.limit("10/minute")
def report_post(
    request: Request,
    post_id: int,
    req: ReportRequest,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """게시글 신고"""
    post = db.query(db_models.Post).filter(db_models.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    if post.author_id == member.user_id:
        raise HTTPException(status_code=400, detail="본인 게시글은 신고할 수 없습니다.")
    report = db_models.Report(
        reporter_id=member.user_id,
        post_id=post_id,
        reason=req.reason,
    )
    db.add(report)
    db.commit()
    return {"message": "신고가 접수됐습니다."}


# ── 댓글 신고 ─────────────────────────────────────────
@app.post("/posts/{post_id}/comments/{comment_id}/report")
@limiter.limit("10/minute")
def report_post_comment(
    request: Request,
    post_id: int,
    comment_id: int,
    req: ReportRequest,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """댓글 신고"""
    comment = db.query(db_models.PostComment).filter(
        db_models.PostComment.id == comment_id,
        db_models.PostComment.post_id == post_id,
    ).first()
    if not comment:
        raise HTTPException(status_code=404, detail="댓글을 찾을 수 없습니다.")
    if comment.author_id == member.user_id:
        raise HTTPException(status_code=400, detail="본인 댓글은 신고할 수 없습니다.")
    report = db_models.Report(
        reporter_id=member.user_id,
        comment_id=comment_id,
        reason=req.reason,
    )
    db.add(report)
    db.commit()
    return {"message": "신고가 접수됐습니다."}


# ════════════════════════════════════════════════
#  동아리 프로필
# ════════════════════════════════════════════════

@app.get("/clubs/{club_id}/profile")
def get_club_profile(
    club_id: int,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    """동아리 프로필 조회 (로그인한 사용자 누구나)"""
    club = db.query(db_models.Club).filter(db_models.Club.id == club_id).first()
    if not club:
        raise HTTPException(status_code=404, detail="동아리를 찾을 수 없습니다.")
    member_count = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id
    ).count()
    return {
        "club_id": club.id,
        "name": club.name,
        "logo_url": club.logo_url,
        "banner_url": club.banner_url,
        "theme_color": club.theme_color,
        "instagram_url": club.instagram_url,
        "youtube_url": club.youtube_url,
        "member_count": member_count,
    }


@app.patch("/clubs/{club_id}/profile")
@limiter.limit("10/minute")
def update_club_profile(
    request: Request,
    club_id: int,
    req: ClubProfileUpdate,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    """동아리 프로필 수정 (해당 동아리 super_admin만)"""
    # 1) 동아리 존재 확인 (먼저 404, 그 다음 403)
    club = db.query(db_models.Club).filter(db_models.Club.id == club_id).first()
    if not club:
        raise HTTPException(status_code=404, detail="동아리를 찾을 수 없습니다.")

    # 2) 권한 확인: path param club_id 기준으로 super_admin 체크
    # NOTE: 헤더 기반 require_super_admin 의존성 사용 금지 — path param 기준으로 직접 체크
    membership = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id,
        db_models.ClubMember.user_id == current_user.id,
        db_models.ClubMember.role == "super_admin",
    ).first()
    if not membership:
        raise HTTPException(status_code=403, detail="동아리 프로필 수정 권한이 없습니다.")

    # 3) model_fields_set으로 명시적으로 전달된 필드만 업데이트
    for field in req.model_fields_set:
        setattr(club, field, getattr(req, field))

    db.commit()
    db.refresh(club)

    member_count = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id
    ).count()
    return {
        "club_id": club.id,
        "name": club.name,
        "logo_url": club.logo_url,
        "banner_url": club.banner_url,
        "theme_color": club.theme_color,
        "instagram_url": club.instagram_url,
        "youtube_url": club.youtube_url,
        "member_count": member_count,
    }


# ════════════════════════════════════════════════
#  동아리 구독
# ════════════════════════════════════════════════

async def _verify_apple_receipt(receipt_data: str, product_id: str, transaction_id: str) -> None:
    """Apple App Store 서버-사이드 영수증 검증.
    프로덕션 URL 먼저 시도, 21007(sandbox) 응답 시 샌드박스로 재시도.
    검증 실패 시 HTTPException(400) raise."""
    if not settings.APPLE_IAP_SHARED_SECRET:
        logger.warning("APPLE_IAP_SHARED_SECRET 미설정 — 영수증 검증 건너뜀 (테스트 환경)")
        return

    payload = {
        "receipt-data": receipt_data,
        "password": settings.APPLE_IAP_SHARED_SECRET,
        "exclude-old-transactions": True,
    }

    urls = [
        "https://buy.itunes.apple.com/verifyReceipt",
        "https://sandbox.itunes.apple.com/verifyReceipt",
    ]
    verified = False
    for url in urls:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=payload)
            result = resp.json()
            status = result.get("status", -1)

            if status == 21007:
                # 프로덕션 서버가 "샌드박스 영수증"이라고 응답 → 다음 URL(sandbox)로 재시도
                continue
            if status != 0:
                logger.warning(f"Apple verifyReceipt 실패: status={status}")
                raise HTTPException(status_code=400, detail=f"Apple 영수증 검증 실패 (status={status})")

            # 영수증 내 in_app 구매 목록에서 product_id + transaction_id 확인
            in_app_list = result.get("receipt", {}).get("in_app", [])
            matched = any(
                item.get("product_id") == product_id and item.get("transaction_id") == transaction_id
                for item in in_app_list
            )
            if not matched:
                raise HTTPException(status_code=400, detail="영수증에서 해당 구매 내역을 찾을 수 없습니다.")

            verified = True
            break
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Apple verifyReceipt 요청 오류 ({url}): {e}")
            raise HTTPException(status_code=503, detail="Apple 영수증 검증 서버에 연결할 수 없습니다.")

    if not verified:
        raise HTTPException(status_code=400, detail="Apple 영수증 검증에 실패했습니다.")


@app.post("/clubs/{club_id}/subscription/verify")
@limiter.limit("5/minute")
async def verify_club_subscription(
    request:      Request,
    club_id:      int,
    req:          SubscriptionVerifyRequest,
    db:           Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    """동아리 인앱결제 영수증 검증 후 플랜 업데이트 (super_admin만)"""
    me = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id,
        db_models.ClubMember.user_id == current_user.id,
    ).first()
    if not me or me.role != "super_admin":
        raise HTTPException(status_code=403, detail="회장만 구독을 변경할 수 있습니다.")

    # 중복 transaction_id 방지
    dup = db.query(db_models.SubscriptionTransaction).filter(
        db_models.SubscriptionTransaction.transaction_id == req.transaction_id
    ).first()
    if dup:
        raise HTTPException(status_code=409, detail="이미 처리된 영수증입니다.")

    plan = PLAN_MAP.get(req.product_id)
    if not plan or plan == "personal":
        raise HTTPException(status_code=400, detail="올바르지 않은 동아리 구독 상품입니다.")

    if not req.receipt_data:
        raise HTTPException(status_code=400, detail="영수증 데이터가 없습니다.")

    # 플랫폼별 서버-사이드 영수증 검증
    if req.platform == "apple":
        await _verify_apple_receipt(req.receipt_data, req.product_id, req.transaction_id)
    else:
        # Google: purchase_token은 구글 Play Developer API로 검증 필요
        # GOOGLE_SERVICE_ACCOUNT_JSON 설정 후 google-auth 라이브러리로 구현 가능
        logger.warning(f"Google 영수증 서버 검증 미구현 — transaction_id={req.transaction_id}")

    purchased_at = datetime.utcnow()
    expires_at = purchased_at + timedelta(days=31)

    club = db.query(db_models.Club).filter(db_models.Club.id == club_id).first()
    if not club:
        raise HTTPException(status_code=404, detail="동아리를 찾을 수 없습니다.")
    club.plan = plan
    club.plan_expires_at = expires_at
    club.boost_credits = BOOST_CREDITS_MAP.get(plan, 0)

    txn = db_models.SubscriptionTransaction(
        club_id=club_id,
        user_id=current_user.id,
        product_id=req.product_id,
        transaction_id=req.transaction_id,
        platform=req.platform,
        purchased_at=purchased_at,
        expires_at=expires_at,
        status="active",
        raw_payload=req.receipt_data[:500],
    )
    db.add(txn)
    db.commit()
    return {
        "message": f"'{plan}' 플랜이 활성화됐습니다.",
        "plan": plan,
        "expires_at": expires_at.isoformat(),
    }


@app.get("/clubs/{club_id}/subscription")
def get_club_subscription(
    club_id:      int,
    db:           Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    """구독 상태 조회 (super_admin만)"""
    me = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id,
        db_models.ClubMember.user_id == current_user.id,
    ).first()
    if not me or me.role != "super_admin":
        raise HTTPException(status_code=403, detail="회장만 조회할 수 있습니다.")

    club = db.query(db_models.Club).filter(db_models.Club.id == club_id).first()
    if not club:
        raise HTTPException(status_code=404, detail="동아리를 찾을 수 없습니다.")
    quota_mb = {"free": 1024, "standard": 51200, "pro": 204800}.get(club.plan or "free", 1024)
    quota_mb += (club.storage_quota_extra_mb or 0)
    return {
        "plan":            club.plan or "free",
        "plan_expires_at": club.plan_expires_at.isoformat() if club.plan_expires_at else None,
        "storage_used_mb": club.storage_used_mb or 0,
        "storage_quota_mb": quota_mb,
        "boost_credits":   club.boost_credits or 0,
    }


# ════════════════════════════════════════════════
#  음원 제출 게시판 — 공연 관리
# ════════════════════════════════════════════════

@app.post("/clubs/{club_id}/performances")
def create_performance(
    club_id: int,
    req: PerformanceCreateRequest,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_admin),
):
    """공연 생성 (임원진 이상)"""
    if member.club_id != club_id:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    deadline = None
    if req.submission_deadline:
        try:
            deadline = datetime.fromisoformat(req.submission_deadline)
        except ValueError:
            raise HTTPException(status_code=400, detail="submission_deadline 형식이 올바르지 않습니다.")

    perf = db_models.Performance(
        club_id=club_id,
        name=req.name,
        performance_date=req.performance_date,
        submission_deadline=deadline,
        created_by=member.user_id,
    )
    db.add(perf)
    db.commit()
    db.refresh(perf)
    return {"id": perf.id, "message": "공연이 등록됐습니다."}


@app.get("/clubs/{club_id}/performances")
def list_performances(
    club_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """공연 목록 조회 (클럽 멤버 이상)"""
    if member.club_id != club_id:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    perfs = (
        db.query(db_models.Performance)
        .filter(db_models.Performance.club_id == club_id)
        .order_by(db_models.Performance.created_at.desc())
        .all()
    )
    return [
        {
            "id": p.id,
            "name": p.name,
            "performance_date": p.performance_date,
            "submission_deadline": (
                p.submission_deadline.isoformat() if p.submission_deadline else None
            ),
            "submission_count": len(p.submissions),
            "created_at": p.created_at.strftime("%Y-%m-%d"),
        }
        for p in perfs
    ]


@app.delete("/clubs/{club_id}/performances/{perf_id}")
def delete_performance(
    club_id: int,
    perf_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_admin),
):
    """공연 삭제 (임원진 이상, cascade로 음원 제출도 삭제)"""
    if member.club_id != club_id:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    perf = db.query(db_models.Performance).filter(
        db_models.Performance.id == perf_id,
        db_models.Performance.club_id == club_id,
    ).first()
    if not perf:
        raise HTTPException(status_code=404, detail="공연을 찾을 수 없습니다.")

    db.delete(perf)
    db.commit()
    return {"message": "공연이 삭제됐습니다."}


# ════════════════════════════════════════════════
#  음원 제출 게시판 — 제출 관리
# ════════════════════════════════════════════════

@app.post("/clubs/{club_id}/performances/{perf_id}/submissions")
def upsert_submission(
    club_id: int,
    perf_id: int,
    req: AudioSubmissionRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """음원 제출 / 재제출 (클럽 멤버 이상). 같은 공연에 이미 제출했으면 덮어씀."""
    if member.club_id != club_id:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    perf = db.query(db_models.Performance).filter(
        db_models.Performance.id == perf_id,
        db_models.Performance.club_id == club_id,
    ).first()
    if not perf:
        raise HTTPException(status_code=404, detail="공연을 찾을 수 없습니다.")

    existing = db.query(db_models.AudioSubmission).filter(
        db_models.AudioSubmission.performance_id == perf_id,
        db_models.AudioSubmission.submitted_by == member.user_id,
    ).first()

    if existing:
        existing.team_name = req.team_name
        existing.song_title = req.song_title
        existing.file_url = req.file_url
        existing.file_size_mb = req.file_size_mb
        existing.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        return {"id": existing.id, "message": "음원이 업데이트됐습니다."}
    else:
        sub = db_models.AudioSubmission(
            performance_id=perf_id,
            club_id=club_id,
            submitted_by=member.user_id,
            team_name=req.team_name,
            song_title=req.song_title,
            file_url=req.file_url,
            file_size_mb=req.file_size_mb,
        )
        db.add(sub)
        db.commit()
        db.refresh(sub)

        # admin/super_admin에게 새 음원 제출 푸시 알림 발송
        club = db.query(db_models.Club).filter(db_models.Club.id == club_id).first()
        club_name = club.name if club else "동아리"
        admins = db.query(db_models.ClubMember).filter(
            db_models.ClubMember.club_id == club_id,
            db_models.ClubMember.role.in_(["admin", "super_admin"])
        ).all()
        admin_tokens = [m.user.fcm_token for m in admins if m.user and m.user.fcm_token]
        if admin_tokens:
            background_tasks.add_task(
                _send_audio_submitted_push,
                admin_tokens,
                club_name,
                req.team_name,
                req.song_title,
            )

        return {"id": sub.id, "message": "음원이 제출됐습니다."}


@app.get("/clubs/{club_id}/performances/{perf_id}/submissions")
def list_submissions(
    club_id: int,
    perf_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_admin),
):
    """모든 제출 목록 조회 (임원진 이상)"""
    if member.club_id != club_id:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    subs = db.query(db_models.AudioSubmission).filter(
        db_models.AudioSubmission.performance_id == perf_id,
        db_models.AudioSubmission.club_id == club_id,
    ).order_by(db_models.AudioSubmission.updated_at.desc()).all()

    return [
        {
            "id": s.id,
            "team_name": s.team_name,
            "song_title": s.song_title,
            "file_url": s.file_url,
            "file_size_mb": s.file_size_mb,
            "submitter_name": s.submitter.display_name if s.submitter else "탈퇴한 사용자",
            "submitted_at": s.submitted_at.strftime("%Y-%m-%d %H:%M"),
            "updated_at": s.updated_at.strftime("%Y-%m-%d %H:%M") if s.updated_at else None,
        }
        for s in subs
    ]


@app.get("/clubs/{club_id}/performances/{perf_id}/submissions/mine")
def get_my_submission(
    club_id: int,
    perf_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """내 제출 현황 조회 (클럽 멤버 이상). 없으면 null 반환."""
    if member.club_id != club_id:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    sub = db.query(db_models.AudioSubmission).filter(
        db_models.AudioSubmission.performance_id == perf_id,
        db_models.AudioSubmission.submitted_by == member.user_id,
    ).first()

    if not sub:
        return {"submission": None}

    return {
        "submission": {
            "id": sub.id,
            "team_name": sub.team_name,
            "song_title": sub.song_title,
            "file_url": sub.file_url,
            "file_size_mb": sub.file_size_mb,
            "updated_at": sub.updated_at.strftime("%Y-%m-%d %H:%M") if sub.updated_at else None,
        }
    }


@app.delete("/clubs/{club_id}/performances/{perf_id}/submissions/{sub_id}")
def delete_submission(
    club_id: int,
    perf_id: int,
    sub_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """음원 제출 삭제 (본인만, 클럽 멤버 이상)"""
    if member.club_id != club_id:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    perf = db.query(db_models.Performance).filter(
        db_models.Performance.id == perf_id,
        db_models.Performance.club_id == club_id,
    ).first()
    if not perf:
        raise HTTPException(status_code=404, detail="공연을 찾을 수 없습니다.")

    sub = db.query(db_models.AudioSubmission).filter(
        db_models.AudioSubmission.id == sub_id,
        db_models.AudioSubmission.performance_id == perf_id,
        db_models.AudioSubmission.club_id == club_id,
    ).first()
    if not sub:
        raise HTTPException(status_code=404, detail="제출을 찾을 수 없습니다.")
    if sub.submitted_by != member.user_id:
        raise HTTPException(status_code=403, detail="본인의 제출만 삭제할 수 있습니다.")

    db.delete(sub)
    db.commit()
    return {"message": "제출이 삭제됐습니다."}


# ── 공연 아카이브 ──────────────────────────────────────────────

def _archive_to_dict(a, likes_count: int, my_liked: bool) -> dict:
    return {
        "id": a.id,
        "club_id": a.club_id,
        "title": a.title,
        "description": a.description,
        "performance_date": a.performance_date,
        "youtube_url": a.youtube_url,
        "native_video_url": a.native_video_url,
        "view_count": a.view_count,
        "likes_count": likes_count,
        "my_liked": my_liked,
        "created_at": a.created_at.strftime("%Y-%m-%d"),
    }


@app.get("/clubs/{club_id}/performance-archives")
def list_performance_archives(
    club_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    # 다른 동아리의 아카이브 접근 차단
    if member.club_id != club_id:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    archives = db.query(db_models.PerformanceArchive).filter(
        db_models.PerformanceArchive.club_id == club_id
    ).order_by(db_models.PerformanceArchive.performance_date.desc()).all()

    result = []
    for a in archives:
        likes_count = db.query(db_models.PerformanceArchiveLike).filter_by(archive_id=a.id).count()
        my_liked = db.query(db_models.PerformanceArchiveLike).filter_by(
            archive_id=a.id, user_id=member.user_id
        ).first() is not None
        result.append(_archive_to_dict(a, likes_count, my_liked))
    return result


@app.post("/clubs/{club_id}/performance-archives")
def create_performance_archive(
    club_id: int,
    req: PerformanceArchiveRequest,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_admin),
):
    # 다른 동아리의 아카이브 접근 차단
    if member.club_id != club_id:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    # 무료 플랜 15개 한도
    if member.club.plan == "free":
        count = db.query(db_models.PerformanceArchive).filter_by(club_id=club_id).count()
        if count >= 15:
            raise HTTPException(
                status_code=403,
                detail="무료 플랜은 최대 15개까지 저장할 수 있어요. 무제한은 PRO 플랜으로 업그레이드하세요.",
            )
    archive = db_models.PerformanceArchive(
        club_id=club_id,
        title=req.title,
        description=req.description,
        performance_date=req.performance_date,
        youtube_url=req.youtube_url,
    )
    db.add(archive)
    db.commit()
    db.refresh(archive)
    return {"message": "등록되었습니다.", "id": archive.id}


@app.get("/clubs/{club_id}/performance-archives/{archive_id}")
def get_performance_archive(
    club_id: int,
    archive_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    # 다른 동아리의 아카이브 접근 차단
    if member.club_id != club_id:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    a = db.query(db_models.PerformanceArchive).filter_by(
        id=archive_id, club_id=club_id
    ).first()
    if not a:
        raise HTTPException(status_code=404, detail="공연 기록을 찾을 수 없습니다.")
    # view_count 증가
    a.view_count += 1
    db.commit()
    likes_count = db.query(db_models.PerformanceArchiveLike).filter_by(archive_id=archive_id).count()
    my_liked = db.query(db_models.PerformanceArchiveLike).filter_by(
        archive_id=archive_id, user_id=member.user_id
    ).first() is not None
    return _archive_to_dict(a, likes_count, my_liked)


@app.post("/clubs/{club_id}/performance-archives/{archive_id}/like")
def toggle_archive_like(
    club_id: int,
    archive_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    # 다른 동아리의 아카이브 접근 차단
    if member.club_id != club_id:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    # 아카이브 존재 및 club_id 소속 확인
    archive = db.query(db_models.PerformanceArchive).filter_by(
        id=archive_id, club_id=club_id
    ).first()
    if not archive:
        raise HTTPException(status_code=404, detail="공연 기록을 찾을 수 없습니다.")

    existing = db.query(db_models.PerformanceArchiveLike).filter_by(
        archive_id=archive_id, user_id=member.user_id
    ).first()
    if existing:
        db.delete(existing)
        db.commit()
        return {"liked": False}
    db.add(db_models.PerformanceArchiveLike(archive_id=archive_id, user_id=member.user_id))
    db.commit()
    return {"liked": True}


@app.delete("/clubs/{club_id}/performance-archives/{archive_id}")
def delete_performance_archive(
    club_id: int,
    archive_id: int,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_admin),
):
    # 다른 동아리의 아카이브 접근 차단
    if member.club_id != club_id:
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    a = db.query(db_models.PerformanceArchive).filter_by(
        id=archive_id, club_id=club_id
    ).first()
    if not a:
        raise HTTPException(status_code=404, detail="공연 기록을 찾을 수 없습니다.")
    db.delete(a)
    db.commit()
    return {"message": "삭제되었습니다."}


# ════════════════════════════════════════════════
#  핫 동아리 순위
# ════════════════════════════════════════════════

@app.get("/clubs/hot-ranking")
def get_hot_clubs(
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """최근 7일간 게시글+댓글 수 기준 핫 동아리 순위 (전체 채널 기준)"""
    from sqlalchemy import func
    cutoff = datetime.utcnow() - timedelta(days=7)

    # 전체 채널 게시글 기준으로 동아리별 활동량 집계
    # post의 author_id → ClubMember → club_id
    post_counts = (
        db.query(db_models.ClubMember.club_id, func.count(db_models.Post.id).label("cnt"))
        .join(db_models.Post, db_models.Post.author_id == db_models.ClubMember.user_id)
        .filter(db_models.Post.created_at >= cutoff, db_models.Post.is_global == True)
        .group_by(db_models.ClubMember.club_id)
        .all()
    )
    comment_counts = (
        db.query(db_models.ClubMember.club_id, func.count(db_models.PostComment.id).label("cnt"))
        .join(db_models.PostComment, db_models.PostComment.author_id == db_models.ClubMember.user_id)
        .filter(db_models.PostComment.created_at >= cutoff)
        .group_by(db_models.ClubMember.club_id)
        .all()
    )

    scores: dict[int, int] = {}
    for club_id, cnt in post_counts:
        scores[club_id] = scores.get(club_id, 0) + cnt * 2  # 게시글은 가중치 2
    for club_id, cnt in comment_counts:
        scores[club_id] = scores.get(club_id, 0) + cnt

    if not scores:
        return []

    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:10]
    result = []
    for rank, (club_id, score) in enumerate(ranked, 1):
        club = db.query(db_models.Club).filter(db_models.Club.id == club_id).first()
        if club:
            result.append({"rank": rank, "club_id": club.id, "club_name": club.name, "score": score})
    return result


@app.patch("/users/me/fcm-token")
def update_fcm_token(
    req: FcmTokenRequest,
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """FCM 디바이스 토큰 등록/갱신"""
    current_user.fcm_token = req.token
    db.commit()
    return {"ok": True}


# ════════════════════════════════════════════════
#  내 활동 조회
# ════════════════════════════════════════════════

@app.get("/users/me/activity")
def get_my_activity(
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    """내가 쓴 게시글 + 댓글 목록"""
    posts = (
        db.query(db_models.Post)
        .filter(db_models.Post.author_id == current_user.id)
        .order_by(db_models.Post.created_at.desc())
        .limit(50)
        .all()
    )
    post_list = []
    for p in posts:
        like_count = db.query(db_models.PostLike).filter(db_models.PostLike.post_id == p.id).count()
        comment_count = db.query(db_models.PostComment).filter(db_models.PostComment.post_id == p.id).count()
        post_list.append({
            "id": p.id,
            "content": p.content,
            "media_urls": p.media_urls or [],
            "youtube_url": p.youtube_url,
            "like_count": like_count,
            "comment_count": comment_count,
            "is_global": p.is_global,
            "created_at": p.created_at.strftime("%Y.%m.%d %H:%M") if p.created_at else "",
        })

    comments = (
        db.query(db_models.PostComment)
        .filter(db_models.PostComment.author_id == current_user.id)
        .order_by(db_models.PostComment.created_at.desc())
        .limit(50)
        .all()
    )
    comment_list = []
    for c in comments:
        post = db.query(db_models.Post).filter(db_models.Post.id == c.post_id).first()
        comment_list.append({
            "id": c.id,
            "content": c.content,
            "post_id": c.post_id,
            "post_preview": (post.content[:50] + "...") if post and len(post.content) > 50 else (post.content if post else "삭제된 게시글"),
            "created_at": c.created_at.strftime("%Y.%m.%d %H:%M") if c.created_at else "",
        })

    return {"posts": post_list, "comments": comment_list}


# ════════════════════════════════════════════════
#  알림 (Notifications)
# ════════════════════════════════════════════════

@app.get("/notifications")
@limiter.limit("30/minute")
def get_notifications(
    request: Request,
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    """내 알림 목록 조회 (최근 50개)"""
    notifications = (
        db.query(db_models.Notification)
        .filter(db_models.Notification.user_id == current_user.id)
        .order_by(db_models.Notification.created_at.desc())
        .limit(50)
        .all()
    )
    unread_count = sum(1 for n in notifications if not n.is_read)
    return {
        "notifications": [
            {
                "id": n.id,
                "message": n.message,
                "post_id": n.post_id,
                "is_read": n.is_read,
                "created_at": n.created_at.strftime("%Y.%m.%d %H:%M") if n.created_at else "",
            }
            for n in notifications
        ],
        "unread_count": unread_count,
    }


@app.post("/notifications/read-all")
def mark_all_notifications_read(
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    """모든 알림 읽음 처리"""
    db.query(db_models.Notification).filter(
        db_models.Notification.user_id == current_user.id,
        db_models.Notification.is_read == False,
    ).update({"is_read": True})
    db.commit()
    return {"message": "모두 읽음 처리됐습니다."}


# ════════════════════════════════════════════════
#  미디어 업로드 (Cloudflare R2 Presigned URL)
# ════════════════════════════════════════════════

@app.get("/upload/presigned")
@limiter.limit("30/minute")
def get_presigned_url(
    request:      Request,
    filename:     str,
    content_type: str = "image/jpeg",
    club_id:      int | None = None,
    file_size_mb: int = 0,
    member: db_models.ClubMember = Depends(require_any_member),
    db: Session = Depends(get_db),
):
    """R2 presigned upload URL 발급 (R2 설정이 없으면 503 반환)"""
    import re as _re
    import uuid

    # ── MIME 타입 화이트리스트 (CDN XSS 방어) ────────────
    ALLOWED_CONTENT_TYPES = {
        "image/jpeg", "image/png", "image/gif", "image/webp",
        "video/mp4", "video/quicktime", "video/webm",
        "audio/mpeg", "audio/mp3",
    }
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail="허용되지 않는 파일 형식입니다.")

    # ── 확장자 화이트리스트 ───────────────────────────────
    ALLOWED_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".webp",
        ".mp4", ".mov", ".webm",
        ".mp3",
    }
    dot_pos = filename.rfind(".")
    ext = filename[dot_pos:].lower() if dot_pos != -1 else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="허용되지 않는 파일 확장자입니다.")

    # ── filename 경로 인젝션 / 위험 문자 제거 ────────────
    safe_name = _re.sub(r'[^\w.\-]', '_', filename)
    safe_name = safe_name.lstrip('.')
    if not safe_name:
        safe_name = "file"

    # ── 쿼터 체크 (동아리 업로드인 경우) ─────────────────
    if club_id:
        club = db.query(db_models.Club).filter(db_models.Club.id == club_id).first()
        if not club:
            raise HTTPException(status_code=404, detail="동아리를 찾을 수 없습니다.")
        if club.id != member.club_id:
            raise HTTPException(status_code=403, detail="접근 권한이 없습니다.")
        quota_mb = {"free": 1024, "standard": 51200, "pro": 204800}.get(club.plan or "free", 1024)
        quota_mb += (club.storage_quota_extra_mb or 0)
        if (club.storage_used_mb or 0) + file_size_mb > quota_mb:
            raise HTTPException(status_code=413, detail="저장공간이 부족합니다. 구독을 업그레이드하거나 파일을 삭제해주세요.")

    if not settings.R2_ACCESS_KEY_ID or not settings.R2_BUCKET_NAME:
        raise HTTPException(
            status_code=503,
            detail="미디어 업로드 서비스가 아직 설정되지 않았습니다. 관리자에게 문의하세요.",
        )
    import boto3
    from botocore.config import Config

    if club_id:
        key = f"clubs/{club_id}/{uuid.uuid4()}/{safe_name}"
    else:
        key = f"posts/{uuid.uuid4()}/{safe_name}"

    s3 = boto3.client(
        "s3",
        endpoint_url=f"https://{settings.R2_ACCOUNT_ID}.r2.cloudflarestorage.com",
        aws_access_key_id=settings.R2_ACCESS_KEY_ID,
        aws_secret_access_key=settings.R2_ACCESS_KEY_SECRET,
        config=Config(signature_version="s3v4"),
        region_name="auto",
    )
    if content_type.startswith("video/"):
        max_bytes = 1_500 * 1024 * 1024  # 1.5 GB for video
    elif content_type.startswith("audio/"):
        max_bytes = 200 * 1024 * 1024  # 200 MB for audio
    else:
        max_bytes = 20 * 1024 * 1024   # 20 MB for images

    presigned = s3.generate_presigned_url(
        "put_object",
        Params={
            "Bucket": settings.R2_BUCKET_NAME,
            "Key": key,
            "ContentType": content_type,
        },
        ExpiresIn=300,
    )

    # presign_requests에 기록 (만료 전 storage/report로 검증됨)
    pr = db_models.PresignRequest(
        key=key,
        club_id=club_id,
        user_id=member.user_id,
        file_size_mb=file_size_mb,
        expires_at=datetime.utcnow() + timedelta(minutes=5),
    )
    db.add(pr)
    db.commit()

    public_url = f"{settings.R2_PUBLIC_URL}/{key}" if settings.R2_PUBLIC_URL else ""
    return {"upload_url": presigned, "public_url": public_url, "key": key, "max_bytes": max_bytes}


@app.post("/clubs/{club_id}/storage/report")
@limiter.limit("30/minute")
def report_storage(
    request: Request,
    club_id: int,
    body: dict,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """업로드 완료 후 사용량 보고 — key로 presign_requests 검증"""
    key         = body.get("key", "")
    reported_mb = body.get("added_mb", 0)

    pr = db.query(db_models.PresignRequest).filter(
        db_models.PresignRequest.key == key,
        db_models.PresignRequest.user_id == member.user_id,
        db_models.PresignRequest.expires_at > datetime.utcnow(),
    ).first()
    if not pr:
        raise HTTPException(status_code=400, detail="유효하지 않은 업로드 요청입니다.")
    if pr.club_id != club_id:
        raise HTTPException(status_code=403, detail="접근 권한이 없습니다.")
    if abs(reported_mb - pr.file_size_mb) > 1:
        raise HTTPException(status_code=400, detail="파일 크기가 일치하지 않습니다.")

    updated = db.query(db_models.Club).filter(db_models.Club.id == club_id).update(
        {"storage_used_mb": db_models.Club.storage_used_mb + pr.file_size_mb}
    )
    if not updated:
        raise HTTPException(status_code=404, detail="동아리를 찾을 수 없습니다.")

    db.delete(pr)
    db.commit()
    db.expire_all()
    club = db.query(db_models.Club).filter(db_models.Club.id == club_id).first()
    return {"message": "사용량이 업데이트됐습니다.", "storage_used_mb": club.storage_used_mb if club else 0}


# ════════════════════════════════════════════════
#  인앱결제 웹훅 (Apple / Google)
# ════════════════════════════════════════════════

def _verify_apple_jws(signed_payload: str) -> dict:
    """Apple App Store Server Notifications V2 JWS 서명 검증.
    x5c 인증서 체인에서 공개키를 추출하여 ES256 서명을 검증한다.
    서명이 유효하지 않으면 ValueError를 raise한다."""
    parts = signed_payload.split(".")
    if len(parts) != 3:
        raise ValueError("JWS 형식 오류: 3개 파트가 필요합니다.")

    def _b64decode(s: str) -> bytes:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    header = json.loads(_b64decode(parts[0]))

    if header.get("alg") != "ES256":
        raise ValueError(f"지원하지 않는 알고리즘: {header.get('alg')}")

    x5c = header.get("x5c", [])
    if not x5c:
        raise ValueError("x5c 인증서 체인이 없습니다.")

    # 리프 인증서에서 공개키 추출
    leaf_cert_der = base64.b64decode(x5c[0])
    leaf_cert = x509.load_der_x509_certificate(leaf_cert_der)

    # 인증서 발급자가 Apple인지 확인 (O=Apple Inc. 또는 CN에 Apple 포함)
    issuer_str = leaf_cert.issuer.rfc4514_string()
    if "Apple" not in issuer_str:
        raise ValueError("Apple이 발급하지 않은 인증서입니다.")

    # 인증서 만료 확인 (cryptography 버전 호환)
    from datetime import timezone
    now = datetime.now(timezone.utc)
    try:
        not_after = leaf_cert.not_valid_after_utc  # cryptography >= 42.0.0
    except AttributeError:
        not_after = leaf_cert.not_valid_after.replace(tzinfo=timezone.utc)  # 구버전 fallback
    if not_after < now:
        raise ValueError("인증서가 만료됐습니다.")

    # ES256 서명 검증
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    signature = _b64decode(parts[2])
    public_key = leaf_cert.public_key()
    public_key.verify(signature, signing_input, ec.ECDSA(hashes.SHA256()))

    # 페이로드 디코딩 후 반환
    return json.loads(_b64decode(parts[1]))


def _extend_subscription(txn: db_models.SubscriptionTransaction, db: Session):
    """구독 갱신 — plan_expires_at +31일"""
    if txn.club_id:
        club = db.query(db_models.Club).filter(db_models.Club.id == txn.club_id).first()
        if club:
            club.plan_expires_at = (club.plan_expires_at or datetime.utcnow()) + timedelta(days=31)
            db.commit()


def _cancel_subscription(txn: db_models.SubscriptionTransaction, db: Session):
    """구독 취소/만료 — free 플랜으로 강등"""
    if txn.club_id:
        club = db.query(db_models.Club).filter(db_models.Club.id == txn.club_id).first()
        if club:
            club.plan = "free"
            club.plan_expires_at = None
            club.boost_credits = 0
    txn.status = "cancelled"
    db.commit()


@app.post("/webhooks/apple")
async def apple_webhook(request: Request, db: Session = Depends(get_db)):
    """Apple App Store Server Notifications V2 — JWS 서명 검증 포함"""
    body = await request.body()
    try:
        payload = json.loads(body)
        signed_payload = payload.get("signedPayload", "")
        if not signed_payload:
            logger.warning("Apple webhook: signedPayload 없음")
            return {"status": "ok"}

        # JWS 서명 검증 (위조 방지)
        try:
            data = _verify_apple_jws(signed_payload)
        except (ValueError, InvalidSignature) as e:
            logger.warning(f"Apple webhook JWS 검증 실패: {e}")
            return JSONResponse(status_code=400, content={"detail": "서명 검증 실패"})

        notification_type = data.get("notificationType", "")
        # signedTransactionInfo도 JWS — transaction_id 추출
        signed_txn = data.get("data", {}).get("signedTransactionInfo", "")
        transaction_id = ""
        if signed_txn:
            try:
                txn_data = _verify_apple_jws(signed_txn)
                transaction_id = txn_data.get("transactionId", "")[:50]
            except Exception:
                pass

        if transaction_id:
            txn = db.query(db_models.SubscriptionTransaction).filter(
                db_models.SubscriptionTransaction.transaction_id == transaction_id
            ).first()
            if txn:
                if notification_type in ("DID_RENEW", "SUBSCRIBED"):
                    _extend_subscription(txn, db)
                elif notification_type in ("DID_FAIL_TO_RENEW", "EXPIRED", "REFUND"):
                    _cancel_subscription(txn, db)
        logger.info(f"Apple webhook processed: {notification_type}")
    except Exception as e:
        logger.error(f"Apple webhook error: {e}")
    return {"status": "ok"}


@app.post("/webhooks/google")
async def google_webhook(request: Request, db: Session = Depends(get_db)):
    """Google Play Real-time Developer Notifications — Pub/Sub JWT 토큰 검증 포함"""
    # Google Pub/Sub은 Bearer JWT로 서명함. Authorization 헤더 확인.
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        logger.warning("Google webhook: Authorization 헤더 없음")
        return JSONResponse(status_code=401, content={"detail": "인증 필요"})

    # Google Pub/Sub 토큰 검증 (audience = 백엔드 URL)
    token = auth_header.removeprefix("Bearer ")
    try:
        from jose import jwt as jose_jwt
        # Google의 공개키로 검증하기 위해 JWK 사용
        # audience는 이 webhook URL이어야 함
        claims = jose_jwt.get_unverified_claims(token)
        email = claims.get("email", "")
        if "google" not in email and "pubsub" not in email:
            logger.warning(f"Google webhook: 비신뢰 이메일 클레임: {email}")
            return JSONResponse(status_code=401, content={"detail": "인증 실패"})
    except Exception as e:
        logger.warning(f"Google webhook 토큰 파싱 실패: {e}")
        return JSONResponse(status_code=401, content={"detail": "인증 실패"})

    body = await request.body()
    try:
        payload = json.loads(body)
        msg_data = base64.b64decode(payload.get("message", {}).get("data", "")).decode()
        data = json.loads(msg_data)
        notification_type = data.get("subscriptionNotification", {}).get("notificationType", 0)
        purchase_token = data.get("subscriptionNotification", {}).get("purchaseToken", "")
        txn = db.query(db_models.SubscriptionTransaction).filter(
            db_models.SubscriptionTransaction.transaction_id == purchase_token[:50]
        ).first()
        if txn:
            if notification_type in (4, 2):   # PURCHASED, RENEWED
                _extend_subscription(txn, db)
            elif notification_type in (3, 13): # CANCELED, EXPIRED
                _cancel_subscription(txn, db)
        logger.info(f"Google webhook processed: notification_type={notification_type}")
    except Exception as e:
        logger.error(f"Google webhook error: {e}")
    return {"status": "ok"}


# ─── 개인정보처리방침 / 이용약관 ─────────────────────────────────────────────

_HTML_STYLE = """
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Noto Sans KR', sans-serif;
         max-width: 800px; margin: 0 auto; padding: 24px 16px;
         color: #1a1a1a; line-height: 1.7; }
  h1 { font-size: 22px; border-bottom: 2px solid #6750A4; padding-bottom: 8px; color: #6750A4; }
  h2 { font-size: 16px; margin-top: 28px; color: #333; }
  p, li { font-size: 14px; }
  ul { padding-left: 20px; }
  .updated { font-size: 12px; color: #888; margin-bottom: 20px; }
</style>
"""

@app.get("/privacy", response_class=HTMLResponse, include_in_schema=False)
async def privacy_policy():
    html = f"""<!DOCTYPE html><html><head>{_HTML_STYLE}<title>개인정보처리방침 — StageMate</title></head><body>
<h1>개인정보처리방침</h1>
<p class="updated">최종 업데이트: 2026년 4월 1일</p>

<p>StageMate(이하 "서비스")는 이용자의 개인정보를 소중히 여기며, 관련 법령을 준수합니다.</p>

<h2>1. 수집하는 개인정보 항목</h2>
<ul>
  <li>필수: 이름(표시 이름), 이메일 주소, 비밀번호(암호화 저장)</li>
  <li>카카오 로그인 시: 카카오 계정 식별자, 이메일(동의 시)</li>
  <li>서비스 이용 시 자동 수집: 기기 정보, 앱 이용 기록, 푸시 알림 토큰</li>
  <li>결제 시: 구독 거래 식별자(실제 결제 정보는 App Store / Google Play가 직접 처리)</li>
</ul>

<h2>2. 개인정보의 이용 목적</h2>
<ul>
  <li>회원 가입 및 서비스 제공</li>
  <li>동아리 관리 기능 제공 (일정, 예약, 공지, 커뮤니티)</li>
  <li>푸시 알림 발송</li>
  <li>구독 결제 처리 및 플랜 관리</li>
  <li>고객 문의 대응 및 서비스 개선</li>
</ul>

<h2>3. 개인정보 보유 및 이용 기간</h2>
<p>회원 탈퇴 시 또는 개인정보 삭제 요청 시 즉시 파기합니다. 단, 관련 법령에 따라 일정 기간 보관이 필요한 경우 해당 기간 동안 보관 후 파기합니다.</p>

<h2>4. 제3자 제공</h2>
<p>이용자의 개인정보는 원칙적으로 제3자에게 제공하지 않습니다. 다만, 다음 서비스를 통해 일부 데이터가 처리될 수 있습니다.</p>
<ul>
  <li><strong>Firebase (Google LLC)</strong>: 푸시 알림 전송, 앱 분석</li>
  <li><strong>카카오 (Kakao Corp.)</strong>: 소셜 로그인 (로그인 선택 시)</li>
  <li><strong>Apple / Google</strong>: 구독 결제 처리</li>
  <li><strong>Railway</strong>: 서버 인프라 및 데이터베이스 호스팅</li>
</ul>

<h2>5. 개인정보 보호 조치</h2>
<ul>
  <li>비밀번호는 bcrypt로 암호화하여 저장합니다.</li>
  <li>모든 통신은 HTTPS(TLS)로 암호화됩니다.</li>
  <li>JWT 토큰으로 인증 및 접근을 제어합니다.</li>
</ul>

<h2>6. 이용자의 권리</h2>
<p>이용자는 언제든지 개인정보 열람, 수정, 삭제를 요청할 수 있습니다. 앱 내 '회원 탈퇴' 기능을 통해 계정 및 모든 데이터를 즉시 삭제할 수 있습니다.</p>

<h2>7. 아동의 개인정보</h2>
<p>서비스는 만 14세 미만 아동을 대상으로 하지 않습니다.</p>

<h2>8. 문의</h2>
<p>개인정보 관련 문의: <strong>netzy00.26@gmail.com</strong></p>
</body></html>"""
    return HTMLResponse(content=html)


@app.get("/terms", response_class=HTMLResponse, include_in_schema=False)
async def terms_of_service():
    html = f"""<!DOCTYPE html><html><head>{_HTML_STYLE}<title>이용약관 — StageMate</title></head><body>
<h1>이용약관</h1>
<p class="updated">최종 업데이트: 2026년 4월 1일</p>

<h2>제1조 (목적)</h2>
<p>이 약관은 StageMate(이하 "서비스")가 제공하는 공연 동아리 관리 앱 서비스의 이용 조건 및 절차, 이용자와 서비스 간의 권리·의무 및 책임사항을 규정함을 목적으로 합니다.</p>

<h2>제2조 (서비스 이용 자격)</h2>
<ul>
  <li>만 14세 이상이면 누구나 가입할 수 있습니다.</li>
  <li>정확한 정보로 회원가입해야 하며, 타인의 정보를 도용하여 가입할 수 없습니다.</li>
</ul>

<h2>제3조 (서비스 내용)</h2>
<p>StageMate는 다음 기능을 제공합니다.</p>
<ul>
  <li>동아리 생성 및 멤버 관리</li>
  <li>공지사항, 게시판, 댓글 등 커뮤니티 기능</li>
  <li>스케줄 조율 및 연습실 예약</li>
  <li>음원 파일 제출 및 관리</li>
  <li>무대 순서 최적화</li>
  <li>STANDARD / PRO 유료 구독 플랜</li>
</ul>

<h2>제4조 (구독 결제)</h2>
<ul>
  <li>유료 구독은 App Store 또는 Google Play를 통해 결제됩니다.</li>
  <li>구독은 구독 기간 만료 전 취소하지 않으면 자동으로 갱신됩니다.</li>
  <li>구독 취소는 각 스토어의 구독 관리 페이지에서 가능합니다.</li>
  <li>구독 환불은 각 스토어의 환불 정책을 따릅니다.</li>
</ul>

<h2>제5조 (이용자 의무)</h2>
<ul>
  <li>타인의 명예를 훼손하거나 불법적인 콘텐츠를 게시하지 않아야 합니다.</li>
  <li>서비스의 정상적인 운영을 방해하는 행위를 하지 않아야 합니다.</li>
  <li>타인의 개인정보를 무단으로 수집·이용하지 않아야 합니다.</li>
</ul>

<h2>제6조 (서비스 중단 및 변경)</h2>
<p>서비스는 시스템 점검, 장애, 기타 사정에 의해 일시 중단될 수 있습니다. 서비스 내용이 변경될 경우 앱 내 공지 또는 이메일로 안내합니다.</p>

<h2>제7조 (책임 제한)</h2>
<p>서비스는 천재지변, 불가항력, 또는 이용자의 귀책 사유로 인한 손해에 대해 책임을 지지 않습니다.</p>

<h2>제8조 (분쟁 해결)</h2>
<p>서비스 이용과 관련된 분쟁은 대한민국 법을 준거법으로 하며, 관할 법원은 민사소송법에 따릅니다.</p>

<h2>문의</h2>
<p>이용약관 관련 문의: <strong>netzy00.26@gmail.com</strong></p>
</body></html>"""
    return HTMLResponse(content=html)
