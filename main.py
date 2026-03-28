import logging
import secrets
import string
import httpx
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
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

# DB 테이블 자동 생성
db_models.Base.metadata.create_all(bind=engine)

# ── Rate Limiter 설정 ──────────────────────────────
limiter = Limiter(key_func=get_remote_address)

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
def reset_member_password(
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

    return {
        "message": f"'{target_user.display_name}' 임시 비밀번호가 발급됐습니다.",
        "temp_password": temp_password,
        "display_name": target_user.display_name,
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
            "author": n.author.display_name,
            "created_at": n.created_at.strftime("%Y-%m-%d %H:%M"),
        }
        for n in notices
    ]


@app.post("/notices")
def create_notice(
    req: NoticeRequest,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_admin)
):
    notice = db_models.Notice(
        club_id=member.club_id,
        title=req.title,
        content=req.content,
        author_id=member.user_id,
    )
    db.add(notice)
    db.commit()
    db.refresh(notice)
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
        "author": notice.author.display_name,
        "created_at": notice.created_at.strftime("%Y-%m-%d %H:%M"),
    }


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
    posts = query.order_by(db_models.Post.created_at.desc()).offset(offset).limit(limit).all()

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
            "like_count": like_count,
            "comment_count": comment_count,
            "view_count": p.view_count or 0,
            "my_liked": my_liked,
            "is_global": p.is_global,
            "created_at": p.created_at.strftime("%Y.%m.%d %H:%M") if p.created_at else "",
        })
    return result


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
            "created_at": c.created_at.strftime("%Y.%m.%d %H:%M") if c.created_at else "",
        })
    return result


@app.post("/posts/{post_id}/comments")
@limiter.limit("30/minute")
def create_post_comment(
    request: Request,
    post_id: int,
    req: PostCommentRequest,
    db: Session = Depends(get_db),
    member: db_models.ClubMember = Depends(require_any_member),
):
    """게시글 댓글 작성"""
    post = db.query(db_models.Post).filter(db_models.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    comment = db_models.PostComment(
        post_id=post_id,
        author_id=member.user_id,
        content=req.content,
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    author = db.query(db_models.User).filter(db_models.User.id == member.user_id).first()

    # ── 게시글 작성자에게 알림 생성 (본인 댓글 제외) ──────
    if post.author_id != member.user_id:
        actor_name = (author.nickname if author and author.nickname else "알 수 없음") if post and post.is_global else (author.display_name if author else "알 수 없음")
        preview = req.content[:30] + ("..." if len(req.content) > 30 else "")
        notif = db_models.Notification(
            user_id=post.author_id,
            actor_id=member.user_id,
            post_id=post_id,
            message=f"{actor_name}님이 내 게시글에 댓글을 남겼어요: {preview}",
        )
        db.add(notif)
        db.commit()

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
        "member_count": member_count,
    }


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
    }
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail="허용되지 않는 파일 형식입니다.")

    # ── 확장자 화이트리스트 ───────────────────────────────
    ALLOWED_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".webp",
        ".mp4", ".mov", ".webm",
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
        quota_mb = {"free": 10240, "standard": 30720, "pro": 102400}.get(club.plan or "free", 10240)
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
    is_video = content_type.startswith("video/")
    max_bytes = 1536 * 1024 * 1024 if is_video else 30 * 1024 * 1024

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
    from datetime import timedelta
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

    club = db.query(db_models.Club).filter(db_models.Club.id == club_id).first()
    if not club:
        raise HTTPException(status_code=404, detail="동아리를 찾을 수 없습니다.")
    club.storage_used_mb = (club.storage_used_mb or 0) + pr.file_size_mb

    db.delete(pr)
    db.commit()
    return {"message": "사용량이 업데이트됐습니다.", "storage_used_mb": club.storage_used_mb}
