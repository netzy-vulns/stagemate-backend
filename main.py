import logging
import secrets
import string
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.orm import Session
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
)
from scheduler import calculate_schedule
from group_schedule import find_common_slots_from_db
from room_booking_db import add_booking_db, get_bookings_db, delete_booking_db
from datetime import datetime

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


# ════════════════════════════════════════════════
#  인증 (Auth)
# ════════════════════════════════════════════════

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

    if db.query(db_models.User).filter(db_models.User.email == req.email).first():
        raise HTTPException(status_code=400, detail="이미 사용 중인 이메일입니다.")

    if db.query(db_models.User).filter(db_models.User.display_name == req.display_name).first():
        raise HTTPException(status_code=400, detail="이미 사용 중인 닉네임입니다.")

    user = db_models.User(
        username=req.username,
        display_name=req.display_name,
        email=req.email,
        hashed_password=hash_password(req.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info(f"New user registered: {user.username}")
    return {
        "message": f"회원가입 완료! 환영해요, {user.display_name}님 🎉",
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
    }


@app.patch("/auth/change-password")
def change_password(
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
                f"감사합니다.\nStageMate 팀 🎭"
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


@app.delete("/auth/me")
def delete_account(
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),
):
    """계정 탈퇴 — 관련 데이터 모두 삭제"""
    uid = current_user.id
    username = current_user.username
    db.query(db_models.AvailabilitySlot).filter(db_models.AvailabilitySlot.user_id == uid).delete()
    db.query(db_models.RoomBookingDB).filter(db_models.RoomBookingDB.user_id == uid).delete()
    db.query(db_models.Notice).filter(db_models.Notice.author_id == uid).delete()
    db.query(db_models.ClubMember).filter(db_models.ClubMember.user_id == uid).delete()
    db.delete(current_user)
    db.commit()
    logger.info(f"Account deleted: {username}")
    return {"message": "계정이 삭제됐습니다."}


# ════════════════════════════════════════════════
#  동아리 (Club)
# ════════════════════════════════════════════════

@app.post("/clubs")
def create_club(
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
def join_club(
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
def kick_member(
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
def update_member_role(
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

    role_labels = {"admin": "임원진", "team_leader": "팀장", "user": "일반 멤버"}
    return {
        "message": f"역할이 '{role_labels[req.role]}'(으)로 변경됐습니다.",
        "user_id": user_id,
        "role": req.role,
    }


@app.post("/clubs/{club_id}/members/{user_id}/reset-password")
def reset_member_password(
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
    db.delete(notice)
    db.commit()
    return {"message": "삭제 완료!"}


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
    member: db_models.ClubMember = Depends(require_team_leader)
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
