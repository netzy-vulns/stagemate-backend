import re
import secrets
import string
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Header, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from database import get_db
from config import settings
import db_models

# ── 환경변수에서 로드 (하드코딩 제거) ──────────────
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


# ── 비밀번호 유틸 ──────────────────────────────
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def validate_password_strength(password: str) -> bool:
    """비밀번호 강도 검증: 최소 8자, 대문자, 소문자, 숫자 각 1개 이상"""
    return (
        len(password) >= 8
        and bool(re.search(r'[A-Z]', password))
        and bool(re.search(r'[a-z]', password))
        and bool(re.search(r'\d', password))
    )


# ── 로그인 실패 잠금 ─────────────────────────────
def check_account_lock(user: db_models.User) -> None:
    """계정 잠금 여부 확인 — 잠긴 경우 HTTPException 발생"""
    if user.locked_until:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if user.locked_until > now:
            remaining = int((user.locked_until - now).total_seconds() / 60) + 1
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"로그인 시도 초과로 계정이 잠겼습니다. {remaining}분 후 다시 시도하세요.",
            )


def handle_failed_login(user: db_models.User, db: Session) -> None:
    """로그인 실패 처리 — 횟수 증가, 한도 초과 시 잠금"""
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
        user.locked_until = (
            datetime.utcnow() + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
        )
    db.commit()


def reset_login_attempts(user: db_models.User, db: Session) -> None:
    """로그인 성공 시 실패 카운터 초기화"""
    if user.failed_login_attempts > 0 or user.locked_until:
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()


# ── JWT 토큰 ───────────────────────────────────
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> db_models.User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="로그인이 필요합니다.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("uid")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # user_id가 있으면 더 빠른 PK 조회, 없으면 username 폴백
    if user_id:
        user = db.query(db_models.User).filter(db_models.User.id == user_id).first()
    else:
        user = db.query(db_models.User).filter(db_models.User.username == username).first()

    if user is None:
        raise credentials_exception
    # 탈퇴된 계정은 토큰이 남아있어도 접근 거부 (M-3)
    if user.deleted_at is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="탈퇴된 계정입니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# ── 초대 코드 생성 (6자리 랜덤, 2일 유효) ─────────
def generate_invite_code() -> tuple[str, datetime]:
    alphabet = string.ascii_uppercase + string.digits
    code = ''.join(secrets.choice(alphabet) for _ in range(6))
    expires_at = datetime.utcnow() + timedelta(days=2)
    return code, expires_at


# ── 동아리 멤버십 의존성 (X-Club-Id 헤더 기반) ──────
def get_club_member(
    club_id: int = Header(..., alias="X-Club-Id"),
    current_user: db_models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> db_models.ClubMember:
    member = db.query(db_models.ClubMember).filter(
        db_models.ClubMember.club_id == club_id,
        db_models.ClubMember.user_id == current_user.id
    ).first()
    if not member:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="해당 동아리의 멤버가 아닙니다."
        )
    return member


# ── 역할 기반 권한 체크 팩토리 ────────────────────
def require_role(*allowed_roles: str):
    """허용된 역할만 접근 가능한 의존성 팩토리"""
    def checker(member: db_models.ClubMember = Depends(get_club_member)):
        if member.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="권한이 없습니다."
            )
        return member
    return checker


# ── 역할별 단축 의존성 ────────────────────────────
# super_admin만
require_super_admin = require_role("super_admin")

# 공지 작성/삭제, 무대순서 최적화 (회장 + 임원진)
require_admin = require_role("super_admin", "admin")

# 연습실 예약 생성 (회장 + 임원진 + 팀장)
require_team_leader = require_role("super_admin", "admin", "team_leader")

# 동아리 멤버 전체 (조회, 가능시간 업로드 등)
require_any_member = require_role("super_admin", "admin", "team_leader", "user")
