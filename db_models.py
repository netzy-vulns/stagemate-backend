from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime, UniqueConstraint, Boolean, Text, JSON
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime


# ── 동아리 테이블 ──────────────────────────────
class Club(Base):
    __tablename__ = "clubs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)
    invite_code = Column(String(6), nullable=False, unique=True)
    invite_code_expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    members = relationship("ClubMember", back_populates="club")


# ── 동아리 멤버 테이블 (역할 포함) ────────────────
class ClubMember(Base):
    __tablename__ = "club_members"

    id = Column(Integer, primary_key=True, index=True)
    club_id = Column(Integer, ForeignKey("clubs.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role = Column(String, nullable=False, default="user")
    # role: "super_admin" | "admin" | "team_leader" | "user"
    joined_at = Column(DateTime, default=datetime.utcnow)

    club = relationship("Club", back_populates="members")
    user = relationship("User", back_populates="memberships")

    __table_args__ = (UniqueConstraint("club_id", "user_id", name="uq_club_member"),)


# ── 유저 테이블 ───────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    display_name = Column(String)
    hashed_password = Column(String)
    email = Column(String, nullable=True, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # ── 소셜 로그인 ─────────────────────────────
    kakao_id = Column(String, unique=True, nullable=True, index=True)

    # ── 로그인 실패 잠금 ────────────────────────
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)  # None = 잠금 없음

    # ── 닉네임 (전체 커뮤니티용) ─────────────────
    nickname = Column(String, nullable=True, unique=True)   # 전체 커뮤니티에서 사용할 닉네임

    # ── 프로필 사진 ──────────────────────────────
    avatar_url = Column(String, nullable=True)              # R2 퍼블릭 URL

    # ── 소프트 삭제 (탈퇴) ──────────────────────
    deleted_at = Column(DateTime, nullable=True)            # 탈퇴 시각 (소프트 삭제)
    reregister_allowed_at = Column(DateTime, nullable=True)  # 재가입 허용 시각 (탈퇴 후 7일)

    memberships = relationship("ClubMember", back_populates="user")
    availability_slots = relationship("AvailabilitySlot", back_populates="user")
    bookings = relationship("RoomBookingDB", back_populates="user")
    notices = relationship("Notice", back_populates="author")
    posts = relationship("Post", foreign_keys="Post.author_id")


# ── 가능 시간 슬롯 테이블 ─────────────────────────
class AvailabilitySlot(Base):
    __tablename__ = "availability_slots"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    club_id = Column(Integer, ForeignKey("clubs.id"), nullable=True)
    room_code = Column(String, index=True)
    day = Column(String)
    start_time = Column(Float)
    end_time = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="availability_slots")


# ── 연습실 예약 테이블 ────────────────────────────
class RoomBookingDB(Base):
    __tablename__ = "room_bookings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    club_id = Column(Integer, ForeignKey("clubs.id"), nullable=True)
    team_name = Column(String)
    room_name = Column(String)
    date = Column(String)
    start_time = Column(Float)
    end_time = Column(Float)
    note = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="bookings")


# ── 공지사항 테이블 ───────────────────────────────
class Notice(Base):
    __tablename__ = "notices"

    id = Column(Integer, primary_key=True, index=True)
    club_id = Column(Integer, ForeignKey("clubs.id"), nullable=True)
    title = Column(String)
    content = Column(String)
    author_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

    author = relationship("User", back_populates="notices")
    comments = relationship("NoticeComment", back_populates="notice", cascade="all, delete-orphan")


# ── 공지사항 댓글 테이블 ──────────────────────────
class NoticeComment(Base):
    __tablename__ = "notice_comments"

    id = Column(Integer, primary_key=True, index=True)
    notice_id = Column(Integer, ForeignKey("notices.id"), nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    notice = relationship("Notice", back_populates="comments")
    author = relationship("User")


# ── 자유게시판 / 전체채널 게시글 ──────────────────────
class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    club_id = Column(Integer, ForeignKey("clubs.id"), nullable=True)  # None이면 전체 채널
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    media_urls = Column(JSON, default=list)   # 이미지/영상 URL 목록
    is_global = Column(Boolean, default=False, nullable=False)  # True=전체채널
    view_count = Column(Integer, default=0, nullable=False)     # 조회수
    post_author_name = Column(String, nullable=True)             # None=실명, "익명"=익명, 닉네임=닉네임
    is_anonymous = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    author = relationship("User")
    likes = relationship("PostLike", back_populates="post", cascade="all, delete-orphan")
    comments = relationship("PostComment", back_populates="post", cascade="all, delete-orphan")


class PostLike(Base):
    __tablename__ = "post_likes"
    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    post = relationship("Post", back_populates="likes")
    __table_args__ = (UniqueConstraint("post_id", "user_id", name="uq_post_like"),)


class PostComment(Base):
    __tablename__ = "post_comments"
    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    post = relationship("Post", back_populates="comments")
    author = relationship("User")


# ── 알림 테이블 ───────────────────────────────────────
class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)  # 알림 받는 사람
    actor_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # 행동한 사람 (None=시스템)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=True)
    message = Column(String, nullable=False)
    is_read = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


# ── 신고 테이블 ───────────────────────────────────────
class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    reporter_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=True)
    comment_id = Column(Integer, ForeignKey("post_comments.id"), nullable=True)
    reason = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
