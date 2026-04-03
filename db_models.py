from sqlalchemy import Column, Integer, BigInteger, String, Float, ForeignKey, DateTime, UniqueConstraint, Boolean, Text, JSON
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

    # ── 구독/플랜 ──────────────────────────────────
    logo_url               = Column(String, nullable=True)
    banner_url             = Column(String, nullable=True)
    theme_color            = Column(String(7), nullable=True)          # "#RRGGBB"
    plan                   = Column(String(20), default="free", nullable=False)
    plan_expires_at        = Column(DateTime, nullable=True)
    storage_used_mb        = Column(BigInteger, default=0, nullable=False)
    storage_quota_extra_mb = Column(BigInteger, default=0, nullable=False)
    boost_credits          = Column(Integer, default=0, nullable=False)

    # ── SNS 링크 ────────────────────────────────────
    instagram_url          = Column(String, nullable=True)
    youtube_url            = Column(String, nullable=True)

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

    # ── FCM 푸시 토큰 ────────────────────────────
    fcm_token = Column(String, nullable=True)

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
    media_urls = Column(JSON, default=list)
    author_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

    author = relationship("User", back_populates="notices")
    comments = relationship("NoticeComment", back_populates="notice", cascade="all, delete-orphan")
    likes = relationship("NoticeLike", back_populates="notice", cascade="all, delete-orphan")


# ── 공지사항 좋아요 테이블 ────────────────────────
class NoticeLike(Base):
    __tablename__ = "notice_likes"
    id = Column(Integer, primary_key=True, index=True)
    notice_id = Column(Integer, ForeignKey("notices.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    notice = relationship("Notice", back_populates="likes")
    __table_args__ = (UniqueConstraint("notice_id", "user_id", name="uq_notice_like"),)


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
    is_boosted       = Column(Boolean, default=False, nullable=False)
    boost_expires_at = Column(DateTime, nullable=True)
    youtube_url      = Column(String(500), nullable=True)
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
    parent_id = Column(Integer, ForeignKey('post_comments.id'), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    post = relationship("Post", back_populates="comments")
    author = relationship("User")
    likes = relationship("CommentLike", back_populates="comment", cascade="all, delete-orphan")


class CommentLike(Base):
    __tablename__ = "comment_likes"
    id         = Column(Integer, primary_key=True, index=True)
    comment_id = Column(Integer, ForeignKey("post_comments.id"), nullable=False)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    comment    = relationship("PostComment", back_populates="likes")
    __table_args__ = (UniqueConstraint("comment_id", "user_id", name="uq_comment_like"),)


# ── 공연 아카이브 ──────────────────────────────
class PerformanceArchive(Base):
    __tablename__ = "performance_archives"

    id               = Column(Integer, primary_key=True, index=True)
    club_id          = Column(Integer, ForeignKey("clubs.id"), nullable=False)
    title            = Column(String, nullable=False)
    description      = Column(Text, nullable=True)
    performance_date = Column(String(10), nullable=False)   # "YYYY-MM-DD"
    youtube_url      = Column(String(500), nullable=True)
    native_video_url = Column(String, nullable=True)        # PRO 전용
    view_count       = Column(Integer, default=0, nullable=False)
    created_at       = Column(DateTime, default=datetime.utcnow)

    club  = relationship("Club")
    likes = relationship("PerformanceArchiveLike", back_populates="archive",
                         cascade="all, delete-orphan")


class PerformanceArchiveLike(Base):
    __tablename__ = "performance_archive_likes"

    id         = Column(Integer, primary_key=True, index=True)
    archive_id = Column(Integer, ForeignKey("performance_archives.id"), nullable=False)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    archive = relationship("PerformanceArchive", back_populates="likes")

    __table_args__ = (
        UniqueConstraint("archive_id", "user_id", name="uq_archive_like"),
    )


class WebArchiveLike(Base):
    __tablename__ = "web_archive_likes"
    id = Column(Integer, primary_key=True, index=True)
    archive_id = Column(Integer, ForeignKey("performance_archives.id", ondelete="CASCADE"), nullable=False)
    ip_address = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    __table_args__ = (UniqueConstraint("archive_id", "ip_address", name="uq_web_like"),)


# ── 챌린지 ────────────────────────────────────
class Challenge(Base):
    __tablename__ = "challenges"

    id         = Column(Integer, primary_key=True, index=True)
    year_month = Column(String(7), nullable=False)   # "YYYY-MM"
    is_active  = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    entries = relationship("ChallengeEntry", back_populates="challenge",
                           cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("year_month", name="uq_challenge_month"),
    )


class ChallengeEntry(Base):
    __tablename__ = "challenge_entries"

    id           = Column(Integer, primary_key=True, index=True)
    challenge_id = Column(Integer, ForeignKey("challenges.id"), nullable=False)
    club_id      = Column(Integer, ForeignKey("clubs.id"), nullable=False)
    archive_id   = Column(Integer, ForeignKey("performance_archives.id"), nullable=False)
    created_at   = Column(DateTime, default=datetime.utcnow)

    challenge = relationship("Challenge", back_populates="entries")
    club      = relationship("Club")
    archive   = relationship("PerformanceArchive")
    likes     = relationship("ChallengeEntryLike", back_populates="entry",
                             cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("challenge_id", "club_id", name="uq_challenge_entry"),
    )


class ChallengeEntryLike(Base):
    __tablename__ = "challenge_entry_likes"

    id         = Column(Integer, primary_key=True, index=True)
    entry_id   = Column(Integer, ForeignKey("challenge_entries.id"), nullable=False)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    entry = relationship("ChallengeEntry", back_populates="likes")

    __table_args__ = (
        UniqueConstraint("entry_id", "user_id", name="uq_entry_like"),
    )


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


# ── 구독 트랜잭션 테이블 ─────────────────────────────
class SubscriptionTransaction(Base):
    __tablename__ = "subscription_transactions"
    id             = Column(Integer, primary_key=True, index=True)
    club_id        = Column(Integer, ForeignKey("clubs.id"), nullable=True, index=True)   # 개인 구독 시 NULL
    user_id        = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    product_id     = Column(String, nullable=False)
    transaction_id = Column(String, unique=True, nullable=False)
    platform       = Column(String(20), nullable=False)   # "apple" | "google"
    purchased_at   = Column(DateTime, nullable=False)
    expires_at     = Column(DateTime, nullable=True)
    status         = Column(String(20), default="active", nullable=False)
    raw_payload    = Column(JSON, nullable=True)
    created_at     = Column(DateTime, default=datetime.utcnow)


# ── 사전 서명 요청 테이블 ──────────────────────────────
class PresignRequest(Base):
    __tablename__ = "presign_requests"
    key          = Column(String, primary_key=True)
    club_id      = Column(Integer, ForeignKey("clubs.id"), nullable=True)
    user_id      = Column(Integer, ForeignKey("users.id"), nullable=False)
    file_size_mb = Column(Integer, nullable=False)
    expires_at   = Column(DateTime, nullable=False, index=True)
    created_at   = Column(DateTime, default=datetime.utcnow)


# ── 공연 테이블 ───────────────────────────────────────
class Performance(Base):
    __tablename__ = "performances"

    id = Column(Integer, primary_key=True, index=True)
    club_id = Column(Integer, ForeignKey("clubs.id"), nullable=False)
    name = Column(String(100), nullable=False)
    performance_date = Column(String(10), nullable=True)   # "YYYY-MM-DD", 선택
    submission_deadline = Column(DateTime, nullable=True)  # 제출 마감일, 선택
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    submissions = relationship(
        "AudioSubmission", back_populates="performance",
        cascade="all, delete-orphan"
    )


# ── 음원 제출 테이블 ──────────────────────────────
class AudioSubmission(Base):
    __tablename__ = "audio_submissions"

    id = Column(Integer, primary_key=True, index=True)
    performance_id = Column(Integer, ForeignKey("performances.id"), nullable=False)
    club_id = Column(Integer, ForeignKey("clubs.id"), nullable=False)
    submitted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    team_name = Column(String(50), nullable=False)
    song_title = Column(String(100), nullable=False)
    file_url = Column(String, nullable=False)       # R2 퍼블릭 URL
    file_size_mb = Column(Integer, nullable=False, default=0)
    submitted_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    performance = relationship("Performance", back_populates="submissions")
    submitter = relationship("User")

    # 팀장 한 명은 공연당 하나의 제출만 가능 (재제출 = UPDATE)
    __table_args__ = (
        UniqueConstraint("performance_id", "submitted_by", name="uq_audio_submission"),
    )
