from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime, UniqueConstraint, Boolean
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

    # ── 로그인 실패 잠금 ────────────────────────
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)  # None = 잠금 없음

    memberships = relationship("ClubMember", back_populates="user")
    availability_slots = relationship("AvailabilitySlot", back_populates="user")
    bookings = relationship("RoomBookingDB", back_populates="user")
    notices = relationship("Notice", back_populates="author")


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
