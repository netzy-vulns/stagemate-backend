import re
from pydantic import BaseModel, Field, field_validator, EmailStr
from typing import List, Literal, Optional

# ───────────────────────────────
# 인증 관련 모델 (입력 검증 강화)
# ───────────────────────────────

class KakaoLoginRequest(BaseModel):
    access_token: str


class RegisterRequest(BaseModel):
    username: str = Field(
        ..., min_length=3, max_length=20,
        description="영문/숫자/언더스코어만 허용 (3~20자)"
    )
    display_name: str = Field(..., min_length=1, max_length=30)
    nickname: str = Field(..., min_length=2, max_length=20, description="전체 커뮤니티 표시명, 필수")
    email: EmailStr = Field(..., description="비밀번호 재설정에 사용되는 이메일")
    password: str = Field(..., min_length=8, max_length=100)

    @field_validator('username')
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('아이디는 영문, 숫자, 언더스코어(_)만 사용 가능합니다.')
        return v.lower()  # 소문자로 정규화

    @field_validator('display_name')
    @classmethod
    def display_name_no_html(cls, v: str) -> str:
        # XSS 방지: HTML 특수문자 거부
        if re.search(r'[<>"\'&]', v):
            raise ValueError('이름에 특수문자(<, >, ", \', &)를 사용할 수 없습니다.')
        return v.strip()

    @field_validator('nickname')
    @classmethod
    def nickname_valid(cls, v: str) -> str:
        v = v.strip()
        if re.search(r'[<>"\'&]', v):
            raise ValueError('닉네임에 특수문자(<, >, ", \', &)를 사용할 수 없습니다.')
        return v


class ClubCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)

    @field_validator('name')
    @classmethod
    def name_no_html(cls, v: str) -> str:
        if re.search(r'[<>"\'&]', v):
            raise ValueError('동아리명에 특수문자(<, >, ", \', &)를 사용할 수 없습니다.')
        return v.strip()


class ClubJoinRequest(BaseModel):
    invite_code: str = Field(..., min_length=6, max_length=6)

    @field_validator('invite_code')
    @classmethod
    def code_alphanumeric(cls, v: str) -> str:
        if not re.match(r'^[A-Z0-9]+$', v.upper()):
            raise ValueError('초대 코드는 영문/숫자만 허용됩니다.')
        return v.upper()


class NoticeRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=100)
    content: str = Field(..., min_length=1, max_length=5000)

    @field_validator('title', 'content')
    @classmethod
    def no_script_tags(cls, v: str) -> str:
        # <script> 태그 삽입 방지
        if re.search(r'<script', v, re.IGNORECASE):
            raise ValueError('스크립트 태그는 허용되지 않습니다.')
        return v


class CommentRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=500)

    @field_validator('content')
    @classmethod
    def no_script_tags(cls, v: str) -> str:
        if re.search(r'<script', v, re.IGNORECASE):
            raise ValueError('스크립트 태그는 허용되지 않습니다.')
        return v.strip()


class DeleteAccountRequest(BaseModel):
    """탈퇴 시 비밀번호 or 확인 텍스트"""
    password: str | None = None          # 일반 계정: 비밀번호 필수
    confirm_text: str | None = None       # 카카오 계정: "탈퇴합니다" 텍스트


class PostRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=2000)
    media_urls: list[str] = Field(default_factory=list, max_length=5)
    is_global: bool = False
    is_anonymous: bool = False  # True면 "익명"으로 게시

    @field_validator('content')
    @classmethod
    def no_script_tags(cls, v: str) -> str:
        if re.search(r'<script', v, re.IGNORECASE):
            raise ValueError('스크립트 태그는 허용되지 않습니다.')
        return v.strip()


class NicknameRequest(BaseModel):
    nickname: str = Field(..., min_length=1, max_length=20)

    @field_validator('nickname')
    @classmethod
    def validate_nickname(cls, v: str) -> str:
        v = v.strip()
        if re.search(r'<script', v, re.IGNORECASE):
            raise ValueError('스크립트 태그는 허용되지 않습니다.')
        return v


class PostCommentRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=500)

    @field_validator('content')
    @classmethod
    def no_script_tags(cls, v: str) -> str:
        if re.search(r'<script', v, re.IGNORECASE):
            raise ValueError('스크립트 태그는 허용되지 않습니다.')
        return v.strip()


class PostEditRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=2000)

    @field_validator('content')
    @classmethod
    def no_script_tags(cls, v: str) -> str:
        if re.search(r'<script', v, re.IGNORECASE):
            raise ValueError('스크립트 태그는 허용되지 않습니다.')
        return v.strip()


class ReportRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=200)

    @field_validator('reason')
    @classmethod
    def no_script_tags(cls, v: str) -> str:
        if re.search(r'<script', v, re.IGNORECASE):
            raise ValueError('스크립트 태그는 허용되지 않습니다.')
        return v.strip()


class RoleUpdateRequest(BaseModel):
    # super_admin은 PATCH로 부여 불가 (생성 시에만 부여됨)
    role: Literal["admin", "user"]


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=100)

    @field_validator('new_password')
    @classmethod
    def new_password_strong(cls, v: str) -> str:
        if not (re.search(r'[A-Z]', v) and re.search(r'[a-z]', v) and re.search(r'\d', v)):
            raise ValueError('새 비밀번호는 8자 이상, 대문자·소문자·숫자 각 1개 이상 포함해야 합니다.')
        return v


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class SlotRequest(BaseModel):
    room_code: str = Field(..., min_length=1, max_length=20)
    day: str = Field(..., min_length=1, max_length=3)
    start_time: float = Field(..., ge=0.0, le=23.75)  # 0:00 ~ 23:45
    end_time: float = Field(..., ge=0.25, le=24.0)    # 0:15 ~ 24:00

    @field_validator('end_time')
    @classmethod
    def end_after_start(cls, v: float, info) -> float:
        if 'start_time' in info.data and v <= info.data['start_time']:
            raise ValueError('종료 시간은 시작 시간보다 늦어야 합니다.')
        return v

    @field_validator('day')
    @classmethod
    def valid_day(cls, v: str) -> str:
        if v not in ['월', '화', '수', '목', '금', '토', '일']:
            raise ValueError('요일은 월~일 중 하나여야 합니다.')
        return v

    @field_validator('room_code')
    @classmethod
    def room_code_safe(cls, v: str) -> str:
        # HTML/스크립트 삽입 방지 (한국어·영문·숫자·특수문자 모두 허용, 단 XSS 문자 제외)
        if re.search(r'[<>"\'&]', v):
            raise ValueError('방 코드에 <, >, ", \', & 문자는 사용할 수 없습니다.')
        return v.strip()


# ───────────────────────────────
# 공연 스케줄 관련 모델
# ───────────────────────────────

# 곡 하나의 정보
class Song(BaseModel):
    id: int
    title: str           # 곡 제목
    members: List[str]   # 참여 멤버 이름 목록
    duration: float      # 곡 길이 (분 단위, 기본 4.5)
    intro_time: float = 1.5 # ← 추가! 무대 전 소개 시간 (기본 1.5분)

# 공연 전체 설정
class PerformanceConfig(BaseModel):
    songs: List[Song]
    min_change_time: float = 7.0    # 의상 교체 최소 시간 (분)
    intro_time: float = 1.5   # ← 곡별 intro_time 미입력시 이 값이 기본값

# 순서 결과 - 무대 하나
class StageResult(BaseModel):
    order: int           # 몇 번째 무대
    song: Song           # 곡 정보
    start_time: float    # 시작 시간 (분)
    end_time: float      # 종료 시간 (분)

# 최종 결과
class ScheduleResult(BaseModel):
    stages: List[StageResult]        # 무대 순서 목록
    warnings: List[str]              # 의상 교체 위험 경고
    total_time: float                # 총 공연 시간
    is_valid: bool                   # 모든 제약 조건 만족 여부

# ───────────────────────────────
# 그룹 스케줄 조율 관련 모델
# ───────────────────────────────

# 멤버 한 명의 가능 시간 슬롯
class TimeSlot(BaseModel):
    day: str        # 요일 "월", "화", "수", "목", "금", "토", "일"
    start: float    # 시작 시간 (24시간 기준, 예: 14.5 = 14:30)
    end: float      # 종료 시간 (예: 18.0 = 18:00)

# 멤버 한 명의 가능 시간 입력
class MemberAvailability(BaseModel):
    member_name: str
    available_slots: List[TimeSlot]

# 그룹 공통 시간 요청
class GroupScheduleRequest(BaseModel):
    room_code: str                      # 방 코드
    members: List[MemberAvailability]   # 멤버별 가능 시간
    duration_needed: float = 2.0        # 필요한 연습 시간 (시간 단위)

# 공통 가능 시간 결과
class CommonSlot(BaseModel):
    day: str
    start: float
    end: float
    available_members: List[str]   # 이 시간에 가능한 멤버
    all_available: bool            # 전원 가능 여부

# 그룹 스케줄 결과
class GroupScheduleResult(BaseModel):
    room_code: str
    common_slots: List[CommonSlot]      # 전원 가능 시간대
    partial_slots: List[CommonSlot]     # 일부만 가능 시간대
    best_slot: CommonSlot | None        # 가장 추천하는 시간

# ───────────────────────────────
# 연습실 예약 관련 모델
# ───────────────────────────────

# 연습실 예약 등록
class RoomBooking(BaseModel):
    id: int | None = None
    team_name: str          # 팀 이름
    room_name: str          # 연습실 이름 (예: "연습실 A")
    date: str               # 날짜 (예: "2026-02-22")
    start_time: float       # 시작 시간 (예: 14.0 = 14:00)
    end_time: float         # 종료 시간 (예: 16.0 = 16:00)
    note: str = ""          # 메모 (선택)

# 예약 현황 조회 결과
class BookingListResult(BaseModel):
    date: str
    bookings: List[RoomBooking]
    conflicts: List[str]    # 충돌 경고 목록


class ClubProfileUpdate(BaseModel):
    """PATCH /clubs/{id}/profile 요청 바디.

    model_fields_set으로 생략(변경 없음)과 null(초기화)을 구분한다.
    - 필드 생략 → model_fields_set에 없음 → DB 변경 없음
    - 필드 null  → model_fields_set에 있음, 값은 None → DB None으로 초기화
    - 필드 빈 문자열 → validator에서 400 에러
    """
    logo_url: Optional[str] = Field(None, max_length=2048)
    banner_url: Optional[str] = Field(None, max_length=2048)
    theme_color: Optional[str] = None  # 7 chars max enforced by regex

    @field_validator('logo_url', 'banner_url')
    @classmethod
    def validate_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if v == '':
            raise ValueError('URL은 빈 문자열일 수 없습니다. null을 사용해 초기화하세요.')
        if not re.match(r'^https?://', v):
            raise ValueError('URL은 http:// 또는 https://로 시작해야 합니다.')
        return v

    @field_validator('theme_color')
    @classmethod
    def validate_theme_color(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if v == '':
            raise ValueError('테마 컬러는 빈 문자열일 수 없습니다. null을 사용해 초기화하세요.')
        if not re.match(r'^#[0-9A-Fa-f]{6}$', v):
            raise ValueError('테마 컬러는 #RRGGBB 형식이어야 합니다. (예: #6750A4)')
        return v


class SubscriptionVerifyRequest(BaseModel):
    product_id:     str
    transaction_id: str
    platform:       Literal["apple", "google"]
    receipt_data:   str   # base64 영수증 (Apple) 또는 purchase_token (Google)


class BoostRequest(BaseModel):
    pass  # 본문 없음, 인증 + club membership으로 충분
