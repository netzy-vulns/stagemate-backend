from models import RoomBooking, BookingListResult
from typing import List

# 임시 메모리 저장소 (나중에 DB로 교체 예정)
_bookings: List[RoomBooking] = []
_next_id = 1

def add_booking(booking: RoomBooking) -> dict:
    """예약 추가 - 충돌 검사 후 등록"""
    global _next_id

    conflicts = _check_conflicts(booking, exclude_id=None)
    if conflicts:
        return {
            "success": False,
            "message": "예약 충돌이 있습니다.",
            "conflicts": conflicts
        }

    booking.id = _next_id
    _next_id += 1
    _bookings.append(booking)

    return {
        "success": True,
        "message": "예약이 완료됐습니다!",
        "booking": booking
    }


def get_bookings(date: str) -> BookingListResult:
    """특정 날짜의 예약 현황 조회"""
    day_bookings = [b for b in _bookings if b.date == date]

    # 시작 시간 순 정렬
    day_bookings.sort(key=lambda b: (b.room_name, b.start_time))

    # 충돌 검사
    conflicts = []
    for i, b1 in enumerate(day_bookings):
        for b2 in day_bookings[i+1:]:
            if b1.room_name == b2.room_name and _is_overlap(b1, b2):
                conflicts.append(
                    f"⚠️ [{b1.room_name}] {b1.team_name}({_fmt(b1.start_time)}~{_fmt(b1.end_time)}) "
                    f"↔ {b2.team_name}({_fmt(b2.start_time)}~{_fmt(b2.end_time)}) 충돌!"
                )

    return BookingListResult(
        date=date,
        bookings=day_bookings,
        conflicts=conflicts
    )


def delete_booking(booking_id: int) -> dict:
    """예약 취소"""
    global _bookings
    before = len(_bookings)
    _bookings = [b for b in _bookings if b.id != booking_id]

    if len(_bookings) < before:
        return {"success": True, "message": "예약이 취소됐습니다."}
    return {"success": False, "message": "예약을 찾을 수 없습니다."}


def _check_conflicts(new_booking: RoomBooking, exclude_id) -> List[str]:
    """새 예약이 기존 예약과 충돌하는지 검사"""
    conflicts = []
    for existing in _bookings:
        if existing.id == exclude_id:
            continue
        if existing.room_name == new_booking.room_name and \
           existing.date == new_booking.date and \
           _is_overlap(existing, new_booking):
            conflicts.append(
                f"{existing.team_name}이(가) {_fmt(existing.start_time)}~"
                f"{_fmt(existing.end_time)}에 이미 예약함"
            )
    return conflicts


def _is_overlap(b1: RoomBooking, b2: RoomBooking) -> bool:
    """두 예약 시간이 겹치는지 확인"""
    return b1.start_time < b2.end_time and b2.start_time < b1.end_time


def _fmt(t: float) -> str:
    """14.5 → '14:30'"""
    h = int(t)
    m = int((t - h) * 60)
    return f"{h:02d}:{m:02d}"
