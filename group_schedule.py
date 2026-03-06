from sqlalchemy.orm import Session
import db_models
from typing import Dict, List, Optional


SLOT_UNIT = 0.25  # 15분 단위


def find_common_slots_from_db(
    room_code: str,
    duration_needed: float,
    db: Session,
    club_id: Optional[int] = None,
) -> dict:
    """DB에서 방 코드의 멤버 가능 시간 조회 후 공통 시간 산출"""

    query = db.query(db_models.AvailabilitySlot).filter(
        db_models.AvailabilitySlot.room_code == room_code
    )
    if club_id is not None:
        query = query.filter(db_models.AvailabilitySlot.club_id == club_id)

    slots = query.all()

    if not slots:
        return {
            "room_code": room_code,
            "common_slots": [],
            "partial_slots": [],
            "best_slot": None
        }

    # 멤버별 슬롯 정리
    member_slots: Dict[str, List] = {}
    for slot in slots:
        name = slot.user.display_name
        if name not in member_slots:
            member_slots[name] = []
        member_slots[name].append({
            "day": slot.day,
            "start": slot.start_time,
            "end": slot.end_time,
        })

    all_members = list(member_slots.keys())
    total = len(all_members)
    days = ["월", "화", "수", "목", "금", "토", "일"]

    common_slots = []
    partial_slots = []

    for day in days:
        time = 6.0
        while time < 24.0:
            slot_end = round(time + SLOT_UNIT, 2)
            available = [
                name for name, s_list in member_slots.items()
                if any(
                    s["day"] == day
                    and s["start"] <= time
                    and s["end"] >= slot_end
                    for s in s_list
                )
            ]
            if len(available) == total:
                common_slots.append({
                    "day": day,
                    "start": time,
                    "end": slot_end,
                    "available_members": available,
                    "all_available": True
                })
            elif len(available) >= max(1, int(total * 0.7)):
                partial_slots.append({
                    "day": day,
                    "start": time,
                    "end": slot_end,
                    "available_members": available,
                    "all_available": False
                })
            time = round(time + SLOT_UNIT, 2)

    # 연속 슬롯 합치기
    common_merged = _merge(common_slots)
    partial_merged = _merge(partial_slots)

    # 필요 시간 이상인 것만 필터링
    common_valid = [
        s for s in common_merged
        if (s["end"] - s["start"]) >= duration_needed
    ]
    partial_valid = [
        s for s in partial_merged
        if (s["end"] - s["start"]) >= duration_needed
    ]

    # 최적 슬롯 선택
    best = None
    if common_valid:
        best = max(common_valid, key=lambda s: s["end"] - s["start"])
    elif partial_valid:
        best = max(partial_valid, key=lambda s: len(s["available_members"]))

    return {
        "room_code": room_code,
        "common_slots": common_valid,
        "partial_slots": partial_valid,
        "best_slot": best
    }


def _merge(slots: list) -> list:
    """연속된 15분 슬롯을 하나로 합치기"""
    if not slots:
        return []

    merged = []
    current = dict(slots[0])

    for next_slot in slots[1:]:
        same_day = current["day"] == next_slot["day"]
        continuous = abs(current["end"] - next_slot["start"]) < 0.01
        same_members = set(current["available_members"]) == set(
            next_slot["available_members"]
        )

        if same_day and continuous and same_members:
            current["end"] = next_slot["end"]
        else:
            merged.append(current)
            current = dict(next_slot)

    merged.append(current)
    return merged
