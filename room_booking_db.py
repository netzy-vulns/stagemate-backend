from sqlalchemy.orm import Session
import db_models
from models import RoomBooking
from typing import List, Optional


def add_booking_db(
    booking: RoomBooking,
    user_id: int,
    club_id: Optional[int],
    db: Session
) -> dict:
    conflicts = _check_conflicts(booking, club_id, db)
    if conflicts:
        return {"success": False, "message": "예약 충돌!", "conflicts": conflicts}

    new_booking = db_models.RoomBookingDB(
        user_id=user_id,
        club_id=club_id,
        team_name=booking.team_name,
        room_name=booking.room_name,
        date=booking.date,
        start_time=booking.start_time,
        end_time=booking.end_time,
        note=booking.note,
    )
    db.add(new_booking)
    db.commit()
    db.refresh(new_booking)
    return {
        "success": True,
        "message": "예약 완료!",
        "booking": {
            "id": new_booking.id,
            "team_name": new_booking.team_name,
            "room_name": new_booking.room_name,
            "date": new_booking.date,
            "start_time": new_booking.start_time,
            "end_time": new_booking.end_time,
            "note": new_booking.note,
        }
    }


def get_bookings_db(
    date: str,
    club_id: Optional[int],
    db: Session
) -> dict:
    query = db.query(db_models.RoomBookingDB).filter(
        db_models.RoomBookingDB.date == date
    )
    if club_id is not None:
        query = query.filter(db_models.RoomBookingDB.club_id == club_id)

    bookings = query.order_by(db_models.RoomBookingDB.start_time).all()

    booking_list = [
        {
            "id": b.id,
            "team_name": b.team_name,
            "room_name": b.room_name,
            "date": b.date,
            "start_time": b.start_time,
            "end_time": b.end_time,
            "note": b.note,
            "user_id": b.user_id,
        }
        for b in bookings
    ]

    conflicts = []
    for i, b1 in enumerate(bookings):
        for b2 in bookings[i+1:]:
            if b1.room_name == b2.room_name and _overlap(
                b1.start_time, b1.end_time,
                b2.start_time, b2.end_time
            ):
                conflicts.append(
                    f"⚠️ [{b1.room_name}] {b1.team_name} ↔ {b2.team_name} 충돌!"
                )

    return {"date": date, "bookings": booking_list, "conflicts": conflicts}


def delete_booking_db(
    booking_id: int,
    user_id: int,
    club_id: Optional[int],
    db: Session
) -> dict:
    query = db.query(db_models.RoomBookingDB).filter(
        db_models.RoomBookingDB.id == booking_id,
        db_models.RoomBookingDB.user_id == user_id  # 본인것만 삭제
    )
    if club_id is not None:
        query = query.filter(db_models.RoomBookingDB.club_id == club_id)

    booking = query.first()
    if not booking:
        raise Exception("예약을 찾을 수 없거나 권한이 없습니다.")
    db.delete(booking)
    db.commit()
    return {"success": True, "message": "예약 취소 완료!"}


def _check_conflicts(
    booking: RoomBooking,
    club_id: Optional[int],
    db: Session
) -> List[str]:
    query = db.query(db_models.RoomBookingDB).filter(
        db_models.RoomBookingDB.room_name == booking.room_name,
        db_models.RoomBookingDB.date == booking.date,
    )
    if club_id is not None:
        query = query.filter(db_models.RoomBookingDB.club_id == club_id)

    existing = query.all()
    conflicts = []
    for e in existing:
        if _overlap(e.start_time, e.end_time, booking.start_time, booking.end_time):
            conflicts.append(
                f"{e.team_name}이(가) {_fmt(e.start_time)}~{_fmt(e.end_time)}에 이미 예약"
            )
    return conflicts


def _overlap(s1, e1, s2, e2) -> bool:
    return s1 < e2 and s2 < e1


def _fmt(t: float) -> str:
    h = int(t)
    m = int((t - h) * 60)
    return f"{h:02d}:{m:02d}"
