"""
비밀번호 긴급 초기화 스크립트
사용법: python reset_password.py <아이디> <새비밀번호>
예시:  python reset_password.py myusername NewPass123!
"""
import sys
from database import SessionLocal
import db_models
from auth import hash_password, validate_password_strength


def reset_password(username: str, new_password: str) -> None:
    if not validate_password_strength(new_password):
        print("❌ 비밀번호 조건 미충족: 8자 이상, 대문자·소문자·숫자 각 1개 이상 포함해야 합니다.")
        sys.exit(1)

    db = SessionLocal()
    try:
        user = db.query(db_models.User).filter(db_models.User.username == username).first()
        if not user:
            print(f"❌ '{username}' 아이디를 찾을 수 없습니다.")
            sys.exit(1)

        user.hashed_password = hash_password(new_password)
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()
        print(f"✅ '{username}' 비밀번호가 초기화됐습니다. 새 비밀번호로 로그인하세요.")
    finally:
        db.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("사용법: python reset_password.py <아이디> <새비밀번호>")
        print("예시:   python reset_password.py myusername NewPass123!")
        sys.exit(1)

    reset_password(sys.argv[1], sys.argv[2])
