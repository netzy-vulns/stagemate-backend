from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from config import settings

# PostgreSQL (프로덕션) / SQLite 폴백 지원
# DATABASE_URL 예시:
#   PostgreSQL: postgresql://user:pass@host/dbname?sslmode=require
#   SQLite(로컬개발): sqlite:///./stagemate.db
if settings.DATABASE_URL.startswith("sqlite"):
    # SQLite: FastAPI 스레드풀에서 안전하게 쓰려면 check_same_thread=False 필요
    engine = create_engine(
        settings.DATABASE_URL,
        connect_args={"check_same_thread": False},
    )
else:
    # PostgreSQL 등: 연결 풀 최적화
    engine = create_engine(
        settings.DATABASE_URL,
        pool_pre_ping=True,    # 끊긴 연결 자동 재시도
        pool_recycle=1800,     # 30분마다 연결 재사용 (idle timeout 방지)
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# DB 세션 의존성 주입용
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
