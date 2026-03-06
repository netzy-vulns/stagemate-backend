# ── Stage 1: 빌드 ─────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# 시스템 의존성 (psycopg2-binary 컴파일에 필요)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt


# ── Stage 2: 런타임 ────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# 런타임 시스템 의존성 (libpq — psycopg2 실행에 필요)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# 빌더에서 패키지만 복사
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# 소스 복사 (.env, __pycache__, .git 제외)
COPY . .

# 비루트 사용자로 실행 (컨테이너 탈출 공격 면적 감소)
RUN adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Railway는 $PORT 환경변수를 자동으로 설정함
# --workers: Railway 무료 플랜 메모리 고려 (1~2 권장)
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
