FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOST=0.0.0.0 \
    PORT=8000

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY codex_proxy.py ./codex_proxy.py

RUN mkdir -p /app/data

EXPOSE 8000

CMD ["sh", "-c", "uvicorn codex_proxy:app --host 0.0.0.0 --port ${PORT:-8000}"]
