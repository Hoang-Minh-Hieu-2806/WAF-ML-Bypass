# T03 — web-app image. Owner: Hoang Minh Hieu.
# Build context là repo root (xem docker-compose.yml).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY web-app/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY web-app/app.py ./app.py

EXPOSE 5000
CMD ["python", "app.py"]
