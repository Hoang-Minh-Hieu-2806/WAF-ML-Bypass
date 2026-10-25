# T03 — waf-ml image. Owner deployment: Hieu. Model: Hoang ML.
# Build context là repo root.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY waf-ml/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app/artifacts
# Tuần 05-06: train.py/build_dataset.py/server.py đi vào image;
# server.py train trong container nếu artifacts trống (sklearn pin sẵn).
COPY waf-ml/app.py waf-ml/build_dataset.py waf-ml/train.py waf-ml/server.py ./
ENV ML_MODEL_DIR=/app/artifacts

EXPOSE 5001
CMD ["python", "server.py"]
