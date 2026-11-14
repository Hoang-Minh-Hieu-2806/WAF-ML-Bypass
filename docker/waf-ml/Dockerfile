# T03 — waf-ml image. Owner deployment: Hieu. Model: Hoang ML.
# Build context là repo root.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY waf-ml/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app/artifacts
COPY waf-ml/artifacts/ /app/artifacts/
# Tuần 05-06: train.py/build_dataset.py/server.py đi vào image;
# server.py train trong container nếu artifacts trống (sklearn pin sẵn).
# Dataset v2 cần corpus (26 SQLi + 10 XSS) — COPY vào vị trí default_corpus_root.
COPY waf-ml/app.py waf-ml/build_dataset.py waf-ml/train.py waf-ml/train_xss_augmented.py waf-ml/server.py waf-ml/test_app.py waf-ml/test_train.py waf-ml/test_train_xss_augmented.py ./
COPY dataset/bypass /dataset/bypass
# External v1.2 source split; kept separate from the v1.1 corpus.
COPY dataset/raw/httpparamsdataset /dataset/httpparamsdataset
ENV ML_MODEL_DIR=/app/artifacts

EXPOSE 5001
CMD ["python", "server.py"]
