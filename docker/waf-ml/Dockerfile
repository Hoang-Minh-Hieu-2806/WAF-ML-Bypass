# T03 — waf-ml image. Owner deployment: Hieu. Model: Hoang ML.
# Build context là repo root.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY waf-ml/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY waf-ml/app.py ./app.py

EXPOSE 5001
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5001"]
