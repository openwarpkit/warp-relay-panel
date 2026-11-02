FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY deploy/backup/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt
COPY backup/backup_archive.py ./backup_archive.py
ENTRYPOINT ["python", "/app/backup_archive.py"]
