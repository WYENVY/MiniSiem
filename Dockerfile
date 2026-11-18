FROM python:3.13-slim

WORKDIR /app

# Install dependencies first so Docker can cache this layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY siem ./siem
COPY rules.yaml .
COPY sample_logs ./sample_logs

# Run as a non-root user
RUN useradd --create-home appuser && mkdir /data && chown appuser /data
USER appuser

ENV SIEM_DB=/data/siem.db
EXPOSE 8000

CMD ["python", "-m", "uvicorn", "siem.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]