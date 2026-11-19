FROM mcr.microsoft.com/playwright/python:v1.50.0-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/pwuser \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

RUN pip install --no-cache-dir --break-system-packages playwright==1.50.0

COPY worker.py /app/worker.py

RUN chown -R pwuser:pwuser /app

USER pwuser

ENTRYPOINT ["python3", "/app/worker.py"]
