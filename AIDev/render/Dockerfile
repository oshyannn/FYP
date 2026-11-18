FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy

RUN python -m pip install --no-cache-dir playwright==1.47.0 \
 && useradd -m -u 10001 renderer

WORKDIR /app
COPY render_pages.py render_one.py /app/

USER renderer
ENTRYPOINT ["python", "/app/render_pages.py"]