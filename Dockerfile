FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
RUN useradd --system --create-home --uid 10001 panel
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY templates ./templates
COPY static ./static
RUN mkdir -p /var/lib/awg-panel && chown -R panel:panel /app /var/lib/awg-panel
USER panel
ENV AGENT_SOCKET=/run/awg-panel/agent.sock \
    AGENT_TIMEOUT=5
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=2)"]
CMD ["uvicorn", "app.asgi:app", "--host", "0.0.0.0", "--port", "5000"]
