# control-plane: Kontrollebene (Kontrollebene-Zone, s. Deployment-Architektur Kap. 1).
# Laeuft NIE offensive Tools - nur Orchestrator + Scope Gateway.
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY migrations ./migrations
COPY scripts ./scripts

RUN useradd -r -u 10002 -s /usr/sbin/nologin controlplane
USER controlplane

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
