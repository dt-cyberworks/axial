# egress-proxy: einziger Weg vom Ausführungsnetz ins Internet
# (Deployment-Architektur Kap. 1/6). Kein offensives Tool, kein LLM.
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN useradd -r -u 10004 -s /usr/sbin/nologin egressproxy
USER egressproxy

EXPOSE 3128
CMD ["python", "-m", "app.main"]
