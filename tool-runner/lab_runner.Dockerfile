# lab_runner.Dockerfile - minimaler Tool-Runner NUR fuer den Lab-Testloop (M1).
#
# Ersatz fuer runner.Dockerfile (Kali + HexStrike, s. dort) in diesem
# Live-Test: nur nmap + ein Python-Stdlib-HTTP-Server. Kleiner, schnellerer,
# zuverlaessigerer Build (keine externe Repo-Clone-Abhaengigkeit). Die volle
# HexStrike-Integration bleibt Roadmap M3 (docs/roadmap.md) - dies ist der
# bewusst minimale, aber echte Pfad Gateway -> Runner -> Findings.
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

RUN apt-get update && apt-get install -y --no-install-recommends nmap \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY lab_runner.py .

RUN useradd -r -u 10005 -s /usr/sbin/nologin labrunner
USER labrunner

EXPOSE 8888
CMD ["python3", "lab_runner.py"]
