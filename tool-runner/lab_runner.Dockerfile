# lab_runner.Dockerfile - minimal tool runner ONLY for the lab test loop.
#
# Replacement for runner.Dockerfile (Kali + HexStrike, see there) in this live
# test: only nmap + a Python stdlib HTTP server. A smaller, faster, more
# reliable build (no external repo-clone dependency). The full HexStrike
# integration lives in runner.Dockerfile - this is the deliberately minimal but
# real path gateway -> runner -> findings.
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

RUN apt-get update && apt-get install -y --no-install-recommends nmap \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY lab_runner.py .

RUN useradd -r -u 10005 -s /usr/sbin/nologin labrunner
USER labrunner

EXPOSE 8888
CMD ["python3", "lab_runner.py"]
