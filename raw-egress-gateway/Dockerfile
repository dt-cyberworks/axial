FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df

RUN apk add --no-cache nftables

WORKDIR /srv
COPY app ./app

# Runs as root with only NET_ADMIN in Compose. The offensive runner remains
# non-root and does not inherit this process capability.

EXPOSE 8765
CMD ["python", "-m", "app.main"]
