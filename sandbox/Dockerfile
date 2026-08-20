# syntax=docker/dockerfile:1.7
FROM eclipse-temurin:21-jdk-jammy AS tools

ARG JADX_VERSION=1.5.5
ARG VINEFLOWER_VERSION=1.12.0
ARG JADX_SHA256=""
ARG VINEFLOWER_SHA256=""

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl -fsSL "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -o /tmp/jadx.zip; \
    if [ -n "$JADX_SHA256" ]; then echo "$JADX_SHA256  /tmp/jadx.zip" | sha256sum -c -; fi; \
    mkdir -p /opt/jadx; \
    unzip -q /tmp/jadx.zip -d /opt/jadx; \
    test -x /opt/jadx/bin/jadx

RUN set -eux; \
    curl -fsSL "https://github.com/Vineflower/vineflower/releases/download/${VINEFLOWER_VERSION}/vineflower-${VINEFLOWER_VERSION}.jar" -o /tmp/vineflower.jar; \
    if [ -n "$VINEFLOWER_SHA256" ]; then echo "$VINEFLOWER_SHA256  /tmp/vineflower.jar" | sha256sum -c -; fi; \
    test -s /tmp/vineflower.jar

FROM eclipse-temurin:21-jre-jammy

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates python3 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --home-dir /nonexistent --shell /usr/sbin/nologin reverser \
 && mkdir -p /opt/safe-reverser /opt/vineflower /workspace /data/jobs /work \
 && chown -R 10001:10001 /data /work

COPY --from=tools /opt/jadx /opt/jadx
COPY --from=tools /tmp/vineflower.jar /opt/vineflower/vineflower.jar
COPY sandbox/mcp_server.py /opt/safe-reverser/mcp_server.py

RUN ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
 && chmod 0555 /opt/safe-reverser/mcp_server.py \
 && chmod -R a-w /opt/jadx /opt/vineflower /opt/safe-reverser

ENV SAFE_REVERSER_WORKSPACE=/workspace \
    SAFE_REVERSER_DATA_ROOT=/data/jobs \
    VINEFLOWER_JAR=/opt/vineflower/vineflower.jar \
    HOME=/tmp/home \
    XDG_CACHE_HOME=/tmp/xdg-cache \
    XDG_CONFIG_HOME=/tmp/xdg-config

WORKDIR /work
USER 10001:10001
ENTRYPOINT ["python3", "/opt/safe-reverser/mcp_server.py"]
