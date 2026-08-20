# syntax=docker/dockerfile:1.7
FROM eclipse-temurin:21-jdk-jammy AS tools

ARG JADX_VERSION=1.5.6
ARG JADX_SHA256=545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974
ARG VINEFLOWER_VERSION=1.12.0
ARG VINEFLOWER_SHA256=""

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl -fsSL "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -o /tmp/jadx.zip; \
    test -n "$JADX_SHA256"; \
    echo "$JADX_SHA256  /tmp/jadx.zip" | sha256sum -c -; \
    mkdir -p /opt/jadx; \
    unzip -q /tmp/jadx.zip -d /opt/jadx; \
    test -x /opt/jadx/bin/jadx

RUN set -eux; \
    curl -fsSL "https://github.com/Vineflower/vineflower/releases/download/${VINEFLOWER_VERSION}/vineflower-${VINEFLOWER_VERSION}.jar" -o /tmp/vineflower.jar; \
    if [ -n "$VINEFLOWER_SHA256" ]; then echo "$VINEFLOWER_SHA256  /tmp/vineflower.jar" | sha256sum -c -; fi; \
    test -s /tmp/vineflower.jar

FROM eclipse-temurin:21-jre-jammy AS python-tools
ARG DEBIAN_FRONTEND=noninteractive
ARG ANDROGUARD_VERSION=4.1.4
ARG ANDROGUARD_WHEEL_SHA256=6265a6d4007401cf5a62a98fa99a1c2994644d4311da031a5398efe3bcaa63b0
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates python3 python3-pip python3-dev build-essential libmagic1 \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /tmp/androguard /opt/python-site \
 && python3 -m pip download --disable-pip-version-check --no-deps --only-binary=:all: --dest /tmp/androguard "androguard==${ANDROGUARD_VERSION}" \
 && echo "${ANDROGUARD_WHEEL_SHA256}  /tmp/androguard/androguard-${ANDROGUARD_VERSION}-py3-none-any.whl" | sha256sum -c - \
 && python3 -m pip install --no-cache-dir --disable-pip-version-check --target=/opt/python-site "/tmp/androguard/androguard-${ANDROGUARD_VERSION}-py3-none-any.whl" \
 && PYTHONPATH=/opt/python-site python3 -c 'import androguard; from androguard.core import dex; from androguard.core.analysis.analysis import Analysis; assert androguard.__version__ == "4.1.4"; assert dex is not None; assert Analysis is not None' \
 && python3 -m pip freeze --path /opt/python-site | sort > /opt/python-site/installed-requirements.txt

FROM eclipse-temurin:21-jre-jammy
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates python3 file binutils libmagic1 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --home-dir /nonexistent --shell /usr/sbin/nologin reverser \
 && mkdir -p /opt/safe-reverser /opt/vineflower /opt/python-site /workspace /data/jobs /work \
 && chown -R 10001:10001 /data /work

COPY --from=tools /opt/jadx /opt/jadx
COPY --from=tools /tmp/vineflower.jar /opt/vineflower/vineflower.jar
COPY --from=python-tools /opt/python-site /opt/python-site
COPY sandbox/mcp_server.py /opt/safe-reverser/mcp_server.py
COPY sandbox/program_understanding.py /opt/safe-reverser/program_understanding.py
COPY sandbox/program_understanding_v2.py /opt/safe-reverser/program_understanding_v2.py
COPY sandbox/pu_source.py /opt/safe-reverser/pu_source.py
COPY sandbox/pu_index.py /opt/safe-reverser/pu_index.py
COPY sandbox/pu_network.py /opt/safe-reverser/pu_network.py
COPY sandbox/mcp_server_v2.py /opt/safe-reverser/mcp_server_v2.py

RUN ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
 && PYTHONPATH=/opt/python-site:/opt/safe-reverser python3 -c 'import program_understanding_v2 as pu; caps=pu.capabilities(); assert caps["androguard"], caps' \
 && chmod 0555 /opt/safe-reverser/mcp_server.py /opt/safe-reverser/mcp_server_v2.py /opt/safe-reverser/program_understanding.py /opt/safe-reverser/program_understanding_v2.py /opt/safe-reverser/pu_source.py /opt/safe-reverser/pu_index.py /opt/safe-reverser/pu_network.py \
 && chmod -R a-w /opt/jadx /opt/vineflower /opt/python-site /opt/safe-reverser

ENV SAFE_REVERSER_WORKSPACE=/workspace \
    SAFE_REVERSER_DATA_ROOT=/data/jobs \
    VINEFLOWER_JAR=/opt/vineflower/vineflower.jar \
    PYTHONPATH=/opt/python-site:/opt/safe-reverser \
    HOME=/tmp/home \
    XDG_CACHE_HOME=/tmp/xdg-cache \
    XDG_CONFIG_HOME=/tmp/xdg-config

WORKDIR /work
USER 10001:10001
ENTRYPOINT ["python3", "/opt/safe-reverser/mcp_server_v2.py"]
