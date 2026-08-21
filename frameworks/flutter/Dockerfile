# syntax=docker/dockerfile:1.7
FROM ubuntu:24.04 AS blutter-source

ARG DEBIAN_FRONTEND=noninteractive
ARG BLUTTER_REPOSITORY=https://github.com/worawit/blutter.git
ARG BLUTTER_COMMIT=4a60ac648bf448c5a7596437243bcd0b9376fdf0

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    git init /opt/blutter; \
    git -C /opt/blutter remote add origin "$BLUTTER_REPOSITORY"; \
    git -C /opt/blutter fetch --depth 1 origin "$BLUTTER_COMMIT"; \
    git -C /opt/blutter checkout --detach FETCH_HEAD; \
    test "$(git -C /opt/blutter rev-parse HEAD)" = "$BLUTTER_COMMIT"; \
    test -f /opt/blutter/LICENSE; \
    grep -q "MIT License" /opt/blutter/LICENSE; \
    rm -rf /opt/blutter/.git

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG SAFE_REVERSER_VERSION
ARG SAFE_REVERSER_BUILD_COMMIT=unknown
ARG BLUTTER_COMMIT=4a60ac648bf448c5a7596437243bcd0b9376fdf0

LABEL org.opencontainers.image.title="safe-android-reverser-flutter" \
      org.opencontainers.image.version="${SAFE_REVERSER_VERSION}" \
      org.opencontainers.image.revision="${SAFE_REVERSER_BUILD_COMMIT}" \
      org.opencontainers.image.description="Offline-safe Flutter/Dart AOT analysis capability profile" \
      org.opencontainers.image.licenses="Apache-2.0 AND MIT" \
      io.safe-reverser.blutter.commit="${BLUTTER_COMMIT}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      python3 \
      python3-pyelftools \
      python3-requests \
      libcapstone4 \
      libicu74 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --home-dir /nonexistent --shell /usr/sbin/nologin reverser \
 && mkdir -p /opt/safe-flutter /input /output /work \
 && chown -R 10001:10001 /output /work

COPY --from=blutter-source /opt/blutter /opt/blutter
COPY frameworks/flutter/cache_identity.py /opt/safe-flutter/cache_identity.py
COPY frameworks/flutter/safe_blutter_adapter.py /opt/safe-flutter/safe_blutter_adapter.py
COPY frameworks/flutter/tools.lock.env /opt/safe-flutter/tools.lock.env

RUN set -eux; \
    test -n "$SAFE_REVERSER_VERSION"; \
    test -f /opt/blutter/LICENSE; \
    test -f /opt/blutter/blutter.py; \
    test -f /opt/blutter/extract_dart_info.py; \
    test -f /opt/safe-flutter/cache_identity.py; \
    test -f /opt/safe-flutter/safe_blutter_adapter.py; \
    python3 -m py_compile /opt/safe-flutter/cache_identity.py /opt/safe-flutter/safe_blutter_adapter.py; \
    chmod 0555 /opt/safe-flutter/cache_identity.py /opt/safe-flutter/safe_blutter_adapter.py; \
    chmod -R a-w /opt/blutter /opt/safe-flutter

ENV SAFE_FLUTTER_INPUT=/input \
    SAFE_FLUTTER_OUTPUT=/output \
    SAFE_BLUTTER_ROOT=/opt/blutter \
    SAFE_BLUTTER_COMMIT=${BLUTTER_COMMIT} \
    SAFE_REVERSER_IMAGE_VERSION=${SAFE_REVERSER_VERSION} \
    SAFE_REVERSER_BUILD_COMMIT=${SAFE_REVERSER_BUILD_COMMIT} \
    HOME=/tmp/home \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

WORKDIR /work
USER 10001:10001
ENTRYPOINT ["python3", "/opt/safe-flutter/safe_blutter_adapter.py"]
