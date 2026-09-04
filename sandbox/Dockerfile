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
ARG SAFE_REVERSER_VERSION
ARG SAFE_REVERSER_BUILD_COMMIT=unknown

LABEL org.opencontainers.image.title="safe-android-reverser" \
      org.opencontainers.image.version="${SAFE_REVERSER_VERSION}" \
      org.opencontainers.image.revision="${SAFE_REVERSER_BUILD_COMMIT}" \
      io.safe-reverser.capability.id="static-core" \
      io.safe-reverser.capability.api="1" \
      io.safe-reverser.worker.abi="1"

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates python3 file binutils libmagic1 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --home-dir /nonexistent --shell /usr/sbin/nologin reverser \
 && mkdir -p /opt/safe-reverser/tool-catalogs /opt/vineflower /opt/python-site /workspace /data/jobs /work \
 && chown -R 10001:10001 /data /work

COPY --from=tools /opt/jadx /opt/jadx
COPY --from=tools /tmp/vineflower.jar /opt/vineflower/vineflower.jar
COPY --from=python-tools /opt/python-site /opt/python-site
COPY plugins/safe-android-reverser/VERSION /opt/safe-reverser/VERSION
COPY plugins/safe-android-reverser/tool-catalogs/static-core.json /opt/safe-reverser/tool-catalogs/static-core.json
COPY ownership_contract.py /opt/safe-reverser/ownership_contract.py
COPY program_model.py /opt/safe-reverser/program_model.py
COPY application_map.py /opt/safe-reverser/application_map.py
COPY context_retrieval.py /opt/safe-reverser/context_retrieval.py
COPY flow_ir.py /opt/safe-reverser/flow_ir.py
COPY value_tracing.py /opt/safe-reverser/value_tracing.py
COPY security_semantics.py /opt/safe-reverser/security_semantics.py
COPY sandbox/mcp_server.py /opt/safe-reverser/mcp_server.py
COPY sandbox/static_semantic_worker.py /opt/safe-reverser/static_semantic_worker.py
COPY sandbox/static_application_map.py /opt/safe-reverser/static_application_map.py
COPY sandbox/static_context_retrieval.py /opt/safe-reverser/static_context_retrieval.py
COPY sandbox/dex_value_tracing.py /opt/safe-reverser/dex_value_tracing.py
COPY sandbox/dex_value_tracing_runtime.py /opt/safe-reverser/dex_value_tracing_runtime.py
COPY sandbox/static_value_tracing.py /opt/safe-reverser/static_value_tracing.py
COPY sandbox/dex_security_semantics.py /opt/safe-reverser/dex_security_semantics.py
COPY sandbox/static_security_semantics.py /opt/safe-reverser/static_security_semantics.py
COPY sandbox/mcp_entrypoint.py /opt/safe-reverser/mcp_entrypoint.py
COPY sandbox/archive_safety.py /opt/safe-reverser/archive_safety.py
COPY sandbox/analysis_routing.py /opt/safe-reverser/analysis_routing.py
COPY sandbox/peg_schema.py /opt/safe-reverser/peg_schema.py
COPY sandbox/flutter_analysis.py /opt/safe-reverser/flutter_analysis.py
COPY sandbox/program_understanding.py /opt/safe-reverser/program_understanding.py
COPY sandbox/program_understanding_v2.py /opt/safe-reverser/program_understanding_v2.py
COPY sandbox/pu_source.py /opt/safe-reverser/pu_source.py
COPY sandbox/pu_index.py /opt/safe-reverser/pu_index.py
COPY sandbox/pu_network.py /opt/safe-reverser/pu_network.py
COPY sandbox/pu_api.py /opt/safe-reverser/pu_api.py
COPY sandbox/pu_ownership.py /opt/safe-reverser/pu_ownership.py
COPY sandbox/pu_ownership_queries.py /opt/safe-reverser/pu_ownership_queries.py
COPY sandbox/pu_program_model.py /opt/safe-reverser/pu_program_model.py
COPY sandbox/ownership_rules.json /opt/safe-reverser/ownership_rules.json

RUN set -eux; \
    test -n "$SAFE_REVERSER_VERSION"; \
    test "$(tr -d '[:space:]' < /opt/safe-reverser/VERSION)" = "$SAFE_REVERSER_VERSION"; \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx; \
    PYTHONPATH=/opt/python-site:/opt/safe-reverser python3 -c 'import application_map as amap; import context_retrieval as ctx; import flow_ir as flow; import value_tracing as trace; import security_semantics as security; import dex_value_tracing as dexflow; import dex_value_tracing_runtime as dexruntime; import dex_security_semantics as dexsecurity; import program_understanding_v2 as pu; import pu_api as api; import pu_ownership as ownership; import pu_program_model as provider; import program_model as pm; import static_semantic_worker as worker; import static_application_map as map_hooks; import static_context_retrieval as context_hooks; import static_value_tracing as flow_hooks; import static_security_semantics as security_hooks; import analysis_routing as routing; import peg_schema as peg; import flutter_analysis as flutter; import archive_safety as archive; caps=pu.capabilities(); assert caps["androguard"], caps; assert caps["code_ownership"], caps; assert api.extract_api is not None; assert ownership.load_rules().schema_version == 1; assert provider.DexProgramProvider is not None; assert pm.descriptor()["program_model_version"] == 1; assert amap.descriptor()["application_map_version"] == 1; assert ctx.descriptor()["context_retrieval_version"] == 1; assert flow.descriptor()["flow_ir_version"] == 1; assert trace.descriptor()["value_tracing_version"] == 1; assert trace.descriptor()["gaps_are_traversable"] is False; assert trace.descriptor()["max_trace_states"] == 10000; assert security.descriptor()["security_semantics_version"] == 1; assert security.descriptor()["gaps_are_traversable"] is False; assert security.descriptor()["raw_secret_values"] is False; d=dexruntime.descriptor(); assert d["dex_flow_producer_version"] == 1; assert d["dalvik_abi_normalization"] is True; assert d["calls_xref_are_data_flow"] is False; assert d["raw_constants_emitted"] is False; assert d["wide_parameter_words_collapsed"] is True; assert d["instance_receiver_preserved_until_semantic_call_layer"] is True; assert d["reflection_gap_precedence"] is True; assert d["shared_field_access_evidence_on_edges"] is True; assert d["declaring_field_owner_canonical"] is True; assert d["static_field_flow_proven"] is True; assert d["instance_field_alias_required"] is True; assert d["instance_field_unproven_is_gap"] is True; assert d["read_before_write_semantics"] is True; assert d["move_exception_is_explicit_gap"] is True; sd=dexsecurity.descriptor(); assert sd["structured_dex_operands"] is True; assert sd["decompiler_grep_is_finding_source"] is False; assert sd["raw_secret_values"] is False; assert map_hooks.INTERNAL_APPLICATION_MAP_TOOLS == {"get_application_map", "expand_application_node"}; assert context_hooks.INTERNAL_CONTEXT_RETRIEVAL_TOOLS == {"get_function_context"}; assert flow_hooks.INTERNAL_VALUE_TRACING_TOOLS == {"trace_value", "find_source_to_sink"}; assert security_hooks.INTERNAL_SECURITY_SEMANTIC_TOOLS == {"find_auth_flow", "trace_crypto"}; map_hooks.install(worker); context_hooks.install(worker); flow_hooks.install(worker); security_hooks.install(worker); internal={"health"} | set(map_hooks.INTERNAL_APPLICATION_MAP_TOOLS) | set(context_hooks.INTERNAL_CONTEXT_RETRIEVAL_TOOLS) | set(flow_hooks.INTERNAL_VALUE_TRACING_TOOLS) | set(security_hooks.INTERNAL_SECURITY_SEMANTIC_TOOLS); raw_names=[item["name"] for item in worker.core.TOOLS]; assert all(raw_names.count(name) == 1 for name in internal), raw_names; public=[item for item in worker.core.TOOLS if item.get("name") not in internal]; assert public; assert {item["name"] for item in public} == set(worker.core.TOOL_HANDLERS) - internal; health=worker.health({}); assert health["value_tracing"]["value_tracing_version"] == 1; assert health["value_tracing"]["max_trace_states"] == 10000; assert health["dex_flow_producer"]["dalvik_abi_normalization"] is True; assert health["security_semantics"]["security_semantics_version"] == 1; assert health["security_semantics"]["raw_secret_values"] is False; assert health["dex_security_producer"]["structured_dex_operands"] is True; assert health["dex_security_producer"]["decompiler_grep_is_finding_source"] is False; assert routing.PROFILE_REGISTRY["static-core"]["status"] == "available"; assert routing.PROFILE_REGISTRY["framework-flutter"]["status"] == "declared"; assert peg.PEG_SCHEMA_VERSION == 2; assert flutter.MAX_ASSET_COUNT == 20000; assert archive.MAX_NESTED_APKS == 128'; \
    chmod 0444 /opt/safe-reverser/VERSION /opt/safe-reverser/ownership_rules.json /opt/safe-reverser/tool-catalogs/static-core.json; \
    chmod 0555 /opt/safe-reverser/ownership_contract.py /opt/safe-reverser/program_model.py /opt/safe-reverser/application_map.py /opt/safe-reverser/context_retrieval.py /opt/safe-reverser/flow_ir.py /opt/safe-reverser/value_tracing.py /opt/safe-reverser/security_semantics.py /opt/safe-reverser/mcp_server.py /opt/safe-reverser/static_semantic_worker.py /opt/safe-reverser/static_application_map.py /opt/safe-reverser/static_context_retrieval.py /opt/safe-reverser/dex_value_tracing.py /opt/safe-reverser/dex_value_tracing_runtime.py /opt/safe-reverser/static_value_tracing.py /opt/safe-reverser/dex_security_semantics.py /opt/safe-reverser/static_security_semantics.py /opt/safe-reverser/mcp_entrypoint.py /opt/safe-reverser/archive_safety.py /opt/safe-reverser/analysis_routing.py /opt/safe-reverser/peg_schema.py /opt/safe-reverser/flutter_analysis.py /opt/safe-reverser/program_understanding.py /opt/safe-reverser/program_understanding_v2.py /opt/safe-reverser/pu_source.py /opt/safe-reverser/pu_index.py /opt/safe-reverser/pu_network.py /opt/safe-reverser/pu_api.py /opt/safe-reverser/pu_ownership.py /opt/safe-reverser/pu_ownership_queries.py /opt/safe-reverser/pu_program_model.py; \
    chmod -R a-w /opt/jadx /opt/vineflower /opt/python-site /opt/safe-reverser

ENV SAFE_REVERSER_WORKSPACE=/workspace \
    SAFE_REVERSER_DATA_ROOT=/data/jobs \
    SAFE_REVERSER_IMAGE_VERSION=${SAFE_REVERSER_VERSION} \
    SAFE_REVERSER_BUILD_COMMIT=${SAFE_REVERSER_BUILD_COMMIT} \
    VINEFLOWER_JAR=/opt/vineflower/vineflower.jar \
    PYTHONPATH=/opt/python-site:/opt/safe-reverser \
    HOME=/tmp/home \
    XDG_CACHE_HOME=/tmp/xdg-cache \
    XDG_CONFIG_HOME=/tmp/xdg-config

WORKDIR /work
USER 10001:10001
ENTRYPOINT ["python3", "/opt/safe-reverser/mcp_entrypoint.py"]
