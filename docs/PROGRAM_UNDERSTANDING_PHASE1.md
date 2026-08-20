# Program Understanding Phase 1

Safe Android Reverser 0.2.0 adds a semantic program-understanding layer on top of the existing sandboxed decompilation flow.

## New MCP tools

```text
build_program_index
find_symbols
find_xrefs
get_cfg
identify_protector
extract_network_model
```

### `build_program_index`

Builds a bounded normalized method/call-edge index for a decompile job. The preferred backend is Androguard DEX XREF analysis. If Androguard cannot analyze a protected or malformed artifact, the server falls back to a lower-confidence source symbol index instead of failing the entire MCP session.

### `find_symbols`

Finds class/method symbols from the program index without asking the agent to scan the whole JADX output.

### `find_xrefs`

Returns incoming/outgoing method references. DEX XREF edges are marked with high confidence and include bytecode offsets when available.

### `get_cfg`

Returns a bounded basic-block control-flow graph for matching DEX methods using Androguard.

### `extract_network_model`

Extends plain URL/endpoint extraction into a structured network model that links Retrofit endpoints to declaring methods, caller XREFs, request/response type hints, auth/signature signals, and evidence locations.

### `identify_protector`

Provides an adapter for APKiD when an `apkid` CLI is present. APKiD is intentionally not bundled in the default 0.2.0 image yet; the adapter uses an external process boundary so licensing/redistribution policy can be finalized independently from the Apache-licensed MCP server.

## Default image additions

The 0.2.0 static image adds:

```text
Androguard 4.1.4
file
binutils (strings/readelf/objdump/nm)
libmagic
```

The runtime image does not retain the compiler or pip build toolchain used to assemble Python analyzer dependencies.

The existing runtime restrictions remain unchanged: network disabled, project read-only, no generic shell MCP tool, non-root execution, dropped capabilities, and bounded CPU/memory/PID resources.

## Recommended analysis workflow

```text
health
  -> fingerprint
  -> identify_protector (when APKiD profile is available)
  -> decompile
  -> build_program_index
  -> find_symbols / find_xrefs / get_cfg
  -> extract_network_model
  -> targeted read_source_file only for evidence verification
```

This moves the AI agent away from reading the entire decompiled tree and toward graph-guided, evidence-backed investigation.

## Known limitations

- Source fallback does not claim full call-graph correctness.
- `extract_network_model` currently performs lexical request/response model inference; full type/data-flow tracing is planned next.
- XAPK is analyzed by extracting contained APK members into ephemeral analysis storage.
- APKiD is an optional external analyzer in this phase.
- Native `.so` xrefs and JNI cross-language flows are not implemented yet.
- The Androguard top-level wheel is digest-verified, but the next supply-chain hardening step should lock and verify its transitive Python dependency set as well.

## Next implementation targets

1. `trace_value` with bounded forward/backward data-flow.
2. `find_auth_flow` and `find_signing_logic` built on data-flow traces.
3. manifest/component/lifecycle graph and Android entrypoint modeling.
4. JNI mapping and native evidence profile.
5. hierarchical feature/module summaries and graph-guided agent retrieval.
