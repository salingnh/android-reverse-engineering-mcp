# Reverse Engineering Roadmap

## Vision

The long-term goal of Safe Android Reverser is to become a **general-purpose, MCP-first reverse-engineering platform** for Android and Android-adjacent application formats, with strong automation, structured evidence, and strict execution boundaries.

The project should evolve beyond a container that merely bundles JADX. The target is an orchestration layer where an AI agent can ask high-level reverse-engineering questions and the MCP server selects the right analyzer, executes it in an appropriate sandbox profile, normalizes the evidence, and returns only the information needed for reasoning.

The guiding principle is:

> **The agent reasons. The MCP server controls. The sandbox executes.**

The practical objective is to integrate enough specialized tooling to handle real-world applications effectively, including heavily obfuscated Java/Kotlin apps, split APK/XAPK packages, native libraries, Flutter, React Native/Hermes, Unity IL2CPP, custom protocols, signing/authentication logic, and eventually controlled dynamic analysis.

---

## Current baseline

The current static sandbox provides a deliberately small toolchain:

- Java 21 runtime;
- JADX 1.5.6;
- Vineflower 1.12.0;
- Python 3 MCP server;
- bounded MCP operations for fingerprinting, decompilation, API extraction, source search, source reads, Kotlin-name recovery, health, and job listing.

Current strengths:

- native Android Java/Kotlin decompilation;
- basic APK/XAPK/APKS/APKM/JAR/AAR handling;
- framework and HTTP-stack fingerprinting;
- API host/endpoint discovery;
- basic obfuscation estimation;
- bounded evidence retrieval without arbitrary shell access.

Current gaps:

- Android resources and Smali-level analysis;
- DEX call/xref analysis;
- packer/protector identification;
- native `.so` reverse engineering;
- deep crypto/signature-flow tracing;
- framework-specific analysis for Flutter/Hermes/Unity;
- security-rule scanning;
- protobuf/gRPC/GraphQL/WebSocket-specific extraction;
- dynamic instrumentation.

---

## Architecture direction

Do not put every reverse-engineering tool into one privileged image. Split the platform by execution profile and privilege model.

```text
safe-android-reverser
├── static-core
│   ├── APK / XAPK / DEX
│   ├── manifest / resources
│   ├── Java / Kotlin / Smali
│   ├── packer / obfuscation detection
│   ├── API / crypto / security analysis
│   └── basic ELF triage
│
├── native
│   ├── ELF / .so
│   ├── ARM / ARM64 / x86
│   ├── symbols / imports / exports
│   ├── xrefs / CFG
│   └── disassembly / decompilation
│
├── framework
│   ├── Flutter
│   ├── React Native / Hermes
│   ├── Unity / IL2CPP
│   └── protobuf / specialized app formats
│
└── dynamic
    ├── ADB / emulator / device
    ├── Frida
    ├── Objection
    ├── proxy / TLS inspection
    └── controlled network/device access
```

The static profile should remain rootless, network-isolated, read-only where possible, and should never silently escalate into the dynamic privilege model.

---

# 1. Static core roadmap

## 1.1 APK/resource/manifest tooling — P0

Add:

- **Apktool**
- **aapt2**
- **apksigner / apksig**
- **smali / baksmali**
- **Androguard**
- **APKiD**
- **file**
- **binutils**: `strings`, `readelf`, `objdump`, `nm`

### Why

JADX is excellent for Java/Kotlin recovery but is not a complete APK-analysis stack. A real reverse-engineering workflow also needs binary Android XML/resources, DEX bytecode, package metadata, signing certificates, packer/protector detection, and binary/native triage.

### Planned MCP operations

```text
inspect_manifest
inspect_resources
inspect_signature
list_components
list_permissions
find_exported_components
inspect_deep_links
inspect_network_security_config
identify_protector
list_dex
inspect_dex
search_smali
read_smali
inspect_elf
list_native_libraries
```

### Expected evidence

Manifest analysis should return structured data rather than raw XML only:

```json
{
  "package": "com.example.app",
  "min_sdk": 26,
  "target_sdk": 35,
  "debuggable": false,
  "uses_cleartext_traffic": false,
  "permissions": [],
  "exported_components": [],
  "deep_links": [],
  "network_security_config": null
}
```

---

## 1.2 DEX and Smali semantic analysis — P0/P1

Java source produced by a decompiler is an approximation. Difficult reverse-engineering tasks require working directly from DEX semantics.

Add programmatic DEX analysis based primarily on Androguard plus smali/baksmali.

### Planned MCP operations

```text
find_class
find_method
find_callers
find_callees
find_xrefs
trace_constant
trace_string_usage
trace_field_usage
find_native_methods
map_java_to_smali
```

### High-value use cases

- determine where an API key is consumed;
- trace where a token is generated;
- find all callers of a signing routine;
- recover control flow hidden by poor Java decompilation;
- identify reflection-heavy or obfuscated dispatch logic;
- identify JNI bridges.

The goal is to move from text search to semantic reverse engineering:

```text
method
  ↓
callers / callees
  ↓
constants / fields
  ↓
data dependencies
  ↓
network / crypto / JNI sink
```

---

## 1.3 Packer, protector, and obfuscation detection — P0

Add **APKiD** early in the fingerprint pipeline.

Target recognizers include classes of:

- R8 / ProGuard;
- DexGuard;
- Allatori;
- DashO;
- DexProtector;
- Jiagu / Bangcle / SecNeo / Legu-style protectors;
- custom loaders and suspicious secondary DEX/native payload patterns.

### Planned MCP operation

```text
identify_protector
```

Example output:

```json
{
  "protector": "suspected DexGuard",
  "confidence": 0.91,
  "evidence": [
    "..."
  ],
  "recommended_route": "dex-and-native-analysis"
}
```

The fingerprint result should route the analysis strategy instead of blindly sending every artifact to JADX.

---

# 2. Native reverse-engineering roadmap

Native analysis is one of the biggest capability gaps because production Android applications frequently move sensitive logic into `.so` libraries.

Common targets:

- request signing;
- custom encryption;
- anti-debugging;
- root/emulator detection;
- certificate pinning;
- proprietary protocols;
- JNI bridges;
- Flutter native snapshots;
- game/Unity code.

## 2.1 Basic ELF triage — P0

Add standard binary utilities:

```text
file
strings
readelf
objdump
nm
```

MCP operations:

```text
inspect_elf
list_sections
list_imports
list_exports
list_symbols
search_native_strings
find_jni_exports
```

This belongs in `static-core` because the tools are small and useful for triage.

---

## 2.2 Rizin-based analysis — P1

Add **Rizin** as the first deeper native-analysis backend.

Reasons:

- headless/CLI-oriented;
- scriptable;
- structured output is easier to normalize;
- appropriate for MCP execution;
- significantly lighter than a full Ghidra installation.

### Planned MCP operations

```text
disassemble_function
find_native_xrefs
analyze_native_function
inspect_jni
find_native_callers
find_native_callees
```

The agent should not be exposed to generic Rizin shell commands. MCP should wrap specific read-only analysis capabilities.

---

## 2.3 Ghidra headless — P2

Add a separate native image/profile containing **Ghidra headless** for complex binaries.

Use it for:

- ARM64 decompilation;
- function recovery;
- control-flow reconstruction;
- complex JNI bridges;
- difficult signing/crypto algorithms;
- native code where basic disassembly is insufficient.

Recommended image boundary:

```text
ghcr.io/.../safe-android-reverser-native:<version>
```

Do not unnecessarily increase the size and attack surface of the default static-core image.

---

# 3. Security and vulnerability analysis

Reverse engineering often needs to answer both “how does this work?” and “where are the security-sensitive paths?”.

## 3.1 Semgrep — P1

Use Semgrep on decompiled Java/Kotlin/XML for high-signal rules such as:

- unsafe WebView configuration;
- weak TLS handling;
- permissive TrustManager / HostnameVerifier;
- hard-coded keys and secrets;
- insecure storage;
- weak crypto;
- dangerous intent/component exposure;
- debug/backdoor code;
- suspicious command execution.

## 3.2 mobsfscan — P1

Add mobile-focused static rules without importing the full MobSF platform into the core image.

### Planned MCP operation

```text
scan_security
```

Normalized result:

```json
{
  "rule": "android-insecure-trust-manager",
  "severity": "high",
  "file": "...",
  "line": 123,
  "evidence": "..."
}
```

Important: security-rule matches are evidence for review, not automatically verified vulnerabilities.

---

# 4. Crypto and request-signature tracing

This should become a first-class platform capability instead of relying on keyword search.

Target APIs and primitives include:

```text
Cipher.getInstance
MessageDigest
Mac.getInstance
SecretKeySpec
KeyStore
KeyGenerator
PBKDF2
AES
RSA
ECDSA
HMAC
SHA
Base64
```

## Planned MCP operations

```text
find_crypto_usage
find_key_material
find_signing_logic
trace_crypto
trace_value
trace_header_generation
```

Target workflow:

```text
request field
   ↓
serialization
   ↓
nonce / timestamp
   ↓
hash / HMAC / encryption
   ↓
Base64 / hex
   ↓
HTTP header or query parameter
```

This is particularly valuable for reversing custom headers such as:

```text
X-Signature
X-Auth
X-Token
Authorization
```

---

# 5. Network/protocol analysis

Expand beyond basic URL extraction.

## Target stacks

```text
Retrofit
OkHttp
Ktor
Volley
Apollo GraphQL
gRPC / protobuf
WebSocket
Socket.IO
SSE
MQTT
custom TLS / certificate pinning
custom DNS / DoH
```

Add protobuf tooling and parsers where useful.

## Planned MCP operations

```text
extract_network_model
extract_protobuf
extract_graphql
inspect_tls_pinning
find_auth_flow
find_network_entrypoints
```

The desired final result is a normalized network model:

```json
{
  "hosts": [],
  "base_urls": [],
  "endpoints": [],
  "auth_flows": [],
  "tls_pinning": [],
  "protocols": []
}
```

---

# 6. Framework-specific analyzers

A core design requirement is **route by framework**. Do not use JADX as if it were a universal analyzer.

## 6.1 Flutter — P2

Fingerprint Flutter using indicators such as:

```text
libapp.so
libflutter.so
assets/flutter_assets
```

Planned analysis:

- Flutter asset inventory;
- Dart snapshot metadata where recoverable;
- string/endpoints extraction;
- native `libapp.so` analysis;
- package/config clues;
- mapping important Java host bridges separately from Dart logic.

MCP operations:

```text
inspect_flutter
extract_flutter_assets
search_flutter_strings
analyze_flutter_native
```

---

## 6.2 React Native / Hermes — P2

Detect:

```text
assets/index.android.bundle
Hermes bytecode
source maps
React Native bridge metadata
```

MCP operations:

```text
inspect_react_native
decompile_hermes
search_js_bundle
extract_js_endpoints
```

Pipeline:

```text
bundle
  ↓
Hermes?
├─ yes → Hermes bytecode analysis
└─ no  → JavaScript bundle analysis
```

---

## 6.3 Unity / IL2CPP — P2/P3

Detect and analyze:

```text
libil2cpp.so
global-metadata.dat
assets/bin/Data
```

Potential tool integrations:

- Il2CppDumper;
- Il2CppInspector or equivalent maintained tooling after license/security review.

MCP operations:

```text
inspect_unity
recover_il2cpp_metadata
map_il2cpp_methods
search_unity_symbols
```

---

# 7. Dynamic analysis — separate trust boundary

Dynamic analysis must **not** be bolted onto the static container.

Candidate tooling:

```text
ADB
Frida
Objection
mitmproxy
Android emulator integration
```

This profile requires capabilities that the static sandbox intentionally denies:

- device/emulator access;
- scoped network access;
- instrumentation;
- process attachment;
- proxy/TLS observation.

Recommended separation:

```text
safe-android-reverser-static
safe-android-reverser-native
safe-android-reverser-dynamic
```

The dynamic MCP should use an explicit opt-in configuration and a separate privilege policy.

Potential MCP operations:

```text
list_devices
inspect_process
attach_frida
trace_method
trace_native_function
capture_http
inspect_runtime_tls
inspect_runtime_crypto
```

These operations should only be implemented for authorized analysis environments.

---

# 8. High-level MCP API strategy

The project should prioritize **semantic reverse-engineering operations**, not expose generic command execution.

Bad abstraction:

```text
run_shell("grep ...")
run_rizin("...")
run_ghidra_script("...")
```

Preferred abstraction:

```text
find_xrefs
trace_value
find_auth_flow
find_signing_logic
inspect_jni
find_network_entrypoints
identify_protector
inspect_manifest
inspect_signature
analyze_native_function
```

Why:

1. tools can be replaced without changing the client contract;
2. path and argument validation stays centralized;
3. output can be normalized and bounded;
4. the agent receives higher-signal evidence;
5. arbitrary shell execution remains outside the MCP surface.

---

# 9. Evidence model

Every analyzer should move toward a shared evidence schema.

Suggested concepts:

```text
Artifact
Component
Class
Method
NativeFunction
String
Endpoint
Host
CredentialSignal
CryptoOperation
CallEdge
DataFlowEdge
Finding
EvidenceLocation
```

Common fields:

```json
{
  "kind": "endpoint",
  "value": "/v2/auth/token",
  "confidence": 0.96,
  "source": {
    "artifact": "artifacts/app.xapk",
    "member": "base.apk",
    "file": "sources/com/example/AuthApi.java",
    "line": 42,
    "method": "refreshToken"
  },
  "analyzer": "jadx+network-model",
  "evidence": []
}
```

This normalized model will later support correlation across JADX, DEX, Smali, native, framework, and dynamic results.

---

# 10. Proposed implementation phases

## Phase 1 — Strong Android static core

**Goal:** make APK/XAPK reverse engineering materially stronger without increasing privileges.

Add:

```text
Apktool
aapt2
apksigner / apksig
smali / baksmali
Androguard
APKiD
file / strings / readelf / objdump / nm
```

Implement MCP:

```text
inspect_manifest
inspect_signature
identify_protector
inspect_dex
find_xrefs
search_smali
inspect_elf
```

Acceptance criteria:

- XAPK/split APK inventory is accurate;
- manifest/resources are parsed structurally;
- signing certificate information is available;
- packer/protector signals affect analyzer routing;
- DEX xrefs work without relying on Java decompilation;
- native libraries are inventoried and triaged.

---

## Phase 2 — Semantic/security/native depth

Add:

```text
Semgrep
mobsfscan
Rizin
```

Implement:

```text
scan_security
find_callers
find_callees
trace_constant
find_crypto_usage
find_signing_logic
find_auth_flow
find_native_xrefs
disassemble_function
inspect_jni
```

Acceptance criteria:

- token/signature-generation paths can be traced across methods;
- Java↔JNI boundaries can be identified;
- native functions can be inspected without generic shell access;
- security findings include file/method/evidence locations.

---

## Phase 3 — Advanced frameworks and deep native analysis

Add specialized profiles/tooling for:

```text
Ghidra headless
Flutter
Hermes
Unity IL2CPP
protobuf / gRPC
GraphQL
```

Implement routing from fingerprint results.

Acceptance criteria:

- Flutter is not falsely treated as a Java-only app;
- Hermes bytecode can be distinguished from plain JS;
- Unity IL2CPP metadata is recognized and mapped;
- difficult native binaries can escalate from Rizin to Ghidra headless;
- protobuf/gRPC service definitions and message clues are recoverable when present.

---

## Phase 4 — Controlled dynamic MCP

Build a separate dynamic profile using:

```text
ADB
Frida
Objection
mitmproxy
emulator/device integration
```

Acceptance criteria:

- explicit opt-in only;
- separate image and MCP server;
- clear device/network permission model;
- static profile remains unchanged and unprivileged;
- runtime evidence uses the same normalized evidence model as static analysis.

---

# 11. Tool integration policy

Before adding any tool:

1. pin the version;
2. verify download hashes or trusted package provenance;
3. review license compatibility and redistribution constraints;
4. prefer headless/non-GUI interfaces;
5. disable network access at runtime unless the profile explicitly needs it;
6. expose only allow-listed MCP operations;
7. add deterministic tests;
8. document expected resource usage;
9. record analyzer name/version in every result;
10. avoid silently falling back to host-installed tools.

Large analyzers such as Ghidra should live in separate images to avoid forcing every user to download them.

---

# 12. Testing strategy

Every new analyzer should have three test layers.

## Unit tests

Validate parsing, normalization, path security, and routing.

## Tool integration tests

Run the actual pinned analyzer against small known fixtures.

## End-to-end MCP tests

Exercise:

```text
initialize
→ health
→ fingerprint
→ analyzer operation
→ structured evidence
```

CI should catch container startup, permissions, tool availability, protocol errors, and schema regressions.

---

# 13. Success metrics

The platform should be evaluated by reverse-engineering effectiveness rather than number of installed tools.

Useful metrics:

- percentage of common APK/XAPK formats successfully fingerprinted;
- percentage of artifacts routed to the correct framework analyzer;
- API host/endpoint recall and precision;
- ability to recover auth/token/signature flows;
- DEX/native xref coverage;
- analysis time and peak memory per profile;
- proportion of findings with direct source/binary evidence;
- number of tasks solvable without generic shell access;
- regression rate across protected/obfuscated sample apps.

---

# 14. Prioritized backlog

## P0

- [ ] Apktool
- [ ] aapt2
- [ ] apksigner/apksig
- [ ] smali/baksmali
- [ ] Androguard
- [ ] APKiD
- [ ] binutils/file/strings
- [ ] `inspect_manifest`
- [ ] `inspect_signature`
- [ ] `identify_protector`
- [ ] `inspect_dex`
- [ ] `find_xrefs`
- [ ] `inspect_elf`

## P1

- [ ] Semgrep
- [ ] mobsfscan
- [ ] Rizin
- [ ] `scan_security`
- [ ] `find_callers` / `find_callees`
- [ ] `find_crypto_usage`
- [ ] `find_signing_logic`
- [ ] `find_auth_flow`
- [ ] `inspect_jni`
- [ ] native xrefs/disassembly

## P2

- [ ] Ghidra headless profile
- [ ] Flutter analyzer
- [ ] React Native/Hermes analyzer
- [ ] protobuf/gRPC analysis
- [ ] GraphQL/WebSocket-specific network modeling
- [ ] normalized cross-analyzer evidence graph

## P3

- [ ] Unity/IL2CPP analyzer
- [ ] dynamic MCP profile
- [ ] ADB/emulator integration
- [ ] Frida/Objection instrumentation
- [ ] controlled proxy/TLS capture
- [ ] static↔dynamic evidence correlation

---

## End state

The intended end state is not an AI agent that manually runs dozens of reverse-engineering commands. It is an MCP platform capable of answering high-level questions such as:

```text
Where is this request signature generated?
Which code path creates the access token?
Which native function is called from this Java method?
Which first-party APIs does this XAPK use?
Is certificate pinning implemented and where?
What protector is present and what analysis route should be used?
Which exported component exposes this deep link?
Where does this Flutter application construct its API request?
```

The MCP layer should choose and combine the right analyzers, preserve the security boundary, and return evidence with enough provenance for a reverse engineer to verify the conclusion.