#!/usr/bin/env python3
"""Sandboxed Android reverse-engineering MCP server.

The server deliberately exposes a small allow-listed tool surface and never
executes caller-provided shell commands. It is intended to run inside a locked
container with /workspace mounted read-only and /data mounted read-write.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.parse
import uuid
import zipfile
from pathlib import Path
from typing import Any, Iterable

SERVER_NAME = "safe-android-reverser"
SERVER_VERSION = "0.1.0"
WORKSPACE = Path(os.environ.get("SAFE_REVERSER_WORKSPACE", "/workspace")).resolve()
DATA_ROOT = Path(os.environ.get("SAFE_REVERSER_DATA_ROOT", "/data/jobs")).resolve()
VINEFLOWER_JAR = Path(os.environ.get("VINEFLOWER_JAR", "/opt/vineflower/vineflower.jar"))
MAX_COMMAND_OUTPUT = 120_000
MAX_SOURCE_FILE_BYTES = 4 * 1024 * 1024
MAX_TOOL_TEXT = 200_000
ALLOWED_ARTIFACT_EXTS = {".apk", ".xapk", ".apks", ".apkm", ".jar", ".aar"}
SOURCE_EXTS = {".java", ".kt", ".xml", ".json", ".txt", ".smali", ".properties", ".gradle", ".kts"}
JOB_ID_RE = re.compile(r"^[a-f0-9]{12}$")
DEX_DESCRIPTOR_RE = re.compile(rb"L([A-Za-z0-9_$]+(?:/[A-Za-z0-9_$]+)+);")
URL_RE = re.compile(r"https?://(?:[A-Za-z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?(?:/[^\s\"'<>]*)?", re.I)
RETROFIT_RE = re.compile(r"@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP)\s*\(\s*\"([^\"]+)\"", re.I)
PATH_LITERAL_RE = re.compile(r"[\"']((?:/[A-Za-z0-9_{}.-]+){2,}/?|(?:api|v\d+|graphql|rest|auth|oauth|users?|account|session|token|profile|order|payment|search|upload|download)(?:/[A-Za-z0-9_{}.-]+)+/?)[\"']", re.I)
DEBUG_METADATA_RE = re.compile(r"@DebugMetadata\([^)]*\bc\s*=\s*\"([^\"]+)\"", re.S)
D2_BLOCK_RE = re.compile(r"\bd2\s*=\s*\{(.*?)\}", re.S)
D2_DESCRIPTOR_RE = re.compile(r"L([A-Za-z_][A-Za-z0-9_]*(?:/[A-Za-z_$][A-Za-z0-9_$]*)+);?")

THIRD_PARTY_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "firebaseio.com", "firebaseapp.com", "appspot.com", "facebook.com",
    "fbcdn.net", "stripe.com", "braintreegateway.com", "paypal.com",
    "sentry.io", "datadoghq.com", "appsflyer.com", "amplitude.com",
    "mixpanel.com", "segment.io", "segment.com", "onesignal.com",
    "intercom.io", "intercomcdn.com", "zendesk.com", "hotjar.com",
    "microsoft.com", "azure.com", "amazonaws.com", "cloudfront.net",
    "github.com", "githubusercontent.com", "googlesyndication.com",
    "doubleclick.net", "crashlytics.com",
}


class ToolError(Exception):
    pass


def _json_text(obj: Any) -> str:
    text = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)
    if len(text) > MAX_TOOL_TEXT:
        text = text[:MAX_TOOL_TEXT] + "\n... [truncated]"
    return text


def _safe_relative(base: Path, user_path: str, *, must_exist: bool = True) -> Path:
    if not isinstance(user_path, str) or not user_path.strip():
        raise ToolError("path must be a non-empty string")
    p = Path(user_path)
    if p.is_absolute():
        raise ToolError("absolute paths are not allowed")
    candidate = (base / p).resolve()
    if candidate != base and base not in candidate.parents:
        raise ToolError("path escapes the allowed sandbox root")
    if must_exist and not candidate.exists():
        raise ToolError(f"path does not exist: {user_path}")
    return candidate


def _workspace_artifact(user_path: str) -> Path:
    p = _safe_relative(WORKSPACE, user_path)
    if not p.is_file():
        raise ToolError("artifact path must reference a file")
    if p.suffix.lower() not in ALLOWED_ARTIFACT_EXTS:
        raise ToolError(f"unsupported artifact type: {p.suffix}")
    return p


def _job_dir(job_id: str) -> Path:
    if not JOB_ID_RE.fullmatch(job_id or ""):
        raise ToolError("invalid job_id")
    p = (DATA_ROOT / job_id).resolve()
    if p.parent != DATA_ROOT:
        raise ToolError("invalid job path")
    if not p.exists():
        raise ToolError(f"job not found: {job_id}")
    return p


def _new_job(artifact: Path, operation: str) -> tuple[str, Path]:
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    job_id = uuid.uuid4().hex[:12]
    job = DATA_ROOT / job_id
    job.mkdir(mode=0o700)
    _write_json(job / "job.json", {
        "job_id": job_id,
        "operation": operation,
        "artifact": str(artifact.relative_to(WORKSPACE)),
        "created_at_epoch": int(time.time()),
        "server_version": SERVER_VERSION,
    })
    return job_id, job


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 900) -> dict[str, Any]:
    if not cmd or any(not isinstance(x, str) for x in cmd):
        raise ToolError("invalid subprocess command")
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": "/tmp/home",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TMPDIR": "/tmp",
        "XDG_CACHE_HOME": "/tmp/xdg-cache",
        "XDG_CONFIG_HOME": "/tmp/xdg-config",
        "JAVA_TOOL_OPTIONS": "-Djava.io.tmpdir=/tmp -Duser.home=/tmp/home",
    }
    for d in ("/tmp/home", "/tmp/xdg-cache", "/tmp/xdg-config"):
        Path(d).mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd or Path("/work")),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return {"exit_code": 124, "timed_out": True, "output": out[-MAX_COMMAND_OUTPUT:]}
    return {"exit_code": proc.returncode, "timed_out": False, "output": proc.stdout[-MAX_COMMAND_OUTPUT:]}


def _zip_names(zf: zipfile.ZipFile) -> list[str]:
    return [i.filename for i in zf.infolist() if not i.is_dir()]


def _nested_apks(artifact: Path) -> Iterable[tuple[str, zipfile.ZipFile]]:
    ext = artifact.suffix.lower()
    if ext == ".apk":
        with zipfile.ZipFile(artifact) as zf:
            yield artifact.name, zf
        return
    if ext not in {".xapk", ".apks", ".apkm"}:
        return
    with zipfile.ZipFile(artifact) as outer, tempfile.TemporaryDirectory(prefix="safe-rev-") as tmp:
        tmpdir = Path(tmp)
        count = 0
        for info in outer.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".apk"):
                continue
            count += 1
            if count > 128:
                raise ToolError("bundle contains too many APK entries")
            dest = tmpdir / f"{count:03d}-{Path(info.filename).name}"
            with outer.open(info) as src, dest.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
            with zipfile.ZipFile(dest) as zf:
                yield info.filename, zf


def _dex_symbols(zf: zipfile.ZipFile) -> set[str]:
    symbols: set[str] = set()
    for info in zf.infolist():
        name = info.filename
        if not re.fullmatch(r"classes\d*\.dex", name):
            continue
        if info.file_size > 512 * 1024 * 1024:
            raise ToolError(f"DEX too large to fingerprint safely: {name}")
        data = zf.read(info)
        for match in DEX_DESCRIPTOR_RE.finditer(data):
            if len(symbols) >= 750_000:
                return symbols
            symbols.add(match.group(1).decode("ascii", "ignore"))
    return symbols


def _contains(paths: set[str], symbols: set[str], pattern: str) -> bool:
    rx = re.compile(pattern)
    return any(rx.search(x) for x in paths) or any(rx.search(x) for x in symbols)


def fingerprint(args: dict[str, Any]) -> dict[str, Any]:
    artifact = _workspace_artifact(args.get("artifact", ""))
    if artifact.suffix.lower() in {".jar", ".aar"}:
        raise ToolError("fingerprint currently supports APK/XAPK/APKS/APKM artifacts")
    all_paths: set[str] = set()
    all_symbols: set[str] = set()
    apk_members: list[str] = []
    try:
        for member_name, zf in _nested_apks(artifact):
            apk_members.append(member_name)
            all_paths.update(_zip_names(zf))
            all_symbols.update(_dex_symbols(zf))
    except zipfile.BadZipFile as exc:
        raise ToolError(f"invalid APK/bundle ZIP: {exc}") from exc
    has = lambda p: _contains(all_paths, all_symbols, p)
    evidence: list[str] = []
    if has(r"^lib/[^/]+/libflutter\.so$"):
        framework = "Flutter"; evidence.append("lib/<abi>/libflutter.so")
    elif has(r"^lib/[^/]+/libhermes\.so$") or has(r"^assets/index\.android\.bundle$") or has(r"^lib/[^/]+/libreactnativejni\.so$"):
        framework = "React Native"; evidence.append("Hermes/React Native native or bundle marker")
    elif has(r"^assets/(?:www|public)/"):
        framework = "Cordova/Capacitor"; evidence.append("assets/www or assets/public")
    elif has(r"^lib/[^/]+/(?:libmonodroid|libmaui)\.so$") or has(r"^assemblies/"):
        framework = "Xamarin/.NET MAUI"; evidence.append("Mono/MAUI native or assemblies marker")
    elif has(r"androidx/compose/"):
        framework = "Native Android (Kotlin + Jetpack Compose)"; evidence.append("androidx/compose descriptors")
    elif any(p.startswith("META-INF/") and p.endswith(".kotlin_module") for p in all_paths) or has(r"kotlin/Metadata"):
        framework = "Native Android (Kotlin)"; evidence.append("Kotlin metadata/module marker")
    else:
        framework = "Native Android (Java/Kotlin)"; evidence.append("no cross-platform framework marker")
    http_stacks = [label for label, pat in [("Retrofit", r"retrofit2/"), ("OkHttp", r"okhttp3/"), ("Ktor", r"io/ktor/"), ("Apollo GraphQL", r"com/apollographql/"), ("Volley", r"com/android/volley/")] if has(pat)]
    di = [label for label, pat in [("Hilt", r"dagger/hilt/"), ("Koin", r"org/koin/"), ("javax.inject", r"javax/inject/")] if has(pat)]
    serializers = [label for label, pat in [("kotlinx.serialization", r"kotlinx/serialization/"), ("Gson", r"com/google/gson/"), ("Moshi", r"com/squareup/moshi/"), ("Jackson", r"com/fasterxml/jackson/")] if has(pat)]
    short_namespaces = set()
    for symbol in all_symbols:
        parts = symbol.split("/")
        if len(parts) >= 3 and len(parts[0]) <= 2 and len(parts[1]) <= 2:
            short_namespaces.add("/".join(parts[:2]))
    n_short = len(short_namespaces)
    if n_short > 30: obf_level, obf_conf = "high", 0.90
    elif n_short > 10: obf_level, obf_conf = "moderate", 0.75
    else: obf_level, obf_conf = "low", 0.60
    native_libs = sorted(p for p in all_paths if re.fullmatch(r"lib/[^/]+/[^/]+\.so", p))[:500]
    build_config = any(s == "BuildConfig" or s.endswith("/BuildConfig") for s in all_symbols)
    sdks = [label for label, pat in [("Firebase", r"com/google/firebase/"), ("Sentry", r"io/sentry/"), ("Datadog", r"com/datadog/"), ("AppsFlyer", r"appsflyer"), ("Stripe", r"com/stripe/"), ("Braintree", r"com/braintreepayments/"), ("Intercom", r"com/intercom/"), ("OneSignal", r"com/onesignal/")] if has(pat)]
    recommendation = {"Flutter": "Prefer Flutter-specific analysis of libapp.so and flutter assets; Java decompilation mostly covers the host shell.", "React Native": "Inspect Hermes/JS bundle first; Java decompilation mostly covers the host shell.", "Cordova/Capacitor": "Inspect assets/www or assets/public directly before Java decompilation.", "Xamarin/.NET MAUI": "Inspect managed assemblies with a .NET decompiler rather than relying on JADX."}
    next_step = next((v for k, v in recommendation.items() if framework.startswith(k)), "Proceed with sandboxed JADX decompilation.")
    return {"artifact": str(artifact.relative_to(WORKSPACE)), "apk_members": apk_members, "framework": {"type": framework, "confidence": 0.9 if framework != "Native Android (Java/Kotlin)" else 0.65, "evidence": evidence}, "obfuscation": {"level": obf_level, "confidence": obf_conf, "short_dex_namespaces": n_short}, "http_stacks": http_stacks, "dependency_injection": di, "serialization": serializers, "build_config_detected": build_config, "native_libraries": native_libs, "third_party_sdks": sdks, "recommended_next_step": next_step}


def _safe_extract(zip_path: Path, dest: Path, *, members: list[str] | None = None) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        wanted = set(members) if members else None
        for info in zf.infolist():
            if info.is_dir() or (wanted is not None and info.filename not in wanted):
                continue
            target = (dest / info.filename).resolve()
            if target != dest and dest not in target.parents:
                raise ToolError(f"unsafe ZIP member: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)


def _run_jadx(artifact: Path, out_dir: Path, *, deobf: bool, no_res: bool, timeout: int) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["jadx", "-d", str(out_dir)]
    if deobf: cmd.append("--deobf")
    if no_res: cmd.append("--no-res")
    cmd.append(str(artifact))
    return _run(cmd, timeout=timeout)


def _run_vineflower(artifact: Path, out_dir: Path, *, timeout: int) -> list[dict[str, Any]]:
    if not VINEFLOWER_JAR.exists(): raise ToolError("Vineflower is not installed in the sandbox image")
    out_dir.mkdir(parents=True, exist_ok=True)
    ext = artifact.suffix.lower(); results = []
    if ext == ".jar":
        results.append(_run(["java", "-jar", str(VINEFLOWER_JAR), str(artifact), str(out_dir)], timeout=timeout)); return results
    if ext == ".aar":
        with tempfile.TemporaryDirectory(prefix="aar-", dir="/tmp") as tmp:
            tmpdir = Path(tmp)
            with zipfile.ZipFile(artifact) as zf:
                jar_members = [i.filename for i in zf.infolist() if not i.is_dir() and (i.filename == "classes.jar" or (i.filename.startswith("libs/") and i.filename.endswith(".jar")))]
            if not jar_members: raise ToolError("AAR contains no classes.jar or libs/*.jar")
            _safe_extract(artifact, tmpdir, members=jar_members)
            for member in jar_members:
                src = tmpdir / member; sub = out_dir / Path(member).stem; sub.mkdir(parents=True, exist_ok=True)
                result = _run(["java", "-jar", str(VINEFLOWER_JAR), str(src), str(sub)], timeout=timeout); result["input"] = member; results.append(result)
        return results
    raise ToolError("Vineflower mode is intentionally limited to JAR/AAR. Use JADX for APK/XAPK/APKS/APKM in the safe image.")


def decompile(args: dict[str, Any]) -> dict[str, Any]:
    artifact = _workspace_artifact(args.get("artifact", "")); engine = str(args.get("engine", "jadx")).lower()
    if engine not in {"jadx", "vineflower", "both"}: raise ToolError("engine must be one of: jadx, vineflower, both")
    deobf = bool(args.get("deobf", True)); no_res = bool(args.get("no_res", False)); timeout = max(30, min(int(args.get("timeout_seconds", 900)), 3600))
    job_id, job = _new_job(artifact, "decompile"); result: dict[str, Any] = {"job_id": job_id, "artifact": str(artifact.relative_to(WORKSPACE)), "engine": engine, "outputs": {}, "runs": []}
    if engine in {"jadx", "both"}:
        out = job / "jadx"; run = _run_jadx(artifact, out, deobf=deobf, no_res=no_res, timeout=timeout); run["engine"] = "jadx"; result["runs"].append(run)
        if out.exists(): result["outputs"]["jadx"] = str(out.relative_to(job))
        if run["exit_code"] != 0 and not any(out.rglob("*.java")) and not any(out.rglob("*.kt")): result["jadx_failed_without_output"] = True
    if engine in {"vineflower", "both"}:
        out = job / "vineflower"
        try:
            runs = _run_vineflower(artifact, out, timeout=timeout)
            for run in runs: run["engine"] = "vineflower"
            result["runs"].extend(runs); result["outputs"]["vineflower"] = str(out.relative_to(job))
        except ToolError as exc:
            if engine == "both" and artifact.suffix.lower() in {".apk", ".xapk", ".apks", ".apkm"}: result["vineflower_skipped"] = str(exc)
            else: raise
    _write_json(job / "result.json", result); return result


def _source_roots(job: Path) -> list[Path]:
    return [p for p in [job / "jadx" / "sources", job / "jadx", job / "vineflower"] if p.exists() and p.is_dir()]


def _iter_source_files(job: Path) -> Iterable[Path]:
    seen = set(); count = 0
    for root in _source_roots(job):
        for p in root.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in {".java", ".kt"}: continue
            rp = p.resolve()
            if rp in seen: continue
            seen.add(rp); count += 1
            if count > 150_000: raise ToolError("source tree exceeds safe file-count limit")
            yield p


def _read_source_text(path: Path) -> str:
    if path.stat().st_size > MAX_SOURCE_FILE_BYTES: return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _is_third_party(host: str) -> bool:
    host = host.lower().rstrip("."); return any(host == domain or host.endswith("." + domain) for domain in THIRD_PARTY_DOMAINS)


def extract_api(args: dict[str, Any]) -> dict[str, Any]:
    job = _job_dir(str(args.get("job_id", ""))); max_items = max(20, min(int(args.get("max_items", 500)), 2000)); urls = {}; endpoints = {}; paths = {}; signals = {"ktor": 0, "apollo": 0, "okhttp": 0, "volley": 0, "bearer": 0, "hmac": 0, "api_key_identifiers": 0}; scanned = 0
    for file in _iter_source_files(job):
        text = _read_source_text(file)
        if not text: continue
        scanned += 1; rel = str(file.relative_to(job))
        for m in URL_RE.finditer(text):
            url = m.group(0).rstrip(".,);]")
            try: parsed = urllib.parse.urlparse(url); host = (parsed.hostname or "").lower()
            except ValueError: continue
            if host and url not in urls and len(urls) < max_items: urls[url] = {"url": url, "host": host, "classification": "third-party" if _is_third_party(host) else "first-party-candidate", "source": rel}
        for m in RETROFIT_RE.finditer(text):
            key = (m.group(1).upper(), m.group(2))
            if key not in endpoints and len(endpoints) < max_items: endpoints[key] = {"method": key[0], "path": key[1], "source": rel, "kind": "retrofit"}
        for m in PATH_LITERAL_RE.finditer(text):
            path = m.group(1)
            if path not in paths and len(paths) < max_items: paths[path] = {"path": path, "source": rel}
        low = text.lower(); signals["ktor"] += len(re.findall(r"\b(?:client|httpclient)\.(?:get|post|put|delete|patch|request)\s*[<(]", low)); signals["apollo"] += text.count("ApolloClient") + text.count(".serverUrl("); signals["okhttp"] += text.count("Request.Builder") + text.count(".newCall("); signals["volley"] += text.count("StringRequest") + text.count("JsonObjectRequest"); signals["bearer"] += len(re.findall(r"\bbearer\b", low)); signals["hmac"] += len(re.findall(r"hmacsha|mac\.getinstance\(\s*\"hmac", low)); signals["api_key_identifiers"] += len(re.findall(r"\b(?:api[_-]?key|client[_-]?secret|access[_-]?token)\b", low))
    report = {"job_id": job.name, "source_files_scanned": scanned, "urls": list(urls.values()), "retrofit_endpoints": list(endpoints.values()), "endpoint_path_literals": list(paths.values()), "signals": signals, "notes": ["URL host classification treats both apex and subdomains of known third-party domains as third-party.", "Auth scanning reports identifiers/counts only; it does not intentionally return secret values."]}
    _write_json(job / "api-report.json", report); return report


def search_source(args: dict[str, Any]) -> dict[str, Any]:
    job = _job_dir(str(args.get("job_id", ""))); query = str(args.get("query", ""))
    if not query or len(query) > 512: raise ToolError("query must be 1..512 characters")
    use_regex = bool(args.get("regex", False)); case_sensitive = bool(args.get("case_sensitive", False)); limit = max(1, min(int(args.get("limit", 100)), 500)); flags = 0 if case_sensitive else re.I
    try: rx = re.compile(query if use_regex else re.escape(query), flags)
    except re.error as exc: raise ToolError(f"invalid regex: {exc}") from exc
    matches = []
    for file in _iter_source_files(job):
        text = _read_source_text(file)
        if not text: continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                matches.append({"file": str(file.relative_to(job)), "line": lineno, "snippet": line.strip()[:500]})
                if len(matches) >= limit: return {"job_id": job.name, "query": query, "matches": matches, "truncated": True}
    return {"job_id": job.name, "query": query, "matches": matches, "truncated": False}


def read_source_file(args: dict[str, Any]) -> dict[str, Any]:
    job = _job_dir(str(args.get("job_id", ""))); rel = str(args.get("path", "")); p = _safe_relative(job, rel)
    if not p.is_file() or p.suffix.lower() not in SOURCE_EXTS: raise ToolError("path must be a readable source/report text file inside the job")
    if p.stat().st_size > 8 * 1024 * 1024: raise ToolError("file exceeds 8 MiB read limit")
    start = max(1, int(args.get("start_line", 1))); end = max(start, min(int(args.get("end_line", start + 300)), start + 1000)); lines = p.read_text(encoding="utf-8", errors="replace").splitlines(); selected = lines[start - 1:end]
    return {"job_id": job.name, "path": rel, "start_line": start, "end_line": min(end, len(lines)), "content": "\n".join(selected)}


def recover_kotlin_names(args: dict[str, Any]) -> dict[str, Any]:
    job = _job_dir(str(args.get("job_id", ""))); candidates = []
    for file in _iter_source_files(job):
        text = _read_source_text(file)
        if not text: continue
        rel = str(file.relative_to(job))
        for m in DEBUG_METADATA_RE.finditer(text): candidates.append({"source": rel, "candidate_fqn": m.group(1), "evidence": "DebugMetadata.c", "confidence": 0.85})
        for block in D2_BLOCK_RE.finditer(text):
            found = []
            for m in D2_DESCRIPTOR_RE.finditer(block.group(1)):
                fqn = m.group(1).replace("/", ".")
                if fqn.startswith(("java.", "kotlin.", "android.", "androidx.")): continue
                if fqn not in found: found.append(fqn)
                if len(found) >= 5: break
            for fqn in found: candidates.append({"source": rel, "candidate_fqn": fqn, "evidence": "Metadata.d2 descriptor", "confidence": 0.55})
        if len(candidates) >= 5000: break
    result = {"job_id": job.name, "candidates": candidates, "warning": "Kotlin metadata is opportunistic evidence, not guaranteed to survive R8/shrinking and not authoritative when present."}; _write_json(job / "kotlin-name-candidates.json", result); return result


def list_jobs(args: dict[str, Any]) -> dict[str, Any]:
    DATA_ROOT.mkdir(parents=True, exist_ok=True); jobs = []
    for p in sorted(DATA_ROOT.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if not p.is_dir() or not JOB_ID_RE.fullmatch(p.name): continue
        meta = p / "job.json"
        try: data = json.loads(meta.read_text(encoding="utf-8")) if meta.exists() else {"job_id": p.name}
        except Exception: data = {"job_id": p.name}
        jobs.append(data)
        if len(jobs) >= 100: break
    return {"jobs": jobs}


def health(args: dict[str, Any]) -> dict[str, Any]:
    return {"server": SERVER_NAME, "version": SERVER_VERSION, "workspace": str(WORKSPACE), "data_root": str(DATA_ROOT), "tools": {"jadx": shutil.which("jadx") is not None, "java": shutil.which("java") is not None, "vineflower": VINEFLOWER_JAR.exists()}, "network_expected": "disabled by container wrapper", "execution_model": "allow-listed subprocess argv only; shell=False"}


TOOL_HANDLERS = {"health": health, "fingerprint": fingerprint, "decompile": decompile, "extract_api": extract_api, "search_source": search_source, "read_source_file": read_source_file, "recover_kotlin_names": recover_kotlin_names, "list_jobs": list_jobs}
TOOLS = [
    {"name": "health", "description": "Check sandbox and reverse-tool availability.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "fingerprint", "description": "Fingerprint an APK/XAPK/APKS/APKM without decompiling. Detect framework, HTTP stack, obfuscation, native libs and SDK signals.", "inputSchema": {"type": "object", "properties": {"artifact": {"type": "string", "description": "Artifact path relative to the Claude project root."}}, "required": ["artifact"], "additionalProperties": False}},
    {"name": "decompile", "description": "Decompile a project artifact inside the isolated sandbox and persist output under plugin data, returning a job_id.", "inputSchema": {"type": "object", "properties": {"artifact": {"type": "string"}, "engine": {"type": "string", "enum": ["jadx", "vineflower", "both"], "default": "jadx"}, "deobf": {"type": "boolean", "default": True}, "no_res": {"type": "boolean", "default": False}, "timeout_seconds": {"type": "integer", "minimum": 30, "maximum": 3600, "default": 900}}, "required": ["artifact"], "additionalProperties": False}},
    {"name": "extract_api", "description": "Extract URLs, Retrofit endpoints, endpoint-shaped strings and network/auth signals from a decompile job.", "inputSchema": {"type": "object", "properties": {"job_id": {"type": "string"}, "max_items": {"type": "integer", "minimum": 20, "maximum": 2000, "default": 500}}, "required": ["job_id"], "additionalProperties": False}},
    {"name": "search_source", "description": "Search decompiled Java/Kotlin within a job. Plain-text search by default; optional regex is bounded and never passed to a shell.", "inputSchema": {"type": "object", "properties": {"job_id": {"type": "string"}, "query": {"type": "string"}, "regex": {"type": "boolean", "default": False}, "case_sensitive": {"type": "boolean", "default": False}, "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100}}, "required": ["job_id", "query"], "additionalProperties": False}},
    {"name": "read_source_file", "description": "Read a bounded line range from a text/source file within a decompile job.", "inputSchema": {"type": "object", "properties": {"job_id": {"type": "string"}, "path": {"type": "string"}, "start_line": {"type": "integer", "minimum": 1, "default": 1}, "end_line": {"type": "integer", "minimum": 1, "default": 300}}, "required": ["job_id", "path"], "additionalProperties": False}},
    {"name": "recover_kotlin_names", "description": "Extract conservative Kotlin original-name candidates from surviving DebugMetadata/Metadata evidence, with confidence values.", "inputSchema": {"type": "object", "properties": {"job_id": {"type": "string"}}, "required": ["job_id"], "additionalProperties": False}},
    {"name": "list_jobs", "description": "List recent sandbox reverse-analysis jobs.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
]


def _send(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"); sys.stdout.flush()


def _tool_result(data: Any, *, is_error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": _json_text(data)}], "isError": is_error}


def _handle(req: dict[str, Any]) -> dict[str, Any] | None:
    method = req.get("method"); request_id = req.get("id"); params = req.get("params") or {}
    if method == "initialize":
        protocol = params.get("protocolVersion") or "2025-06-18"; result = {"protocolVersion": protocol, "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}, "instructions": "Use only these MCP tools for Android reverse-engineering operations. Artifacts are read from the project mount; analysis outputs stay in plugin data."}
    elif method in {"notifications/initialized", "notifications/cancelled"}: return None
    elif method == "ping": result = {}
    elif method == "tools/list": result = {"tools": TOOLS}
    elif method == "tools/call":
        name = params.get("name"); args = params.get("arguments") or {}
        if name not in TOOL_HANDLERS: result = _tool_result({"error": f"unknown tool: {name}"}, is_error=True)
        else:
            try: result = _tool_result(TOOL_HANDLERS[name](args))
            except ToolError as exc: result = _tool_result({"error": str(exc)}, is_error=True)
            except Exception as exc: traceback.print_exc(file=sys.stderr); result = _tool_result({"error": f"internal error: {type(exc).__name__}: {exc}"}, is_error=True)
    else:
        if request_id is None: return None
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}
    if request_id is None: return None
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def main() -> int:
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw: continue
        try:
            req = json.loads(raw)
            if not isinstance(req, dict): raise ValueError("request must be a JSON object")
            response = _handle(req)
            if response is not None: _send(response)
        except Exception as exc:
            _send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse/dispatch error: {exc}"}})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
