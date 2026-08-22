from __future__ import annotations

from pathlib import Path
from typing import Any

from .contracts import CapabilityManifest
from .jobs import AnalysisJobStore, JobStoreError
from .paths import PathPolicyError, remove_direct_child, secure_child
from .runtime import ContainerRuntime, RuntimeErrorSafe, VerifiedImage

MAX_QUERY_TEXT = 512
MAX_SYMBOL_TEXT = 1024
MAX_QUERY_LIMIT = 200
RUNTIME_CACHE_SCHEMA = 2
COMMIT_CHARS = set("0123456789abcdef")
SNAPSHOT_CHARS = COMMIT_CHARS


class FlutterCapabilityError(RuntimeError):
    pass


def _bounded_text(value: Any, field: str, limit: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit or "\x00" in text:
        raise FlutterCapabilityError(f"{field} must be 1..{limit} characters")
    return text


def _bounded_limit(value: Any, default: int) -> int:
    try:
        parsed = int(default if value is None else value)
    except (TypeError, ValueError) as exc:
        raise FlutterCapabilityError("limit must be an integer") from exc
    return max(1, min(parsed, MAX_QUERY_LIMIT))


def _is_hex(value: str, minimum: int, maximum: int) -> bool:
    return minimum <= len(value) <= maximum and all(
        ch in SNAPSHOT_CHARS for ch in value
    )


def _immutable_ref(verified: Any, fallback: str) -> str:
    """Use immutable runtime identity when supplied by the shared Runtime Driver.

    The fallback keeps lightweight unit-test fakes compatible; production
    ContainerRuntime.ensure_image() always returns VerifiedImage.
    """
    value = getattr(verified, "immutable_ref", None)
    return str(value or fallback)


class FlutterCapability:
    def __init__(
        self,
        runtime: ContainerRuntime,
        manifest: CapabilityManifest,
        *,
        version: str,
        project_dir: Path,
        data_dir: Path,
        output_tmpfs: str = "4g",
    ) -> None:
        self.runtime = runtime
        self.manifest = manifest
        self.version = version
        self.project_dir = project_dir.resolve()
        self.data_dir = data_dir.resolve()
        self.base_image = f"{manifest.image_repository}:{version}"
        self.output_tmpfs = output_tmpfs
        self.runtime.validate_tmpfs_spec(
            f"/output:rw,nosuid,nodev,size={self.output_tmpfs}"
        )
        self.jobs = AnalysisJobStore(self.data_dir, manifest.capability_id)
        self._verified_base: VerifiedImage | None = None
        self._base_probe: dict[str, Any] | None = None

    def required_base_labels(self) -> dict[str, str]:
        return {
            "org.opencontainers.image.version": self.version,
            "io.safe-reverser.capability.id": self.manifest.capability_id,
            "io.safe-reverser.capability.api": str(self.manifest.capability_api),
            "io.safe-reverser.worker.abi": str(self.manifest.worker_abi),
        }

    def ensure_base_ready(self) -> VerifiedImage:
        if self._verified_base is None:
            self._verified_base = self.runtime.ensure_image(
                self.base_image,
                required_labels=self.required_base_labels(),
            )
        return self._verified_base

    def _probe_base_worker(self) -> dict[str, Any]:
        if self._base_probe is not None:
            return dict(self._base_probe)
        verified = self.ensure_base_ready()
        payload = self._run_cli(
            image=_immutable_ref(verified, self.base_image),
            mounts=[],
            command=["health"],
            timeout=90,
        )
        constraints = payload.get("required_runtime_constraints")
        orchestration = payload.get("orchestration")
        if (
            payload.get("status") != "ok"
            or payload.get("network_required_at_runtime") is not False
            or payload.get("build_on_demand_allowed") is not False
            or payload.get("registry_selection_owned_by_worker") is not False
            or not isinstance(constraints, dict)
            or constraints.get("network") != "none"
            or not isinstance(orchestration, dict)
            or orchestration.get("runtime_download_inside_sandbox") is not False
            or orchestration.get("runtime_build_inside_sandbox") is not False
        ):
            raise FlutterCapabilityError(
                "Flutter worker health does not satisfy Worker ABI offline/runtime constraints"
            )
        self._base_probe = dict(payload)
        return dict(payload)

    def diagnostics(self) -> dict[str, Any]:
        return self._probe_base_worker()

    def status(self) -> dict[str, Any]:
        try:
            verified = self.ensure_base_ready()
        except RuntimeErrorSafe as exc:
            return {
                "state": "unavailable",
                "detail": str(exc),
                "image": self.base_image,
            }
        try:
            self._probe_base_worker()
        except (FlutterCapabilityError, RuntimeErrorSafe) as exc:
            return {
                "state": "degraded",
                "detail": str(exc),
                "image": self.base_image,
                "image_id": _immutable_ref(verified, self.base_image),
            }
        return {
            "state": "ready",
            "image": self.base_image,
            "image_id": _immutable_ref(verified, self.base_image),
            "image_version": verified.get("org.opencontainers.image.version"),
            "worker_abi": verified.get("io.safe-reverser.worker.abi"),
            "capability_api": verified.get("io.safe-reverser.capability.api"),
            "blutter_commit": verified.get("io.safe-reverser.blutter.commit"),
        }

    def _artifact(self, value: Any) -> tuple[Path, str]:
        try:
            path = secure_child(self.project_dir, str(value or ""))
        except PathPolicyError as exc:
            raise FlutterCapabilityError(str(exc)) from exc
        if path.is_symlink() or not path.is_file():
            raise FlutterCapabilityError("artifact must be a regular project file")
        if path.suffix.lower() not in {".apk", ".xapk", ".apks", ".apkm"}:
            raise FlutterCapabilityError(
                f"unsupported Flutter artifact type: {path.suffix}"
            )
        return path, path.relative_to(self.project_dir).as_posix()

    def _run_cli(
        self,
        *,
        image: str,
        mounts: list[tuple[Path, str, str]],
        command: list[str],
        timeout: int,
        tmpfs: list[str] | None = None,
    ) -> dict[str, Any]:
        run = self.runtime.run_container(
            image=image,
            policy=self.manifest.sandbox,
            mounts=mounts,
            command=command,
            timeout=timeout,
            tmpfs=tmpfs,
        )
        if run.timed_out:
            raise FlutterCapabilityError(
                f"Flutter worker timed out: {command[0] if command else 'worker'}"
            )
        payload = self.runtime.parse_json_tail(run)
        if run.exit_code != 0 or payload.get("status") == "error":
            raise FlutterCapabilityError(
                str(payload.get("error") or "Flutter worker failed")
            )
        return payload

    def _prepare(self, job: Path, artifact_rel: str) -> dict[str, Any]:
        verified = self.ensure_base_ready()
        return self._run_cli(
            image=_immutable_ref(verified, self.base_image),
            mounts=[
                (self.project_dir, "/workspace", "ro"),
                (job, "/output", "rw"),
            ],
            command=["prepare_artifact", artifact_rel, "input"],
            timeout=600,
        )

    def _runtime_image(
        self, prepared: dict[str, Any]
    ) -> tuple[str, dict[str, Any], str]:
        runtime = prepared.get("runtime")
        if (
            not isinstance(runtime, dict)
            or runtime.get("identity_status") != "identified"
        ):
            raise FlutterCapabilityError("Flutter runtime identity is incomplete")
        tag = str(runtime.get("cache_tag") or "")
        if (
            not tag
            or len(tag) > 128
            or any(
                ch
                not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
                for ch in tag
            )
        ):
            raise FlutterCapabilityError("Flutter runtime cache tag is invalid")
        if runtime.get("arch") != "arm64" or runtime.get("os") != "android":
            raise FlutterCapabilityError(
                "Flutter runtime architecture/OS is unsupported"
            )
        snapshot = str(runtime.get("snapshot_hash") or "").lower()
        if not _is_hex(snapshot, 32, 64):
            raise FlutterCapabilityError("Flutter runtime snapshot hash is invalid")
        blutter_commit = str(prepared.get("blutter_commit") or "").lower()
        if len(blutter_commit) != 40 or any(
            ch not in COMMIT_CHARS for ch in blutter_commit
        ):
            raise FlutterCapabilityError(
                "prepared Flutter evidence has invalid Blutter commit"
            )
        image = f"{self.manifest.image_repository}:{tag}"
        return image, runtime, blutter_commit

    def _ensure_runtime_ready(
        self, image: str, runtime: dict[str, Any], blutter_commit: str
    ) -> tuple[VerifiedImage | None, str]:
        required = {
            "io.safe-reverser.capability.id": self.manifest.capability_id,
            "io.safe-reverser.capability.api": str(self.manifest.capability_api),
            "io.safe-reverser.worker.abi": str(self.manifest.worker_abi),
            "io.safe-reverser.runtime-cache.schema": str(RUNTIME_CACHE_SCHEMA),
            "io.safe-reverser.blutter.commit": blutter_commit,
            "io.safe-reverser.dart.version": str(runtime.get("dart_version") or ""),
            "io.safe-reverser.dart.snapshot": str(
                runtime.get("snapshot_hash") or ""
            ),
            "io.safe-reverser.dart.arch": "arm64",
            "io.safe-reverser.dart.compressed-pointers": (
                "true" if bool(runtime.get("compressed_pointers")) else "false"
            ),
        }
        try:
            verified = self.runtime.ensure_image(image, required_labels=required)
        except RuntimeErrorSafe as exc:
            return None, str(exc)
        return verified, "ready"

    def _execute(self, job: Path, image: str, timeout: int) -> dict[str, Any]:
        input_dir = job / "input"
        if (
            input_dir.is_symlink()
            or not input_dir.is_dir()
            or input_dir.resolve().parent != job
        ):
            raise FlutterCapabilityError("prepared Flutter input is missing or unsafe")
        return self._run_cli(
            image=image,
            mounts=[
                (input_dir.resolve(), "/input", "ro"),
                (job, "/export", "rw"),
            ],
            command=[
                "analyze_export",
                ".",
                "analysis",
                "--timeout",
                str(timeout),
            ],
            timeout=min(3600, timeout + 120),
            tmpfs=[f"/output:rw,nosuid,nodev,size={self.output_tmpfs}"],
        )

    def _analysis_dir(self, job: Path) -> Path:
        path = job / "analysis"
        if path.is_symlink() or not path.is_dir() or path.resolve().parent != job:
            raise FlutterCapabilityError(
                "Flutter semantic analysis output is unavailable"
            )
        index = path / "flutter-index.sqlite"
        if (
            index.is_symlink()
            or not index.is_file()
            or index.resolve().parent != path.resolve()
        ):
            raise FlutterCapabilityError("Flutter semantic index is unavailable")
        return path.resolve()

    def analyze(self, args: dict[str, Any]) -> dict[str, Any]:
        _, artifact_rel = self._artifact(args.get("artifact"))
        try:
            timeout = int(args.get("timeout_seconds", 900))
        except (TypeError, ValueError) as exc:
            raise FlutterCapabilityError(
                "timeout_seconds must be an integer"
            ) from exc
        timeout = max(30, min(timeout, 3480))
        self._probe_base_worker()
        try:
            job_id, job, meta = self.jobs.create(
                artifact=artifact_rel,
                profile=self.manifest.capability_id,
                controller_version=self.version,
            )
        except JobStoreError as exc:
            raise FlutterCapabilityError(str(exc)) from exc
        meta["status"] = "preparing"
        self.jobs.write(job, meta)
        prepared_created = False
        try:
            prepared = self._prepare(job, artifact_rel)
            prepared_created = (job / "input").is_dir()
            meta["prepare"] = prepared
            meta["status"] = str(prepared.get("status") or "unknown")
            self.jobs.write(job, meta)
            if prepared.get("status") == "unsupported":
                return {"job_id": job_id, **prepared}
            runtime = prepared.get("runtime")
            if (
                not isinstance(runtime, dict)
                or runtime.get("identity_status") != "identified"
            ):
                return {
                    "job_id": job_id,
                    **prepared,
                    "executed": False,
                    "limitation": (
                        "exact Dart runtime identity is required before AOT analysis"
                    ),
                }
            image, runtime, blutter_commit = self._runtime_image(prepared)
            verified_runtime, reason = self._ensure_runtime_ready(
                image, runtime, blutter_commit
            )
            if verified_runtime is None:
                meta["status"] = "runtime_cache_unavailable"
                meta["runtime_image"] = image
                meta["runtime_cache_reason"] = reason[-4000:]
                self.jobs.write(job, meta)
                return {
                    "job_id": job_id,
                    "status": "runtime_cache_unavailable",
                    "executed": False,
                    "runtime": runtime,
                    "runtime_image": image,
                    "cache_tag": runtime.get("cache_tag"),
                    "reason": reason[-4000:],
                    "next_action": (
                        "build/publish the exact runtime cache through the controlled "
                        "GitHub workflow; analysis stays offline"
                    ),
                }
            runtime_image_id = _immutable_ref(verified_runtime, image)
            result = self._execute(job, runtime_image_id, timeout)
            meta["runtime_image"] = image
            meta["runtime_image_id"] = runtime_image_id
            meta["analysis"] = result
            meta["status"] = str(result.get("status") or "unknown")
            self.jobs.write(job, meta)
            return {
                "job_id": job_id,
                "runtime_image": image,
                "runtime_image_id": runtime_image_id,
                **result,
            }
        except Exception:
            meta["status"] = "error"
            try:
                self.jobs.write(job, meta)
            except Exception:
                pass
            raise
        finally:
            if prepared_created:
                try:
                    remove_direct_child(job, "input")
                except PathPolicyError as exc:
                    raise FlutterCapabilityError(str(exc)) from exc

    def _semantic(
        self,
        job_id: Any,
        command: str,
        argv: list[str],
        *,
        timeout: int = 120,
    ) -> dict[str, Any]:
        try:
            job = self.jobs.get(str(job_id or ""))
        except JobStoreError as exc:
            raise FlutterCapabilityError(str(exc)) from exc
        analysis = self._analysis_dir(job)
        self._probe_base_worker()
        verified = self.ensure_base_ready()
        payload = self._run_cli(
            image=_immutable_ref(verified, self.base_image),
            mounts=[(analysis, "/output", "ro")],
            command=[command, ".", *argv],
            timeout=timeout,
        )
        payload["job_id"] = job.name
        return payload

    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "analyze_flutter_aot":
            return self.analyze(args)
        if name == "find_dart_symbols":
            query = _bounded_text(args.get("query"), "query", MAX_QUERY_TEXT)
            limit = _bounded_limit(args.get("limit"), 50)
            return self._semantic(
                args.get("job_id"), name, [query, "--limit", str(limit)]
            )
        if name == "find_dart_strings":
            query = _bounded_text(args.get("query"), "query", MAX_QUERY_TEXT)
            limit = _bounded_limit(args.get("limit"), 50)
            return self._semantic(
                args.get("job_id"), name, [query, "--limit", str(limit)]
            )
        if name == "find_dart_xrefs":
            symbol = _bounded_text(args.get("symbol"), "symbol", MAX_SYMBOL_TEXT)
            direction = str(args.get("direction") or "both")
            if direction not in {"incoming", "outgoing", "both"}:
                raise FlutterCapabilityError(
                    "direction must be incoming, outgoing, or both"
                )
            limit = _bounded_limit(args.get("limit"), 100)
            return self._semantic(
                args.get("job_id"),
                name,
                [symbol, "--direction", direction, "--limit", str(limit)],
            )
        if name == "map_dart_to_native":
            symbol = _bounded_text(args.get("symbol"), "symbol", MAX_SYMBOL_TEXT)
            return self._semantic(args.get("job_id"), name, [symbol])
        if name == "extract_flutter_network_model":
            limit = _bounded_limit(args.get("limit"), 100)
            return self._semantic(
                args.get("job_id"),
                name,
                ["--limit", str(limit)],
                timeout=180,
            )
        if name == "list_flutter_jobs":
            try:
                jobs = self.jobs.list()
            except JobStoreError as exc:
                raise FlutterCapabilityError(str(exc)) from exc
            return {
                "jobs": [
                    {
                        "job_id": item.get("job_id"),
                        "artifact": item.get("artifact"),
                        "status": item.get("status"),
                        "created_at_epoch": item.get("created_at_epoch"),
                        "runtime_image": item.get("runtime_image"),
                        "runtime_image_id": item.get("runtime_image_id"),
                    }
                    for item in jobs
                ]
            }
        raise FlutterCapabilityError(
            f"unknown Flutter capability operation: {name}"
        )

    @staticmethod
    def tools() -> list[dict[str, Any]]:
        return [
            {
                "name": "analyze_flutter_aot",
                "description": "Analyze Flutter Dart AOT through the framework-flutter capability using a verified exact runtime-cache image and persist a bounded semantic index.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "artifact": {"type": "string"},
                        "timeout_seconds": {
                            "type": "integer",
                            "minimum": 30,
                            "maximum": 3480,
                            "default": 900,
                        },
                    },
                    "required": ["artifact"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "find_dart_symbols",
                "description": "Search a Flutter Dart semantic index for libraries, classes and functions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "job_id": {"type": "string"},
                        "query": {"type": "string", "maxLength": MAX_QUERY_TEXT},
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": MAX_QUERY_LIMIT,
                            "default": 50,
                        },
                    },
                    "required": ["job_id", "query"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "find_dart_strings",
                "description": "Search bounded Dart AOT/object-pool string evidence.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "job_id": {"type": "string"},
                        "query": {"type": "string", "maxLength": MAX_QUERY_TEXT},
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": MAX_QUERY_LIMIT,
                            "default": 50,
                        },
                    },
                    "required": ["job_id", "query"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "find_dart_xrefs",
                "description": "Query bounded Dart call/XREF adjacency; XREFs are not proof of value flow.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "job_id": {"type": "string"},
                        "symbol": {
                            "type": "string",
                            "maxLength": MAX_SYMBOL_TEXT,
                        },
                        "direction": {
                            "type": "string",
                            "enum": ["incoming", "outgoing", "both"],
                            "default": "both",
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": MAX_QUERY_LIMIT,
                            "default": 100,
                        },
                    },
                    "required": ["job_id", "symbol"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "map_dart_to_native",
                "description": "Map a uniquely resolved Dart function to its libapp.so-relative native offset.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "job_id": {"type": "string"},
                        "symbol": {
                            "type": "string",
                            "maxLength": MAX_SYMBOL_TEXT,
                        },
                    },
                    "required": ["job_id", "symbol"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "extract_flutter_network_model",
                "description": "Reconstruct bounded Flutter endpoint/client/header/auth/signing/crypto evidence without claiming value flow.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "job_id": {"type": "string"},
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": MAX_QUERY_LIMIT,
                            "default": 100,
                        },
                    },
                    "required": ["job_id"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "list_flutter_jobs",
                "description": "List recent framework-flutter analysis jobs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            },
        ]
