from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import context_retrieval as context
import program_model as pm
import pu_program_model
import pu_source
import static_application_map

INTERNAL_CONTEXT_RETRIEVAL_TOOLS = frozenset({"get_function_context"})
MAX_SOURCE_SCAN_FILES = 2_000
MAX_SOURCE_SCAN_SECONDS = 2
MAX_CONTEXT_SOURCE_FILE_BYTES = 4 * 1024 * 1024


class DexContextSourceProvider:
    def __init__(self, job: Path) -> None:
        self.job = Path(job).resolve()

    def _safe_file(self, candidate: Path, root: Path) -> Path | None:
        """Return a bounded regular file without traversing symlink components."""
        try:
            lexical_root = Path(os.path.abspath(root))
            lexical_candidate = Path(os.path.abspath(candidate))
            if lexical_root.is_symlink() or not lexical_root.is_dir():
                return None
            if lexical_root != self.job and self.job not in lexical_root.parents:
                return None
            if (
                lexical_candidate == lexical_root
                or lexical_root not in lexical_candidate.parents
            ):
                return None
            current = lexical_root
            for part in lexical_candidate.relative_to(lexical_root).parts:
                current = current / part
                if current.is_symlink():
                    return None
            root_resolved = lexical_root.resolve()
            resolved = lexical_candidate.resolve()
        except (OSError, ValueError):
            return None
        if resolved == root_resolved or root_resolved not in resolved.parents:
            return None
        try:
            if not resolved.is_file() or resolved.stat().st_size > MAX_CONTEXT_SOURCE_FILE_BYTES:
                return None
        except OSError:
            return None
        return resolved

    def _from_locator(self, source_file: str) -> Path | None:
        rel = Path(str(source_file or ""))
        if not str(rel) or rel.is_absolute() or ".." in rel.parts:
            return None
        roots = (
            self.job,
            self.job / "jadx" / "sources",
            self.job / "jadx",
            self.job / "vineflower",
        )
        for root in roots:
            path = self._safe_file(root / rel, root)
            if path is not None:
                return path
        return None

    def _direct_class_path(self, entity: pm.ProgramEntity) -> Path | None:
        display = str(entity.display_name or "")
        if "." not in display:
            return None
        class_name = display.rsplit(".", 1)[0].split("$", 1)[0]
        rel = Path(*class_name.split("."))
        root = self.job / "jadx" / "sources"
        for suffix in (".java", ".kt"):
            path = self._safe_file((root / rel).with_suffix(suffix), root)
            if path is not None:
                return path
        return None

    def _scan_class_path(self, entity: pm.ProgramEntity) -> Path | None:
        display = str(entity.display_name or "")
        if "." not in display:
            return None
        class_name = display.rsplit(".", 1)[0]
        outer_name = class_name.split("$", 1)[0]
        started = time.monotonic()
        scanned = 0
        for path in pu_source.sources(self.job):
            scanned += 1
            if scanned > MAX_SOURCE_SCAN_FILES or time.monotonic() - started > MAX_SOURCE_SCAN_SECONDS:
                break
            safe = self._safe_file(path, self.job)
            if safe is None:
                continue
            try:
                value = pu_source.text(safe)
            except OSError:
                continue
            if not value:
                continue
            package, simple = pu_source.source_meta(value, safe)
            qualified = f"{package}.{simple}" if package else simple
            if qualified == outer_name:
                return safe
        return None

    @staticmethod
    def _evidence_locator(evidence: tuple[dict[str, Any], ...]) -> tuple[str | None, int | None]:
        candidates: list[tuple[str, int | None]] = []
        for record in evidence:
            location = record.get("location") if isinstance(record, dict) else None
            if not isinstance(location, dict):
                continue
            source_file = location.get("source_file")
            if not isinstance(source_file, str) or not source_file.strip():
                continue
            line = location.get("line") if isinstance(location.get("line"), int) else None
            candidates.append((source_file.strip(), line))
        if not candidates:
            return None, None
        candidates.sort(key=lambda item: (item[0], item[1] if item[1] is not None else 2**31))
        return candidates[0]

    @staticmethod
    def _method_name(entity: pm.ProgramEntity) -> str:
        display = str(entity.display_name or "")
        return display.rsplit(".", 1)[-1] if "." in display else display

    def _range_for_function(
        self,
        value: str,
        path: Path,
        entity: pm.ProgramEntity,
        evidence_line: int | None,
    ) -> tuple[int, int]:
        lines = value.splitlines()
        if not lines:
            return 1, 1
        package, simple = pu_source.source_meta(value, path)
        _ = package
        declarations = pu_source.declarations(value, simple)
        scopes = pu_source.class_scopes(value, simple)
        method_name = self._method_name(entity)
        parameter_count = entity.properties.get("parameter_count")
        matches = [item for item in declarations if item.get("name") == method_name]
        if isinstance(parameter_count, int):
            exact = [item for item in matches if item.get("parameter_count") == parameter_count]
            if exact:
                matches = exact
        if evidence_line is not None:
            near = sorted(
                matches,
                key=lambda item: (
                    abs(int(item["line"]) - evidence_line),
                    int(item["line"]),
                ),
            )
            if near:
                matches = near
        target = matches[0] if matches else None
        if target is not None:
            for start, end, item in pu_source.ranges(declarations, len(lines), scopes):
                if item is target:
                    return max(1, start), min(len(lines), end)
        if evidence_line is not None:
            return max(1, evidence_line - 20), min(len(lines), evidence_line + 80)
        return 1, min(len(lines), 120)

    @staticmethod
    def _bounded_text_lines(
        lines: list[str],
        *,
        start_line: int,
        end_line: int,
        line_limit: int,
        byte_limit: int,
    ) -> tuple[str, int, bool]:
        start = max(1, start_line)
        end = min(len(lines), max(start, end_line))
        desired = lines[start - 1 : end]
        if len(desired) > line_limit:
            desired = desired[:line_limit]
        output: list[str] = []
        used = 0
        truncated = (end_line - start_line + 1) > len(desired)
        for raw in desired:
            encoded = (raw + "\n").encode("utf-8", "replace")
            if used + len(encoded) > byte_limit:
                truncated = True
                break
            output.append(raw)
            used += len(encoded)
        if not output and desired:
            prefix = desired[0].encode("utf-8", "replace")[: max(1, byte_limit - 1)]
            output = [prefix.decode("utf-8", "ignore")]
            truncated = True
        return "\n".join(output), len(output), truncated

    def source_slice(
        self,
        *,
        entity: pm.ProgramEntity,
        evidence: tuple[dict[str, Any], ...],
        line_limit: int,
        byte_limit: int,
    ) -> dict[str, Any] | None:
        source_file, evidence_line = self._evidence_locator(evidence)
        path = self._from_locator(source_file) if source_file else None
        if path is None:
            path = self._direct_class_path(entity)
        if path is None:
            path = self._scan_class_path(entity)
        if path is None:
            return None
        try:
            value = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        if not value:
            return None
        start_line, end_line = self._range_for_function(value, path, entity, evidence_line)
        lines = value.splitlines()
        text, returned_lines, truncated = self._bounded_text_lines(
            lines,
            start_line=start_line,
            end_line=end_line,
            line_limit=line_limit,
            byte_limit=byte_limit,
        )
        if not text:
            return None
        try:
            relative = path.resolve().relative_to(self.job)
        except ValueError:
            return None
        return {
            "entity_id": entity.entity_id,
            "source_kind": "decompiled-source",
            "representation": entity.representation,
            "source_file": relative.as_posix(),
            "start_line": start_line,
            "end_line": start_line + max(0, returned_lines - 1),
            "returned_lines": returned_lines,
            "truncated": truncated,
            "canonical_truth": False,
            "text": text,
        }


def _repository(server: Any, args: dict[str, Any]) -> tuple[pm.ProgramRepository, Path]:
    job = server.core._job_dir(str(args.get("job_id", "")))
    provider = pu_program_model.DexProgramProvider(
        job,
        server.core.WORKSPACE,
        server.pu.capabilities(),
    )
    return pm.ProgramRepository((provider,)), job


def _get_function_context(server: Any, args: dict[str, Any]) -> dict[str, Any]:
    repo, job = _repository(server, args)
    retriever = context.ContextRetriever(repo, DexContextSourceProvider(job))
    kinds = args.get("relationship_kinds")
    if kinds is not None and not isinstance(kinds, list):
        raise server.core.ToolError("relationship_kinds must be an array")
    return retriever.get_function_context(
        entity_id=str(args.get("entity_id", "")),
        ownership_scope=str(args.get("ownership_scope", "application")),
        direction=str(args.get("direction", "both")),
        relationship_kinds=kinds,
        relationship_limit=int(args.get("relationship_limit", context.DEFAULT_RELATIONSHIP_LIMIT)),
        evidence_limit=int(args.get("evidence_limit", context.DEFAULT_EVIDENCE_LIMIT)),
        source_line_limit=int(args.get("source_line_limit", context.DEFAULT_SOURCE_LINE_LIMIT)),
        source_byte_limit=int(args.get("source_byte_limit", context.DEFAULT_SOURCE_BYTE_LIMIT)),
        response_budget_bytes=int(
            args.get("response_budget_bytes", context.DEFAULT_RESPONSE_BUDGET_BYTES)
        ),
        cursor=str(args.get("cursor")) if args.get("cursor") else None,
    )


def _tool_descriptor() -> dict[str, Any]:
    return {
        "name": "get_function_context",
        "description": "Internal static-core bounded Program Model context retrieval hook.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "entity_id": {"type": "string", "maxLength": 256},
                "ownership_scope": {
                    "type": "string",
                    "enum": [
                        "application",
                        "all",
                        "first_party",
                        "third_party",
                        "platform",
                        "generated",
                        "unknown",
                    ],
                    "default": "application",
                },
                "direction": {
                    "type": "string",
                    "enum": ["incoming", "outgoing", "both"],
                    "default": "both",
                },
                "relationship_kinds": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(pm.RELATIONSHIP_KINDS)},
                    "maxItems": 32,
                },
                "relationship_limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": context.MAX_RELATIONSHIP_LIMIT,
                    "default": context.DEFAULT_RELATIONSHIP_LIMIT,
                },
                "evidence_limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": context.MAX_EVIDENCE_LIMIT,
                    "default": context.DEFAULT_EVIDENCE_LIMIT,
                },
                "source_line_limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": context.MAX_SOURCE_LINE_LIMIT,
                    "default": context.DEFAULT_SOURCE_LINE_LIMIT,
                },
                "source_byte_limit": {
                    "type": "integer",
                    "minimum": 1024,
                    "maximum": context.MAX_SOURCE_BYTE_LIMIT,
                    "default": context.DEFAULT_SOURCE_BYTE_LIMIT,
                },
                "response_budget_bytes": {
                    "type": "integer",
                    "minimum": context.MIN_RESPONSE_BUDGET_BYTES,
                    "maximum": context.MAX_RESPONSE_BUDGET_BYTES,
                    "default": context.DEFAULT_RESPONSE_BUDGET_BYTES,
                },
                "cursor": {"type": "string", "maxLength": pm.MAX_CURSOR_BYTES},
            },
            "required": ["job_id", "entity_id"],
            "additionalProperties": False,
        },
    }


def install(server: Any) -> None:
    if getattr(server, "_context_retrieval_installed", False):
        return
    original_health = server.health

    def health(args: dict[str, Any]) -> dict[str, Any]:
        result = original_health(args)
        result["context_retrieval"] = context.descriptor()
        contract = result.get("tool_contract")
        if isinstance(contract, dict):
            internal = (
                {"health"}
                | set(static_application_map.INTERNAL_APPLICATION_MAP_TOOLS)
                | set(INTERNAL_CONTEXT_RETRIEVAL_TOOLS)
            )
            contract["public_operation_count"] = len(
                [item for item in server.core.TOOLS if item.get("name") not in internal]
            )
        return result

    def get_function_context(args: dict[str, Any]) -> dict[str, Any]:
        return server._pu_call(
            _get_function_context,
            server,
            args,
            timeout_seconds=server._timeout(args, 300),
        )

    server.health = health
    server.core.TOOL_HANDLERS.update(
        {
            "health": health,
            "get_function_context": get_function_context,
        }
    )
    names = {str(item.get("name") or "") for item in server.core.TOOLS}
    descriptor = _tool_descriptor()
    if descriptor["name"] not in names:
        server.core.TOOLS.append(descriptor)
    server._context_retrieval_installed = True
