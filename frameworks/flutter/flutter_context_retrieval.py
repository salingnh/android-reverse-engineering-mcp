from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import program_model as pm

MAX_CONTEXT_SOURCE_FILE_BYTES = 4 * 1024 * 1024
DEFAULT_BEFORE_LINES = 20


class FlutterContextSourceProvider:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = Path(output_dir).resolve()

    def _safe_file(self, source_file: str) -> Path | None:
        rel = Path(str(source_file or ""))
        if not str(rel) or rel.is_absolute() or ".." in rel.parts:
            return None
        try:
            lexical_root = Path(os.path.abspath(self.output_dir))
            lexical = Path(os.path.abspath(lexical_root / rel))
            if lexical_root.is_symlink() or not lexical_root.is_dir():
                return None
            if lexical == lexical_root or lexical_root not in lexical.parents:
                return None
            current = lexical_root
            for part in lexical.relative_to(lexical_root).parts:
                current = current / part
                if current.is_symlink():
                    return None
            resolved = lexical.resolve()
            root_resolved = lexical_root.resolve()
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

    @staticmethod
    def _locator(evidence: tuple[dict[str, Any], ...]) -> tuple[str | None, int | None]:
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
    def _bounded_lines(
        lines: list[str],
        *,
        anchor: int,
        line_limit: int,
        byte_limit: int,
    ) -> tuple[str, int, int, bool]:
        if not lines:
            return "", 1, 0, False
        start = max(1, anchor - DEFAULT_BEFORE_LINES)
        end = min(len(lines), start + line_limit - 1)
        selected = lines[start - 1 : end]
        output: list[str] = []
        used = 0
        truncated = start > 1 or end < len(lines)
        for raw in selected:
            encoded = (raw + "\n").encode("utf-8", "replace")
            if used + len(encoded) > byte_limit:
                truncated = True
                break
            output.append(raw)
            used += len(encoded)
        if not output and selected:
            prefix = selected[0].encode("utf-8", "replace")[: max(1, byte_limit - 1)]
            output = [prefix.decode("utf-8", "ignore")]
            truncated = True
        return "\n".join(output), start, len(output), truncated

    def source_slice(
        self,
        *,
        entity: pm.ProgramEntity,
        evidence: tuple[dict[str, Any], ...],
        line_limit: int,
        byte_limit: int,
    ) -> dict[str, Any] | None:
        source_file, line = self._locator(evidence)
        if source_file is None:
            return None
        path = self._safe_file(source_file)
        if path is None:
            return None
        try:
            value = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        lines = value.splitlines()
        if not lines:
            return None
        anchor = max(1, min(int(line or 1), len(lines)))
        text, start, returned_lines, truncated = self._bounded_lines(
            lines,
            anchor=anchor,
            line_limit=line_limit,
            byte_limit=byte_limit,
        )
        if not text:
            return None
        try:
            relative = path.relative_to(self.output_dir)
        except ValueError:
            return None
        return {
            "entity_id": entity.entity_id,
            "source_kind": "dart-aot-semantic-source",
            "representation": entity.representation,
            "source_file": relative.as_posix(),
            "start_line": start,
            "end_line": start + max(0, returned_lines - 1),
            "returned_lines": returned_lines,
            "truncated": truncated,
            "canonical_truth": False,
            "text": text,
        }
