from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

import program_understanding as legacy

IDENT_RE = re.compile(r"([A-Za-z_$][\w$]*)$")
CLASS_DECL_RE = re.compile(r"\b(?:class|interface|enum|object)\s+([A-Za-z_$][\w$]*)")
JAVA_MODIFIERS = {
    "public", "protected", "private", "static", "final", "abstract", "synchronized",
    "native", "default", "strictfp", "transient", "volatile",
}
CONTROL_WORDS = {
    "if", "for", "while", "switch", "catch", "when", "return", "throw", "new", "case",
    "else", "do", "try", "finally", "assert", "synchronized",
}
MODEL_NOISE = {
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "HTTP", "Call", "Response",
    "Headers", "Header", "Query", "Path", "Body", "Field", "FormUrlEncoded", "Multipart", "Part",
}


def sources(job: Path) -> Iterable[Path]:
    root = job.resolve()
    for path in legacy._sources(job):
        resolved = path.resolve()
        if resolved == root or root in resolved.parents:
            yield path


def text(path: Path) -> str:
    return legacy._text(path)


def source_meta(value: str, path: Path) -> tuple[str, str]:
    return legacy._source_meta(value, path)


def matching_paren(value: str, start: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(start, len(value)):
        char = value[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _mask_comments_and_strings(value: str) -> str:
    """Mask comments/string literals while preserving offsets and newlines."""
    output = list(value)
    index = 0
    state = "code"
    quote: str | None = None
    while index < len(value):
        char = value[index]
        if state == "code":
            if char == "/" and index + 1 < len(value) and value[index + 1] == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "line-comment"
                continue
            if char == "/" and index + 1 < len(value) and value[index + 1] == "*":
                output[index] = output[index + 1] = " "
                index += 2
                state = "block-comment"
                continue
            if char in {'"', "'"}:
                quote = char
                output[index] = " "
                index += 1
                state = "string"
                continue
            index += 1
            continue
        if state == "line-comment":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
            index += 1
            continue
        if state == "block-comment":
            if char == "*" and index + 1 < len(value) and value[index + 1] == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "code"
                continue
            if char != "\n":
                output[index] = " "
            index += 1
            continue
        if state == "string":
            if char == "\\" and index + 1 < len(value):
                output[index] = " "
                if value[index + 1] != "\n":
                    output[index + 1] = " "
                index += 2
                continue
            if char == quote:
                output[index] = " "
                index += 1
                state = "code"
                quote = None
                continue
            if char != "\n":
                output[index] = " "
            index += 1
    return "".join(output)


def _matching_brace(masked: str, start: int) -> int | None:
    depth = 0
    for index in range(start, len(masked)):
        char = masked[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _line_number(value: str, position: int) -> int:
    return value.count("\n", 0, position) + 1


def class_scopes(value: str, default_class: str) -> list[dict[str, Any]]:
    """Return lexical class scopes; nested classes use JVM-like Outer$Inner names."""
    masked = _mask_comments_and_strings(value)
    scopes: list[dict[str, Any]] = []
    for match in CLASS_DECL_RE.finditer(masked):
        brace = masked.find("{", match.end())
        if brace < 0:
            continue
        semicolon = masked.find(";", match.end(), brace)
        if semicolon >= 0:
            continue
        end = _matching_brace(masked, brace)
        if end is None:
            continue
        scopes.append({
            "name": match.group(1),
            "start_pos": match.start(),
            "brace_pos": brace,
            "end_pos": end,
            "start_line": _line_number(value, match.start()),
            "end_line": _line_number(value, end),
        })
    scopes.sort(key=lambda item: (item["start_pos"], -item["end_pos"]))
    for index, scope in enumerate(scopes):
        parent = None
        for candidate in scopes[:index]:
            if candidate["brace_pos"] < scope["start_pos"] < candidate["end_pos"]:
                if parent is None or candidate["brace_pos"] > parent["brace_pos"]:
                    parent = candidate
        scope["class_name"] = f"{parent['class_name']}${scope['name']}" if parent else scope["name"]
    if not scopes and default_class:
        scopes.append({
            "name": default_class,
            "class_name": default_class,
            "start_pos": 0,
            "brace_pos": 0,
            "end_pos": len(value),
            "start_line": 1,
            "end_line": max(1, len(value.splitlines())),
        })
    return scopes


def class_name_at_line(scopes: list[dict[str, Any]], line: int, default_class: str) -> str:
    matches = [scope for scope in scopes if scope["start_line"] <= line <= scope["end_line"]]
    if not matches:
        return default_class
    return max(matches, key=lambda scope: scope["start_line"])["class_name"]


def strip_leading_annotations(candidate: str) -> str:
    value = candidate.lstrip()
    while value.startswith("@"):
        match = re.match(r"@[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", value)
        if not match:
            return value
        position = match.end()
        while position < len(value) and value[position].isspace():
            position += 1
        if position < len(value) and value[position] == "(":
            end = matching_paren(value, position)
            if end is None:
                return value
            position = end + 1
        value = value[position:].lstrip()
        if not value:
            return ""
    return value


def parameter_count(params: str) -> int:
    if not params.strip():
        return 0
    depths = {"angle": 0, "paren": 0, "bracket": 0, "brace": 0}
    quote: str | None = None
    escaped = False
    count = 1
    for char in params:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "<":
            depths["angle"] += 1
        elif char == ">" and depths["angle"]:
            depths["angle"] -= 1
        elif char == "(":
            depths["paren"] += 1
        elif char == ")" and depths["paren"]:
            depths["paren"] -= 1
        elif char == "[":
            depths["bracket"] += 1
        elif char == "]" and depths["bracket"]:
            depths["bracket"] -= 1
        elif char == "{":
            depths["brace"] += 1
        elif char == "}" and depths["brace"]:
            depths["brace"] -= 1
        elif char == "," and not any(depths.values()):
            count += 1
    return count


def dex_parameter_count(descriptor: str) -> int | None:
    if not descriptor.startswith("(") or ")" not in descriptor:
        return None
    params = descriptor[1:descriptor.index(")")]
    primitives = set("ZBSCIJFD")
    count = 0
    index = 0
    while index < len(params):
        while index < len(params) and params[index] == "[":
            index += 1
        if index >= len(params):
            return None
        if params[index] in primitives:
            count += 1
            index += 1
        elif params[index] == "L":
            end = params.find(";", index)
            if end < 0:
                return None
            count += 1
            index = end + 1
        else:
            return None
    return count


def parse_declaration(candidate: str, class_name: str) -> tuple[str, str, int] | None:
    candidate = strip_leading_annotations(candidate).strip()
    if not candidate or "(" not in candidate:
        return None
    open_pos = candidate.find("(")
    close_pos = matching_paren(candidate, open_pos)
    if close_pos is None:
        return None
    before = candidate[:open_pos].strip()
    params = candidate[open_pos + 1:close_pos].strip()
    after = candidate[close_pos + 1:].strip()
    if not before or "=" in before or "->" in before:
        return None
    first = before.split(None, 1)[0].lower()
    if first in CONTROL_WORDS:
        return None

    if re.search(r"(?:^|\s)fun\s+", before):
        match = IDENT_RE.search(before)
        if not match or match.group(1) in CONTROL_WORDS:
            return None
        return match.group(1), params, parameter_count(params)

    match = IDENT_RE.search(before)
    if not match or match.group(1) in CONTROL_WORDS:
        return None
    name = match.group(1)
    prefix = before[:match.start()].strip()
    if prefix.endswith(".") or "=" in prefix:
        return None
    tokens = [
        token for token in re.split(r"\s+", re.sub(r"<[^>]*>", " ", prefix))
        if token
    ]
    non_modifiers = [token for token in tokens if token not in JAVA_MODIFIERS and not token.startswith("@")]
    constructor = name == class_name and not non_modifiers and (
        after.startswith("{") or after.startswith("throws ")
    )
    if not constructor and not non_modifiers:
        return None
    if after and not (
        after.startswith(("{", ";", "=", ":"))
        or after.startswith("throws ")
        or after.startswith("default ")
        or after.startswith("/*")
    ):
        return None
    return name, params, parameter_count(params)


def declarations(value: str, class_name: str) -> list[dict[str, Any]]:
    lines = value.splitlines()
    scopes = class_scopes(value, class_name)
    output: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str]] = set()
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            index += 1
            continue
        candidate = strip_leading_annotations(stripped)
        if not candidate or "(" not in candidate:
            index += 1
            continue
        open_pos = candidate.find("(")
        close_pos = matching_paren(candidate, open_pos)
        consumed = index
        while close_pos is None and consumed + 1 < len(lines) and consumed - index < 12:
            consumed += 1
            candidate += " " + lines[consumed].strip()
            close_pos = matching_paren(candidate, open_pos)
        owner = class_name_at_line(scopes, index + 1, class_name)
        owner_simple = owner.rsplit("$", 1)[-1]
        parsed = parse_declaration(candidate, owner_simple)
        if parsed:
            name, params, arity = parsed
            key = (index + 1, owner, name)
            if key not in seen:
                seen.add(key)
                output.append({
                    "line": index + 1,
                    "name": name,
                    "params": params,
                    "parameter_count": arity,
                    "class_name": owner,
                })
            index = consumed + 1
        else:
            index += 1
    return output


def ranges(
    items: list[dict[str, Any]],
    line_count: int,
    scopes: list[dict[str, Any]] | None = None,
) -> list[tuple[int, int, dict[str, Any]]]:
    output = []
    scope_ends = {scope["class_name"]: scope["end_line"] for scope in (scopes or [])}
    for index, item in enumerate(items):
        owner = item.get("class_name")
        next_line = None
        for candidate in items[index + 1:]:
            if candidate.get("class_name") == owner:
                next_line = candidate["line"]
                break
        end = next_line - 1 if next_line is not None else scope_ends.get(owner, line_count)
        output.append((item["line"], max(item["line"], end), item))
    return output


def context(
    items: list[tuple[int, int, dict[str, Any]]],
    line: int,
    class_name: str | None = None,
) -> dict[str, Any] | None:
    for start, end, item in items:
        if start <= line <= end and (class_name is None or item.get("class_name") == class_name):
            return item
    return None


def declaration_after(
    items: list[dict[str, Any]],
    line: int,
    max_distance: int = 8,
    class_name: str | None = None,
) -> dict[str, Any] | None:
    for item in items:
        if item["line"] < line:
            continue
        if item["line"] > line + max_distance:
            break
        if class_name is None or item.get("class_name") == class_name:
            return item
    return None
