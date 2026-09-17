#!/usr/bin/env python3
"""Reject likely credentials without printing their values."""

from __future__ import annotations

import argparse
import ast
import codecs
import functools
import html
import io
import os
import re
import shlex
import subprocess
import sys
import tokenize
import warnings
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


ROOT = Path(__file__).resolve().parents[1]
MAX_BLOB_BYTES = 2 * 1024 * 1024
MAX_HELM_VARIANTS = 512
SENSITIVE_NAME = (
    rb"(?<![A-Za-z0-9_.-])(?:(?:[A-Za-z0-9_.-]*(?:api[_.-]?key|private[_.-]?key|"
    rb"secret[_.-]?access[_.-]?key|secret[_.-]?key[_.-]?base|secret[_.-]?key|"
    rb"password|passphrase|credential|"
    rb"passwd|secret|token)|(?:[A-Za-z0-9]+[_.-])*(?:pass|pwd))"
    rb"(?:[_.-]?value)?)"
    rb"(?![A-Za-z0-9_.-])"
)
SENSITIVE_NAME_RE = re.compile(rb"(?i)^" + SENSITIVE_NAME + rb"$")
SENSITIVE_NAME_SEARCH = re.compile(rb"(?i)" + SENSITIVE_NAME)
DOCUMENTATION_PLACEHOLDER = re.compile(
    rb"(?i)^(?:disabled(?: value)?|example|placeholder|replace(?:[_-]me)?|"
    rb"your[_-](?:api[_-]?key|token|secret|password|credential)(?:[_-]here)?)$"
)
SAFE_REFERENCE = (
    rb"(?:\$\{\{\s*(?:secrets|vars|env)\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}|"
    rb"\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$env:[A-Za-z_][A-Za-z0-9_]*|"
    rb"\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|"
    rb"\{\{\s*[A-Za-z_][A-Za-z0-9_.]*\s*\}\})"
)
SAFE_REFERENCE_RE = re.compile(rb"(?i)^" + SAFE_REFERENCE + rb"$")
JAVASCRIPT_NUMERIC_LITERAL = (
    rb"[-+]?(?:"
    rb"(?:0[xX][0-9A-Fa-f](?:_?[0-9A-Fa-f])*|"
    rb"0[bB][01](?:_?[01])*|0[oO][0-7](?:_?[0-7])*|"
    rb"[0-9](?:_?[0-9])*)n|"
    rb"(?:[0-9](?:_?[0-9])*(?:\.(?:[0-9](?:_?[0-9])*)?)?|"
    rb"\.[0-9](?:_?[0-9])*)(?:[eE][+-]?[0-9](?:_?[0-9])*)?|"
    rb"0[xX][0-9A-Fa-f](?:_?[0-9A-Fa-f])*|"
    rb"0[bB][01](?:_?[01])*|0[oO][0-7](?:_?[0-7])*"
    rb")"
)
TOML_MULTILINE_ASSIGNMENT = re.compile(
    rb"(?i)[\"']?" + SENSITIVE_NAME + rb"[\"']?\s*=\s*(?P<delimiter>\"\"\"|''')"
)
UNQUOTED_EQUALS_ASSIGNMENT = re.compile(
    rb"(?im)^[ \t]*(?:-[ \t]*)?(?:(?:ARG|ENV|export|readonly|local|const|let|var)"
    rb"\s+|(?:declare|typeset)(?:\s+-[A-Za-z]+)*\s+)?[\"']?"
    + SENSITIVE_NAME
    + rb"[\"']?\s*(?:\|\|=|\?\?=|&&=|\+=|=)\s*(?P<value>[^\r\n]+?)\s*$"
)
DOCKER_SPACE_ASSIGNMENT = re.compile(
    rb"(?im)^[ \t]*ENV[ \t]+(?P<key>" + SENSITIVE_NAME
    + rb")[ \t]+(?P<value>[^\r\n]+?)[ \t]*$"
)
UNQUOTED_COLON_ASSIGNMENT = re.compile(
    rb"(?i)[\"']?" + SENSITIVE_NAME + rb"[\"']?[ \t]*:[ \t]*"
)
QUOTED_ASSIGNMENT = re.compile(
    rb"(?i)[\"']?" + SENSITIVE_NAME
    + rb"[\"']?\s*(?::|\|\|=|\?\?=|&&=|\+=|=)\s*"
    + rb"(?P<quote>[\"'`])(?P<value>(?:\\[^\r\n]|[^\r\n])*?)(?P=quote)"
)
TEMPLATE_EXPRESSION = re.compile(
    r"(?<!\$)\{\{-?\s*(?P<body>.*?)\s*-?\}\}", re.DOTALL
)
MARKUP_TAG_START = re.compile(
    rb"(?is)<\s*(?P<closing>/\s*)?(?P<tag>[A-Za-z_][A-Za-z0-9_.:-]*)\b"
)
CLI_RAW_SPECIAL_VALUE = re.compile(
    rb"(?i)--(?P<option>[A-Za-z0-9_.-]+)(?:=|[ \t]+)"
    rb"(?P<value>\"?(?:\$'(?:\\.|[^'])*'|\$\"(?:\\.|[^\"])*\"|"
    rb"'(?:\\.|[^'])*'|"
    rb"\\\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-]|"
    rb"\{(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-])\}))\"?)"
)
KIND_LINE = re.compile(
    r"(?im)^(?P<indent>[ \t]*)[\"']?kind[\"']?[ \t]*:(?P<value>[^\r\n]*)"
)
BRACKETED_ASSIGNMENT = re.compile(
    rb"(?i)(?<![A-Za-z0-9_.$])[A-Za-z_$][A-Za-z0-9_.$]*"
    rb"\[[ \t]*(?P<key_quote>[\"'])"
    rb"(?P<key>[A-Za-z0-9_.-]+)(?P=key_quote)[ \t]*\][ \t]*"
    rb"(?:\|\|=|\?\?=|&&=|\+=|=)[ \t]*"
    rb"(?P<value>[^\r\n]+)"
)
SAFE_INDIRECT_EXPRESSION_RE = re.compile(
    rb"(?i)^(?:process\.env(?:\.[A-Za-z_][A-Za-z0-9_]*|"
    rb"\[[\"'][A-Za-z_][A-Za-z0-9_]*[\"']\])|"
    rb"os\.environ\[[\"'][A-Za-z_][A-Za-z0-9_]*[\"']\]|"
    rb"[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\.|\?\.)[A-Za-z_$][A-Za-z0-9_$]*)+|"
    rb"[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\.|\?\.)[A-Za-z_$][A-Za-z0-9_$]*)*"
    rb"(?:\?\.)?\[[\"'][A-Za-z0-9_.-]+[\"']\])$"
)
HELM_VALUE_RE = re.compile(rb"(?s)^\{\{-?\s*(?P<body>.*?)\s*-?\}\}$")
AUTHORIZATION_VALUE_START = re.compile(
    rb"(?i)\bauthorization(?:(?:[\"'`]?\s*[:=])|(?:[\"'`]\s*,))\s*"
)

SIGNATURE_PATTERNS = {
    "private key": re.compile(
        rb"-----BEGIN (?:(?:[A-Z0-9 ]+ )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
    ),
    "GitHub to" + "ken": re.compile(
        rb"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
    ),
    "Slack to" + "ken": re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "Google API key": re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Stripe secret key": re.compile(rb"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    "JWT": re.compile(
        rb"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
    ),
    "authorization bearer value": re.compile(
        rb"(?i)authorization[\"'`]?\s*[:=]\s*[\"'`]?bearer\s+"
        rb"[A-Za-z0-9._~+/-]{4,}"
    ),
    "authorization basic value": re.compile(
        rb"(?i)authorization[\"'`]?\s*[:=]\s*[\"'`]?basic\s+"
        rb"[A-Za-z0-9+/=]{4,}"
    ),
    "authorization bearer call value": re.compile(
        rb"(?i)authorization[\"'`]\s*,\s*[\"'`]bearer\s+"
        rb"[A-Za-z0-9._~+/-]{4,}"
    ),
    "authorization basic call value": re.compile(
        rb"(?i)authorization[\"'`]\s*,\s*[\"'`]basic\s+[A-Za-z0-9+/=]{4,}"
    ),
    "npm auth value": re.compile(
        rb"(?im)^[ \t]*_auth[ \t]*=[ \t]*[\"'`]?[A-Za-z0-9+/=]{4,}"
    ),
    "embedded URL creden" + "tials": re.compile(
        rb"(?i)\b[a-z][a-z0-9+.-]{1,31}://[^\s/:@]*:(?!"
        + SAFE_REFERENCE
        + rb"@)[^\s/@]+@"
    ),
}

FORBIDDEN_NAMES = {
    ".env",
    ".env.local",
    ".netrc",
    "_netrc",
    "credentials.json",
    "service-account.json",
}
FORBIDDEN_SUFFIXES = {".key", ".p12", ".pfx", ".pem", ".jks"}


def git(*args: str, input_data: bytes | None = None) -> bytes:
    return subprocess.check_output(
        ["git", *args], cwd=ROOT, input=input_data, stderr=subprocess.DEVNULL
    )


def tracked_paths() -> list[str]:
    return git("ls-files", "-z").decode().rstrip("\0").split("\0")


def working_tree_blob(path: str) -> bytes:
    candidate = ROOT / path
    return os.readlink(candidate).encode() if candidate.is_symlink() else candidate.read_bytes()


def history_blobs() -> list[tuple[str, str]]:
    """Return every distinct blob/path pair reachable from every commit."""
    entries: set[tuple[str, str]] = set()
    for commit in git("rev-list", "--all").decode().splitlines():
        tree = git("ls-tree", "-r", "-z", "--full-tree", commit)
        for item in tree.rstrip(b"\0").split(b"\0"):
            if not item:
                continue
            metadata, separator, raw_path = item.partition(b"\t")
            fields = metadata.split()
            if separator and len(fields) == 3 and fields[1] == b"blob":
                entries.add(
                    (
                        fields[2].decode(),
                        raw_path.decode("utf-8", errors="surrogateescape"),
                    )
                )
    return sorted(entries)


def normalized_scalar(value: object) -> bytes | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return str(value).encode()
    if isinstance(value, bytes):
        return value.strip()
    if isinstance(value, str):
        return re.sub(rb"\s+", b" ", value.encode()).strip()
    return None


def scalar_looks_sensitive(value: object, *, strict: bool = False) -> bool:
    scalar = normalized_scalar(value)
    if not scalar:
        return False
    if SAFE_REFERENCE_RE.fullmatch(scalar) or DOCUMENTATION_PLACEHOLDER.fullmatch(scalar):
        return False
    return strict or len(re.sub(rb"\s+", b"", scalar)) >= 16


PYTHON_TYPE_ATOM = (
    rb"(?:str|bytes|int|float|bool|complex|object|None|Any|SecretStr|SecretBytes|"
    rb"(?:typing\.)?(?:Optional|Union|Literal|Annotated|ClassVar|Final|"
    rb"List|Dict|Tuple|Set|FrozenSet|Sequence|Mapping|Callable)\s*\[[^\r\n]+\]|"
    rb"(?:list|dict|tuple|set|frozenset|type)\s*\[[^\r\n]+\])"
)
PYTHON_TYPE_EXPRESSION = re.compile(
    PYTHON_TYPE_ATOM + rb"(?:\s*\|\s*" + PYTHON_TYPE_ATOM + rb")*"
)
PYTHON_USER_TYPE_ATOM = (
    rb"(?:[A-Za-z_][A-Za-z0-9_]*\.)*[A-Z][A-Za-z0-9_]*"
    rb"(?:\s*\[[^\r\n]+\])?"
)
PYTHON_ANNOTATION_ATOM = rb"(?:" + PYTHON_TYPE_ATOM + rb"|" + PYTHON_USER_TYPE_ATOM + rb")"
PYTHON_USER_TYPE_EXPRESSION = re.compile(
    PYTHON_ANNOTATION_ATOM
    + rb"(?:\s*\|\s*"
    + PYTHON_ANNOTATION_ATOM
    + rb")*"
)


def python_type_annotation_only(value: bytes) -> bool:
    annotation = value.strip()
    if len(annotation) >= 2 and annotation[:1] == annotation[-1:] \
            and annotation[:1] in {b'"', b"'"}:
        annotation = annotation[1:-1].strip()
    return PYTHON_TYPE_EXPRESSION.fullmatch(annotation) is not None


def python_user_type_annotation_only(value: bytes) -> bool:
    annotation = value.strip()
    if len(annotation) >= 2 and annotation[:1] == annotation[-1:] \
            and annotation[:1] in {b'"', b"'"}:
        annotation = annotation[1:-1].strip()
    return PYTHON_USER_TYPE_EXPRESSION.fullmatch(annotation) is not None


def python_name_is_code(data: bytes, position: int) -> bool:
    line_start = data.rfind(b"\n", 0, position) + 1
    try:
        row = data.count(b"\n", 0, position) + 1
        column = len(data[line_start:position].decode("utf-8"))
        for token in tokenize.tokenize(io.BytesIO(data).readline):
            if token.type == tokenize.NAME and token.start == (row, column):
                return True
            if token.start > (row, column):
                return False
    except (IndentationError, SyntaxError, UnicodeDecodeError, tokenize.TokenError):
        return False
    return False


@functools.lru_cache(maxsize=64)
def python_annotation_targets(
    data: bytes,
) -> tuple[tuple[int, int, bytes | None], ...]:
    try:
        source = data.decode("utf-8")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return ()
    targets: list[tuple[int, int, bytes | None]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
        ):
            if node.value is None:
                targets.append((node.target.lineno, node.target.col_offset, None))
                continue
            segment = ast.get_source_segment(source, node.value)
            targets.append(
                (
                    node.target.lineno,
                    node.target.col_offset,
                    segment.encode() if segment is not None else b"",
                )
            )
    return tuple(targets)


def python_annotation_at_position(
    data: bytes, position: int
) -> tuple[bool, bytes | None]:
    line_start = data.rfind(b"\n", 0, position) + 1
    row = data.count(b"\n", 0, position) + 1
    column = len(data[line_start:position])
    for target_row, target_column, initializer in python_annotation_targets(data):
        if (target_row, target_column) == (row, column):
            return True, initializer
    return False, None


def key_is_sensitive(value: object) -> bool:
    return (
        isinstance(value, str)
        and SENSITIVE_NAME_RE.fullmatch(value.encode()) is not None
    )


def key_allows_typed_scalar(value: object) -> bool:
    if not isinstance(value, str):
        return False
    normalized = re.sub(r"[^a-z0-9]", "", value.lower())
    return normalized.startswith(
        ("allow", "enable", "generate", "has", "require", "use")
    ) or normalized.endswith(
        ("count", "enabled", "expiration", "limit", "timeout", "ttl")
    )


def key_is_reference_field(value: object) -> bool:
    if not isinstance(value, str):
        return False
    normalized = re.sub(r"[^a-z0-9]", "", value.lower())
    return normalized.endswith(("id", "name", "ref", "reference")) or normalized in {
        "existingsecret",
        "imagepullsecrets",
        "secretproviderclass",
    }


def yaml_node_looks_sensitive(
    node: Node, *, strict: bool = False, allow_typed: bool = False
) -> bool:
    if isinstance(node, ScalarNode):
        if node.tag in {"tag:yaml.org,2002:bool", "tag:yaml.org,2002:null"}:
            return False
        if allow_typed and node.tag in {
            "tag:yaml.org,2002:bool",
            "tag:yaml.org,2002:float",
            "tag:yaml.org,2002:int",
            "tag:yaml.org,2002:timestamp",
        }:
            return False
        return scalar_looks_sensitive(node.value, strict=strict)
    if isinstance(node, (MappingNode, SequenceNode)):
        return False
    return False


def yaml_mapping_pairs(
    node: MappingNode, merging: set[int] | None = None
) -> list[tuple[str, Node]]:
    """Return scalar-key pairs with YAML merge keys expanded."""
    active = merging or set()
    identity = id(node)
    if identity in active:
        return []
    active.add(identity)
    merged_pairs: list[tuple[str, Node]] = []
    explicit_pairs: list[tuple[str, Node]] = []
    for key_node, value_node in node.value:
        if not isinstance(key_node, ScalarNode):
            continue
        if key_node.value != "<<":
            explicit_pairs.append((key_node.value, value_node))
            continue
        merged = (
            [value_node]
            if isinstance(value_node, MappingNode)
            else reversed(value_node.value)
            if isinstance(value_node, SequenceNode)
            else []
        )
        for candidate in merged:
            if isinstance(candidate, MappingNode):
                merged_pairs.extend(yaml_mapping_pairs(candidate, active))
    active.remove(identity)
    return merged_pairs + explicit_pairs


def yaml_object_has_sensitive_value(
    value: object, seen: set[int] | None = None
) -> bool:
    active = seen or set()
    if isinstance(value, (dict, list)):
        identity = id(value)
        if identity in active:
            return False
        active.add(identity)
    if isinstance(value, list):
        return any(yaml_object_has_sensitive_value(item, active) for item in value)
    if not isinstance(value, dict):
        return False

    kind = value.get("kind")
    if isinstance(kind, str) and kind.strip() == "Secret":
        for field in ("data", "stringData"):
            mapping = value.get(field)
            if isinstance(mapping, dict) and any(
                scalar_looks_sensitive(item, strict=True) for item in mapping.values()
            ):
                return True

    auths = value.get("auths")
    if isinstance(auths, dict):
        for registry in auths.values():
            if (
                isinstance(registry, dict)
                and "auth" in registry
                and scalar_looks_sensitive(registry.get("auth"), strict=True)
            ):
                return True

    environment = value.get("env")
    if isinstance(environment, list):
        for item in environment:
            if (
                isinstance(item, dict)
                and key_is_sensitive(item.get("name"))
                and scalar_looks_sensitive(item.get("value"), strict=True)
            ):
                return True

    for key, item in value.items():
        if (
            key_is_sensitive(key)
            and not key_is_reference_field(key)
            and not (
                isinstance(item, bool)
                or key_allows_typed_scalar(key)
                and isinstance(item, (int, float))
            )
            and scalar_looks_sensitive(item, strict=True)
        ):
            return True
        if yaml_object_has_sensitive_value(item, active):
            return True
    return False


def yaml_node_has_sensitive_value(node: Node, seen: set[int] | None = None) -> bool:
    active = seen or set()
    identity = id(node)
    if identity in active:
        return False
    active.add(identity)
    if isinstance(node, SequenceNode):
        return any(yaml_node_has_sensitive_value(item, active) for item in node.value)
    if not isinstance(node, MappingNode):
        return False

    fields = dict(yaml_mapping_pairs(node))
    kind = fields.get("kind")
    if isinstance(kind, ScalarNode) and kind.value.strip() == "Secret":
        for key in ("data", "stringData"):
            mapping = fields.get(key)
            if isinstance(mapping, MappingNode) and any(
                yaml_node_looks_sensitive(item, strict=True)
                for item in dict(yaml_mapping_pairs(mapping)).values()
            ):
                return True
    environment = fields.get("env")
    if isinstance(environment, SequenceNode):
        for item in environment.value:
            if not isinstance(item, MappingNode):
                continue
            item_fields = dict(yaml_mapping_pairs(item))
            name = item_fields.get("name")
            assigned = item_fields.get("value")
            if (
                isinstance(name, ScalarNode)
                and key_is_sensitive(name.value)
                and assigned is not None
                and yaml_node_looks_sensitive(assigned, strict=True)
            ):
                return True
    for key, value_node in fields.items():
        if (
            key_is_sensitive(key)
            and not key_is_reference_field(key)
            and yaml_node_looks_sensitive(
                value_node,
                strict=True,
                allow_typed=key_allows_typed_scalar(key),
            )
        ):
            return True
        if yaml_node_has_sensitive_value(value_node, active):
            return True
    return False


def helm_keyword(match: re.Match[str]) -> str:
    body = match.group("body").strip()
    return body.split(maxsplit=1)[0] if body else ""


def split_helm_pipeline(body: str) -> list[str]:
    segments: list[str] = []
    quote: str | None = None
    start = 0
    cursor = 0
    while cursor < len(body):
        character = body[cursor]
        if quote is not None:
            if character == "\\":
                cursor += 2
                continue
            if character == quote:
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character == "|":
            segments.append(body[start:cursor])
            start = cursor + 1
        cursor += 1
    segments.append(body[start:])
    return segments


def split_helm_arguments(segment: str) -> list[str]:
    closing = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    quote: str | None = None
    start: int | None = None
    arguments: list[str] = []
    cursor = 0
    while cursor < len(segment):
        character = segment[cursor]
        if quote is not None:
            if character == "\\":
                cursor += 2
                continue
            if character == quote:
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character in closing:
            stack.append(closing[character])
        elif stack and character == stack[-1]:
            stack.pop()
        elif character.isspace() and not stack:
            if start is not None:
                arguments.append(segment[start:cursor])
                start = None
            cursor += 1
            continue
        if start is None:
            start = cursor
        cursor += 1
    if start is not None:
        arguments.append(segment[start:])
    return arguments


def helm_value_literals(body: str) -> list[str]:
    literal = re.compile(r"(?P<quote>[\"'])(?P<value>(?:\\.|(?!\1).)*)(?P=quote)")
    number = re.compile(r"[-+]?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?")
    leading_control_literals = {
        "contains": 1,
        "date": 1,
        "hasPrefix": 1,
        "hasSuffix": 1,
        "join": 1,
        "regexMatch": 1,
        "regexReplaceAll": 1,
        "regexReplaceAllLiteral": 1,
        "replace": 1,
        "required": 1,
        "split": 1,
        "splitList": 1,
        "trimAll": 1,
        "trimPrefix": 1,
        "trimSuffix": 1,
    }
    numeric_value_functions = {
        "coalesce",
        "default",
        "printf",
        "quote",
        "squote",
        "ternary",
        "toString",
    }
    indirect_functions = {
        "env",
        "fail",
        "get",
        "hasKey",
        "include",
        "index",
        "lookup",
        "pluck",
        "readFile",
        "template",
    }
    values: list[str] = []
    for index, segment in enumerate(split_helm_pipeline(body)):
        stripped = segment.strip()
        if index == 0 and number.fullmatch(stripped):
            values.append(stripped)
            continue
        literals = [item.group("value") for item in literal.finditer(stripped)]
        if index == 0 and stripped.startswith(("\"", "'")):
            values.extend(literals)
            continue
        function = re.match(r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b", stripped)
        if function is None:
            continue
        name = function.group("name")
        arguments = split_helm_arguments(stripped)
        if name in indirect_functions:
            for argument in arguments[1:]:
                container = argument.strip()
                if not (container.startswith("(") and container.endswith(")")):
                    continue
                tokens = split_helm_arguments(container[1:-1].strip())
                if not tokens:
                    continue
                if tokens[0] == "dict":
                    candidates = tokens[2::2]
                elif tokens[0] in {"list", "tuple"}:
                    candidates = tokens[1:]
                else:
                    continue
                for candidate in candidates:
                    item = literal.fullmatch(candidate)
                    if item is not None:
                        values.append(item.group("value"))
                    elif number.fullmatch(candidate):
                        values.append(candidate)
            continue
        if name == "dig":
            default_index = -1 if index > 0 else -2
            if len(arguments) >= abs(default_index):
                candidate = arguments[default_index]
                default = literal.fullmatch(candidate)
                if default is not None:
                    values.append(default.group("value"))
                elif number.fullmatch(candidate):
                    values.append(candidate)
            continue
        if name == "printf":
            if not literals:
                continue
            format_text = literals[0]
            literal_text = re.sub(
                r"%(?:\[[0-9]+\])?[-+#0 ']*[0-9]*(?:\.[0-9]+)?[a-zA-Z%]",
                "",
                format_text,
            )
            if literal_text:
                values.append(format_text)
            values.extend(literals[1:])
            values.extend(
                argument for argument in arguments[1:] if number.fullmatch(argument)
            )
            continue
        if name == "dict":
            for candidate in arguments[2::2]:
                item = literal.fullmatch(candidate)
                if item is not None:
                    values.append(item.group("value"))
                elif number.fullmatch(candidate):
                    values.append(candidate)
            continue
        values.extend(literals[leading_control_literals.get(name, 0) :])
        if name in numeric_value_functions:
            values.extend(
                argument for argument in arguments[1:] if number.fullmatch(argument)
            )
    return list(dict.fromkeys(values))


def first_helm_conditional(
    source: str,
) -> tuple[int, int, list[str]] | None:
    tokens = list(TEMPLATE_EXPRESSION.finditer(source))
    branch_openers = {"if", "with", "range"}
    opening_index = next(
        (
            index
            for index, token in enumerate(tokens)
            if helm_keyword(token) in branch_openers
        ),
        None,
    )
    if opening_index is None:
        return None
    opening = tokens[opening_index]
    depth = 1
    nested_openers = {"if", "range", "with", "define", "block"}
    branch_start = opening.end()
    branches: list[str] = []
    has_alternate = False
    for token in tokens[opening_index + 1 :]:
        keyword = helm_keyword(token)
        if keyword in nested_openers:
            depth += 1
        elif keyword == "end":
            depth -= 1
            if depth == 0:
                branches.append(source[branch_start : token.start()])
                if not has_alternate:
                    branches.append("")
                return opening.start(), token.end(), branches
        elif keyword == "else" and depth == 1:
            branches.append(source[branch_start : token.start()])
            branch_start = token.end()
            has_alternate = True
    return None


def contains_structured_sensitive_value(
    data: bytes, *, allow_python_annotations: bool = False
) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False

    def sanitize_templates(source: str) -> str:
        variable_literals: dict[str, list[str]] = {}

        def replace_template(match: re.Match[str]) -> str:
            body = match.group("body").strip()
            assignment = re.match(
                r"(?P<name>\$[A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*(?P<value>.+?)\s*$",
                body,
            )
            if assignment is not None:
                literals = helm_value_literals(assignment.group("value"))
                if literals:
                    variable_literals[assignment.group("name")] = literals
                else:
                    variable_literals.pop(assignment.group("name"), None)
                return ""
            if body in variable_literals:
                literal = "".join(variable_literals[body]).replace("'", "''")
                return f"'{literal}'"
            line_start = source.rfind("\n", 0, match.start()) + 1
            line_end = source.find("\n", match.end())
            if line_end < 0:
                line_end = len(source)
            if not source[line_start : match.start()].strip() and not source[
                match.end() : line_end
            ].strip():
                return ""
            keyword = body.split(maxsplit=1)[0] if body else ""
            if keyword in {"if", "else", "end", "range", "with", "define", "block"}:
                return "\n"
            if body.startswith("/*") and body.endswith("*/"):
                return ""
            literals = helm_value_literals(body)
            if literals:
                literal = "".join(literals).replace("'", "''")
                return f"'{literal}'"
            return "${TEMPLATE_REFERENCE}"

        return TEMPLATE_EXPRESSION.sub(replace_template, source)

    def branch_coverage(choices: tuple[int, ...]) -> set[tuple[int, ...]]:
        coverage = {(index, choice) for index, choice in enumerate(choices)}
        coverage.update(
            (left, choices[left], right, choices[right])
            for left in range(len(choices))
            for right in range(left + 1, len(choices))
        )
        coverage.update(
            (
                left,
                choices[left],
                middle,
                choices[middle],
                right,
                choices[right],
            )
            for left in range(len(choices))
            for middle in range(left + 1, len(choices))
            for right in range(middle + 1, len(choices))
        )
        coverage.update(
            (
                first,
                choices[first],
                second,
                choices[second],
                third,
                choices[third],
                fourth,
                choices[fourth],
            )
            for first in range(len(choices))
            for second in range(first + 1, len(choices))
            for third in range(second + 1, len(choices))
            for fourth in range(third + 1, len(choices))
        )
        return coverage

    def select_pairwise(
        states: list[tuple[str, tuple[int, ...]]], limit: int
    ) -> list[tuple[str, tuple[int, ...]]]:
        if len(states) <= limit:
            return states
        coverages = [branch_coverage(choices) for _, choices in states]
        uncovered = set().union(*coverages)
        selected: list[tuple[str, tuple[int, ...]]] = []
        remaining = list(range(len(states)))
        while uncovered and remaining and len(selected) < limit:
            best = max(remaining, key=lambda item: len(coverages[item] & uncovered))
            selected.append(states[best])
            uncovered.difference_update(coverages[best])
            remaining.remove(best)
        return selected

    branch_states = [(text, ())]
    while any(first_helm_conditional(source) for source, _ in branch_states):
        expanded: list[tuple[str, tuple[int, ...]]] = []
        for source, choices in branch_states:
            conditional = first_helm_conditional(source)
            if conditional is None:
                expanded.append((source, choices))
                continue
            start, end, branches = conditional
            before, after = source[:start], source[end:]
            expanded.extend(
                (before + branch + after, choices + (branch_index,))
                for branch_index, branch in enumerate(branches)
            )
        distinct = {
            source: choices for source, choices in reversed(expanded)
        }
        branch_states = select_pairwise(list(distinct.items()), MAX_HELM_VARIANTS)
    branch_sources = [source for source, _ in branch_states]
    candidates: list[str] = []
    for source in branch_sources:
        templated = sanitize_templates(source)
        candidates.append(templated)
        if re.search(r"(?im)^[ \t]*[\"']?kind[\"']?[ \t]*:[ \t]*[\"']?Secret[\"']?", templated):
            def preserve_secret_kind(match: re.Match[str]) -> str:
                value = match.group("value")
                comparable = value.split("#", 1)[0].strip().strip("\"'")
                if comparable == "Secret":
                    return match.group(0)
                return f'{match.group("indent")}alternateKind:{value}'

            candidates.append(KIND_LINE.sub(preserve_secret_kind, templated))
    for candidate in dict.fromkeys(candidates):
        source_lines = candidate.splitlines(keepends=True)
        candidate_bytes = candidate.encode()
        byte_offset = 0
        for index, line in enumerate(source_lines):
            annotation_position = (
                byte_offset + len(line) - len(line.lstrip(" \t"))
            )
            annotation = re.match(
                r"^(?P<prefix>[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*:[ \t]*)"
                r"(?P<type>[^#\r\n]+?)(?P<suffix>[ \t]*(?:#.*)?(?:\r?\n)?$)",
                line,
            )
            ast_annotation, ast_initializer = (
                python_annotation_at_position(candidate_bytes, annotation_position)
                if allow_python_annotations
                and candidate_bytes == data
                and annotation is not None
                and key_is_sensitive(
                    annotation.group("prefix").split(":", 1)[0].strip()
                )
                else (False, None)
            )
            if (
                allow_python_annotations
                and annotation is not None
                and python_name_is_code(
                    candidate_bytes,
                    annotation_position,
                )
                and key_is_sensitive(
                    annotation.group("prefix").split(":", 1)[0].strip()
                )
                and (
                    ast_annotation and ast_initializer is None
                    or
                    python_type_annotation_only(
                        annotation.group("type").strip().encode()
                    )
                    or python_user_type_annotation_only(
                        annotation.group("type").strip().encode()
                    )
                )
            ):
                source_lines[index] = (
                    annotation.group("prefix")
                    + "${PYTHON_TYPE_ANNOTATION}"
                    + annotation.group("suffix")
                )
            byte_offset += len(line.encode())
        candidate = "".join(source_lines)
        documents = re.split(r"(?m)^---[ \t]*(?:#.*)?$", candidate)
        for document in documents:
            try:
                node = yaml.compose(document)
                if node is not None and yaml_node_has_sensitive_value(node):
                    return True
            except yaml.YAMLError:
                pass
            try:
                if yaml_object_has_sensitive_value(yaml.safe_load(document)):
                    return True
            except yaml.YAMLError:
                pass
    return False


def contains_toml_multiline_sensitive_value(data: bytes) -> bool:
    for match in TOML_MULTILINE_ASSIGNMENT.finditer(data):
        delimiter = match.group("delimiter")
        start = match.end()
        cursor = start
        while True:
            close = data.find(delimiter, cursor)
            if close < 0:
                break
            if delimiter == b'"""':
                backslashes = 0
                position = close - 1
                while position >= start and data[position : position + 1] == b"\\":
                    backslashes += 1
                    position -= 1
                if backslashes % 2:
                    cursor = close + 1
                    continue
            run_end = close
            quote_character = delimiter[:1]
            while data[run_end : run_end + 1] == quote_character:
                run_end += 1
            if run_end - close > 3:
                close = run_end - 3
            if scalar_looks_sensitive(data[start:close], strict=True):
                return True
            break
    return False


def balanced_assignment_value(data: bytes, start: int, fallback: bytes) -> bytes:
    quote_opener = data[start : start + 1]
    if quote_opener in {b'"', b"'", b"`"}:
        local_cursor = 1
        local_closing = False
        while local_cursor < len(fallback):
            if fallback[local_cursor : local_cursor + 1] == b"\\":
                local_cursor += 2
                continue
            if fallback[local_cursor : local_cursor + 1] == quote_opener:
                local_closing = True
                break
            local_cursor += 1
        if not local_closing:
            cursor = start + 1
            while cursor < len(data):
                if data[cursor : cursor + 1] == b"\\":
                    cursor += 2
                    continue
                if data[cursor : cursor + 1] == quote_opener:
                    return data[start : cursor + 1].strip()
                if data[cursor : cursor + 1] in b"\r\n" and quote_opener != b"`":
                    break
                cursor += 1
    opener_offset = 0
    opener = data[start : start + 1]
    closing = {b"(": ord(")"), b"[": ord("]"), b"{": ord("}")}
    if opener not in closing:
        call = re.fullmatch(rb"[A-Za-z_][A-Za-z0-9_.]*\s*\(", fallback)
        if call is None:
            return fallback
        opener_offset = fallback.rfind(b"(")
        opener = b"("
    expression_start = start + opener_offset
    stack = [closing[opener]]
    quote: int | None = None
    cursor = expression_start + 1
    while cursor < len(data):
        character = data[cursor]
        if quote is not None:
            if character == ord("\\"):
                cursor += 2
                continue
            if character == quote:
                quote = None
        elif character in (ord('"'), ord("'"), ord("`")):
            quote = character
        elif character in (ord("("), ord("["), ord("{")):
            stack.append({ord("("): ord(")"), ord("["): ord("]"), ord("{"): ord("}")}[character])
        elif character in (ord(")"), ord("]"), ord("}")) and character == stack[-1]:
            stack.pop()
            if not stack:
                return data[start : cursor + 1].strip()
        cursor += 1
    return data[start:].strip()


def contains_unquoted_equals_sensitive_value(data: bytes) -> bool:
    declaration_commands = {"export", "readonly", "local", "declare", "typeset"}
    for line in shell_logical_lines(data):
        if b"=" not in line or SENSITIVE_NAME_SEARCH.search(line) is None:
            continue
        try:
            fields = shlex.split(line.decode("utf-8"), comments=True)
        except (UnicodeDecodeError, ValueError):
            continue
        if not fields:
            continue
        declaration = fields[0] in declaration_commands
        cursor = 1 if declaration else 0
        if declaration:
            while cursor < len(fields) and fields[cursor].startswith("-"):
                cursor += 1
        elif "=" not in fields[0]:
            continue
        while cursor < len(fields):
            field = fields[cursor]
            key, separator, value = field.partition("=")
            if not separator:
                if declaration:
                    cursor += 1
                    continue
                break
            if key_is_sensitive(key) and assignment_expression_looks_sensitive(
                value.encode()
            ):
                return True
            cursor += 1
    for match in UNQUOTED_EQUALS_ASSIGNMENT.finditer(data):
        value = balanced_assignment_value(
            data, match.start("value"), match.group("value").strip()
        )
        comment = re.search(rb"[ \t]+[;#]", value)
        if comment:
            value = value[: comment.start()].rstrip()
        value = value.rstrip(b"; ")
        if assignment_expression_looks_sensitive(value):
            return True
    return False


def shell_logical_lines(data: bytes) -> list[bytes]:
    def has_sensitive_option_value_start(
        line: bytes, value_starts: tuple[bytes, ...]
    ) -> bool:
        for match in re.finditer(
            rb"--(?P<option>[A-Za-z0-9_.-]+)(?:=|[ \t]+)(?P<value>[^\r\n]*)",
            line,
        ):
            if not key_is_sensitive(match.group("option").decode(errors="ignore")):
                continue
            if match.group("value").lstrip().startswith(value_starts):
                return True
        return False

    def has_unclosed_substitution(line: bytes) -> bool:
        depth = 0
        quote: int | None = None
        cursor = 0
        while cursor < len(line):
            character = line[cursor]
            if character == ord("\\"):
                cursor += 2
                continue
            if quote == ord("'"):
                if character == quote:
                    quote = None
            elif character == ord("'"):
                quote = character
            elif line[cursor : cursor + 2] == b"$(":
                depth += 1
                cursor += 1
            elif depth and character == ord("("):
                depth += 1
            elif depth and character == ord(")"):
                depth -= 1
            cursor += 1
        return depth > 0

    def has_parsed_sensitive_option_value(line: bytes) -> bool:
        try:
            source = line.decode("utf-8")
        except UnicodeDecodeError:
            return False
        quote: str | None = None
        quote_start = 0
        cursor = 0
        while cursor < len(source):
            character = source[cursor]
            if quote == "'":
                if character == quote:
                    quote = None
            elif quote == '"':
                if character == "\\":
                    cursor += 2
                    continue
                if character == quote:
                    quote = None
            elif character == "\\":
                cursor += 2
                continue
            elif character in {'"', "'"}:
                quote = character
                quote_start = cursor
            cursor += 1
        if quote is None:
            return False
        try:
            fields = shlex.split(source[:quote_start], comments=True)
        except ValueError:
            return False
        if not fields or not fields[-1].startswith("--"):
            return False
        option, _, _ = fields[-1][2:].partition("=")
        return key_is_sensitive(option)

    logical: list[bytes] = []
    pending = b""
    for physical in data.splitlines():
        stripped = physical.rstrip()
        trailing_backslashes = len(stripped) - len(stripped.rstrip(b"\\"))
        if trailing_backslashes % 2:
            continued = pending + stripped[:-1]
            try:
                shlex.split(continued.decode("utf-8"), comments=True)
            except (UnicodeDecodeError, ValueError):
                if has_sensitive_option_value_start(
                    continued, (b'"', b"'", b"`")
                ) or has_parsed_sensitive_option_value(continued):
                    pending = continued
                    continue
                logical.append(continued)
                pending = b""
                continue
            pending = continued
            continue
        candidate = pending + physical
        try:
            shlex.split(candidate.decode("utf-8"), comments=True)
            incomplete_quote = False
        except ValueError:
            incomplete_quote = True
        except UnicodeDecodeError:
            incomplete_quote = False
        incomplete_sensitive_value = incomplete_quote and (
            has_sensitive_option_value_start(candidate, (b'"', b"'", b"`"))
            or has_parsed_sensitive_option_value(candidate)
            or re.search(
                rb"(?i)(?:^|[ \t])" + SENSITIVE_NAME + rb"[ \t]*=[ \t]*[\"'`]",
                candidate,
            )
            is not None
        )
        incomplete_sensitive_substitution = has_unclosed_substitution(
            candidate
        ) and has_sensitive_option_value_start(candidate, (b"$(",))
        if incomplete_sensitive_value or incomplete_sensitive_substitution:
            pending = candidate + b" "
            continue
        logical.append(candidate)
        pending = b""
    if pending:
        logical.append(pending)
    return logical


def contains_docker_space_sensitive_value(data: bytes) -> bool:
    for match in DOCKER_SPACE_ASSIGNMENT.finditer(data):
        value = match.group("value").strip()
        comment = re.search(rb"[ \t]+#", value)
        if comment:
            value = value[: comment.start()].rstrip()
        if assignment_expression_looks_sensitive(value):
            return True
    for line in data.splitlines():
        instruction = re.match(rb"(?i)^[ \t]*ENV[ \t]+(?P<body>.+)$", line)
        if instruction is None:
            continue
        try:
            fields = shlex.split(instruction.group("body").decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue
        for field in fields:
            key, separator, value = field.partition("=")
            if (
                separator
                and key_is_sensitive(key)
                and assignment_expression_looks_sensitive(value.encode())
            ):
                return True
    return False


def shell_substitution_is_indirect(value: bytes) -> bool:
    substitution = re.fullmatch(
        rb"(?s)\$\(\s*(?P<body>.*?)\s*\)|`\s*(?P<legacy>.*?)\s*`",
        value,
    )
    if substitution is None:
        return False
    captured = substitution.group("body")
    command = (
        captured if captured is not None else substitution.group("legacy") or b""
    ).strip()
    if b"\n" in command or b"\r" in command or b"$(" in command or b"`" in command:
        return False
    try:
        literal_marker = "__ADERESO_AUDIT_LITERAL__"
        command_text = command.decode()

        def preserve_ansi_literal(match: re.Match[str]) -> str:
            try:
                decoded = codecs.decode(match.group(1), "unicode_escape")
            except UnicodeDecodeError:
                decoded = match.group(1)
            return shlex.quote(literal_marker + decoded)

        command_text = re.sub(
            r"\$'((?:\\.|[^'])*)'", preserve_ansi_literal, command_text
        )
        command_text = re.sub(
            r"'(\$[^']*)'",
            lambda match: shlex.quote(literal_marker + match.group(1)),
            command_text,
        )
        command_text = re.sub(
            r"\\(\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-]|"
            r"\{(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-])\}))",
            lambda match: literal_marker + match.group(1),
            command_text,
        )
        lexer = shlex.shlex(
            command_text, posix=True, punctuation_chars=";&|"
        )
        lexer.whitespace_split = True
        lexer.commenters = ""
        fields = list(lexer)
    except (UnicodeDecodeError, ValueError):
        return False
    if not fields or any(set(field) <= set(";&|") for field in fields):
        return False
    executable = Path(fields[0]).name
    if executable in {"echo", "printf"}:
        arguments = [
            (
                field.removeprefix(literal_marker),
                field.startswith(literal_marker),
            )
            for field in fields[1:]
        ]
        if executable == "echo":
            while (
                arguments
                and not arguments[0][1]
                and re.fullmatch(r"-[neE]+", arguments[0][0])
            ):
                arguments = arguments[1:]
        elif arguments[:1] == [("-v", False)] and len(arguments) >= 2:
            return True
        if arguments[:1] == [("--", False)]:
            arguments = arguments[1:]
        if executable == "printf" and arguments:
            static_format = re.sub(
                r"%(?:\[[0-9]+\])?[-+#0 ']*[0-9]*(?:\.[0-9]+)?[a-zA-Z%]",
                "",
                arguments[0][0],
            )
            static_format = re.sub(
                r"\\(?:[abfnrtv]|0[0-7]{0,3}|x0[aAdD])", "", static_format
            )
            arguments = (
                [(static_format, arguments[0][1])] if static_format else []
            ) + arguments[1:]
        return all(
            not argument
            or not forced_literal
            and (
                argument == SHELL_REFERENCE_MARKER
                or SAFE_REFERENCE_RE.fullmatch(argument.encode())
            )
            for argument, forced_literal in arguments
        )
    fields = [field.removeprefix(literal_marker) for field in fields]
    return bool(
        executable == "pass"
        and len(fields) > 1
        and fields[1]
        not in {"cp", "edit", "generate", "git", "grep", "init", "insert", "mv", "rm"}
        or executable == "op"
        and fields[1:2] == ["read"]
        or executable == "vault"
        and (fields[1:2] == ["read"] or fields[1:3] == ["kv", "get"])
        or executable == "secret-tool"
        and fields[1:2] == ["lookup"]
        or executable == "security"
        and len(fields) > 1
        and fields[1].startswith("find-")
        or executable == "gcloud"
        and fields[1:4] == ["secrets", "versions", "access"]
        or executable == "aws"
        and fields[1:3] == ["secretsmanager", "get-secret-value"]
        or executable == "cat"
        and len(fields) == 2
        and fields[1].startswith("/run/secrets/")
    )


def contains_raw_shell_cli_literal(line: bytes) -> bool:
    for match in CLI_RAW_SPECIAL_VALUE.finditer(line):
        if not key_is_sensitive(match.group("option").decode(errors="ignore")):
            continue
        value = match.group("value")
        if value.startswith(b'"') and value.endswith(b'"'):
            value = value[1:-1]
        forced_literal = False
        if value.startswith(b"$'") and value.endswith(b"'"):
            try:
                literal = codecs.decode(value[2:-1], "unicode_escape").encode()
            except (UnicodeDecodeError, UnicodeEncodeError):
                literal = value[2:-1]
            forced_literal = True
        elif value.startswith(b'$"') and value.endswith(b'"'):
            literal = value[2:-1]
            try:
                preserved = preserve_shell_references(literal.decode())
            except UnicodeDecodeError:
                preserved = ""
            if SHELL_REFERENCE_MARKER in preserved:
                static = preserved.replace(SHELL_REFERENCE_MARKER, "")
                if not static:
                    continue
                if scalar_looks_sensitive(static.encode(), strict=True):
                    return True
        elif value.startswith(b"'") and value.endswith(b"'"):
            literal = value[1:-1]
            forced_literal = True
        else:
            literal = value[2:]
        if forced_literal and literal.startswith(b"$"):
            literal = literal[1:]
        if scalar_looks_sensitive(literal, strict=True):
            return True
    return False


def group_unquoted_command_substitutions(source: str) -> str:
    grouped: list[str] = []
    cursor = 0
    quote: str | None = None
    while cursor < len(source):
        character = source[cursor]
        if character == "\\":
            grouped.append(source[cursor : cursor + 2])
            cursor += 2
            continue
        if quote is not None:
            grouped.append(character)
            if character == quote:
                quote = None
            cursor += 1
            continue
        if character in {"'", '"'}:
            quote = character
            grouped.append(character)
            cursor += 1
            continue
        if character == "`":
            end = cursor + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == "`":
                    end += 1
                    break
                end += 1
            grouped.append(shlex.quote(source[cursor:end]))
            cursor = end
            continue
        if source[cursor : cursor + 2] == "$(":
            end = cursor + 2
            depth = 1
            inner_quote: str | None = None
            while end < len(source) and depth:
                item = source[end]
                if item == "\\":
                    end += 2
                    continue
                if inner_quote is not None:
                    if item == inner_quote:
                        inner_quote = None
                elif item in {"'", '"', "`"}:
                    inner_quote = item
                elif item == "(":
                    depth += 1
                elif item == ")":
                    depth -= 1
                end += 1
            grouped.append(shlex.quote(source[cursor:end]))
            cursor = end
            continue
        grouped.append(character)
        cursor += 1
    return "".join(grouped)


SHELL_REFERENCE_MARKER = "__ADERESO_AUDIT_SHELL_REFERENCE__"


def preserve_shell_references(source: str) -> str:
    preserved: list[str] = []
    cursor = 0
    single_quoted = False
    reference = re.compile(
        r"\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-]|"
        r"\{(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-]|"
        r"[A-Za-z_][A-Za-z0-9_]*(?:(?:#{1,2}|%{1,2})[^}\r\n]*|"
        r"\^{1,2}|,{1,2}|/{1,2}(?:\\.|[^/}\r\n])+/|"
        r":(?![-=?+])[^}\r\n]+|@[A-Za-z]))\})"
    )
    while cursor < len(source):
        character = source[cursor]
        if character == "\\":
            preserved.append(source[cursor : cursor + 2])
            cursor += 2
            continue
        if character == "'":
            single_quoted = not single_quoted
            preserved.append(character)
            cursor += 1
            continue
        if not single_quoted and source[cursor : cursor + 2] == '$"':
            preserved.append('"')
            cursor += 2
            continue
        match = None if single_quoted else reference.match(source, cursor)
        if match is not None:
            preserved.append(SHELL_REFERENCE_MARKER)
            cursor = match.end()
            continue
        preserved.append(character)
        cursor += 1
    return "".join(preserved)


def expand_shell_ansi_c_quotes(source: str) -> str:
    def expand(match: re.Match[str]) -> str:
        try:
            decoded = codecs.decode(match.group(1), "unicode_escape")
        except UnicodeDecodeError:
            decoded = match.group(1)
        return shlex.quote(decoded)

    return re.sub(r"\$'((?:\\.|[^'])*)'", expand, source)


def split_env_string(source: str) -> list[str]:
    escaped: list[str] = []
    cursor = 0
    escape_values = {
        "_": " ",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "f": "\f",
    }
    while cursor < len(source):
        if source[cursor] != "\\" or cursor + 1 >= len(source):
            escaped.append(source[cursor])
            cursor += 1
            continue
        following = source[cursor + 1]
        if following == "c":
            break
        if following in escape_values:
            escaped.append(escape_values[following])
        else:
            escaped.extend(("\\", following))
        cursor += 2
    return shlex.split("".join(escaped))


def cli_value_is_matching_metavariable(value: str, option: str) -> bool:
    unwrapped = value
    if len(value) >= 2 and (value[0], value[-1]) in {
        ("<", ">"),
        ("[", "]"),
        ("{", "}"),
    }:
        unwrapped = value[1:-1]
    expected = re.sub(r"[.-]+", "_", option).upper()
    return unwrapped == expected and re.fullmatch(r"[A-Z][A-Z0-9_]*", unwrapped) is not None


def contains_cli_sensitive_value(
    data: bytes, *, allow_documentation_prose: bool = False
) -> bool:
    for line in shell_logical_lines(data):
        if b"--" not in line:
            continue
        if contains_raw_shell_cli_literal(line):
            return True
        try:
            fields = shlex.split(
                preserve_shell_references(
                    expand_shell_ansi_c_quotes(
                        group_unquoted_command_substitutions(line.decode("utf-8"))
                    )
                ),
                comments=True,
            )
        except (UnicodeDecodeError, ValueError):
            continue
        if fields:
            command_fields = fields
            while command_fields:
                wrapper = Path(command_fields[0]).name
                if wrapper == "env":
                    command_index = 1
                    split_fields: list[str] | None = None
                    while command_index < len(command_fields):
                        field = command_fields[command_index]
                        if field == "--":
                            command_index += 1
                            break
                        split_string: str | None = None
                        remaining_index = command_index + 1
                        if field.startswith("--split-string="):
                            split_string = field.partition("=")[2]
                        elif field.startswith("-S") and field != "-S":
                            split_string = field[2:]
                        elif field in {"-S", "--split-string"}:
                            if remaining_index < len(command_fields):
                                split_string = command_fields[remaining_index]
                                remaining_index += 1
                            else:
                                split_fields = []
                                break
                        if split_string is not None:
                            try:
                                split_fields = split_env_string(split_string) + command_fields[
                                    remaining_index:
                                ]
                            except ValueError:
                                split_fields = []
                            break
                        if field in {
                            "-C",
                            "-u",
                            "--chdir",
                            "--unset",
                        }:
                            command_index += 2
                            continue
                        if field.startswith("-") or re.fullmatch(
                            r"[A-Za-z_][A-Za-z0-9_]*=.*", field
                        ):
                            command_index += 1
                            continue
                        break
                    command_fields = (
                        split_fields
                        if split_fields is not None
                        else command_fields[command_index:]
                    )
                    continue
                if wrapper == "command":
                    command_index = 1
                    while command_index < len(command_fields) and command_fields[
                        command_index
                    ] in {"-p", "--"}:
                        command_index += 1
                    if command_index < len(command_fields) and command_fields[
                        command_index
                    ] in {"-v", "-V"}:
                        command_fields = []
                    else:
                        command_fields = command_fields[command_index:]
                    continue
                if wrapper == "exec":
                    command_index = 1
                    while command_index < len(command_fields):
                        option = command_fields[command_index]
                        if option == "--":
                            command_index += 1
                            break
                        if option == "-a" and command_index + 1 < len(command_fields):
                            command_index += 2
                            continue
                        if (
                            option.startswith("-")
                            and option[1:]
                            and set(option[1:]) <= {"c", "l"}
                        ):
                            command_index += 1
                            continue
                        break
                    command_fields = command_fields[command_index:]
                    continue
                if wrapper == "sudo":
                    command_index = 1
                    sudo_value_options = {
                        "-C",
                        "-D",
                        "-g",
                        "-h",
                        "-p",
                        "-R",
                        "-r",
                        "-T",
                        "-t",
                        "-u",
                        "--chdir",
                        "--close-from",
                        "--group",
                        "--host",
                        "--prompt",
                        "--role",
                        "--type",
                        "--user",
                    }
                    while command_index < len(command_fields):
                        option = command_fields[command_index]
                        if option == "--":
                            command_index += 1
                            break
                        if option in sudo_value_options:
                            command_index += 2
                            continue
                        if option.startswith("-") or re.fullmatch(
                            r"[A-Za-z_][A-Za-z0-9_]*=.*", option
                        ):
                            command_index += 1
                            continue
                        break
                    command_fields = command_fields[command_index:]
                    continue
                if wrapper == "timeout":
                    command_index = 1
                    while command_index < len(command_fields):
                        option = command_fields[command_index]
                        if option == "--":
                            command_index += 1
                            break
                        if option in {"-k", "-s", "--kill-after", "--signal"}:
                            command_index += 2
                            continue
                        if option.startswith("-"):
                            command_index += 1
                            continue
                        break
                    if command_index < len(command_fields):
                        command_index += 1
                    command_fields = command_fields[command_index:]
                    continue
                if wrapper == "nice":
                    command_index = 1
                    while command_index < len(command_fields):
                        option = command_fields[command_index]
                        if option == "--":
                            command_index += 1
                            break
                        if option in {"-n", "--adjustment"}:
                            command_index += 2
                            continue
                        if option.startswith("-"):
                            command_index += 1
                            continue
                        break
                    command_fields = command_fields[command_index:]
                    continue
                if wrapper == "nohup":
                    command_index = 1
                    while command_index < len(command_fields):
                        option = command_fields[command_index]
                        if option == "--":
                            command_index += 1
                            break
                        if option.startswith("-"):
                            command_index += 1
                            continue
                        break
                    command_fields = command_fields[command_index:]
                    continue
                if wrapper == "setsid":
                    command_index = 1
                    while command_index < len(command_fields):
                        option = command_fields[command_index]
                        if option == "--":
                            command_index += 1
                            break
                        if option.startswith("-"):
                            command_index += 1
                            continue
                        break
                    command_fields = command_fields[command_index:]
                    continue
                if wrapper == "time":
                    command_index = 1
                    while command_index < len(command_fields):
                        option = command_fields[command_index]
                        if option == "--":
                            command_index += 1
                            break
                        if option in {"-f", "-o", "--format", "--output"}:
                            command_index += 2
                            continue
                        if option.startswith("-"):
                            command_index += 1
                            continue
                        break
                    command_fields = command_fields[command_index:]
                    continue
                break
            executable = Path(command_fields[0]).name if command_fields else ""
            if executable in {"bash", "dash", "ksh", "sh", "zsh"}:
                for option_index, option in enumerate(command_fields[1:], start=1):
                    if option.startswith("-") and "c" in option[1:]:
                        command_index = option_index + 1
                        if (
                            command_index < len(command_fields)
                            and command_fields[command_index] == "--"
                        ):
                            command_index += 1
                        if command_index < len(
                            command_fields
                        ) and contains_cli_sensitive_value(
                            command_fields[command_index].encode()
                        ):
                            return True
            elif executable == "eval" and len(command_fields) > 1:
                if contains_cli_sensitive_value(" ".join(command_fields[1:]).encode()):
                    return True
        for index, field in enumerate(fields):
            if not field.startswith("--"):
                continue
            prefix = fields[:index]
            if prefix[:1] and prefix[0] in {"-", "*", "+"}:
                prefix = prefix[1:]
            prose_words = [word.lower() for word in prefix if word.isalpha()]
            prose_verbs = {
                "accept",
                "accepts",
                "add",
                "describe",
                "describes",
                "pass",
                "provide",
                "require",
                "requires",
                "set",
                "specify",
                "support",
                "supports",
                "take",
                "takes",
                "use",
            }
            prose_starters = prose_verbs | {"a", "an", "the"}
            if (
                allow_documentation_prose
                and prefix
                and (
                    len(prefix) == 1
                    and prefix[0].isalpha()
                    and prefix[0].lower() in prose_starters
                    or len(prose_words) >= 2
                    and prose_words[0] in {"a", "an", "the", "please", "we", "you"}
                    and prose_words[-1] in prose_verbs
                    or len(prose_words) >= 2
                    and prose_words[-1] in {"a", "an", "the"}
                    and prose_words[-2] in prose_verbs
                    and prose_words[0] in prose_verbs | {"please", "we", "you"}
                )
            ):
                continue
            option, separator, assigned = field[2:].partition("=")
            if not key_is_sensitive(option):
                continue
            if separator:
                value = assigned
            elif index + 1 < len(fields) and not fields[index + 1].startswith("--"):
                value = fields[index + 1]
            else:
                continue
            if cli_value_is_matching_metavariable(value, option):
                continue
            if value.lower() in {
                "argument",
                "accepts",
                "flag",
                "for",
                "is",
                "option",
                "parameter",
                "setting",
                "takes",
                "to",
            }:
                continue
            encoded_value = value.encode()
            if shell_substitution_is_indirect(encoded_value):
                continue
            if SHELL_REFERENCE_MARKER in value:
                static = value.replace(SHELL_REFERENCE_MARKER, "")
                if not static:
                    continue
                if scalar_looks_sensitive(static.encode(), strict=True):
                    return True
            if assignment_expression_looks_sensitive(encoded_value):
                return True
    return False


def split_template_interpolations(value: bytes) -> tuple[bytes, list[bytes]]:
    static: list[bytes] = []
    interpolations: list[bytes] = []
    cursor = 0
    start = 0
    while cursor < len(value):
        if value[cursor : cursor + 1] == b"\\":
            cursor += 2
            continue
        if value[cursor : cursor + 2] != b"${":
            cursor += 1
            continue
        static.append(value[start:cursor])
        expression_start = cursor + 2
        cursor = expression_start
        depth = 1
        quote: int | None = None
        block_comment = False
        line_comment = False
        regex_literal = False
        regex_class = False
        while cursor < len(value) and depth:
            character = value[cursor]
            if block_comment:
                if value[cursor : cursor + 2] == b"*/":
                    block_comment = False
                    cursor += 2
                    continue
            elif line_comment:
                if character in (ord("\r"), ord("\n")):
                    line_comment = False
            elif regex_literal:
                if character == ord("\\"):
                    cursor += 2
                    continue
                if character == ord("["):
                    regex_class = True
                elif character == ord("]"):
                    regex_class = False
                elif character == ord("/") and not regex_class:
                    regex_literal = False
            elif quote is not None:
                if character == ord("\\"):
                    cursor += 2
                    continue
                if character == quote:
                    quote = None
            elif value[cursor : cursor + 2] == b"/*":
                block_comment = True
                cursor += 2
                continue
            elif value[cursor : cursor + 2] == b"//":
                line_comment = True
                cursor += 2
                continue
            elif character == ord("/") and javascript_regex_starts(
                value, cursor, expression_start
            ):
                regex_literal = True
                regex_class = False
            elif character in (ord('"'), ord("'"), ord("`")):
                quote = character
            elif character == ord("{"):
                depth += 1
            elif character == ord("}"):
                depth -= 1
            cursor += 1
        if depth:
            static.append(value[expression_start - 2 :])
            return b"".join(static), interpolations
        interpolations.append(value[expression_start : cursor - 1])
        start = cursor
    static.append(value[start:])
    return b"".join(static), interpolations


def javascript_regex_starts(source: bytes, cursor: int, start: int = 0) -> bool:
    prefix = source[start:cursor].rstrip()
    return (
        not prefix
        or prefix[-1:] in b"(=:[,!&|?{;}+-*%^~<>"
        or prefix.endswith(b"=>")
        or re.search(
            rb"\b(?:await|case|delete|in|instanceof|of|return|throw|typeof|void|yield)$",
            prefix,
        )
        is not None
    )


def jsx_braced_expression(element: bytes, start: int) -> bytes | None:
    cursor = start
    depth = 1
    quote: int | None = None
    block_comment = False
    line_comment = False
    regex_literal = False
    regex_class = False
    while cursor < len(element) and depth:
        character = element[cursor]
        if block_comment:
            if element[cursor : cursor + 2] == b"*/":
                block_comment = False
                cursor += 2
                continue
        elif line_comment:
            if character in (ord("\r"), ord("\n")):
                line_comment = False
        elif regex_literal:
            if character == ord("\\"):
                cursor += 2
                continue
            if character == ord("["):
                regex_class = True
            elif character == ord("]"):
                regex_class = False
            elif character == ord("/") and not regex_class:
                regex_literal = False
        elif quote is not None:
            if character == ord("\\"):
                cursor += 2
                continue
            if character == quote:
                quote = None
        elif element[cursor : cursor + 2] == b"/*":
            block_comment = True
            cursor += 2
            continue
        elif element[cursor : cursor + 2] == b"//":
            line_comment = True
            cursor += 2
            continue
        elif character == ord("/") and javascript_regex_starts(element, cursor):
            regex_literal = True
            regex_class = False
        elif character in (ord('"'), ord("'"), ord("`")):
            quote = character
        elif character == ord("{"):
            depth += 1
        elif character == ord("}"):
            depth -= 1
        cursor += 1
    return element[start : cursor - 1].strip() if depth == 0 else None


def jsx_value_attribute_expressions(element: bytes) -> list[bytes]:
    expressions: list[bytes] = []
    attribute = re.compile(
        rb"(?i)\b(?:(?:default|initial|fallback)[_.-]?)?"
        rb"(?:value|content|text|children)\s*=\s*\{"
    )
    for match in attribute.finditer(element):
        expression = jsx_braced_expression(element, match.end())
        if expression is not None:
            expressions.append(expression)
    return expressions


def jsx_sensitive_attribute_expressions(element: bytes) -> list[bytes]:
    expressions: list[bytes] = []
    for match in re.finditer(
        rb"(?i)\b(?P<attribute>[A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*\{",
        element,
    ):
        if not key_is_sensitive(match.group("attribute").decode(errors="ignore")):
            continue
        expression = jsx_braced_expression(element, match.end())
        if expression is not None:
            expressions.append(expression)
    return expressions


def decode_javascript_static_key(key: bytes) -> bytes:
    def replace_escape(match: re.Match[bytes]) -> bytes:
        codepoint = match.group("fixed") or match.group("braced")
        try:
            return chr(int(codepoint, 16)).encode()
        except (UnicodeEncodeError, ValueError):
            return match.group(0)

    key = re.sub(
        rb"\\u(?:(?P<fixed>[0-9A-Fa-f]{4})|\{(?P<braced>[0-9A-Fa-f]{1,6})\})",
        replace_escape,
        key,
    )
    key = re.sub(
        rb"\\x(?P<hex>[0-9A-Fa-f]{2})",
        lambda match: bytes([int(match.group("hex"), 16)]),
        key,
    )
    key = re.sub(rb"\\(?:\r\n|[\r\n])", b"", key)
    key = re.sub(
        rb"\\(?P<octal>[0-7]{1,3})",
        lambda match: bytes([int(match.group("octal"), 8) & 0xFF]),
        key,
    )
    simple_escapes = {
        ord("b"): b"\b",
        ord("f"): b"\f",
        ord("n"): b"\n",
        ord("r"): b"\r",
        ord("t"): b"\t",
        ord("v"): b"\v",
    }
    return re.sub(
        rb"\\(?P<escaped>[^\r\n])",
        lambda match: simple_escapes.get(
            match.group("escaped")[0], match.group("escaped")
        ),
        key,
    )


def fold_javascript_static_template(key: bytes) -> bytes:
    if not (key.startswith(b"`") and key.endswith(b"`")):
        return key
    value = key[1:-1]
    interpolation = re.compile(rb"\$\{(?P<expression>[^{}]*)\}")

    def fold_interpolation(match: re.Match[bytes]) -> bytes:
        expression = unwrap_javascript_grouping(match.group("expression"))
        expression = unwrap_grouped_javascript_string_operands(expression)
        parts = concatenated_string_parts(expression)
        return b"".join(parts) if parts is not None else match.group(0)

    folded = interpolation.sub(fold_interpolation, value)
    return key if b"${" in folded else folded


def unwrap_javascript_grouping(value: bytes) -> bytes:
    value = value.strip()
    while value.startswith(b"("):
        depth = 0
        quote: int | None = None
        cursor = 0
        closing = None
        while cursor < len(value):
            character = value[cursor]
            if quote is not None:
                if character == ord("\\"):
                    cursor += 2
                    continue
                if character == quote:
                    quote = None
            elif character in (ord('"'), ord("'"), ord("`")):
                quote = character
            elif character == ord("("):
                depth += 1
            elif character == ord(")"):
                depth -= 1
                if depth == 0:
                    closing = cursor
                    break
            cursor += 1
        if closing is None or value[closing + 1 :].strip():
            break
        value = value[1:closing].strip()
    return value


def unwrap_grouped_javascript_string_operands(value: bytes) -> bytes:
    grouped_literal = re.compile(
        rb"\(\s*(?P<literal>(?P<quote>[\"'`])(?:\\.|(?!\2).)*(?P=quote))\s*\)"
    )
    while True:
        unwrapped = grouped_literal.sub(lambda match: match.group("literal"), value)
        if unwrapped == value:
            return value
        value = unwrapped


def split_javascript_property(property_value: bytes) -> tuple[bytes, bytes, bytes]:
    closing = {ord("("): ord(")"), ord("["): ord("]"), ord("{"): ord("}")}
    stack: list[int] = []
    quote: int | None = None
    block_comment = False
    line_comment = False
    regex_literal = False
    regex_class = False
    cursor = 0
    while cursor < len(property_value):
        character = property_value[cursor]
        if block_comment:
            if property_value[cursor : cursor + 2] == b"*/":
                block_comment = False
                cursor += 2
                continue
        elif line_comment:
            if character in (ord("\r"), ord("\n")):
                line_comment = False
        elif regex_literal:
            if character == ord("\\"):
                cursor += 2
                continue
            if character == ord("["):
                regex_class = True
            elif character == ord("]"):
                regex_class = False
            elif character == ord("/") and not regex_class:
                regex_literal = False
        elif quote is not None:
            if character == ord("\\"):
                cursor += 2
                continue
            if character == quote:
                quote = None
        elif property_value[cursor : cursor + 2] == b"/*":
            block_comment = True
            cursor += 2
            continue
        elif property_value[cursor : cursor + 2] == b"//":
            line_comment = True
            cursor += 2
            continue
        elif character == ord("/") and javascript_regex_starts(property_value, cursor):
            regex_literal = True
            regex_class = False
        elif character in (ord('"'), ord("'"), ord("`")):
            quote = character
        elif character in closing:
            stack.append(closing[character])
        elif stack and character == stack[-1]:
            stack.pop()
        elif character == ord(":") and not stack:
            return property_value[:cursor], b":", property_value[cursor + 1 :]
        cursor += 1
    return property_value, b"", b""


def jsx_spread_properties(element: bytes) -> list[tuple[bytes, bytes]]:
    properties: list[tuple[bytes, bytes]] = []
    for match in re.finditer(rb"\{\s*\.\.\.\s*\(*\s*\{", element):
        start = match.end()
        spread_object = jsx_braced_expression(element, start)
        if spread_object is None:
            continue
        for property_value in split_call_arguments(spread_object):
            key, separator, value = split_javascript_property(property_value)
            key = re.sub(rb"(?s)/\*.*?\*/|//[^\r\n]*", b" ", key)
            key = key.strip()
            if key.startswith(b"[") and key.endswith(b"]"):
                key = key[1:-1].strip()
            key = unwrap_javascript_grouping(key)
            key = fold_javascript_static_template(key)
            key = unwrap_grouped_javascript_string_operands(key)
            key_parts = concatenated_string_parts(key)
            if key_parts is not None:
                key = b"".join(key_parts)
            key = decode_javascript_static_key(key)
            normalized_key = re.sub(
                rb"[_.-]", b"", key.strip(b" \t\"'`")
            ).lower()
            if separator:
                properties.append((normalized_key, value.strip()))
    return properties


def jsx_spread_value_expressions(element: bytes) -> list[bytes]:
    value_keys = {
        b"value",
        b"defaultvalue",
        b"initialvalue",
        b"fallbackvalue",
        b"content",
        b"text",
        b"children",
    }
    return [
        expression
        for key, expression in jsx_spread_properties(element)
        if key in value_keys
    ]


def jsx_expression_looks_sensitive(expression: bytes) -> bool:
    if SAFE_INDIRECT_EXPRESSION_RE.fullmatch(expression):
        return False
    runtime_call = re.fullmatch(
        rb"(?s)(?P<callee>[A-Za-z_][A-Za-z0-9_.]*)\s*\(.*\)",
        expression,
    )
    if runtime_call is not None and call_uses_first_argument_as_selector(
        runtime_call.group("callee")
    ):
        return assignment_expression_looks_sensitive(expression)
    for static_call in re.finditer(
        rb"(?<![A-Za-z0-9_.$])(?:String|Number|BigInt)\s*\(",
        expression,
    ):
        start = static_call.end()
        cursor = start
        depth = 1
        quote: int | None = None
        while cursor < len(expression) and depth:
            character = expression[cursor]
            if quote is not None:
                if character == ord("\\"):
                    cursor += 2
                    continue
                if character == quote:
                    quote = None
            elif character in (ord('"'), ord("'"), ord("`")):
                quote = character
            elif character == ord("("):
                depth += 1
            elif character == ord(")"):
                depth -= 1
            cursor += 1
        if depth == 0 and jsx_expression_looks_sensitive(
            expression[start : cursor - 1].strip()
        ):
            return True
    if expression.startswith(b"`") and expression.endswith(b"`"):
        static, interpolations = split_template_interpolations(expression[1:-1])
        if scalar_looks_sensitive(static, strict=True):
            return True
        return any(
            jsx_expression_looks_sensitive(interpolation.strip())
            for interpolation in interpolations
        )
    literals = list(
        re.finditer(
            rb"(?s)(?P<quote>[\"'`])(?P<value>(?:\\.|(?!\1).)*)(?P=quote)",
            expression,
        )
    )
    for item in literals:
        before_literal = expression[: item.start()].rstrip()
        before_bracket = before_literal[:-1].rstrip() if before_literal.endswith(b"[") else b""
        if (
            before_bracket
            and re.search(rb"(?:[A-Za-z0-9_$)\]]|\?\.)$", before_bracket)
            is not None
            and expression[item.end() :].lstrip().startswith(b"]")
        ):
            continue
        selector_call = re.search(
            rb"(?P<callee>[A-Za-z_][A-Za-z0-9_.]*)\s*\(\s*$",
            before_literal,
        )
        if (
            selector_call is not None
            and call_uses_first_argument_as_selector(selector_call.group("callee"))
            and expression[item.end() :].lstrip().startswith((b")", b","))
        ):
            continue
        literal_value = item.group("value")
        if item.group("quote") == b"`":
            literal_value, interpolations = split_template_interpolations(
                literal_value
            )
            if any(
                jsx_expression_looks_sensitive(interpolation.strip())
                for interpolation in interpolations
            ):
                return True
        if scalar_looks_sensitive(literal_value, strict=True):
            return True
    if (
        len(literals) == 1
        and literals[0].group("quote") == b"`"
        and literals[0].span() == (0, len(expression))
    ):
        return False
    without_literals = re.sub(
        rb"(?s)(?P<quote>[\"'`])(?:\\.|(?!\1).)*(?P=quote)",
        b"",
        expression,
    )
    without_literals = re.sub(
        rb"(?s)/\*.*?\*/|//[^\r\n]*", b" ", without_literals
    )
    if re.search(
        rb"(?:(?:\|\||&&|\?\?|(?<!\?)\?(?!\?)|:|\+)\s*\(*\s*"
        + JAVASCRIPT_NUMERIC_LITERAL
        + rb"\s*\)*"
        + rb"|"
        + rb"\(*\s*"
        + JAVASCRIPT_NUMERIC_LITERAL
        + rb"\s*\)*\s*(?:\+|\|\||\?\?))"
        rb"(?![A-Za-z0-9_$])",
        without_literals,
    ):
        return True
    if re.search(
        rb"(?:\[|,)\s*"
        + JAVASCRIPT_NUMERIC_LITERAL
        + rb"\s*(?=,|\])",
        without_literals,
    ):
        return True
    if re.search(
        rb",\s*\(*\s*"
        + JAVASCRIPT_NUMERIC_LITERAL
        + rb"\s*\)*\s*$",
        without_literals,
    ):
        return True
    for match in re.finditer(
        rb"(?P<number>"
        + JAVASCRIPT_NUMERIC_LITERAL
        + rb")\s*\)*\s*&&",
        without_literals,
    ):
        normalized = match.group("number").replace(b"_", b"").lower()
        if normalized.endswith(b"n"):
            normalized = normalized[:-1]
        try:
            numeric_value = (
                int(normalized, 0)
                if normalized.lstrip(b"+-").startswith((b"0x", b"0b", b"0o"))
                else float(normalized)
            )
        except ValueError:
            continue
        if numeric_value == 0:
            return True
    if re.search(
        rb"(?:\(\s*)?"
        + JAVASCRIPT_NUMERIC_LITERAL
        + rb"(?:\s*\))?\s*\.\s*"
        rb"(?:toString|toFixed|toExponential|toPrecision)\s*\(",
        without_literals,
    ):
        return True
    if re.fullmatch(
        rb"\s*\(*\s*" + JAVASCRIPT_NUMERIC_LITERAL + rb"\s*\)*\s*",
        without_literals,
    ):
        return True
    if re.match(
        rb"\s*\(*\s*"
        + JAVASCRIPT_NUMERIC_LITERAL
        + rb"\s*\)*\s+(?:as|satisfies)\b",
        without_literals,
    ):
        return True
    if re.search(rb"[A-Za-z_$]", without_literals):
        return False
    return assignment_expression_looks_sensitive(expression)


def markup_tags(
    data: bytes, *, allow_jsx: bool
) -> list[tuple[bytes, int, int, bool, bool]]:
    tags: list[tuple[bytes, int, int, bool, bool]] = []
    cursor = 0
    while True:
        match = MARKUP_TAG_START.search(data, cursor)
        if match is None:
            break
        position = match.end()
        quote: int | None = None
        brace_depth = 0
        type_argument_depth = 0
        block_comment = False
        line_comment = False
        regex_literal = False
        regex_class = False
        while position < len(data):
            character = data[position]
            if block_comment:
                if data[position : position + 2] == b"*/":
                    block_comment = False
                    position += 2
                    continue
            elif line_comment:
                if character in (ord("\r"), ord("\n")):
                    line_comment = False
            elif regex_literal:
                if character == ord("\\"):
                    position += 2
                    continue
                if character == ord("["):
                    regex_class = True
                elif character == ord("]"):
                    regex_class = False
                elif character == ord("/") and not regex_class:
                    regex_literal = False
            elif quote is not None:
                if character == ord("\\"):
                    position += 2
                    continue
                if character == quote:
                    quote = None
            elif allow_jsx and brace_depth and data[position : position + 2] == b"/*":
                block_comment = True
                position += 2
                continue
            elif allow_jsx and brace_depth and data[position : position + 2] == b"//":
                line_comment = True
                position += 2
                continue
            elif (
                allow_jsx
                and brace_depth
                and character == ord("/")
                and javascript_regex_starts(data, position, match.end())
            ):
                regex_literal = True
                regex_class = False
            elif character in (ord('"'), ord("'"), ord("`")):
                quote = character
            elif allow_jsx and character == ord("{"):
                brace_depth += 1
            elif allow_jsx and character == ord("}") and brace_depth:
                brace_depth -= 1
            elif (
                allow_jsx
                and brace_depth == 0
                and character == ord("<")
                and (
                    type_argument_depth > 0
                    or not data[match.end() : position].strip()
                )
            ):
                type_argument_depth += 1
            elif allow_jsx and type_argument_depth and character == ord(">"):
                if position == 0 or data[position - 1] != ord("="):
                    type_argument_depth -= 1
            elif character == ord(">") and brace_depth == 0:
                end = position + 1
                raw = data[match.start() : end]
                tags.append(
                    (
                        match.group("tag"),
                        match.start(),
                        end,
                        match.group("closing") is not None,
                        raw[:-1].rstrip().endswith(b"/"),
                    )
                )
                cursor = end
                break
            position += 1
        else:
            break
    return tags


def jsx_component_is_sensitive(tag: str) -> bool:
    suffix = re.compile(
        r"(?i)(?:[-_.]?(?:control|display|editor|field|input|text|view))$"
    )
    for candidate in (tag, re.split(r"[.:]", tag)[-1]):
        component = candidate
        while True:
            if key_is_sensitive(component):
                return True
            stripped = suffix.sub("", component)
            if stripped == component:
                break
            component = stripped
    return False


def jsx_static_string(expression: bytes) -> bytes | None:
    expression = unwrap_javascript_grouping(expression)
    expression = fold_javascript_static_template(expression)
    expression = unwrap_grouped_javascript_string_operands(expression)
    parts = concatenated_string_parts(expression)
    if parts is None:
        return None
    return decode_javascript_static_key(b"".join(parts))


def jsx_designates_sensitive_value(opening: bytes) -> bool:
    designators = {b"type", b"name", b"key"}
    for match in re.finditer(
        rb"(?i)\b(?P<attribute>type|name|key)\s*=\s*\{", opening
    ):
        expression = jsx_braced_expression(opening, match.end())
        static = jsx_static_string(expression) if expression is not None else None
        if static is not None and key_is_sensitive(static.decode(errors="ignore")):
            return True
    for key, expression in jsx_spread_properties(opening):
        if key not in designators:
            continue
        static = jsx_static_string(expression)
        if static is not None and key_is_sensitive(static.decode(errors="ignore")):
            return True
    return False


def contains_xml_sensitive_value(data: bytes, *, allow_jsx: bool = False) -> bool:
    tags = markup_tags(data, allow_jsx=allow_jsx)
    for index, (raw_tag, start, end, closing_tag, self_closing) in enumerate(tags):
        if closing_tag:
            continue
        tag = raw_tag.rsplit(b":", 1)[-1].decode(errors="ignore")
        opening = data[start:end]
        literal_attributes: dict[str, bytes] = {}
        for attribute in re.finditer(
            rb"(?is)\b(?P<name>[A-Za-z_:][A-Za-z0-9_.:-]*)\s*=\s*"
            rb"(?P<quote>[\"'])(?P<value>(?:\\.|(?!\2).)*)(?P=quote)",
            opening,
        ):
            name = attribute.group("name").rsplit(b":", 1)[-1].decode(errors="ignore")
            try:
                value = html.unescape(attribute.group("value").decode()).encode()
            except UnicodeDecodeError:
                value = attribute.group("value")
            literal_attributes[name.lower()] = value
        designated_sensitive = any(
            key_is_sensitive(literal_attributes.get(attribute, b"").decode(errors="ignore"))
            for attribute in ("type", "name", "key")
        )
        if allow_jsx:
            designated_sensitive = (
                designated_sensitive or jsx_designates_sensitive_value(opening)
            )
            for expression in jsx_sensitive_attribute_expressions(opening):
                if jsx_expression_looks_sensitive(expression):
                    return True
            for key, expression in jsx_spread_properties(opening):
                if key_is_sensitive(key.decode(errors="ignore")) and (
                    jsx_expression_looks_sensitive(expression)
                ):
                    return True
        if not designated_sensitive and not key_is_sensitive(tag) and not (
            allow_jsx and jsx_component_is_sensitive(tag)
        ):
            continue
        for attribute in re.finditer(
            rb"(?is)\b(?:(?:default|initial|fallback)[_.-]?)?"
            rb"(?:value|content|text|children)\s*=\s*"
            rb"(?P<quote>[\"'])(?P<value>(?:\\.|(?!\1).)*)(?P=quote)",
            opening,
        ):
            if assignment_expression_looks_sensitive(attribute.group("value")):
                return True
        if allow_jsx:
            for expression in jsx_value_attribute_expressions(opening):
                if jsx_expression_looks_sensitive(expression):
                    return True
            for expression in jsx_spread_value_expressions(opening):
                if jsx_expression_looks_sensitive(expression):
                    return True
        if self_closing:
            continue
        depth = 1
        closing_start: int | None = None
        for nested_tag, nested_start, _, nested_closing, nested_self_closing in tags[
            index + 1 :
        ]:
            if nested_tag.lower() != raw_tag.lower():
                continue
            if nested_closing:
                depth -= 1
                if depth == 0:
                    closing_start = nested_start
                    break
            elif not nested_self_closing:
                depth += 1
        if closing_start is None:
            continue
        value = data[end:closing_start].strip()
        raw_jsx = (
            re.fullmatch(rb"(?s)\{\s*(?P<expression>.*?)\s*\}", value)
            if allow_jsx
            else None
        )
        if raw_jsx is not None:
            try:
                expression = html.unescape(
                    raw_jsx.group("expression").decode()
                ).encode()
            except UnicodeDecodeError:
                return True
            if jsx_expression_looks_sensitive(expression):
                return True
            continue
        text_parts: list[bytes] = []
        cursor = 0
        for cdata in re.finditer(rb"(?s)<!\[CDATA\[(.*?)\]\]>", value):
            text_parts.append(re.sub(rb"(?s)<[^>]+>", b"", value[cursor:cdata.start()]))
            text_parts.append(cdata.group(1))
            cursor = cdata.end()
        text_parts.append(re.sub(rb"(?s)<[^>]+>", b"", value[cursor:]))
        value = b"".join(text_parts).strip()
        try:
            value = html.unescape(value.decode()).encode()
        except UnicodeDecodeError:
            continue
        jsx = (
            re.fullmatch(rb"(?s)\{\s*(?P<expression>.*?)\s*\}", value)
            if allow_jsx
            else None
        )
        if jsx is not None:
            expression = jsx.group("expression").strip()
            if jsx_expression_looks_sensitive(expression):
                return True
            continue
        if assignment_expression_looks_sensitive(value):
            return True
    return False


def contains_bracketed_sensitive_assignment(data: bytes) -> bool:
    for match in BRACKETED_ASSIGNMENT.finditer(data):
        if not key_is_sensitive(match.group("key").decode(errors="ignore")):
            continue
        value = match.group("value").strip().rstrip(b"; ")
        if assignment_expression_looks_sensitive(value):
            return True
    return False


def colon_assignment_value(
    data: bytes, start: int, outer_quote: int | None = None
) -> bytes:
    closing = {ord("("): ord(")"), ord("["): ord("]"), ord("{"): ord("}")}
    stack: list[int] = []
    quote: int | None = None
    cursor = start
    while cursor < len(data):
        character = data[cursor]
        if character in b"\r\n" and quote != ord("`"):
            break
        if outer_quote is not None and quote is None:
            if character == outer_quote:
                break
            if character == ord("\\") and data[cursor + 1 : cursor + 2] in {b"n", b"r"}:
                break
        if quote is not None:
            if character == ord("\\"):
                cursor += 2
                continue
            if character == quote:
                quote = None
        elif character in (ord('"'), ord("'"), ord("`")):
            quote = character
        elif character in closing:
            stack.append(closing[character])
        elif character in (ord(")"), ord("]"), ord("}")):
            if not stack:
                break
            if character == stack[-1]:
                stack.pop()
        elif not stack and character in (ord(","), ord(";")):
            break
        cursor += 1
    return data[start:cursor].strip()


def concatenated_string_parts(value: bytes) -> list[bytes] | None:
    literal = re.compile(
        rb"[ \t]*(?P<quote>[\"'`])(?P<value>(?:\\.|(?!\1).)*)(?P=quote)",
        re.DOTALL,
    )
    parts: list[bytes] = []
    cursor = 0
    while cursor < len(value):
        match = literal.match(value, cursor)
        if not match:
            return None
        parts.append(match.group("value"))
        cursor = match.end()
        while cursor < len(value) and value[cursor] in b" \t":
            cursor += 1
        if cursor == len(value):
            return parts
        if value[cursor : cursor + 1] == b"+":
            cursor += 1
            continue
        if value[cursor : cursor + 1] in {b'"', b"'", b"`"}:
            continue
        return None
    return parts or None


def concatenated_parts_look_sensitive(
    parts: list[bytes], *, strict: bool = False
) -> bool:
    normalized = [part.strip() for part in parts]
    return not all(
        not part
        or SAFE_REFERENCE_RE.fullmatch(part)
        or DOCUMENTATION_PLACEHOLDER.fullmatch(part)
        for part in normalized
    ) and scalar_looks_sensitive(b"".join(normalized), strict=strict)


def contains_concatenated_authorization_value(data: bytes) -> bool:
    authorization_pattern = re.compile(
        rb"(?i)^\s*(?:bearer\s+[A-Za-z0-9._~+/-]{4,}|"
        rb"basic\s+[A-Za-z0-9+/=]{4,})\s*$"
    )
    for match in AUTHORIZATION_VALUE_START.finditer(data):
        value = colon_assignment_value(data, match.end())
        parts = concatenated_string_parts(value)
        if parts is not None and authorization_pattern.fullmatch(b"".join(parts)):
            return True
    return False


def split_call_arguments(arguments: bytes) -> list[bytes]:
    closing = {ord("("): ord(")"), ord("["): ord("]"), ord("{"): ord("}")}
    stack: list[int] = []
    quote: int | None = None
    block_comment = False
    line_comment = False
    regex_literal = False
    regex_class = False
    start = 0
    parts: list[bytes] = []
    cursor = 0
    while cursor < len(arguments):
        character = arguments[cursor]
        if block_comment:
            if arguments[cursor : cursor + 2] == b"*/":
                block_comment = False
                cursor += 2
                continue
        elif line_comment:
            if character in (ord("\r"), ord("\n")):
                line_comment = False
        elif regex_literal:
            if character == ord("\\"):
                cursor += 2
                continue
            if character == ord("["):
                regex_class = True
            elif character == ord("]"):
                regex_class = False
            elif character == ord("/") and not regex_class:
                regex_literal = False
        elif quote is not None:
            if character == ord("\\"):
                cursor += 2
                continue
            if character == quote:
                quote = None
        elif arguments[cursor : cursor + 2] == b"/*":
            block_comment = True
            cursor += 2
            continue
        elif arguments[cursor : cursor + 2] == b"//":
            line_comment = True
            cursor += 2
            continue
        elif character == ord("/") and javascript_regex_starts(arguments, cursor):
            regex_literal = True
            regex_class = False
        elif character in (ord('"'), ord("'"), ord("`")):
            quote = character
        elif character in closing:
            stack.append(closing[character])
        elif stack and character == stack[-1]:
            stack.pop()
        elif character == ord(",") and not stack:
            parts.append(arguments[start:cursor].strip())
            start = cursor + 1
        cursor += 1
    parts.append(arguments[start:].strip())
    return parts


def call_uses_first_argument_as_selector(callee: bytes) -> bool:
    leaf = callee.rsplit(b".", 1)[-1].lower()
    if leaf == b"get":
        return True
    return leaf.endswith((b"config", b"setting")) and leaf.startswith(
        (b"get", b"load", b"lookup", b"read", b"resolve")
    )


def assignment_expression_looks_sensitive(value: bytes) -> bool:
    if not value:
        return False
    if value in {b"None", b"null", b"~", b"{", b"[", b"{}", b"[]"}:
        return False
    if value.startswith(b"(") and value.endswith(b")"):
        return assignment_expression_looks_sensitive(value[1:-1].strip())
    parts = concatenated_string_parts(value)
    if parts is not None:
        return concatenated_parts_look_sensitive(parts, strict=True)
    if SAFE_REFERENCE_RE.fullmatch(value) or SAFE_INDIRECT_EXPRESSION_RE.fullmatch(value):
        return False
    call = re.fullmatch(
        rb"(?s)(?P<callee>[A-Za-z_][A-Za-z0-9_.]*)\s*\((?P<arguments>.*)\)",
        value,
    )
    if call:
        callee = call.group("callee").lower()
        arguments = call.group("arguments").strip()
        if not arguments:
            return False
        if b"getenv" in callee or callee == b"os.environ.get":
            return any(
                assignment_expression_looks_sensitive(
                    argument.partition(b"=")[2].strip()
                    if b"=" in argument
                    else argument
                )
                for argument in split_call_arguments(arguments)[1:]
            )
        if call_uses_first_argument_as_selector(call.group("callee")):
            return any(
                assignment_expression_looks_sensitive(
                    argument.partition(b"=")[2].strip()
                    if b"=" in argument
                    else argument
                )
                for argument in split_call_arguments(arguments)[1:]
            )
        if any(marker in callee for marker in (b"get_secret", b"vault")):
            for argument in split_call_arguments(arguments)[1:]:
                key, separator, assigned = argument.partition(b"=")
                named_default = separator and key.strip().lower() in {
                    b"default",
                    b"fallback",
                    b"value",
                }
                if (named_default or not separator) and assignment_expression_looks_sensitive(
                    assigned.strip() if named_default else argument
                ):
                    return True
            return False
        parts = concatenated_string_parts(arguments)
        if parts is not None:
            return concatenated_parts_look_sensitive(parts, strict=True)
        literals = re.finditer(
            rb"(?P<quote>[\"'`])(?P<value>(?:\\.|(?!\1).)*)(?P=quote)",
            arguments,
        )
        return any(
            scalar_looks_sensitive(item.group("value"), strict=True)
            for item in literals
        )
    if value[:1] in {b'"', b"'", b"`"}:
        if value[-1:] == value[:1] and len(value) >= 2:
            return scalar_looks_sensitive(value[1:-1], strict=True)
        return False
    return scalar_looks_sensitive(value, strict=True)


def quote_at_position(data: bytes, position: int) -> int | None:
    quote: int | None = None
    cursor = data.rfind(b"\n", 0, position) + 1
    while cursor < position:
        character = data[cursor]
        if quote is not None and character == ord("\\"):
            cursor += 2
            continue
        if character in (ord('"'), ord("'")):
            quote = None if character == quote else character if quote is None else quote
        cursor += 1
    return quote


def contains_unquoted_colon_sensitive_value(
    data: bytes, *, allow_python_annotations: bool = False
) -> bool:
    for match in UNQUOTED_COLON_ASSIGNMENT.finditer(data):
        outer_quote = quote_at_position(data, match.start())
        first = data[match.start() : match.start() + 1]
        prefix = data[match.start() : match.end()].rstrip()
        key = prefix[:-1].rstrip() if prefix.endswith(b":") else prefix
        key_name = key.strip(b" \t\"'").decode("utf-8", errors="ignore")
        if key_is_reference_field(key_name):
            continue
        if outer_quote is None and first in {b'"', b"'"} and not key.endswith(first):
            outer_quote = first[0]
        line_end = data.find(b"\n", match.end())
        if line_end < 0:
            line_end = len(data)
        after = data[match.end() : line_end]
        simple_type = rb"[A-Za-z_$][A-Za-z0-9_.$<>\[\]|&?, \t]*"
        function_type = rb"\([^()\r\n]*\)\s*=>\s*" + simple_type
        type_expression = rb"(?:" + simple_type + rb"|" + function_type + rb")"
        source_context = data[max(0, match.start() - 4096) : match.start()]
        python_parameter = allow_python_annotations and re.search(
            rb"\bdef\s+[A-Za-z_][A-Za-z0-9_]*\([^)]*$", source_context
        ) is not None
        typescript_parameter = (
            re.search(
                rb"\bfunction\s+[A-Za-z_$][A-Za-z0-9_$]*\([^)]*$",
                source_context,
            )
            is not None
            or re.match(
                rb"\s*" + type_expression + rb"[^)]*\)\s*=>",
                data[match.end() : match.end() + 4096],
                re.DOTALL,
            )
            is not None
        )
        type_block = (
            re.search(
                rb"\b(?:class|interface|type)\s+[A-Za-z_$][A-Za-z0-9_$]*"
                rb"[^{}]*\{[^{}]*$",
                source_context,
            )
            is not None
        )
        python_syntax = allow_python_annotations and python_name_is_code(
            data, match.start()
        )
        python_annotation = after.partition(b"#")[0].rstrip(b";, \t")
        ast_annotation, ast_initializer = python_annotation_at_position(
            data, match.start()
        ) if python_syntax else (False, None)
        python_variable = python_syntax and python_type_annotation_only(
            python_annotation
        )
        python_user_type_variable = (
            python_syntax
            and python_user_type_annotation_only(python_annotation)
        )
        if (python_parameter or typescript_parameter or type_block) and re.match(
            rb"\s*" + type_expression + rb"\s*(?:[;,)\]}]|$)", after
        ):
            continue
        if (
            python_variable
            or python_user_type_variable
            or ast_annotation and ast_initializer is None
        ):
            continue
        value = colon_assignment_value(data, match.end(), outer_quote)
        type_annotation = re.fullmatch(
            type_expression + rb"\s*=\s*(?P<value>.+)",
            value,
        )
        if type_annotation:
            if assignment_expression_looks_sensitive(
                type_annotation.group("value").strip().rstrip(b"; ")
            ):
                return True
            continue
        helm = HELM_VALUE_RE.fullmatch(value)
        if helm:
            literals = helm_value_literals(
                helm.group("body").decode("utf-8", errors="ignore")
            )
            if any(
                scalar_looks_sensitive(item, strict=True) for item in literals
            ):
                return True
            continue
        if value in {b"null", b"~", b"{}", b"[]"}:
            continue
        if (
            value.startswith(b"{")
            and value.endswith(b"}")
            or value.startswith(b"[")
            and value.endswith(b"]")
        ):
            continue
        parts = concatenated_string_parts(value)
        if parts is not None:
            if concatenated_parts_look_sensitive(parts, strict=True):
                return True
            continue
        if not value or value[:1] in {b'"', b"'", b"`", b"|", b">"}:
            continue
        call = re.fullmatch(
            rb"(?P<callee>[A-Za-z_][A-Za-z0-9_.]*)\s*\((?P<arguments>.*)\)",
            value,
        )
        if call:
            if call.group("callee") == b"re.compile":
                continue
            if assignment_expression_looks_sensitive(value):
                return True
            continue
        if SAFE_INDIRECT_EXPRESSION_RE.fullmatch(value):
            continue
        comment = re.search(rb"[ \t]+#", value)
        if comment:
            value = value[: comment.start()].rstrip()
        try:
            typed = yaml.compose(value.decode("utf-8"))
        except (UnicodeDecodeError, yaml.YAMLError):
            typed = None
        if isinstance(typed, ScalarNode) and (
            typed.tag == "tag:yaml.org,2002:bool"
            or key_allows_typed_scalar(key_name)
            and typed.tag
            in {
                "tag:yaml.org,2002:float",
                "tag:yaml.org,2002:int",
                "tag:yaml.org,2002:null",
                "tag:yaml.org,2002:timestamp",
            }
        ):
            continue
        if scalar_looks_sensitive(value, strict=True):
            return True
    return False


def contains_quoted_assignment_sensitive_value(
    data: bytes, *, allow_python_annotations: bool = False
) -> bool:
    for match in QUOTED_ASSIGNMENT.finditer(data):
        ast_annotation, initializer = (
            python_annotation_at_position(data, match.start())
            if allow_python_annotations
            else (False, None)
        )
        if ast_annotation:
            if initializer is not None and assignment_expression_looks_sensitive(
                initializer
            ):
                return True
            continue
        if scalar_looks_sensitive(match.group("value"), strict=True):
            return True
    return False


def path_from_label(label: str) -> str:
    if label.startswith("working tree:"):
        return label.removeprefix("working tree:")
    if label.startswith("history:"):
        return re.sub(r"@[0-9a-f]{12,64}$", "", label.removeprefix("history:"))
    return label


def label_allows_python_annotations(label: str) -> bool:
    path_label = path_from_label(label)
    return Path(path_label).suffix.lower() in {".py", ".pyi"}


def label_allows_jsx(label: str) -> bool:
    path_label = path_from_label(label)
    return Path(path_label).suffix.lower() in {".jsx", ".tsx", ".mdx"}


def label_uses_shell_syntax(label: str) -> bool:
    path_label = path_from_label(label)
    return Path(path_label).suffix.lower() in {".bash", ".ksh", ".sh", ".zsh"}


def mask_shell_references(data: bytes) -> bytes:
    try:
        return preserve_shell_references(data.decode("utf-8")).encode()
    except UnicodeDecodeError:
        return data


def label_allows_documentation_prose(label: str) -> bool:
    path_label = path_from_label(label)
    return Path(path_label).suffix.lower() in {".md", ".mdx", ".rst", ".txt"}


def scan_blob(label: str, data: bytes) -> list[str]:
    if len(data) > MAX_BLOB_BYTES:
        return [f"{label}: file exceeds the scanner size limit"]
    if b"\0" in data:
        return [f"{label}: binary file requires manual review"]
    findings = [
        f"{label}: {rule}"
        for rule, pattern in SIGNATURE_PATTERNS.items()
        if pattern.search(data)
    ]
    python_source = label_allows_python_annotations(label)
    assignment_data = mask_shell_references(data) if label_uses_shell_syntax(label) else data
    if contains_structured_sensitive_value(
        data, allow_python_annotations=python_source
    ):
        findings.append(f"{label}: structured YAML/JSON credential")
    if contains_toml_multiline_sensitive_value(data):
        findings.append(f"{label}: TOML multiline assigned credential")
    if contains_unquoted_equals_sensitive_value(data):
        findings.append(f"{label}: unquoted assigned credential phrase")
    if contains_docker_space_sensitive_value(data):
        findings.append(f"{label}: Dockerfile assigned credential")
    if contains_cli_sensitive_value(
        data, allow_documentation_prose=label_allows_documentation_prose(label)
    ):
        findings.append(f"{label}: command-line credential option")
    if contains_bracketed_sensitive_assignment(data):
        findings.append(f"{label}: bracketed assigned credential")
    if contains_unquoted_colon_sensitive_value(
        assignment_data, allow_python_annotations=python_source
    ):
        findings.append(f"{label}: unquoted colon-assigned credential")
    if contains_quoted_assignment_sensitive_value(
        data, allow_python_annotations=python_source
    ):
        findings.append(f"{label}: quoted assigned credential")
    if contains_concatenated_authorization_value(data):
        findings.append(f"{label}: concatenated authorization credential")
    if contains_xml_sensitive_value(data, allow_jsx=label_allows_jsx(label)):
        findings.append(f"{label}: XML element credential")
    return findings


def risky_name(path: str) -> bool:
    candidate = Path(path)
    dotenv = candidate.name == ".env" or (
        candidate.name.startswith(".env.")
        and candidate.name not in {".env.example", ".env.sample", ".env.template"}
    )
    return (
        dotenv
        or candidate.name in FORBIDDEN_NAMES
        or candidate.suffix.lower() in FORBIDDEN_SUFFIXES
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--history", action="store_true", help="scan every reachable Git blob")
    args = parser.parse_args()
    findings: list[str] = []
    for path in tracked_paths():
        if not path:
            continue
        if risky_name(path):
            findings.append(f"working tree:{path}: forbidden credential filename")
        findings.extend(scan_blob(f"working tree:{path}", working_tree_blob(path)))
    if args.history:
        scanned_objects: set[tuple[str, bool, bool, bool, bool]] = set()
        for object_id, path in history_blobs():
            if risky_name(path):
                findings.append(
                    f"history:{path}@{object_id[:12]}: forbidden credential filename"
                )
            cache_key = (
                object_id,
                label_allows_python_annotations(path),
                label_allows_jsx(path),
                label_allows_documentation_prose(path),
                label_uses_shell_syntax(path),
            )
            if cache_key not in scanned_objects:
                findings.extend(
                    scan_blob(
                        f"history:{path}@{object_id[:12]}",
                        git("cat-file", "blob", object_id),
                    )
                )
                scanned_objects.add(cache_key)
    if findings:
        print("Potential public-repository safety issues:", file=sys.stderr)
        for finding in sorted(set(findings)):
            print(f"- {finding}", file=sys.stderr)
        return 1
    scope = "working tree and Git history" if args.history else "working tree"
    print(f"No credential patterns or forbidden files found in {scope}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
