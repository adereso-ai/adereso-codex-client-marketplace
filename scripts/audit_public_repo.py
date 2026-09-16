#!/usr/bin/env python3
"""Reject likely credentials without printing their values."""

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys
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
    r"(?<!\$)\{\{-?\s*(?P<body>.*?)\s*-?\}\}"
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
    rb"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+|"
    rb"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*"
    rb"\[[\"'][A-Za-z0-9_.-]+[\"']\])$"
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


def python_type_annotation_only(value: bytes) -> bool:
    return PYTHON_TYPE_EXPRESSION.fullmatch(value.strip()) is not None


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


def contains_structured_sensitive_value(data: bytes) -> bool:
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
        for index, line in enumerate(source_lines):
            annotation = re.match(
                r"^(?P<prefix>[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*:[ \t]*)"
                r"(?P<type>[^#\r\n]+?)(?P<suffix>[ \t]*(?:#.*)?(?:\r?\n)?$)",
                line,
            )
            if (
                annotation is not None
                and key_is_sensitive(
                    annotation.group("prefix").split(":", 1)[0].strip()
                )
                and python_type_annotation_only(
                    annotation.group("type").strip().encode()
                )
            ):
                source_lines[index] = (
                    annotation.group("prefix")
                    + "${PYTHON_TYPE_ANNOTATION}"
                    + annotation.group("suffix")
                )
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
    for line in data.splitlines():
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
    start = 0
    parts: list[bytes] = []
    cursor = 0
    while cursor < len(arguments):
        character = arguments[cursor]
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
        elif stack and character == stack[-1]:
            stack.pop()
        elif character == ord(",") and not stack:
            parts.append(arguments[start:cursor].strip())
            start = cursor + 1
        cursor += 1
    parts.append(arguments[start:].strip())
    return parts


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
        if callee == b"get" or callee.endswith(b".get"):
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


def contains_unquoted_colon_sensitive_value(data: bytes) -> bool:
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
        python_parameter = re.search(
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
        python_variable = python_type_annotation_only(after.rstrip(b";, \t"))
        if (python_parameter or typescript_parameter or type_block) and re.match(
            rb"\s*" + type_expression + rb"\s*(?:[;,)\]}]|$)", after
        ):
            continue
        if python_variable:
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


def contains_quoted_assignment_sensitive_value(data: bytes) -> bool:
    for match in QUOTED_ASSIGNMENT.finditer(data):
        if scalar_looks_sensitive(match.group("value"), strict=True):
            return True
    return False


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
    if contains_structured_sensitive_value(data):
        findings.append(f"{label}: structured YAML/JSON credential")
    if contains_toml_multiline_sensitive_value(data):
        findings.append(f"{label}: TOML multiline assigned credential")
    if contains_unquoted_equals_sensitive_value(data):
        findings.append(f"{label}: unquoted assigned credential phrase")
    if contains_docker_space_sensitive_value(data):
        findings.append(f"{label}: Dockerfile assigned credential")
    if contains_bracketed_sensitive_assignment(data):
        findings.append(f"{label}: bracketed assigned credential")
    if contains_unquoted_colon_sensitive_value(data):
        findings.append(f"{label}: unquoted colon-assigned credential")
    if contains_quoted_assignment_sensitive_value(data):
        findings.append(f"{label}: quoted assigned credential")
    if contains_concatenated_authorization_value(data):
        findings.append(f"{label}: concatenated authorization credential")
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
        scanned_objects: set[str] = set()
        for object_id, path in history_blobs():
            if risky_name(path):
                findings.append(
                    f"history:{path}@{object_id[:12]}: forbidden credential filename"
                )
            if object_id not in scanned_objects:
                findings.extend(
                    scan_blob(
                        f"history:{path}@{object_id[:12]}",
                        git("cat-file", "blob", object_id),
                    )
                )
                scanned_objects.add(object_id)
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
