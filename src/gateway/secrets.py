import base64
import json
import os
import re
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PLACEHOLDER_PATTERN = re.compile(r"\$\{([a-zA-Z0-9_]+):([^}]*)\}")
ANY_PLACEHOLDER_PATTERN = re.compile(r"\$\{[^}]*\}")
REDACTED_MARKER = "[REDACTED]"


class SecretResolutionError(ValueError):
    pass


@dataclass(frozen=True)
class ResolvedTemplate:
    value: str
    secrets: tuple[str, ...]


def _validate_secret_chars(value: str, source: str) -> str:
    if not value:
        raise SecretResolutionError(f"Resolved placeholder {source} is empty")
    if "\r" in value or "\n" in value:
        raise SecretResolutionError(f"Resolved placeholder {source} contains newline characters")
    return value


def _read_secret_file(raw_path: str) -> str:
    if not raw_path:
        raise SecretResolutionError("Empty path in file placeholder")
    path = Path(raw_path)
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SecretResolutionError(f"Cannot read secret file {raw_path}: {exc}") from exc
    stripped = content.rstrip("\r\n")
    return _validate_secret_chars(stripped, f"file:{raw_path}")


def _read_env_var(name: str, scheme: str) -> str:
    if not name:
        raise SecretResolutionError(f"Empty variable name in {scheme} placeholder")
    value = os.environ.get(name)
    if value is None:
        raise SecretResolutionError(f"Environment variable {name} is not set")
    return _validate_secret_chars(value, f"{scheme}:{name}")


def resolve_template(
    template: str,
    *,
    treat_env_as_secret: bool = False,
    secret_env_names: Iterable[str] = (),
) -> ResolvedTemplate:
    secret_env_set = set(secret_env_names)
    collected_secrets: list[str] = []

    def replace_match(match: re.Match[str]) -> str:
        scheme = match.group(1)
        target = match.group(2)
        if scheme == "file":
            resolved = _read_secret_file(target)
            collected_secrets.append(resolved)
            return resolved
        if scheme == "secret_env":
            resolved = _read_env_var(target, scheme)
            collected_secrets.append(resolved)
            return resolved
        if scheme == "env":
            resolved = _read_env_var(target, scheme)
            if treat_env_as_secret or target in secret_env_set:
                collected_secrets.append(resolved)
            return resolved
        raise SecretResolutionError(f"Unsupported placeholder scheme '{scheme}'")

    resolved_value = PLACEHOLDER_PATTERN.sub(replace_match, template)
    leftover = ANY_PLACEHOLDER_PATTERN.search(resolved_value)
    if leftover is not None:
        raise SecretResolutionError(f"Unresolved placeholder syntax near '{leftover.group(0)}'")
    if "${" in resolved_value:
        raise SecretResolutionError("Unclosed placeholder syntax in configuration value")
    return ResolvedTemplate(value=resolved_value, secrets=tuple(collected_secrets))


def template_has_file_placeholder(template: str) -> bool:
    return any(match.group(1) == "file" for match in PLACEHOLDER_PATTERN.finditer(template))


def template_has_explicit_secret_placeholder(template: str) -> bool:
    return any(
        match.group(1) in ("file", "secret_env")
        for match in PLACEHOLDER_PATTERN.finditer(template)
    )


class Redactor:
    def __init__(self, secrets: Iterable[str]) -> None:
        variants: set[str] = set()
        for raw_secret in secrets:
            if not raw_secret:
                continue
            self._add_variants(raw_secret, variants)
        ordered = sorted(variants, key=len, reverse=True)
        self._pattern = (
            re.compile("|".join(re.escape(item) for item in ordered))
            if ordered
            else None
        )

    @staticmethod
    def _add_variants(secret: str, target: set[str]) -> None:
        target.add(secret)
        encoded_bytes = secret.encode("utf-8")
        quoted = urllib.parse.quote(secret, safe="")
        quoted_plus = urllib.parse.quote_plus(secret)
        b64_std = base64.b64encode(encoded_bytes).decode("ascii")
        b64_url = base64.urlsafe_b64encode(encoded_bytes).decode("ascii")
        json_escaped = json.dumps(secret)[1:-1]
        for candidate in (
            quoted,
            quoted_plus,
            b64_std,
            b64_std.rstrip("="),
            b64_url,
            b64_url.rstrip("="),
            json_escaped,
        ):
            if len(candidate) >= 4:
                target.add(candidate)

    def scrub_text(self, text: str) -> str:
        if not text or self._pattern is None:
            return text
        return self._pattern.sub(REDACTED_MARKER, text)

    def scrub_headers(self, headers: dict[str, str]) -> dict[str, str]:
        return {key: self.scrub_text(value) for key, value in headers.items()}

    def scrub_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.scrub_text(value)
        if isinstance(value, list):
            return [self.scrub_value(item) for item in value]
        if isinstance(value, dict):
            return {
                self.scrub_text(str(key)) if isinstance(key, str) else key: self.scrub_value(val)
                for key, val in value.items()
            }
        return value
