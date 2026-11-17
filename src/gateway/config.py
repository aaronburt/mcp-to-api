import base64
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from gateway.secrets import (
    Redactor,
    SecretResolutionError,
    resolve_template,
    template_has_explicit_secret_placeholder,
)


ALLOWED_HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
DEFAULT_RESPONSE_HEADERS = ("content-type", "etag", "last-modified", "retry-after")
_ALLOWED_ACL_PATH_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:@!$&'()*+,=/"
)

_RATE_LIMIT_RE = re.compile(
    r"^\s*(\d+)\s*/\s*(s|sec|second|seconds|m|min|minute|minutes|h|hr|hour|hours)\s*$",
    re.IGNORECASE,
)
_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h)?\s*$", re.IGNORECASE)
_SIZE_RE = re.compile(r"^\s*(\d+)\s*(b|k|kb|kib|m|mb|mib|g|gb|gib)?\s*$", re.IGNORECASE)
_SHA256_RE = re.compile(r"^sha256:([0-9a-fA-F]{64})$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class RateLimitSpec:
    limit: int
    window_seconds: float
    raw: str


@dataclass(frozen=True)
class OriginSpec:
    scheme: str
    host: str
    port: int
    base_path: str
    base_url: str


@dataclass(frozen=True)
class ResolvedAuth:
    style: Literal["header", "bearer", "basic", "query"]
    header_name: str | None
    header_value: str | None
    query_param: str | None
    query_value: str | None
    secrets: tuple[str, ...]


@dataclass(frozen=True)
class ResolvedService:
    name: str
    description: str
    notes: str
    origin: OriginSpec
    tls_verify: bool
    auth: ResolvedAuth
    rate_limit: RateLimitSpec
    global_rate_limit: RateLimitSpec | None
    max_concurrent: int
    connect_timeout: float
    timeout: float
    max_response_bytes: int
    max_request_body_bytes: int
    allowed_response_headers: frozenset[str]
    reserved_query_params: frozenset[str]


@dataclass(frozen=True)
class CompiledACLRule:
    acl_name: str
    service_name: str
    method: str
    pattern: str
    segments: tuple[str, ...]


@dataclass(frozen=True)
class AgentTokenSpec:
    name: str
    sha256_hex: str
    acls: tuple[str, ...]
    enabled: bool


@dataclass(frozen=True)
class LoadedGatewayConfig:
    services: dict[str, ResolvedService]
    acl_rules: dict[str, dict[str, dict[str, tuple[CompiledACLRule, ...]]]]
    tokens: tuple[AgentTokenSpec, ...]
    agents: dict[str, AgentTokenSpec]
    audit_stdout: bool
    audit_file: str | None
    server: "ServerConfig"
    invalid_request_rate_limit: RateLimitSpec
    redactor: Redactor


def parse_rate_limit(raw: str) -> RateLimitSpec:
    match = _RATE_LIMIT_RE.match(raw)
    if match is None:
        raise ConfigError(f"Invalid rate limit '{raw}'")
    count = int(match.group(1))
    if count <= 0:
        raise ConfigError(f"Rate limit count must be positive in '{raw}'")
    unit = match.group(2).lower()
    if unit in ("s", "sec", "second", "seconds"):
        window = 1.0
    elif unit in ("m", "min", "minute", "minutes"):
        window = 60.0
    else:
        window = 3600.0
    return RateLimitSpec(limit=count, window_seconds=window, raw=raw.strip())


def parse_duration(raw: str | int | float) -> float:
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        value = float(raw)
        if not math.isfinite(value) or value <= 0:
            raise ConfigError(f"Duration must be positive: {raw}")
        return value
    if not isinstance(raw, str):
        raise ConfigError(f"Invalid duration: {raw!r}")
    match = _DURATION_RE.match(raw)
    if match is None:
        raise ConfigError(f"Invalid duration '{raw}'")
    num = float(match.group(1))
    unit = (match.group(2) or "s").lower()
    multipliers = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}
    seconds = num * multipliers[unit]
    if not math.isfinite(seconds) or seconds <= 0:
        raise ConfigError(f"Duration must be positive: '{raw}'")
    return seconds


def parse_size(raw: str | int) -> int:
    if isinstance(raw, int) and not isinstance(raw, bool):
        if raw <= 0:
            raise ConfigError(f"Size must be positive: {raw}")
        return raw
    if not isinstance(raw, str):
        raise ConfigError(f"Invalid size: {raw!r}")
    match = _SIZE_RE.match(raw)
    if match is None:
        raise ConfigError(f"Invalid size '{raw}'")
    num = int(match.group(1))
    unit = (match.group(2) or "b").lower()
    multipliers = {
        "b": 1,
        "k": 1024,
        "kb": 1024,
        "kib": 1024,
        "m": 1024 * 1024,
        "mb": 1024 * 1024,
        "mib": 1024 * 1024,
        "g": 1024 * 1024 * 1024,
        "gb": 1024 * 1024 * 1024,
        "gib": 1024 * 1024 * 1024,
    }
    total = num * multipliers[unit]
    if total <= 0:
        raise ConfigError(f"Size must be positive: '{raw}'")
    return total


def validate_acl_pattern(pattern: str) -> tuple[str, ...]:
    if not isinstance(pattern, str) or not pattern:
        raise ConfigError(f"ACL path pattern must be a non-empty string: {pattern!r}")
    if not pattern.startswith("/"):
        raise ConfigError(f"ACL path pattern must start with '/': '{pattern}'")
    if pattern.startswith("//"):
        raise ConfigError(f"ACL path pattern cannot start with '//': '{pattern}'")
    for ch in pattern:
        code = ord(ch)
        if code < 0x21 or code == 0x7F:
            raise ConfigError(f"ACL path pattern contains whitespace or control chars: '{pattern}'")
    if any(forbidden in pattern for forbidden in ("\\", "?", "#", ";", "%")):
        raise ConfigError(f"ACL path pattern contains forbidden character: '{pattern}'")
    for ch in pattern:
        if ch not in _ALLOWED_ACL_PATH_CHARS:
            raise ConfigError(f"ACL path pattern contains forbidden or non-ASCII character '{ch}': '{pattern}'")
    if pattern == "/":
        return ()
    if pattern.endswith("/"):
        raise ConfigError(f"ACL path pattern cannot end with '/': '{pattern}'")
    raw_segments = pattern[1:].split("/")
    for seg in raw_segments:
        if not seg or seg in (".", ".."):
            raise ConfigError(f"ACL path pattern contains invalid segment '{seg}': '{pattern}'")
        if "*" in seg and seg != "*":
            raise ConfigError(f"Wildcard '*' must occupy an entire segment in '{pattern}'")
    return tuple(raw_segments)


class DefaultsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rate_limit: str = "60/min"
    global_rate_limit: str | None = None
    max_concurrent: int = Field(default=10, ge=1)
    connect_timeout: str | int | float = "5s"
    timeout: str | int | float = "20s"
    max_response: str | int = "2MB"
    max_request_body: str | int = "64KB"
    allowed_response_headers: list[str] = Field(default_factory=lambda: list(DEFAULT_RESPONSE_HEADERS))


class TLSConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verify: bool = True
    allow_insecure_http: bool = False


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["header", "bearer", "basic", "query"] | None = None
    header: str | None = None
    value: str | None = None
    token: str | None = None
    prefix: str = "Bearer "
    username: str | None = None
    password: str | None = None
    param: str | None = None
    secret_env: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_auth_shape(self) -> "AuthConfig":
        resolved_type = self.type
        if resolved_type is None:
            if self.header is not None and self.value is not None:
                resolved_type = "header"
            else:
                raise ValueError("auth.type is required unless auth.header and auth.value are provided")
        self.type = resolved_type

        if resolved_type == "header":
            if not self.header or self.value is None:
                raise ValueError("header auth requires 'header' and 'value'")
            if not _HEADER_NAME_RE.match(self.header):
                raise ValueError(f"Invalid HTTP header name '{self.header}'")
            if any(x is not None for x in (self.token, self.username, self.password, self.param)):
                raise ValueError("header auth cannot set token, username, password, or param")
        elif resolved_type == "bearer":
            if self.token is None:
                raise ValueError("bearer auth requires 'token'")
            header_name = self.header or "Authorization"
            if not _HEADER_NAME_RE.match(header_name):
                raise ValueError(f"Invalid HTTP header name '{header_name}'")
            self.header = header_name
            if any(x is not None for x in (self.value, self.username, self.password, self.param)):
                raise ValueError("bearer auth cannot set value, username, password, or param")
        elif resolved_type == "basic":
            if self.username is None or self.password is None:
                raise ValueError("basic auth requires 'username' and 'password'")
            if any(x is not None for x in (self.header, self.value, self.token, self.param)):
                raise ValueError("basic auth cannot set header, value, token, or param")
        elif resolved_type == "query":
            if not self.param or self.value is None:
                raise ValueError("query auth requires 'param' and 'value'")
            if any(x is not None for x in (self.header, self.token, self.username, self.password)):
                raise ValueError("query auth cannot set header, token, username, or password")
        return self


class ServiceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str
    description: str = ""
    notes: str = ""
    tls: TLSConfig = Field(default_factory=TLSConfig)
    auth: AuthConfig
    rate_limit: str | None = None
    global_rate_limit: str | None = None
    max_concurrent: int | None = Field(default=None, ge=1)
    connect_timeout: str | int | float | None = None
    timeout: str | int | float | None = None
    max_response: str | int | None = None
    max_request_body: str | int | None = None
    allowed_response_headers: list[str] | None = None
    reserved_query_params: list[str] = Field(default_factory=list)


class TokenConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hash: str
    acls: list[str] = Field(min_length=1)
    enabled: bool = True

    @field_validator("hash")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        match = _SHA256_RE.match(value.strip())
        if match is None:
            raise ValueError("token hash must match 'sha256:<64 hex chars>'")
        return f"sha256:{match.group(1).lower()}"


class AuditConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stdout: bool = True
    file: str | None = None


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = "0.0.0.0"
    port: int = Field(default=8080, ge=1, le=65535)
    mcp_path: str = "/mcp"
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_origins: list[str] = Field(default_factory=list)
    block_browser_origins: bool = True
    stateless_http: bool = False
    invalid_request_rate_limit: str = "120/min"

    @field_validator("mcp_path")
    @classmethod
    def validate_mcp_path(cls, value: str) -> str:
        if not value.startswith("/") or len(value) < 2:
            raise ValueError("server.mcp_path must start with '/' and not be root")
        return value.rstrip("/")


class GatewayConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defaults: DefaultsConfig = Field(default_factory=DefaultsConfig)
    services: dict[str, ServiceConfig] = Field(min_length=1)
    acls: dict[str, dict[str, dict[str, list[str]]]] = Field(default_factory=dict)
    tokens: dict[str, TokenConfig] = Field(default_factory=dict)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)


def _parse_service_origin(url: str, allow_insecure_http: bool) -> OriginSpec:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme == "http" and not allow_insecure_http:
        raise ConfigError(f"Service URL '{url}' must use HTTPS unless tls.allow_insecure_http is true")
    if scheme not in ("https", "http"):
        raise ConfigError(f"Service URL '{url}' has unsupported scheme '{parts.scheme}'")
    if not parts.hostname:
        raise ConfigError(f"Service URL '{url}' is missing hostname")
    if parts.username is not None or parts.password is not None:
        raise ConfigError(f"Service URL '{url}' must not embed credentials")
    if parts.query or parts.fragment:
        raise ConfigError(f"Service URL '{url}' must not contain query or fragment")
    port = parts.port or (443 if scheme == "https" else 80)
    host = parts.hostname.lower()
    base_path = parts.path.rstrip("/")
    netloc = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    host_port = f"{netloc}:{port}" if port != default_port else netloc
    canonical_base = f"{scheme}://{host_port}{base_path}"
    return OriginSpec(
        scheme=scheme,
        host=host,
        port=port,
        base_path=base_path,
        base_url=canonical_base,
    )


def _resolve_service_auth(service_name: str, auth: AuthConfig) -> ResolvedAuth:
    try:
        if auth.type == "header":
            assert auth.header is not None and auth.value is not None
            has_explicit = template_has_explicit_secret_placeholder(auth.value) or bool(auth.secret_env)
            resolved = resolve_template(
                auth.value,
                treat_env_as_secret=not has_explicit,
                secret_env_names=auth.secret_env,
            )
            secrets = tuple(dict.fromkeys((*resolved.secrets, resolved.value)))
            return ResolvedAuth(
                style="header",
                header_name=auth.header,
                header_value=resolved.value,
                query_param=None,
                query_value=None,
                secrets=secrets,
            )
        if auth.type == "bearer":
            assert auth.header is not None and auth.token is not None
            resolved = resolve_template(
                auth.token,
                treat_env_as_secret=True,
                secret_env_names=auth.secret_env,
            )
            header_val = f"{auth.prefix}{resolved.value}"
            secrets = tuple(dict.fromkeys((*resolved.secrets, resolved.value, header_val)))
            return ResolvedAuth(
                style="bearer",
                header_name=auth.header,
                header_value=header_val,
                query_param=None,
                query_value=None,
                secrets=secrets,
            )
        if auth.type == "basic":
            assert auth.username is not None and auth.password is not None
            resolved_user = resolve_template(
                auth.username,
                treat_env_as_secret=False,
                secret_env_names=auth.secret_env,
            )
            resolved_pass = resolve_template(
                auth.password,
                treat_env_as_secret=True,
                secret_env_names=auth.secret_env,
            )
            pair = f"{resolved_user.value}:{resolved_pass.value}".encode("utf-8")
            encoded = base64.b64encode(pair).decode("ascii")
            header_val = f"Basic {encoded}"
            secrets = tuple(
                dict.fromkeys(
                    (
                        *resolved_user.secrets,
                        *resolved_pass.secrets,
                        resolved_pass.value,
                        encoded,
                        header_val,
                    )
                )
            )
            return ResolvedAuth(
                style="basic",
                header_name="Authorization",
                header_value=header_val,
                query_param=None,
                query_value=None,
                secrets=secrets,
            )
        assert auth.param is not None and auth.value is not None
        has_explicit = template_has_explicit_secret_placeholder(auth.value) or bool(auth.secret_env)
        resolved = resolve_template(
            auth.value,
            treat_env_as_secret=not has_explicit,
            secret_env_names=auth.secret_env,
        )
        secrets = tuple(dict.fromkeys((*resolved.secrets, resolved.value)))
        return ResolvedAuth(
            style="query",
            header_name=None,
            header_value=None,
            query_param=auth.param,
            query_value=resolved.value,
            secrets=secrets,
        )
    except SecretResolutionError as exc:
        raise ConfigError(f"Service '{service_name}' auth resolution failed: {exc}") from exc


def load_config_from_dict(raw_data: dict[str, Any]) -> LoadedGatewayConfig:
    try:
        model = GatewayConfigModel.model_validate(raw_data)
    except Exception as exc:
        raise ConfigError(f"Invalid configuration: {exc}") from exc

    defaults = model.defaults
    default_rate = parse_rate_limit(defaults.rate_limit)
    default_global_rate = (
        parse_rate_limit(defaults.global_rate_limit) if defaults.global_rate_limit else None
    )
    default_connect = parse_duration(defaults.connect_timeout)
    default_timeout = parse_duration(defaults.timeout)
    default_max_resp = parse_size(defaults.max_response)
    default_max_body = parse_size(defaults.max_request_body)
    default_resp_headers = frozenset(h.strip().lower() for h in defaults.allowed_response_headers if h.strip())

    resolved_services: dict[str, ResolvedService] = {}
    all_secrets: list[str] = []

    for svc_name, svc in model.services.items():
        if not svc_name or not svc_name.strip():
            raise ConfigError("Service name cannot be empty")
        try:
            resolved_url = resolve_template(svc.url, treat_env_as_secret=False)
        except SecretResolutionError as exc:
            raise ConfigError(f"Service '{svc_name}' URL resolution failed: {exc}") from exc
        all_secrets.extend(resolved_url.secrets)
        origin = _parse_service_origin(resolved_url.value, svc.tls.allow_insecure_http)
        resolved_auth = _resolve_service_auth(svc_name, svc.auth)
        all_secrets.extend(resolved_auth.secrets)

        svc_rate = parse_rate_limit(svc.rate_limit) if svc.rate_limit else default_rate
        svc_global_rate = (
            parse_rate_limit(svc.global_rate_limit)
            if svc.global_rate_limit is not None
            else default_global_rate
        )
        svc_connect = (
            parse_duration(svc.connect_timeout)
            if svc.connect_timeout is not None
            else default_connect
        )
        svc_timeout = parse_duration(svc.timeout) if svc.timeout is not None else default_timeout
        if svc_connect > svc_timeout:
            raise ConfigError(
                f"Service '{svc_name}' connect_timeout ({svc_connect}s) exceeds timeout ({svc_timeout}s)"
            )
        svc_max_resp = parse_size(svc.max_response) if svc.max_response is not None else default_max_resp
        svc_max_body = (
            parse_size(svc.max_request_body) if svc.max_request_body is not None else default_max_body
        )
        svc_resp_headers = (
            frozenset(h.strip().lower() for h in svc.allowed_response_headers if h.strip())
            if svc.allowed_response_headers is not None
            else default_resp_headers
        )
        reserved_query = {k.strip().lower() for k in svc.reserved_query_params if k.strip()}
        if resolved_auth.query_param is not None:
            reserved_query.add(resolved_auth.query_param.lower())

        resolved_services[svc_name] = ResolvedService(
            name=svc_name,
            description=svc.description,
            notes=svc.notes,
            origin=origin,
            tls_verify=svc.tls.verify,
            auth=resolved_auth,
            rate_limit=svc_rate,
            global_rate_limit=svc_global_rate,
            max_concurrent=svc.max_concurrent if svc.max_concurrent is not None else defaults.max_concurrent,
            connect_timeout=svc_connect,
            timeout=svc_timeout,
            max_response_bytes=svc_max_resp,
            max_request_body_bytes=svc_max_body,
            allowed_response_headers=svc_resp_headers,
            reserved_query_params=frozenset(reserved_query),
        )

    compiled_acls: dict[str, dict[str, dict[str, tuple[CompiledACLRule, ...]]]] = {}
    for acl_name, svc_map in model.acls.items():
        compiled_svc_map: dict[str, dict[str, tuple[CompiledACLRule, ...]]] = {}
        for svc_name, method_map in svc_map.items():
            if svc_name not in resolved_services:
                raise ConfigError(f"ACL '{acl_name}' references unknown service '{svc_name}'")
            compiled_method_map: dict[str, tuple[CompiledACLRule, ...]] = {}
            for raw_method, patterns in method_map.items():
                method = raw_method.upper()
                if method not in ALLOWED_HTTP_METHODS:
                    raise ConfigError(
                        f"ACL '{acl_name}' service '{svc_name}' has invalid HTTP method '{raw_method}'"
                    )
                if not patterns:
                    raise ConfigError(
                        f"ACL '{acl_name}' service '{svc_name}' method '{method}' has empty path list"
                    )
                rules: list[CompiledACLRule] = []
                for pattern in patterns:
                    segments = validate_acl_pattern(pattern)
                    rules.append(
                        CompiledACLRule(
                            acl_name=acl_name,
                            service_name=svc_name,
                            method=method,
                            pattern=pattern,
                            segments=segments,
                        )
                    )
                compiled_method_map[method] = tuple(rules)
            compiled_svc_map[svc_name] = compiled_method_map
        compiled_acls[acl_name] = compiled_svc_map

    token_specs: list[AgentTokenSpec] = []
    agents_by_name: dict[str, AgentTokenSpec] = {}
    seen_hashes: set[str] = set()
    for agent_name, token_cfg in model.tokens.items():
        if not agent_name or not agent_name.strip():
            raise ConfigError("Token agent name cannot be empty")
        for acl_name in token_cfg.acls:
            if acl_name not in compiled_acls:
                raise ConfigError(f"Token '{agent_name}' references unknown ACL '{acl_name}'")
        sha_hex = token_cfg.hash.split(":", 1)[1]
        if sha_hex in seen_hashes:
            raise ConfigError(f"Token '{agent_name}' duplicates another token hash")
        seen_hashes.add(sha_hex)
        spec = AgentTokenSpec(
            name=agent_name,
            sha256_hex=sha_hex,
            acls=tuple(dict.fromkeys(token_cfg.acls)),
            enabled=token_cfg.enabled,
        )
        token_specs.append(spec)
        agents_by_name[agent_name] = spec

    invalid_rate = parse_rate_limit(model.server.invalid_request_rate_limit)

    return LoadedGatewayConfig(
        services=resolved_services,
        acl_rules=compiled_acls,
        tokens=tuple(token_specs),
        agents=agents_by_name,
        audit_stdout=model.audit.stdout,
        audit_file=model.audit.file,
        server=model.server,
        invalid_request_rate_limit=invalid_rate,
        redactor=Redactor(all_secrets),
    )


def load_config(path: str | Path) -> LoadedGatewayConfig:
    config_path = Path(path)
    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read config file {config_path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {config_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Config file {config_path} must contain a top-level YAML mapping")
    return load_config_from_dict(data)
