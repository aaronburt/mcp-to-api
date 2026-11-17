import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from gateway.secrets import Redactor


def safe_audit_str(value: Any, max_len: int = 512) -> str | None:
    if not isinstance(value, str):
        return None
    return "".join(ch if 0x20 <= ord(ch) < 0x7F else "?" for ch in value[:max_len])


class AuditLogger:
    def __init__(
        self,
        *,
        stdout: bool = True,
        file_path: str | None = None,
        redactor: Redactor | None = None,
        stream: TextIO | None = None,
    ) -> None:
        self._stdout = stdout
        self._stream = stream
        self._file_path = Path(file_path) if file_path else None
        self._file_handle: TextIO | None = None
        self._redactor = redactor
        self._lock = threading.Lock()
        if self._file_path is not None:
            self._file_path.parent.mkdir(parents=True, exist_ok=True)
            self._file_handle = self._file_path.open("a", encoding="utf-8")

    def log(
        self,
        *,
        request_id: str,
        agent: str | None,
        service: str | None,
        method: str | None,
        path: str | None,
        query_keys: list[str] | None,
        status: int | None,
        response_bytes: int | None,
        duration_ms: float,
        outcome: str,
        acl: str | None = None,
        denial_reason: str | None = None,
        client_ip: str | None = None,
    ) -> dict[str, Any]:
        safe_reason = (
            self._redactor.scrub_text(denial_reason)
            if denial_reason is not None and self._redactor is not None
            else denial_reason
        )
        record: dict[str, Any] = {
            "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "request_id": request_id,
            "agent": safe_audit_str(agent, 128),
            "service": safe_audit_str(service, 128),
            "method": safe_audit_str(method, 16),
            "path": safe_audit_str(path, 512),
            "query_keys": query_keys if query_keys is not None else [],
            "status": status,
            "response_bytes": response_bytes,
            "duration_ms": round(duration_ms, 2),
            "outcome": outcome,
            "acl": safe_audit_str(acl, 128),
            "denial_reason": safe_reason,
        }
        if client_ip is not None:
            record["client_ip"] = safe_audit_str(client_ip, 128)
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            if self._stdout:
                out = self._stream if self._stream is not None else sys.stdout
                out.write(line + "\n")
                out.flush()
            if self._file_handle is not None:
                self._file_handle.write(line + "\n")
                self._file_handle.flush()
        return record

    def close(self) -> None:
        with self._lock:
            if self._file_handle is not None:
                self._file_handle.close()
                self._file_handle = None
