"""Helpers for OpenAI Sentinel tokens backed by the official SDK."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from shutil import which
from typing import Any, Optional, Sequence
from urllib.request import Request, urlopen


logger = logging.getLogger(__name__)

SENTINEL_VERSION = "20260219f9f6"
SENTINEL_SDK_URL = f"https://sentinel.openai.com/sentinel/{SENTINEL_VERSION}/sdk.js"
SENTINEL_REQ_URL = "https://sentinel.openai.com/backend-api/sentinel/req"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/146.0.0.0 Safari/537.36"
)
DEFAULT_SEC_CH_UA = '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"'
DEFAULT_ACCEPT_LANGUAGE = "en-US,en;q=0.9"
DEFAULT_LANGUAGE = "en-US"
DEFAULT_LANGUAGES = ("en-US", "en")

ROOT_DIR = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = ROOT_DIR / "scripts"
NODE_VM_FILE = SCRIPTS_DIR / "openai_sentinel_vm.js"
SDK_CACHE_DIR = Path(tempfile.gettempdir()) / "codex-console" / "openai-sentinel" / SENTINEL_VERSION
SDK_CACHE_FILE = SDK_CACHE_DIR / "sdk.js"


class SentinelPOWError(RuntimeError):
    """Compatibility exception for Sentinel token generation failures."""


class SentinelTokenError(SentinelPOWError):
    """Raised when a Sentinel token cannot be generated."""


def _normalize_languages(accept_language: Optional[str], languages: Optional[Sequence[str]]) -> list[str]:
    if languages:
        cleaned = [str(item).strip() for item in languages if str(item).strip()]
        if cleaned:
            return cleaned
    if accept_language:
        parsed = []
        for item in str(accept_language).split(","):
            lang = item.split(";", 1)[0].strip()
            if lang:
                parsed.append(lang)
        if parsed:
            return parsed
    return list(DEFAULT_LANGUAGES)


def _primary_language(accept_language: Optional[str], languages: Optional[Sequence[str]]) -> str:
    normalized = _normalize_languages(accept_language, languages)
    return normalized[0] if normalized else DEFAULT_LANGUAGE


def resolve_node_binary() -> str:
    candidate = os.getenv("OPENAI_SENTINEL_NODE_PATH", "").strip()
    if candidate and Path(candidate).exists():
        return candidate
    node_binary = which("node")
    if node_binary:
        return node_binary
    raise SentinelTokenError("node not found; install Node.js or set OPENAI_SENTINEL_NODE_PATH")


def ensure_vm_file() -> Path:
    if NODE_VM_FILE.exists():
        return NODE_VM_FILE
    raise SentinelTokenError(f"sentinel vm script not found: {NODE_VM_FILE}")


def ensure_sdk_file() -> Path:
    direct = os.getenv("OPENAI_SENTINEL_SDK_FILE", "").strip()
    if direct and Path(direct).exists():
        return Path(direct)

    SDK_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if SDK_CACHE_FILE.exists() and SDK_CACHE_FILE.stat().st_size > 0:
        return SDK_CACHE_FILE

    request = Request(
        SENTINEL_SDK_URL,
        headers={
            "User-Agent": "Mozilla/5.0",
            "Referer": "https://auth.openai.com/",
            "Accept": "*/*",
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            SDK_CACHE_FILE.write_bytes(response.read())
    except Exception as exc:
        raise SentinelTokenError(f"failed to download sentinel sdk: {exc}") from exc
    return SDK_CACHE_FILE


def build_node_environment(
    device_id: str,
    *,
    user_agent: Optional[str] = None,
    accept_language: Optional[str] = None,
    languages: Optional[Sequence[str]] = None,
) -> dict[str, Any]:
    perf_now = 12345.67
    normalized_languages = _normalize_languages(accept_language, languages)
    return {
        "device_id": device_id,
        "user_agent": str(user_agent or DEFAULT_USER_AGENT),
        "language": _primary_language(accept_language, normalized_languages),
        "languages": normalized_languages,
        "hardware_concurrency": 12,
        "screen_width": 1366,
        "screen_height": 768,
        "performance_now": perf_now,
        "time_origin": (time.time() * 1000.0) - perf_now,
        "js_heap_size_limit": 4294967296,
    }


def run_node_vm(action: str, payload: dict[str, Any], *, timeout: int = 40) -> dict[str, Any]:
    node_binary = resolve_node_binary()
    sdk_file = ensure_sdk_file()
    vm_file = ensure_vm_file()
    full_payload = {
        "action": action,
        "sdk_path": str(sdk_file),
        **payload,
    }
    process = subprocess.run(
        [node_binary, str(vm_file)],
        input=json.dumps(full_payload, separators=(",", ":")),
        text=True,
        capture_output=True,
        cwd=str(ROOT_DIR),
        timeout=timeout,
        check=False,
    )
    if process.returncode != 0:
        stderr = (process.stderr or "").strip()
        if "Cannot find module 'happy-dom'" in stderr:
            raise SentinelTokenError("missing happy-dom; run `npm install` in the project root")
        raise SentinelTokenError(stderr or process.stdout.strip() or f"node exit={process.returncode}")
    if not process.stdout.strip():
        raise SentinelTokenError("node vm returned empty stdout")
    try:
        payload = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise SentinelTokenError(f"node vm returned invalid json: {process.stdout[:200]}") from exc
    if not isinstance(payload, dict):
        raise SentinelTokenError("node vm result is not a JSON object")
    return payload


def build_sentinel_request_headers(
    *,
    user_agent: Optional[str] = None,
    sec_ch_ua: Optional[str] = None,
    accept_language: Optional[str] = None,
    extra_headers: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={SENTINEL_VERSION}",
        "Origin": "https://sentinel.openai.com",
        "User-Agent": str(user_agent or DEFAULT_USER_AGENT),
        "Accept-Language": str(accept_language or DEFAULT_ACCEPT_LANGUAGE),
        "sec-ch-ua": str(sec_ch_ua or DEFAULT_SEC_CH_UA),
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Priority": "u=1, i",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }
    if extra_headers:
        headers.update({str(key): str(value) for key, value in extra_headers.items() if value is not None})
    return headers


def fetch_sentinel_challenge(
    session: Any,
    device_id: str,
    *,
    flow: str = "authorize_continue",
    request_p: str,
    user_agent: Optional[str] = None,
    sec_ch_ua: Optional[str] = None,
    accept_language: Optional[str] = None,
    proxies: Optional[dict[str, str]] = None,
    impersonate: Optional[str] = None,
    extra_headers: Optional[dict[str, str]] = None,
    timeout: int = 20,
) -> dict[str, Any]:
    body = {
        "p": request_p,
        "id": device_id,
        "flow": flow,
    }
    kwargs: dict[str, Any] = {
        "data": json.dumps(body, separators=(",", ":")),
        "headers": build_sentinel_request_headers(
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            accept_language=accept_language,
            extra_headers=extra_headers,
        ),
        "timeout": timeout,
    }
    if proxies:
        kwargs["proxies"] = proxies
    if impersonate:
        kwargs["impersonate"] = impersonate

    response = session.post(SENTINEL_REQ_URL, **kwargs)
    raise_for_status = getattr(response, "raise_for_status", None)
    if callable(raise_for_status):
        raise_for_status()

    payload: Any = {}
    json_loader = getattr(response, "json", None)
    if callable(json_loader):
        try:
            payload = json_loader()
        except Exception:
            payload = {}
    if not isinstance(payload, dict):
        raise SentinelTokenError("challenge response is not a JSON object")
    return payload


def build_sentinel_pow_token(
    user_agent: str,
    *,
    device_id: Optional[str] = None,
    accept_language: Optional[str] = None,
    languages: Optional[Sequence[str]] = None,
) -> str:
    """Compatibility helper returning the SDK-generated requirements token."""
    current_device_id = str(device_id or uuid.uuid4())
    request_payload = run_node_vm(
        "requirements",
        build_node_environment(
            current_device_id,
            user_agent=user_agent,
            accept_language=accept_language,
            languages=languages,
        ),
    )
    request_p = str(request_payload.get("request_p") or "").strip()
    if not request_p:
        raise SentinelTokenError("missing request_p")
    return request_p


def build_openai_sentinel_token(
    session: Any,
    device_id: str,
    *,
    flow: str = "authorize_continue",
    user_agent: Optional[str] = None,
    sec_ch_ua: Optional[str] = None,
    accept_language: Optional[str] = None,
    languages: Optional[Sequence[str]] = None,
    proxies: Optional[dict[str, str]] = None,
    impersonate: Optional[str] = None,
    extra_headers: Optional[dict[str, str]] = None,
    timeout: int = 20,
) -> str:
    current_device_id = str(device_id or "").strip()
    if not current_device_id:
        raise SentinelTokenError("device_id is required")

    node_env = build_node_environment(
        current_device_id,
        user_agent=user_agent,
        accept_language=accept_language,
        languages=languages,
    )

    request_payload = run_node_vm("requirements", node_env, timeout=timeout * 2)
    request_p = str(request_payload.get("request_p") or "").strip()
    if not request_p:
        raise SentinelTokenError("missing request_p")

    challenge = fetch_sentinel_challenge(
        session,
        current_device_id,
        flow=str(flow or "authorize_continue").strip() or "authorize_continue",
        request_p=request_p,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
        accept_language=accept_language,
        proxies=proxies,
        impersonate=impersonate,
        extra_headers=extra_headers,
        timeout=timeout,
    )
    c_value = str(challenge.get("token") or "").strip()
    if not c_value:
        raise SentinelTokenError("challenge token is empty")

    solved = run_node_vm(
        "solve",
        {
            **node_env,
            "request_p": request_p,
            "challenge": challenge,
        },
        timeout=timeout * 2,
    )
    final_p = str(solved.get("final_p") or solved.get("p") or "").strip()
    if not final_p:
        raise SentinelTokenError("missing final_p")

    t_value = solved.get("t")
    dx_value = None
    turnstile = challenge.get("turnstile")
    if isinstance(turnstile, dict):
        dx_value = str(turnstile.get("dx") or "").strip()
    if dx_value and not str(t_value or "").strip():
        raise SentinelTokenError("missing t for turnstile challenge")

    token = {
        "p": final_p,
        "t": "" if t_value is None else str(t_value),
        "c": c_value,
        "id": current_device_id,
        "flow": str(flow or "authorize_continue").strip() or "authorize_continue",
    }
    return json.dumps(token, separators=(",", ":"))
