"""Playwright-backed auth request fallback for registration-critical steps."""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse

from .browser_bind import _add_cookies_resilient
from .sentinel import SENTINEL_SDK_URL


logger = logging.getLogger(__name__)

DEFAULT_EXT_PASSKEY_CAPABILITIES = '{"isUserVerifyingPlatformAuthenticatorAvailable":false}'


def _primary_locale(accept_language: Optional[str]) -> str:
    text = str(accept_language or "").strip()
    if not text:
        return "en-US"
    first = text.split(",", 1)[0].split(";", 1)[0].strip()
    return first or "en-US"


def _headless_for_mode(browser_mode: Optional[str]) -> bool:
    return str(browser_mode or "protocol").strip().lower() != "headed"


def _cookie_http_only(cookie: Any) -> bool:
    rest = getattr(cookie, "_rest", None) or {}
    for key in ("HttpOnly", "httponly"):
        if key in rest:
            value = str(rest.get(key) or "").strip().lower()
            return value in {"", "1", "true", "yes"}
    return False


def _cookie_expires(cookie: Any) -> Optional[int]:
    expires = getattr(cookie, "expires", None)
    try:
        if expires is None:
            return None
        return int(expires)
    except Exception:
        return None


def _session_cookie_items(session: Any, device_id: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    cookies = getattr(session, "cookies", None)
    if cookies is not None:
        try:
            iterator = list(cookies.jar)
        except Exception:
            try:
                iterator = list(cookies)
            except Exception:
                iterator = []
        for cookie in iterator:
            name = str(getattr(cookie, "name", "") or "").strip()
            value = str(getattr(cookie, "value", "") or "").strip()
            if not name or not value:
                continue
            domain = str(getattr(cookie, "domain", "") or "").strip()
            path = str(getattr(cookie, "path", "") or "/").strip() or "/"
            key = (name, domain, path)
            if key in seen:
                continue
            seen.add(key)
            item: dict[str, Any] = {
                "name": name,
                "value": value,
                "path": path,
                "secure": bool(getattr(cookie, "secure", True)),
                "sameSite": "Lax",
                "httpOnly": _cookie_http_only(cookie),
            }
            expires = _cookie_expires(cookie)
            if expires and expires > 0:
                item["expires"] = expires
            if name.startswith("__Host-"):
                host = domain.lstrip(".") or "auth.openai.com"
                item["url"] = f"https://{host}/"
            elif domain:
                item["domain"] = domain
            else:
                item["url"] = "https://auth.openai.com/"
            items.append(item)

    did = str(device_id or "").strip()
    if did:
        for host in ("auth.openai.com", "chatgpt.com"):
            key = ("oai-did", host, "/")
            if key in seen:
                continue
            seen.add(key)
            items.append(
                {
                    "name": "oai-did",
                    "value": did,
                    "url": f"https://{host}/",
                    "path": "/",
                    "secure": True,
                    "sameSite": "Lax",
                    "httpOnly": False,
                }
            )
    return items


def submit_auth_request_with_playwright(
    *,
    session: Any,
    url: str,
    payload: Dict[str, Any],
    device_id: str,
    user_agent: str,
    accept_language: Optional[str],
    referer: str,
    flow: str = "username_password_create",
    proxy: Optional[str] = None,
    browser_mode: Optional[str] = None,
    timeout_seconds: int = 45,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Execute a registration request inside a real browser context."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        return {
            "success": False,
            "error": f"playwright not installed: {exc}",
            "status": 0,
            "text": "",
            "json": None,
            "current_url": "",
        }

    target_url = str(url or "").strip()
    referer_url = str(referer or "").strip() or "https://auth.openai.com/about-you"
    if not target_url:
        return {
            "success": False,
            "error": "target url empty",
            "status": 0,
            "text": "",
            "json": None,
            "current_url": "",
        }

    def _log(message: str) -> None:
        if log_fn:
            try:
                log_fn(message)
            except Exception:
                logger.info(message)
        else:
            logger.info(message)

    launch_kwargs: Dict[str, Any] = {"headless": _headless_for_mode(browser_mode)}
    proxy_server = str(proxy or "").strip()
    if proxy_server:
        launch_kwargs["proxy"] = {"server": proxy_server}

    locale = _primary_locale(accept_language)
    timeout_ms = max(int(timeout_seconds), 20) * 1000
    cookie_items = _session_cookie_items(session, device_id)
    referer_origin = ""
    try:
        referer_origin = urlparse(referer_url).scheme + "://" + urlparse(referer_url).netloc
    except Exception:
        referer_origin = "https://auth.openai.com"

    _log(f"Playwright 兜底启动: flow={flow} referer={referer_url}")
    with sync_playwright() as p:
        browser = p.chromium.launch(**launch_kwargs)
        try:
            context = browser.new_context(
                viewport={"width": 1366, "height": 900},
                user_agent=str(user_agent or ""),
                locale=locale,
                extra_http_headers={
                    "Accept-Language": str(accept_language or "en-US,en;q=0.9"),
                },
            )
            if cookie_items:
                _add_cookies_resilient(context, cookie_items, stage="registration-browser")
            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            page.goto(referer_url, wait_until="domcontentloaded", timeout=timeout_ms)
            page.wait_for_timeout(1200)

            result = page.evaluate(
                """
                async ({ targetUrl, payload, deviceId, flow, sdkUrl, timeoutMs, refererOrigin }) => {
                  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
                  const isObject = (value) => !!value && typeof value === "object" && !Array.isArray(value);
                  const normalizeToken = (value) => {
                    if (value == null) {
                      return "";
                    }
                    if (typeof value === "string") {
                      return value.trim();
                    }
                    if (isObject(value)) {
                      return JSON.stringify(value);
                    }
                    return String(value).trim();
                  };
                  const ensureSdk = async () => {
                    const deadline = Date.now() + timeoutMs;
                    while (Date.now() < deadline) {
                      const sdk = window.SentinelSDK;
                      if (sdk && (typeof sdk.token === "function" || typeof sdk.getToken === "function")) {
                        return sdk;
                      }
                      await sleep(100);
                    }
                    await new Promise((resolve, reject) => {
                      const existing = Array.from(document.scripts || []).find(
                        (item) => item && item.src && item.src.includes("/sentinel/") && item.src.includes("/sdk.js")
                      );
                      if (existing) {
                        existing.addEventListener("load", () => resolve(), { once: true });
                        existing.addEventListener("error", () => reject(new Error("existing sentinel sdk failed")), { once: true });
                        return;
                      }
                      const script = document.createElement("script");
                      script.src = sdkUrl;
                      script.async = true;
                      script.onload = () => resolve();
                      script.onerror = () => reject(new Error("failed to load sentinel sdk"));
                      (document.head || document.documentElement || document.body).appendChild(script);
                    });
                    const secondDeadline = Date.now() + timeoutMs;
                    while (Date.now() < secondDeadline) {
                      const sdk = window.SentinelSDK;
                      if (sdk && (typeof sdk.token === "function" || typeof sdk.getToken === "function")) {
                        return sdk;
                      }
                      await sleep(100);
                    }
                    throw new Error("SentinelSDK not available");
                  };
                  const buildPasskeyCapabilities = async () => {
                    let supported = false;
                    try {
                      const fn = window.PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable;
                      if (typeof fn === "function") {
                        supported = await fn.call(window.PublicKeyCredential);
                      }
                    } catch (_) {}
                    return JSON.stringify({
                      isUserVerifyingPlatformAuthenticatorAvailable: Boolean(supported),
                    });
                  };
                  const getSentinelToken = async (sdk) => {
                    const candidates = [
                      () => sdk.token?.({ flow, id: deviceId }),
                      () => sdk.token?.({ flow }),
                      () => sdk.token?.(),
                      () => sdk.getToken?.({ flow, id: deviceId }),
                      () => sdk.getToken?.({ flow }),
                      () => sdk.getToken?.(),
                    ];
                    let lastError = "";
                    for (const factory of candidates) {
                      try {
                        const token = normalizeToken(await factory());
                        if (token) {
                          return token;
                        }
                      } catch (error) {
                        lastError = error && error.message ? error.message : String(error);
                      }
                    }
                    throw new Error(lastError || "sentinel token empty");
                  };

                  const sdk = await ensureSdk();
                  const sentinelToken = await getSentinelToken(sdk);
                  const passkeyCapabilities = await buildPasskeyCapabilities();
                  const response = await fetch(targetUrl, {
                    method: "POST",
                    credentials: "include",
                    headers: {
                      "Accept": "application/json",
                      "Content-Type": "application/json",
                      "Referer": location.href || refererOrigin,
                      "oai-device-id": deviceId,
                      "openai-sentinel-token": sentinelToken,
                      "ext-passkey-client-capabilities": passkeyCapabilities,
                    },
                    body: JSON.stringify(payload),
                  });
                  const text = await response.text();
                  let data = null;
                  try {
                    data = JSON.parse(text);
                  } catch (_) {}
                  return {
                    success: response.ok,
                    status: response.status,
                    text,
                    json: data,
                    sentinel_token: sentinelToken,
                    current_url: location.href || refererOrigin,
                    passkey_capabilities: passkeyCapabilities,
                  };
                }
                """,
                {
                    "targetUrl": target_url,
                    "payload": payload,
                    "deviceId": str(device_id or "").strip(),
                    "flow": str(flow or "").strip() or "username_password_create",
                    "sdkUrl": SENTINEL_SDK_URL,
                    "timeoutMs": timeout_ms,
                    "refererOrigin": referer_origin,
                },
            )
            if not isinstance(result, dict):
                return {
                    "success": False,
                    "error": f"unexpected playwright result: {result}",
                    "status": 0,
                    "text": "",
                    "json": None,
                    "current_url": page.url,
                }
            return result
        except Exception as exc:
            return {
                "success": False,
                "error": str(exc),
                "status": 0,
                "text": "",
                "json": None,
                "current_url": "",
            }
        finally:
            try:
                browser.close()
            except Exception:
                pass
