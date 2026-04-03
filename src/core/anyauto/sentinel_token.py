"""Shared OpenAI Sentinel token helpers for the anyauto flows."""

from __future__ import annotations

from typing import Optional

from ..openai.sentinel import (
    build_openai_sentinel_token,
    build_sentinel_pow_token,
    fetch_sentinel_challenge as shared_fetch_sentinel_challenge,
)

_last_sentinel_error = ""


def get_last_sentinel_error() -> str:
    return str(_last_sentinel_error or "").strip()


def build_sentinel_token(
    session,
    device_id,
    flow="authorize_continue",
    user_agent=None,
    sec_ch_ua=None,
    impersonate=None,
    accept_language: Optional[str] = None,
):
    """构建完整的 openai-sentinel-token JSON 字符串。"""
    global _last_sentinel_error
    try:
        token = build_openai_sentinel_token(
            session,
            device_id,
            flow=flow,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            impersonate=impersonate,
            accept_language=accept_language,
        )
        _last_sentinel_error = ""
        return token
    except Exception as exc:
        _last_sentinel_error = str(exc or "").strip()
        return None


def fetch_sentinel_challenge(
    session,
    device_id,
    *,
    flow="authorize_continue",
    request_p: str,
    user_agent=None,
    sec_ch_ua=None,
    impersonate=None,
    accept_language: Optional[str] = None,
):
    """透传共享 challenge 请求逻辑，供调试或扩展流程复用。"""
    return shared_fetch_sentinel_challenge(
        session,
        device_id,
        flow=flow,
        request_p=request_p,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
        accept_language=accept_language,
        impersonate=impersonate,
    )


__all__ = [
    "build_sentinel_pow_token",
    "build_sentinel_token",
    "fetch_sentinel_challenge",
    "get_last_sentinel_error",
]
