#!/usr/bin/env python3
"""
Key system end-to-end smoke test for the Netlify/Pages functions app.

Usage:
  1) Start app locally (example): npx wrangler pages dev . --port 8788
  2) Run: python3 key_system_test.py --base-url http://127.0.0.1:8788

What this validates:
- Session creation works with a valid 128-hex HWID.
- /api/get-key returns key + nonce for the created session.
- /api/verify-key accepts the correct tuple (key, hwid, sid, st, nonce).
- /key page references the original logo image file (not text fallback).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
import time
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


@dataclass
class Resp:
    status: int
    data: dict
    raw: str


def http_json(method: str, url: str, payload: dict | None = None, timeout: int = 15) -> Resp:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = Request(url, data=body, method=method.upper(), headers=headers)
    try:
        with urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw) if raw else {}
            return Resp(r.status, parsed, raw)
    except HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"_non_json": raw}
        return Resp(e.code, parsed, raw)
    except URLError as e:
        raise RuntimeError(f"Network error calling {url}: {e}") from e


def http_text(url: str, timeout: int = 15) -> tuple[int, str]:
    req = Request(url, method="GET")
    with urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", errors="replace")


def make_hwid(seed: str) -> str:
    return hashlib.sha512(seed.encode("utf-8")).hexdigest()


def expect(name: str, condition: bool, details: str = "") -> None:
    if condition:
        print(f"[PASS] {name}")
    else:
        print(f"[FAIL] {name} {details}".rstrip())
        raise AssertionError(name)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", default="http://127.0.0.1:8788", help="Local server base URL")
    p.add_argument("--retries", type=int, default=3, help="Retries while waiting for local server")
    args = p.parse_args()

    base = args.base_url.rstrip("/")

    # 1) Request session
    hwid = make_hwid(f"incognito-test-{secrets.token_hex(8)}")
    expect("HWID format", len(hwid) == 128 and all(c in "0123456789abcdef" for c in hwid))

    session_resp = None
    for i in range(args.retries):
        try:
            session_resp = http_json("POST", f"{base}/api/request-session", {"hwid": hwid})
            break
        except RuntimeError:
            if i == args.retries - 1:
                raise
            time.sleep(0.8)

    assert session_resp is not None
    expect("request-session HTTP 201", session_resp.status == 201, str(session_resp.data))
    expect("request-session ok", session_resp.data.get("ok") is True, str(session_resp.data))

    sid = session_resp.data.get("sessionId")
    st = session_resp.data.get("sessionToken")
    expect("sessionId present", isinstance(sid, str) and len(sid) > 0)
    expect("sessionToken present", isinstance(st, str) and len(st) > 0)

    # 2) Get key
    q = urlencode({"sid": sid, "st": st})
    get_key = http_json("GET", f"{base}/api/get-key?{q}")
    expect("get-key HTTP 200", get_key.status == 200, str(get_key.data))
    expect("get-key ok", get_key.data.get("ok") is True, str(get_key.data))

    key = get_key.data.get("key")
    nonce = get_key.data.get("nonce")
    expect("key format", isinstance(key, str) and key.startswith("incognito_v2_"), str(key))
    expect("nonce format", isinstance(nonce, str) and len(nonce) == 32, str(nonce))

    # 3) Verify key
    verify_payload = {"key": key, "hwid": hwid, "sid": sid, "st": st, "nonce": nonce}
    verify = http_json("POST", f"{base}/api/verify-key", verify_payload)
    expect("verify-key HTTP 200", verify.status == 200, str(verify.data))
    expect("verify-key ok", verify.data.get("ok") is True, str(verify.data))
    expect(
        "verify-key payload success",
        isinstance(verify.data.get("payload"), dict) and verify.data["payload"].get("success") is True,
        str(verify.data),
    )

    # 4) Key page includes original logo asset.
    status, key_page = http_text(f"{base}/key")
    expect("/key HTTP 200", status == 200)
    expect(
        "key page uses original logo file",
        '/assets/incognito-logo.svg' in key_page,
        "Expected /assets/incognito-logo.svg in /key HTML",
    )

    print("\nAll checks passed. Key system flow works and logo is sourced from original image asset.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError:
        raise SystemExit(1)
