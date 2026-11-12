#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build a V2Ray (base64 URI list) subscription from the clash.yaml stored in
the same Gist and patch it back as v2ray.txt.

Why this exists: subscribe/collect.py converts with subconverter, whose
v2ray target cannot export some protocols (e.g. hysteria2). When the whole
alive pool is such a protocol, v2ray.txt comes out empty and collect.py
skips uploading it. This fallback rebuilds v2ray.txt from clash.yaml so
all three formats are always present.

Retention rule: if zero nodes can be mapped, the Gist is left untouched
(previous v2ray.txt, if any, is kept).

Env:
  GIST_PAT   GitHub token with gist scope
  GIST_LINK  "username/gist_id"
"""
import base64
import json
import os
import sys
import urllib.parse
import urllib.request

import yaml

API = "https://api.github.com/gists/"


def http(method, url, token, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def q(s) -> str:
    return urllib.parse.quote(str(s), safe="")


def to_uri(p: dict):
    t = str(p.get("type", "")).lower()
    name = q(p.get("name", "node"))
    server, port = p.get("server", ""), p.get("port", "")
    if not server or not port:
        return None

    if t == "ss":
        userinfo = base64.urlsafe_b64encode(
            f"{p.get('cipher','')}:{p.get('password','')}".encode()
        ).decode().rstrip("=")
        return f"ss://{userinfo}@{server}:{port}#{name}"

    if t == "trojan":
        params = {}
        if p.get("sni"):
            params["sni"] = p["sni"]
        if p.get("skip-cert-verify"):
            params["allowInsecure"] = "1"
        qs = ("?" + urllib.parse.urlencode(params)) if params else ""
        return f"trojan://{q(p.get('password',''))}@{server}:{port}{qs}#{name}"

    if t == "vmess":
        obj = {
            "v": "2",
            "ps": p.get("name", "node"),
            "add": server,
            "port": str(port),
            "id": p.get("uuid", ""),
            "aid": str(p.get("alterId", 0)),
            "scy": p.get("cipher", "auto"),
            "net": p.get("network", "tcp"),
            "type": "none",
            "host": (p.get("ws-opts", {}) or {}).get("headers", {}).get("Host", "")
            if isinstance(p.get("ws-opts"), dict)
            else "",
            "path": (p.get("ws-opts", {}) or {}).get("path", "")
            if isinstance(p.get("ws-opts"), dict)
            else "",
            "tls": "tls" if p.get("tls") else "",
            "sni": p.get("servername", "") or p.get("sni", ""),
            "alpn": "",
            "fp": "",
        }
        return "vmess://" + b64(json.dumps(obj, ensure_ascii=False))

    if t == "vless":
        params = {"encryption": "none"}
        if p.get("tls"):
            params["security"] = "tls"
        if p.get("flow"):
            params["flow"] = p["flow"]
        params["type"] = p.get("network", "tcp")
        sni = p.get("servername", "") or p.get("sni", "")
        if sni:
            params["sni"] = sni
        return (
            f"vless://{p.get('uuid','')}@{server}:{port}"
            f"?{urllib.parse.urlencode(params)}#{name}"
        )

    if t in ("hysteria2", "hy2"):
        auth = p.get("password", "") or p.get("auth-str", "") or p.get("auth_str", "")
        params = {}
        sni = p.get("sni", "")
        if sni:
            params["sni"] = sni
        if p.get("skip-cert-verify"):
            params["insecure"] = "1"
        if p.get("obfs") and p.get("obfs-password"):
            params["obfs"] = p["obfs"]
            params["obfs-password"] = p["obfs-password"]
        qs = ("?" + urllib.parse.urlencode(params)) if params else ""
        return f"hysteria2://{q(auth)}@{server}:{port}{qs}#{name}"

    if t == "tuic":
        params = {}
        sni = p.get("sni", "")
        if sni:
            params["sni"] = sni
        alpn = p.get("alpn")
        if isinstance(alpn, list) and alpn:
            params["alpn"] = ",".join(alpn)
        qs = ("?" + urllib.parse.urlencode(params)) if params else ""
        return (
            f"tuic://{p.get('uuid','')}:{q(p.get('password',''))}"
            f"@{server}:{port}{qs}#{name}"
        )

    return None


def main() -> int:
    token = os.environ.get("GIST_PAT", "").strip()
    link = os.environ.get("GIST_LINK", "").strip()
    if not token or "/" not in link:
        print("GIST_PAT / GIST_LINK not set, skip v2ray fallback")
        return 0
    gist_id = link.split("/", 1)[1].strip()

    gist = http("GET", API + gist_id, token)
    files = gist.get("files", {})
    clash = files.get("clash.yaml", {})
    content = clash.get("content", "")
    if clash.get("truncated") or not content:
        raw = files.get("clash.yaml", {}).get("raw_url", "")
        if not raw:
            print("clash.yaml not found in gist, skip")
            return 0
        with urllib.request.urlopen(raw, timeout=60) as resp:
            content = resp.read().decode("utf-8")

    data = yaml.safe_load(content) or {}
    proxies = data.get("proxies", []) or []
    uris, skipped = [], 0
    for p in proxies:
        uri = to_uri(p) if isinstance(p, dict) else None
        if uri:
            uris.append(uri)
        else:
            skipped += 1

    print(f"proxies: {len(proxies)}, mapped: {len(uris)}, skipped: {skipped}")
    if not uris:
        print("no mappable nodes, keep existing v2ray.txt untouched")
        return 0

    payload = {"files": {"v2ray.txt": {"content": b64("\n".join(uris))}}}
    http("PATCH", API + gist_id, token, payload)
    print("v2ray.txt updated in gist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
