#!/usr/bin/env python3
"""
Ollama Mobile Chat (single-file)
- Mobile-first chat UI (dark grey/black, accent #ffae00, 8px radius, monospace)
- Local auth (SQLite) with token stored in localStorage (client)
- Client-side persistence via IndexedDB (sessions + messages)
- Model capability detection:
    - /api/tags then /api/show to fetch capabilities
    - Show "thinking" controls only for models with capability "thinking"
    - Show image upload only for models with capability "vision"
- Safe Ollama proxy:
    - /api/chat (streaming NDJSON)
    - /api/generate (streaming NDJSON)
    - /api/embed
    - /api/tags, /api/show
- UPnP IGD mapping:
    - Random external port forwarded to local server port (no manual port forwarding)

Run:
  python3 chat.py --bind 0.0.0.0 --port 0 --upnp
Then open:
  Local:  http://127.0.0.1:<localport>/
  Public: http://<router-external-ip>:<random-external-port>/
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import datetime as _dt
import hashlib
import hmac
import json
import os
import random
import secrets
import socket
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

# --- bootstrap aiohttp (self-install via local .venv to avoid PEP 668) ---
def _ensure_aiohttp():
    """
    If aiohttp isn't available:
      1) Prefer installing into an existing active venv, if we're already in one.
      2) Otherwise, create ./\.venv next to this script, install aiohttp there,
         then re-exec this script under the venv interpreter.

    This avoids Debian/Ubuntu "externally-managed-environment" (PEP 668).
    """
    try:
        import aiohttp  # noqa: F401
        from aiohttp import web  # noqa: F401
        return
    except Exception:
        pass

    import subprocess
    import pathlib

    # Detect whether we're already inside a virtualenv
    in_venv = (getattr(sys, "base_prefix", sys.prefix) != sys.prefix) or bool(os.environ.get("VIRTUAL_ENV"))

    req_spec = "aiohttp>=3.9.0"

    def _run(cmd: list[str]) -> None:
        subprocess.check_call(cmd)

    def _try_install_in_current_python():
        # If pip is missing in this interpreter, try ensurepip
        try:
            _run([sys.executable, "-m", "pip", "--version"])
        except Exception:
            try:
                _run([sys.executable, "-m", "ensurepip", "--upgrade"])
            except Exception:
                pass
        _run([sys.executable, "-m", "pip", "install", "-q", "--upgrade", "pip", "setuptools", "wheel"])
        _run([sys.executable, "-m", "pip", "install", "-q", req_spec])

    if in_venv:
        print("[bootstrap] Installing aiohttp into active virtualenv...", file=sys.stderr)
        _try_install_in_current_python()
        import aiohttp  # noqa: F401
        from aiohttp import web  # noqa: F401
        return

    # Not in a venv: create/use .venv next to this script
    script_dir = pathlib.Path(__file__).resolve().parent
    venv_dir = script_dir / ".venv"

    if os.name == "nt":
        venv_python = venv_dir / "Scripts" / "python.exe"
    else:
        venv_python = venv_dir / "bin" / "python"

    try:
        if not venv_python.exists():
            print(f"[bootstrap] Creating virtualenv at: {venv_dir}", file=sys.stderr)
            _run([sys.executable, "-m", "venv", str(venv_dir)])

        print("[bootstrap] Installing aiohttp into .venv...", file=sys.stderr)
        _run([str(venv_python), "-m", "pip", "install", "-q", "--upgrade", "pip", "setuptools", "wheel"])
        _run([str(venv_python), "-m", "pip", "install", "-q", req_spec])

        # Re-exec under venv python
        print("[bootstrap] Re-launching under .venv interpreter...", file=sys.stderr)
        os.execv(str(venv_python), [str(venv_python), *sys.argv])

    except subprocess.CalledProcessError as e:
        # Most common: python3-venv not installed (Debian/Ubuntu)
        msg = (
            "[bootstrap] Failed to create/use .venv automatically.\n"
            "On Debian/Ubuntu you likely need the venv package installed:\n"
            "  sudo apt-get install -y python3-venv\n"
            "Then re-run:\n"
            "  python3 chat.py --bind 0.0.0.0 --port 0 --upnp\n"
        )
        raise RuntimeError(msg) from e

_ensure_aiohttp()
import aiohttp
from aiohttp import web

OLLAMA_BASE = os.environ.get("OLLAMA_BASE", "http://127.0.0.1:11434").rstrip("/")
DB_PATH = os.environ.get("APP_DB", "ollama_mobile_chat.sqlite3")

MODELS_CACHE_TTL_SEC = 20
SHOW_CACHE_TTL_SEC = 60

MAX_JSON_BODY = 2_000_000
MAX_IMAGE_B64_BYTES = 10_000_000

# =========================
# UPnP IGD (SSDP + SOAP)
# =========================

USER_AGENT = "python-upnp-ollama-chat/1.0"
SSDP_ADDR = ("239.255.255.250", 1900)
SSDP_ST = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"

def _now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())

def ssdp_discover(timeout: float = 3.0) -> Optional[str]:
    msg = "\r\n".join([
        "M-SEARCH * HTTP/1.1",
        f"HOST: {SSDP_ADDR[0]}:{SSDP_ADDR[1]}",
        'MAN: "ssdp:discover"',
        "MX: 2",
        f"ST: {SSDP_ST}",
        f"USER-AGENT: {USER_AGENT}",
        "",
        "",
    ]).encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    try:
        sock.sendto(msg, SSDP_ADDR)
        end = time.time() + timeout
        while time.time() < end:
            data, _ = sock.recvfrom(65535)
            text = data.decode("utf-8", errors="ignore")
            headers = {}
            for line in text.split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            loc = headers.get("location")
            if loc:
                return loc
    except socket.timeout:
        return None
    finally:
        sock.close()
    return None

def http_get(url: str, timeout: float = 6.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()

def find_igd_control_url(device_desc_url: str) -> Tuple[Optional[str], Optional[str]]:
    raw = http_get(device_desc_url)
    xml = ET.fromstring(raw)

    def strip_ns(tag: str) -> str:
        return tag.split("}", 1)[-1] if "}" in tag else tag

    base_url = device_desc_url
    urlbase = None
    for el in xml.iter():
        if strip_ns(el.tag) == "URLBase" and el.text:
            urlbase = el.text.strip()
            break
    if urlbase:
        base_url = urlbase

    service_candidates = [
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
    ]

    for service in xml.iter():
        if strip_ns(service.tag) != "service":
            continue
        service_type = None
        control_url = None
        for child in list(service):
            name = strip_ns(child.tag)
            if name == "serviceType" and child.text:
                service_type = child.text.strip()
            elif name == "controlURL" and child.text:
                control_url = child.text.strip()
        if service_type in service_candidates and control_url:
            full_control = urllib.parse.urljoin(base_url, control_url)
            return full_control, service_type

    return None, None

def escape_xml(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )

def soap_call(control_url: str, service_type: str, action: str, body_xml: str, timeout: float = 8.0) -> bytes:
    envelope = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:{action} xmlns:u="{service_type}">
      {body_xml}
    </u:{action}>
  </s:Body>
</s:Envelope>
""".encode("utf-8")

    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": f'"{service_type}#{action}"',
        "User-Agent": USER_AGENT,
    }
    req = urllib.request.Request(control_url, data=envelope, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()

def get_external_ip(control_url: str, service_type: str) -> Optional[str]:
    resp = soap_call(control_url, service_type, "GetExternalIPAddress", "")
    xml = ET.fromstring(resp)
    for el in xml.iter():
        if el.tag.endswith("NewExternalIPAddress") and el.text:
            return el.text.strip()
    return None

def add_port_mapping(control_url: str, service_type: str, external_port: int, internal_ip: str,
                     internal_port: int, desc: str, lease_seconds: int = 0) -> None:
    body = f"""
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{external_port}</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
<NewInternalPort>{internal_port}</NewInternalPort>
<NewInternalClient>{internal_ip}</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>{escape_xml(desc)}</NewPortMappingDescription>
<NewLeaseDuration>{lease_seconds}</NewLeaseDuration>
""".strip()
    soap_call(control_url, service_type, "AddPortMapping", body)

def delete_port_mapping(control_url: str, service_type: str, external_port: int) -> None:
    body = f"""
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{external_port}</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
""".strip()
    soap_call(control_url, service_type, "DeletePortMapping", body)

# =========================
# Auth DB (SQLite)
# =========================

def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

DB = db_connect()

def db_init() -> None:
    DB.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      pw_hash BLOB NOT NULL,
      salt BLOB NOT NULL,
      created_at INTEGER NOT NULL
    );
    """)
    DB.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      last_seen INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    DB.commit()

def _pbkdf2(password: str, salt: bytes, iters: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=32)

def create_user(username: str, password: str) -> None:
    username = username.strip()
    if not username or len(username) < 3:
        raise ValueError("Username too short.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 chars.")
    salt = secrets.token_bytes(16)
    pw_hash = _pbkdf2(password, salt)
    try:
        DB.execute(
            "INSERT INTO users(username, pw_hash, salt, created_at) VALUES(?,?,?,?)",
            (username, pw_hash, salt, int(time.time())),
        )
        DB.commit()
    except sqlite3.IntegrityError:
        raise ValueError("Username already exists.")

def verify_user(username: str, password: str) -> Optional[int]:
    row = DB.execute("SELECT id, pw_hash, salt FROM users WHERE username = ?", (username.strip(),)).fetchone()
    if not row:
        return None
    uid, pw_hash, salt = row
    cand = _pbkdf2(password, salt)
    if hmac.compare_digest(pw_hash, cand):
        return int(uid)
    return None

def new_session_token(uid: int, ttl: int = 7 * 24 * 3600) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    DB.execute(
        "INSERT INTO sessions(token, user_id, created_at, last_seen, expires_at) VALUES(?,?,?,?,?)",
        (token, uid, now, now, now + ttl),
    )
    DB.commit()
    return token

def get_user_by_token(token: str) -> Optional[Tuple[int, str]]:
    if not token:
        return None
    now = int(time.time())
    row = DB.execute(
        "SELECT u.id, u.username, s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?",
        (token,),
    ).fetchone()
    if not row:
        return None
    uid, username, expires_at = row
    if int(expires_at) < now:
        DB.execute("DELETE FROM sessions WHERE token=?", (token,))
        DB.commit()
        return None
    DB.execute("UPDATE sessions SET last_seen=? WHERE token=?", (now, token))
    DB.commit()
    return int(uid), str(username)

# =========================
# Ollama proxy + capability cache
# =========================

_models_cache: Tuple[float, List[Dict[str, Any]]] = (0.0, [])
_show_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}

async def ollama_fetch_json(session: aiohttp.ClientSession, method: str, path: str, payload: Any = None) -> Dict[str, Any]:
    url = f"{OLLAMA_BASE}{path}"
    kwargs = {}
    if payload is not None:
        kwargs["json"] = payload
    async with session.request(method, url, **kwargs, timeout=None) as resp:
        text = await resp.text()
        if resp.status >= 400:
            try:
                j = json.loads(text) if text else {}
            except Exception:
                j = {"error": text}
            raise web.HTTPBadRequest(text=json.dumps({"error": j.get("error", f"Ollama error {resp.status}")}),
                                     content_type="application/json")
        return json.loads(text) if text else {}

async def ollama_get_show(session: aiohttp.ClientSession, model: str) -> Dict[str, Any]:
    now = time.time()
    cached = _show_cache.get(model)
    if cached and (now - cached[0]) < SHOW_CACHE_TTL_SEC:
        return cached[1]
    data = await ollama_fetch_json(session, "POST", "/api/show", {"model": model})
    _show_cache[model] = (now, data)
    return data

async def get_models_with_capabilities(session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
    global _models_cache  # MUST be before first use

    now = time.time()
    t_cached, models_cached = _models_cache
    if models_cached and (now - t_cached) < MODELS_CACHE_TTL_SEC:
        return models_cached

    tags = await ollama_fetch_json(session, "GET", "/api/tags", None)
    models = tags.get("models", []) or []

    enriched: List[Dict[str, Any]] = []
    for m in models:
        name = m.get("name") or m.get("model") or ""
        if not name:
            continue

        caps = m.get("capabilities")
        details = m.get("details") or {}

        if not caps:
            try:
                show = await ollama_get_show(session, name)
                caps = show.get("capabilities") or []
                if show.get("details"):
                    details = show.get("details") or details
            except Exception:
                caps = []

        if isinstance(caps, list):
            caps_norm = [str(c) for c in caps]
        else:
            caps_norm = [str(caps)]

        enriched.append({
            "name": name,
            "modified_at": m.get("modified_at"),
            "size": m.get("size"),
            "digest": m.get("digest"),
            "details": details,
            "capabilities": caps_norm,
        })

    enriched.sort(key=lambda x: x["name"])
    _models_cache = (now, enriched)
    return enriched

async def model_capabilities(session: aiohttp.ClientSession, model: str) -> List[str]:
    show = await ollama_get_show(session, model)
    caps = show.get("capabilities") or []
    if isinstance(caps, list):
        return [str(c) for c in caps]
    return [str(caps)]

def _strip_data_url(b64_or_dataurl: str) -> str:
    s = b64_or_dataurl.strip()
    if "base64," in s:
        s = s.split("base64,", 1)[1]
    return s.strip()

# =========================
# Web UI
# =========================

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
  <title>Ollama Mobile Chat</title>
  <style>
    :root{
      --bg:#0b0b0c;
      --panel:#121315;
      --panel2:#17191c;
      --text:#e8e8e8;
      --muted:#a0a0a0;
      --accent:#ffae00;
      --radius:8px;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono","Courier New", monospace;
      --shadow: 0 12px 28px rgba(0,0,0,.45);
      --border: 1px solid rgba(255,255,255,.08);
    }
    *{box-sizing:border-box}
    html,body{height:100%}
    body{margin:0;background:var(--bg);color:var(--text);font-family:var(--mono)}
    button,input,select,textarea{font-family:var(--mono)}
    .app{height:100%;display:flex;overflow:hidden}
    .sidebar{
      position:fixed;inset:0 auto 0 0;
      width:min(86vw, 360px);
      background:linear-gradient(180deg, var(--panel), var(--panel2));
      border-right: var(--border);
      transform:translateX(-105%);
      transition:transform .22s ease;
      z-index:30;
      box-shadow:var(--shadow);
      display:flex;flex-direction:column;
      padding:12px;gap:12px;
    }
    .sidebar.open{transform:translateX(0)}
    .sidebar-header{
      display:flex;align-items:center;justify-content:space-between;gap:10px;
      padding:10px;border:var(--border);border-radius:var(--radius);
      background:rgba(255,255,255,.02);
    }
    .pill{
      display:inline-flex;align-items:center;gap:8px;
      padding:8px 10px;border-radius:999px;border:var(--border);
      background:rgba(255,255,255,.02);color:var(--muted);font-size:12px;white-space:nowrap;
    }
    .btn{
      border:var(--border);background:rgba(255,255,255,.03);
      color:var(--text);padding:10px 12px;border-radius:var(--radius);
      cursor:pointer;transition:transform .02s ease, border-color .15s ease, background .15s ease;
    }
    .btn:active{transform:translateY(1px)}
    .btn.primary{border-color:rgba(255,174,0,.35);background:rgba(255,174,0,.12)}
    .btn.ghost{background:transparent;color:var(--muted)}
    .btn.danger{border-color:rgba(255,80,80,.35);background:rgba(255,80,80,.10)}
    .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
    .col{display:flex;flex-direction:column;gap:8px}
    .label{font-size:12px;color:var(--muted)}
    .input,.select,.textarea{
      width:100%;padding:10px 12px;border-radius:var(--radius);
      border:var(--border);background:rgba(255,255,255,.02);color:var(--text);outline:none;
    }
    .divider{height:1px;background:rgba(255,255,255,.08);margin:6px 0}
    .sessions{display:flex;flex-direction:column;gap:8px;overflow:auto;padding-bottom:8px}
    .session-item{
      padding:10px;border-radius:var(--radius);border:var(--border);
      background:rgba(255,255,255,.02);cursor:pointer;
      display:flex;flex-direction:column;gap:6px;
    }
    .session-item.active{border-color:rgba(255,174,0,.35);background:rgba(255,174,0,.08)}
    .session-title{font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .session-meta{font-size:11px;color:var(--muted);display:flex;gap:8px;flex-wrap:wrap}
    .main{flex:1;display:flex;flex-direction:column;width:100%}
    .topbar{
      position:sticky;top:0;z-index:10;display:flex;align-items:center;justify-content:space-between;
      gap:10px;padding:10px 12px;border-bottom:var(--border);
      background:rgba(10,10,11,.92);backdrop-filter: blur(8px);
    }
    .brand{display:flex;align-items:center;gap:10px;min-width:0}
    .burger{
      width:40px;height:40px;display:grid;place-items:center;border-radius:var(--radius);
      border:var(--border);background:rgba(255,255,255,.02);cursor:pointer;flex:0 0 auto;
    }
    .title{font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:48vw}
    .badges{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
    .badge{
      font-size:11px;padding:6px 8px;border-radius:999px;border:var(--border);
      background:rgba(255,255,255,.02);color:var(--muted);
    }
    .badge.accent{border-color:rgba(255,174,0,.35);background:rgba(255,174,0,.10);color:var(--text)}
    .chat{flex:1;overflow:auto;padding:14px 12px 10px;display:flex;flex-direction:column;gap:10px}
    .msg{
      max-width:min(820px, 96vw);padding:12px;border-radius:var(--radius);
      border:var(--border);background:rgba(255,255,255,.02);
      word-wrap:break-word;white-space:pre-wrap;line-height:1.35;
    }
    .msg.user{align-self:flex-end;background:rgba(255,174,0,.07);border-color:rgba(255,174,0,.25)}
    .msg.assistant{align-self:flex-start}
    .msg .meta{display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:11px;color:var(--muted);margin-bottom:8px}
    .thinking{
      margin-top:10px;padding:10px;border-radius:var(--radius);
      border:1px dashed rgba(255,174,0,.35);background:rgba(255,174,0,.06);
      font-size:12px;white-space:pre-wrap;
    }
    .imggrid{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
    .imggrid img{max-width:220px;border-radius:var(--radius);border:var(--border);background:rgba(0,0,0,.25)}
    .composer{
      padding:10px 12px;border-top:var(--border);
      background:rgba(10,10,11,.92);backdrop-filter: blur(8px);
      display:flex;flex-direction:column;gap:10px;
    }
    .composer-row{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap}
    .composer textarea{flex:1;min-height:44px;max-height:140px;resize:none;overflow:auto}
    .hint{font-size:11px;color:var(--muted)}
    .overlay{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:20;display:none}
    .overlay.show{display:block}
    .modal{position:fixed;inset:0;display:none;place-items:center;z-index:40;padding:16px}
    .modal.show{display:grid}
    .card{
      width:min(560px, 92vw);background:linear-gradient(180deg, var(--panel), var(--panel2));
      border:var(--border);border-radius:var(--radius);box-shadow:var(--shadow);padding:14px;
      display:flex;flex-direction:column;gap:12px;
    }
    .card h2{margin:0;font-size:14px}
    .card p{margin:0;color:var(--muted);font-size:12px;line-height:1.4}
    .card .grid{display:grid;grid-template-columns:1fr;gap:10px}
    @media(min-width:720px){.title{max-width:40vw}.card .grid{grid-template-columns:1fr 1fr}}
    .tiny{font-size:11px;color:var(--muted)}
    .right{margin-left:auto}
    .hide{display:none !important}
  </style>
</head>
<body>
<div class="app">
  <div id="overlay" class="overlay"></div>

  <aside id="sidebar" class="sidebar" aria-label="Sidebar">
    <div class="sidebar-header">
      <div class="col" style="gap:2px;min-width:0;">
        <div style="font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
          <span style="color:var(--accent)">ollama</span> / mobile chat
        </div>
        <div class="tiny" id="whoami">not signed in</div>
      </div>
      <button class="btn ghost" id="closeSidebar">Close</button>
    </div>

    <div class="row">
      <button class="btn primary" id="newSession">New session</button>
      <button class="btn" id="refreshModels">Refresh models</button>
    </div>

    <div class="divider"></div>

    <div class="col">
      <div class="label">Sessions</div>
      <div id="sessions" class="sessions"></div>
    </div>

    <div class="divider"></div>

    <div class="col">
      <div class="label">Settings</div>

      <div class="row" style="align-items:flex-start">
        <div class="col" style="flex:1;min-width:240px">
          <div class="label">Model</div>
          <select id="modelSelect" class="select"></select>
          <div id="modelCaps" class="row" style="gap:8px"></div>
        </div>

        <div class="col" style="flex:1;min-width:240px">
          <div class="label">Thinking</div>

          <div id="thinkBoolWrap" class="row hide">
            <button id="thinkToggle" class="btn">Thinking: off</button>
            <button id="showThinkingToggle" class="btn">Show trace: on</button>
          </div>

          <div id="thinkLevelWrap" class="col hide">
            <select id="thinkLevel" class="select">
              <option value="low">Thinking: low</option>
              <option value="medium">Thinking: medium</option>
              <option value="high">Thinking: high</option>
            </select>
            <div class="tiny">GPT-OSS uses levels.</div>
            <button id="showThinkingToggle2" class="btn">Show trace: on</button>
          </div>

          <div id="thinkUnsupported" class="tiny">This model does not advertise thinking capability.</div>
        </div>
      </div>

      <div class="row">
        <button class="btn" id="clearToken">Sign out</button>
      </div>

      <div class="tiny" id="statusLine"></div>
    </div>
  </aside>

  <main class="main">
    <header class="topbar">
      <div class="brand">
        <div class="burger" id="openSidebar" aria-label="Open sidebar">☰</div>
        <div class="title" id="sessionTitle">No session</div>
      </div>
      <div class="badges" id="topBadges"></div>
    </header>

    <section id="chat" class="chat" aria-label="Chat"></section>

    <footer class="composer">
      <div class="composer-row">
        <button class="btn" id="attachBtn">Attach</button>
        <input id="fileInput" type="file" accept="image/*" class="hide" />
        <textarea id="prompt" class="input" placeholder="Type a message…" spellcheck="false"></textarea>
        <button class="btn primary" id="sendBtn">Send</button>
      </div>
      <div class="hint" id="composerHint">Select a session and model to chat.</div>
    </footer>
  </main>
</div>

<div id="authModal" class="modal">
  <div class="card">
    <div class="row" style="justify-content:space-between;align-items:center">
      <h2>Sign in</h2>
      <span class="pill">token → localStorage</span>
    </div>
    <p>Auth is required. Chat history is stored on-device in IndexedDB.</p>
    <div class="grid">
      <div class="col">
        <div class="label">Username</div>
        <input id="authUser" class="input" autocomplete="username" />
      </div>
      <div class="col">
        <div class="label">Password</div>
        <input id="authPass" type="password" class="input" autocomplete="current-password" />
      </div>
    </div>
    <div class="row">
      <button class="btn primary" id="loginBtn">Login</button>
      <button class="btn" id="signupBtn">Sign up</button>
      <span class="right tiny" id="authMsg"></span>
    </div>
  </div>
</div>

<script>
(() => {
  function uuidv4() {
    if (globalThis.crypto && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    const bytes = new Uint8Array(16);
    if (globalThis.crypto && crypto.getRandomValues) crypto.getRandomValues(bytes);
    else for (let i=0;i<16;i++) bytes[i] = Math.floor(Math.random()*256);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = [...bytes].map(b => b.toString(16).padStart(2,'0')).join('');
    return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
  }

  const el = (id) => document.getElementById(id);
  const sidebar = el('sidebar');
  const overlay = el('overlay');
  const authModal = el('authModal');

  function setStatus(msg){ el('statusLine').textContent = msg || ''; }
  function setAuthMsg(msg){ el('authMsg').textContent = msg || ''; }
  function clampTitle(s){ return (s||'').trim().slice(0,60) || 'Untitled'; }

  function openSidebar(){ sidebar.classList.add('open'); overlay.classList.add('show'); }
  function closeSidebar(){ sidebar.classList.remove('open'); overlay.classList.remove('show'); }

  el('openSidebar').onclick = openSidebar;
  el('closeSidebar').onclick = closeSidebar;
  overlay.onclick = closeSidebar;

  const TOKEN_KEY = 'ollama_chat_token';
  const USER_KEY = 'ollama_chat_user';

  function getToken(){ return localStorage.getItem(TOKEN_KEY) || ''; }
  function setToken(t){ localStorage.setItem(TOKEN_KEY, t); }
  function clearToken(){
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  }

  async function api(path, {method='GET', body=null, headers={}} = {}) {
    const h = Object.assign({}, headers);
    if (body && !h['Content-Type']) h['Content-Type'] = 'application/json';
    const tok = getToken();
    if (tok) h['Authorization'] = 'Bearer ' + tok;

    const res = await fetch(path, { method, headers: h, body: body ? (typeof body === 'string' ? body : JSON.stringify(body)) : null });
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
    if (!res.ok) {
      const msg = (data && (data.error || data.message)) ? (data.error || data.message) : `HTTP ${res.status}`;
      const err = new Error(msg);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  function showAuthModal(show){ authModal.classList.toggle('show', !!show); }

  async function whoami() {
    try{
      const me = await api('/api/auth/me');
      el('whoami').textContent = `signed in as ${me.username}`;
      localStorage.setItem(USER_KEY, me.username);
      return me;
    }catch(e){
      el('whoami').textContent = 'not signed in';
      return null;
    }
  }

  el('clearToken').onclick = async () => {
    clearToken();
    showAuthModal(true);
    setStatus('Signed out.');
  };

  el('loginBtn').onclick = async () => {
    setAuthMsg('');
    const username = el('authUser').value.trim();
    const password = el('authPass').value;
    if (!username || !password){ setAuthMsg('missing fields'); return; }
    try{
      const out = await api('/api/auth/login', {method:'POST', body:{username,password}});
      setToken(out.token);
      localStorage.setItem(USER_KEY, out.username);
      showAuthModal(false);
      await boot();
    }catch(e){
      setAuthMsg(e.message);
    }
  };

  el('signupBtn').onclick = async () => {
    setAuthMsg('');
    const username = el('authUser').value.trim();
    const password = el('authPass').value;
    if (!username || !password){ setAuthMsg('missing fields'); return; }
    try{
      await api('/api/auth/signup', {method:'POST', body:{username,password}});
      setAuthMsg('created — now login');
    }catch(e){
      setAuthMsg(e.message);
    }
  };

  // IndexedDB
  const DB_NAME = 'ollama_mobile_chat';
  const DB_VER = 1;
  const STORE_SESS = 'sessions';
  const STORE_MSG = 'messages';

  function openDB(){
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VER);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE_SESS)) {
          const s = db.createObjectStore(STORE_SESS, { keyPath:'id' });
          s.createIndex('by_user', 'user', { unique:false });
          s.createIndex('by_updated', 'updatedAt', { unique:false });
        }
        if (!db.objectStoreNames.contains(STORE_MSG)) {
          const m = db.createObjectStore(STORE_MSG, { keyPath:'id' });
          m.createIndex('by_user', 'user', { unique:false });
          m.createIndex('by_session', 'sessionId', { unique:false });
          m.createIndex('by_session_ts', ['sessionId','ts'], { unique:false });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function dbTx(store, mode, fn){
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(store, mode);
      const st = tx.objectStore(store);
      const out = fn(st, tx);
      tx.oncomplete = () => resolve(out);
      tx.onerror = () => reject(tx.error);
    });
  }

  async function putSession(sess){ return dbTx(STORE_SESS, 'readwrite', (st) => st.put(sess)); }
  async function addMessage(msg){ return dbTx(STORE_MSG, 'readwrite', (st) => st.put(msg)); }

  async function delSession(id){
    await dbTx(STORE_SESS, 'readwrite', (st) => st.delete(id));
    const db = await openDB();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_MSG, 'readwrite');
      const idx = tx.objectStore(STORE_MSG).index('by_session');
      const req = idx.openCursor(IDBKeyRange.only(id));
      req.onsuccess = () => { const cur = req.result; if (cur){ cur.delete(); cur.continue(); } };
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  }

  async function listSessions(){
    const user = localStorage.getItem(USER_KEY) || '';
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_SESS, 'readonly');
      const idx = tx.objectStore(STORE_SESS).index('by_user');
      const req = idx.getAll(IDBKeyRange.only(user));
      req.onsuccess = () => {
        const items = req.result || [];
        items.sort((a,b) => (b.updatedAt||0)-(a.updatedAt||0));
        resolve(items);
      };
      req.onerror = () => reject(req.error);
    });
  }

  async function listMessages(sessionId){
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_MSG, 'readonly');
      const idx = tx.objectStore(STORE_MSG).index('by_session_ts');
      const req = idx.getAll(IDBKeyRange.bound([sessionId,0],[sessionId,Number.MAX_SAFE_INTEGER]));
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });
  }

  // App state
  let MODELS = [];
  let MODEL_BY_NAME = new Map();
  let activeSessionId = null;
  let activeSession = null;
  let activeMessages = [];
  let pendingImages = []; // [{dataUrl,b64}]

  function modelInfo(name){ return MODEL_BY_NAME.get(name) || null; }
  function capsFor(name){
    const m = modelInfo(name);
    const caps = (m && m.capabilities) ? m.capabilities : [];
    return Array.isArray(caps) ? caps : [];
  }
  function hasCap(name, cap){ return capsFor(name).includes(cap); }

  function renderCapsBadges(target, caps){
    target.innerHTML = '';
    (caps||[]).forEach(c => {
      const b = document.createElement('span');
      b.className = 'badge' + ((c==='vision' || c==='thinking') ? ' accent' : '');
      b.textContent = c;
      target.appendChild(b);
    });
  }

  function applyModelUI(){
    const sel = el('modelSelect').value;
    const caps = capsFor(sel);
    renderCapsBadges(el('modelCaps'), caps);
    renderCapsBadges(el('topBadges'), caps);

    // image upload only for vision
    el('attachBtn').classList.toggle('hide', !caps.includes('vision'));

    // thinking controls only for thinking
    const canThink = caps.includes('thinking');
    const isGptOss = (sel || '').toLowerCase().includes('gpt-oss');

    el('thinkUnsupported').classList.toggle('hide', canThink);
    el('thinkBoolWrap').classList.toggle('hide', !(canThink && !isGptOss));
    el('thinkLevelWrap').classList.toggle('hide', !(canThink && isGptOss));

    if (activeSession) {
      if (canThink && !isGptOss) {
        const enabled = !!activeSession.thinkEnabled;
        el('thinkToggle').textContent = 'Thinking: ' + (enabled ? 'on' : 'off');
      }
      if (canThink && isGptOss) {
        el('thinkLevel').value = activeSession.thinkLevel || 'low';
      }
      const st = (activeSession.showThinkingTrace !== false);
      el('showThinkingToggle').textContent = 'Show trace: ' + (st ? 'on' : 'off');
      el('showThinkingToggle2').textContent = 'Show trace: ' + (st ? 'on' : 'off');
    }
  }

  function setComposerHint(){
    if (!activeSession) { el('composerHint').textContent = 'Create/select a session to chat.'; return; }
    const m = el('modelSelect').value;
    if (!m) { el('composerHint').textContent = 'Select a model.'; return; }
    const caps = capsFor(m);
    const parts = [];
    if (caps.includes('vision')) parts.push('vision');
    if (caps.includes('thinking')) parts.push('thinking');
    el('composerHint').textContent = parts.length ? `Model supports: ${parts.join(', ')}` : 'Model loaded.';
  }

  // Rendering
  function renderSessions(items){
    const host = el('sessions');
    host.innerHTML = '';
    items.forEach(sess => {
      const div = document.createElement('div');
      div.className = 'session-item' + (sess.id === activeSessionId ? ' active':'');
      div.onclick = async () => { await loadSession(sess.id); closeSidebar(); };

      const title = document.createElement('div');
      title.className = 'session-title';
      title.textContent = sess.title || 'Untitled';

      const meta = document.createElement('div');
      meta.className = 'session-meta';
      const model = sess.model || '(no model)';
      const t = new Date(sess.updatedAt || sess.createdAt || Date.now()).toLocaleString();
      meta.textContent = `${model} · ${t}`;

      const row = document.createElement('div');
      row.className = 'row';
      row.style.justifyContent = 'space-between';

      const del = document.createElement('button');
      del.className = 'btn danger';
      del.textContent = 'Delete';
      del.onclick = async (e) => {
        e.stopPropagation();
        if (!confirm('Delete this session (client-side)?')) return;
        await delSession(sess.id);
        if (activeSessionId === sess.id) {
          activeSessionId = null;
          activeSession = null;
          activeMessages = [];
          el('sessionTitle').textContent = 'No session';
          renderChat();
        }
        await refreshSessions();
      };

      row.appendChild(title);
      row.appendChild(del);
      div.appendChild(row);
      div.appendChild(meta);
      host.appendChild(div);
    });
  }

  function renderChat(){
    const chat = el('chat');
    chat.innerHTML = '';
    activeMessages.forEach(m => {
      const msg = document.createElement('div');
      msg.className = 'msg ' + (m.role === 'user' ? 'user' : 'assistant');

      const meta = document.createElement('div');
      meta.className = 'meta';
      const ts = new Date(m.ts).toLocaleTimeString();
      meta.textContent = `${m.role} · ${ts}`;
      msg.appendChild(meta);

      const body = document.createElement('div');
      body.textContent = m.content || '';
      msg.appendChild(body);

      if (m.images && m.images.length) {
        const grid = document.createElement('div');
        grid.className = 'imggrid';
        m.images.forEach(url => {
          const im = document.createElement('img');
          im.src = url;
          im.alt = 'image';
          grid.appendChild(im);
        });
        msg.appendChild(grid);
      }

      const showTrace = activeSession ? (activeSession.showThinkingTrace !== false) : true;
      if (showTrace && m.thinking) {
        const th = document.createElement('div');
        th.className = 'thinking';
        th.textContent = m.thinking;
        msg.appendChild(th);
      }

      chat.appendChild(msg);
    });
    chat.scrollTop = chat.scrollHeight;
  }

  // Model loading
  async function refreshModels(){
    setStatus('Loading models…');
    const data = await api('/api/models');
    MODELS = data.models || [];
    MODEL_BY_NAME = new Map(MODELS.map(m => [m.name, m]));

    const sel = el('modelSelect');
    const current = sel.value || (activeSession && activeSession.model) || '';
    sel.innerHTML = '';
    MODELS.forEach(m => {
      const opt = document.createElement('option');
      opt.value = m.name;
      opt.textContent = m.name;
      sel.appendChild(opt);
    });

    const pick = (activeSession && activeSession.model && MODEL_BY_NAME.has(activeSession.model))
      ? activeSession.model
      : (MODEL_BY_NAME.has(current) ? current : (MODELS[0] ? MODELS[0].name : ''));

    sel.value = pick;
    if (activeSession) {
      activeSession.model = pick;
      activeSession.updatedAt = Date.now();
      await putSession(activeSession);
    }

    applyModelUI();
    setComposerHint();
    setStatus(`Loaded ${MODELS.length} model(s).`);
  }

  el('refreshModels').onclick = async () => { try { await refreshModels(); } catch(e){ setStatus('Model refresh failed: ' + e.message); } };

  el('modelSelect').onchange = async () => {
    if (!activeSession) { applyModelUI(); setComposerHint(); return; }
    activeSession.model = el('modelSelect').value;
    activeSession.updatedAt = Date.now();
    await putSession(activeSession);
    applyModelUI();
    setComposerHint();
    await refreshSessions();
  };

  // Thinking controls
  el('thinkToggle').onclick = async () => {
    if (!activeSession) return;
    activeSession.thinkEnabled = !activeSession.thinkEnabled;
    activeSession.updatedAt = Date.now();
    await putSession(activeSession);
    el('thinkToggle').textContent = 'Thinking: ' + (activeSession.thinkEnabled ? 'on' : 'off');
    await refreshSessions();
    renderChat();
  };
  el('showThinkingToggle').onclick = async () => {
    if (!activeSession) return;
    activeSession.showThinkingTrace = !(activeSession.showThinkingTrace !== false);
    activeSession.updatedAt = Date.now();
    await putSession(activeSession);
    const st = (activeSession.showThinkingTrace !== false);
    el('showThinkingToggle').textContent = 'Show trace: ' + (st ? 'on':'off');
    el('showThinkingToggle2').textContent = el('showThinkingToggle').textContent;
    renderChat();
  };
  el('showThinkingToggle2').onclick = el('showThinkingToggle').onclick;

  el('thinkLevel').onchange = async () => {
    if (!activeSession) return;
    activeSession.thinkLevel = el('thinkLevel').value || 'low';
    activeSession.updatedAt = Date.now();
    await putSession(activeSession);
    await refreshSessions();
  };

  // Sessions
  async function refreshSessions(){ renderSessions(await listSessions()); }

  async function createSession(){
    const user = localStorage.getItem(USER_KEY) || '';
    const id = uuidv4();
    const now = Date.now();
    const firstModel = (MODELS[0] && MODELS[0].name) ? MODELS[0].name : '';
    const sess = {
      id, user,
      title: 'New chat',
      createdAt: now,
      updatedAt: now,
      model: firstModel,
      thinkEnabled: false,
      thinkLevel: 'low',
      showThinkingTrace: true
    };
    await putSession(sess);
    await refreshSessions();
    await loadSession(id);
  }

  el('newSession').onclick = async () => { if (!MODELS.length) await refreshModels(); await createSession(); closeSidebar(); };

  async function loadSession(id){
    const items = await listSessions();
    const sess = items.find(s => s.id === id);
    if (!sess) return;
    activeSessionId = id;
    activeSession = sess;
    el('sessionTitle').textContent = clampTitle(sess.title || 'Session');
    if (sess.model && MODEL_BY_NAME.has(sess.model)) el('modelSelect').value = sess.model;
    applyModelUI();
    setComposerHint();
    activeMessages = await listMessages(id);
    renderChat();
    await refreshSessions();
  }

  // Composer
  function resetComposer(){
    el('prompt').value = '';
    pendingImages = [];
    el('fileInput').value = '';
  }

  el('attachBtn').onclick = () => el('fileInput').click();

  el('fileInput').onchange = async () => {
    if (!activeSession) return;
    const model = el('modelSelect').value;
    if (!hasCap(model, 'vision')) { alert('This model does not advertise vision capability.'); el('fileInput').value=''; return; }

    const files = el('fileInput').files;
    if (!files || !files.length) return;

    for (const f of files) {
      const buf = await f.arrayBuffer();
      const bytes = new Uint8Array(buf);
      let bin = '';
      for (let i=0;i<bytes.length;i++) bin += String.fromCharCode(bytes[i]);
      const b64 = btoa(bin);
      const dataUrl = `data:${f.type || 'image/png'};base64,${b64}`;
      pendingImages.push({ dataUrl, b64 });
    }
    setStatus(`Attached ${pendingImages.length} image(s).`);
  };

  function inferTitleFrom(text){
    const t = (text || '').trim().split('\n')[0].slice(0,40);
    return t || 'New chat';
  }

  async function sendMessage(){
    if (!activeSession) { openSidebar(); return; }
    const model = el('modelSelect').value;
    if (!model) { openSidebar(); return; }

    const content = el('prompt').value.trim();
    if (!content && !pendingImages.length) return;

    const now = Date.now();

    const userMsg = {
      id: uuidv4(),
      user: localStorage.getItem(USER_KEY) || '',
      sessionId: activeSessionId,
      ts: now,
      role: 'user',
      content: content,
      thinking: '',
      images: pendingImages.map(x => x.dataUrl)
    };
    activeMessages.push(userMsg);
    await addMessage(userMsg);

    if ((activeSession.title || 'New chat') === 'New chat') activeSession.title = inferTitleFrom(content);
    activeSession.updatedAt = now;
    await putSession(activeSession);

    const asstId = uuidv4();
    const asstMsg = {
      id: asstId,
      user: localStorage.getItem(USER_KEY) || '',
      sessionId: activeSessionId,
      ts: now + 1,
      role: 'assistant',
      content: '',
      thinking: '',
      images: []
    };
    activeMessages.push(asstMsg);
    await addMessage(asstMsg);

    renderChat();
    resetComposer();

    // Build messages for Ollama (include images on last user message only)
    const messages = activeMessages
      .filter(m => m.role === 'user' || m.role === 'assistant')
      .map(m => ({ role: m.role, content: m.content || '' }));

    if (userMsg.images && userMsg.images.length) {
      const lastUserIdx = (() => {
        for (let i = messages.length - 1; i >= 0; i--) if (messages[i].role === 'user') return i;
        return -1;
      })();
      if (lastUserIdx >= 0) {
        const b64s = (userMsg.images || []).map(u => (u.split('base64,')[1] || '')).filter(Boolean);
        messages[lastUserIdx].images = b64s;
      }
    }

    // Thinking setting
    const caps = capsFor(model);
    const canThink = caps.includes('thinking');
    const isGptOss = (model || '').toLowerCase().includes('gpt-oss');
    let think = undefined;
    if (canThink) think = isGptOss ? (activeSession.thinkLevel || 'low') : !!activeSession.thinkEnabled;

    try{
      setStatus('Streaming…');

      const payload = { model, messages, stream: true };
      if (think !== undefined) payload.think = think;

      const res = await fetch('/api/ollama/chat', {
        method:'POST',
        headers:{ 'Content-Type':'application/json', 'Authorization':'Bearer ' + getToken() },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const t = await res.text();
        let j=null; try{ j=JSON.parse(t);}catch{}
        throw new Error((j && (j.error||j.message)) ? (j.error||j.message) : (t || `HTTP ${res.status}`));
      }

      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = '';

      while(true){
        const {value, done} = await reader.read();
        if (done) break;
        buf += dec.decode(value, {stream:true});

        let idx;
        while((idx = buf.indexOf('\n')) >= 0){
          const line = buf.slice(0, idx).trim();
          buf = buf.slice(idx + 1);
          if (!line) continue;
          let obj=null; try{ obj=JSON.parse(line);}catch{continue;}

          const part = (obj.message && obj.message.content) ? obj.message.content : '';
          const thinkPart = (obj.message && obj.message.thinking) ? obj.message.thinking : '';
          if (part) asstMsg.content += part;
          if (thinkPart) asstMsg.thinking += thinkPart;
          renderChat();
        }
      }

      asstMsg.ts = Date.now();
      await addMessage(asstMsg);
      activeSession.updatedAt = Date.now();
      await putSession(activeSession);

      setStatus('Done.');
      await refreshSessions();
      renderChat();
    }catch(e){
      setStatus('Error: ' + e.message);
      asstMsg.content += `\n\n[error] ${e.message}`;
      await addMessage(asstMsg);
      renderChat();
    }
  }

  el('sendBtn').onclick = sendMessage;
  el('prompt').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });

  // Boot
  async function boot(){
    const me = await whoami();
    if (!me){ showAuthModal(true); return; }
    showAuthModal(false);
    await refreshModels();
    await refreshSessions();
    const sessions = await listSessions();
    if (sessions.length) await loadSession(sessions[0].id);
    else await createSession();
    applyModelUI();
    setComposerHint();
  }

  (async () => { if (!getToken()) showAuthModal(true); await boot(); })();
})();
</script>
</body>
</html>
"""

# =========================
# HTTP handlers
# =========================

@web.middleware
async def security_headers(request: web.Request, handler):
    resp: web.StreamResponse = await handler(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp

async def require_auth(request: web.Request) -> Tuple[int, str]:
    auth = request.headers.get("Authorization", "")
    token = ""
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
    if not token:
        raise web.HTTPUnauthorized(text=json.dumps({"error": "Missing token"}), content_type="application/json")
    user = get_user_by_token(token)
    if not user:
        raise web.HTTPUnauthorized(text=json.dumps({"error": "Invalid token"}), content_type="application/json")
    return user

async def read_json_limited(request: web.Request) -> Dict[str, Any]:
    raw = await request.read()
    if len(raw) > MAX_JSON_BODY:
        raise web.HTTPRequestEntityTooLarge(text=json.dumps({"error": "Body too large"}), content_type="application/json")
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        raise web.HTTPBadRequest(text=json.dumps({"error": "Invalid JSON"}), content_type="application/json")

async def index(request: web.Request) -> web.Response:
    return web.Response(text=INDEX_HTML, content_type="text/html", charset="utf-8")

# auth
async def auth_signup(request: web.Request) -> web.Response:
    data = await read_json_limited(request)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    try:
        create_user(username, password)
        return web.json_response({"ok": True})
    except ValueError as e:
        raise web.HTTPBadRequest(text=json.dumps({"error": str(e)}), content_type="application/json")

async def auth_login(request: web.Request) -> web.Response:
    data = await read_json_limited(request)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    uid = verify_user(username, password)
    if not uid:
        raise web.HTTPUnauthorized(text=json.dumps({"error": "Invalid credentials"}), content_type="application/json")
    token = new_session_token(uid)
    return web.json_response({"token": token, "username": username})

async def auth_me(request: web.Request) -> web.Response:
    uid, username = await require_auth(request)
    return web.json_response({"id": uid, "username": username})

# models (capabilities-enriched)
async def api_models(request: web.Request) -> web.Response:
    await require_auth(request)
    async with aiohttp.ClientSession() as session:
        models = await get_models_with_capabilities(session)
        return web.json_response({"models": models})

# safe proxy endpoints
async def ollama_tags(request: web.Request) -> web.Response:
    await require_auth(request)
    async with aiohttp.ClientSession() as session:
        data = await ollama_fetch_json(session, "GET", "/api/tags", None)
        return web.json_response(data)

async def ollama_show(request: web.Request) -> web.Response:
    await require_auth(request)
    data = await read_json_limited(request)
    model = (data.get("model") or "").strip()
    if not model:
        raise web.HTTPBadRequest(text=json.dumps({"error": "Missing model"}), content_type="application/json")
    async with aiohttp.ClientSession() as session:
        out = await ollama_fetch_json(session, "POST", "/api/show", {"model": model})
        return web.json_response(out)

async def _proxy_stream(request: web.Request, ollama_path: str, payload: Dict[str, Any]) -> web.StreamResponse:
    async with aiohttp.ClientSession() as session:
        url = f"{OLLAMA_BASE}{ollama_path}"
        async with session.post(url, json=payload, timeout=None) as resp:
            if resp.status >= 400:
                txt = await resp.text()
                try:
                    j = json.loads(txt) if txt else {}
                except Exception:
                    j = {"error": txt}
                raise web.HTTPBadRequest(text=json.dumps({"error": j.get("error", f"Ollama error {resp.status}")}),
                                         content_type="application/json")
            out = web.StreamResponse(status=200)
            out.content_type = "application/x-ndjson"
            await out.prepare(request)
            async for chunk in resp.content.iter_chunked(4096):
                await out.write(chunk)
            await out.write_eof()
            return out

async def ollama_chat(request: web.Request) -> web.StreamResponse:
    await require_auth(request)
    data = await read_json_limited(request)

    model = (data.get("model") or "").strip()
    if not model:
        raise web.HTTPBadRequest(text=json.dumps({"error": "Missing model"}), content_type="application/json")

    messages = data.get("messages")
    if not isinstance(messages, list) or not messages:
        raise web.HTTPBadRequest(text=json.dumps({"error": "messages must be a non-empty list"}), content_type="application/json")

    # Enforce image gating
    async with aiohttp.ClientSession() as session:
        caps = await model_capabilities(session, model)

        for msg in messages:
            if not isinstance(msg, dict):
                continue
            imgs = msg.get("images")
            if imgs:
                if "vision" not in caps:
                    raise web.HTTPBadRequest(text=json.dumps({"error": "Model does not support images (vision missing)."}),
                                             content_type="application/json")
                if not isinstance(imgs, list):
                    raise web.HTTPBadRequest(text=json.dumps({"error": "images must be a list"}), content_type="application/json")
                clean = []
                for b in imgs:
                    if not isinstance(b, str):
                        continue
                    s = _strip_data_url(b)
                    if len(s) > MAX_IMAGE_B64_BYTES:
                        raise web.HTTPRequestEntityTooLarge(text=json.dumps({"error": "Image too large"}),
                                                            content_type="application/json")
                    # mild validation
                    try:
                        base64.b64decode(s[:128] + "==", validate=False)
                    except Exception:
                        pass
                    clean.append(s)
                msg["images"] = clean

    payload: Dict[str, Any] = {"model": model, "messages": messages, "stream": bool(data.get("stream", True))}
    if "think" in data:
        payload["think"] = data["think"]
    if "options" in data and isinstance(data["options"], dict):
        payload["options"] = data["options"]
    if "format" in data:
        payload["format"] = data["format"]
    if "keep_alive" in data:
        payload["keep_alive"] = data["keep_alive"]
    if "tools" in data:
        payload["tools"] = data["tools"]

    return await _proxy_stream(request, "/api/chat", payload)

async def ollama_generate(request: web.Request) -> web.StreamResponse:
    await require_auth(request)
    data = await read_json_limited(request)
    model = (data.get("model") or "").strip()
    if not model:
        raise web.HTTPBadRequest(text=json.dumps({"error": "Missing model"}), content_type="application/json")

    payload: Dict[str, Any] = {"model": model, "prompt": data.get("prompt", ""), "stream": bool(data.get("stream", True))}
    if "options" in data and isinstance(data["options"], dict):
        payload["options"] = data["options"]
    if "think" in data:
        payload["think"] = data["think"]
    for k in ("suffix", "system", "template", "format", "keep_alive", "raw"):
        if k in data:
            payload[k] = data[k]

    return await _proxy_stream(request, "/api/generate", payload)

async def ollama_embed(request: web.Request) -> web.Response:
    await require_auth(request)
    data = await read_json_limited(request)
    async with aiohttp.ClientSession() as session:
        out = await ollama_fetch_json(session, "POST", "/api/embed", data)
        return web.json_response(out)

def make_app() -> web.Application:
    app = web.Application(client_max_size=MAX_JSON_BODY + 4096, middlewares=[security_headers])
    app.router.add_get("/", index)

    app.router.add_post("/api/auth/signup", auth_signup)
    app.router.add_post("/api/auth/login", auth_login)
    app.router.add_get("/api/auth/me", auth_me)

    app.router.add_get("/api/models", api_models)

    app.router.add_get("/api/ollama/tags", ollama_tags)
    app.router.add_post("/api/ollama/show", ollama_show)
    app.router.add_post("/api/ollama/chat", ollama_chat)
    app.router.add_post("/api/ollama/generate", ollama_generate)
    app.router.add_post("/api/ollama/embed", ollama_embed)
    return app

# =========================
# Programmatic start + UPnP
# =========================

async def start_aiohttp(app: web.Application, host: str, port: int) -> Tuple[web.AppRunner, web.TCPSite, int]:
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host=host, port=port, shutdown_timeout=2.0)
    await site.start()

    # Retrieve bound port if port==0
    bound_port = port
    # site._server is an asyncio.Server
    srv = getattr(site, "_server", None)
    if srv and srv.sockets:
        bound_port = int(srv.sockets[0].getsockname()[1])

    return runner, site, bound_port

async def upnp_map_random(local_ip: str, local_port: int, desc: str, lease: int, retries: int = 12) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[str]]:
    """
    Returns: (external_ip, external_port, control_url, service_type)
    """
    def _work() -> Tuple[Optional[str], Optional[int], Optional[str], Optional[str]]:
        location = ssdp_discover(timeout=3.0)
        if not location:
            return None, None, None, None
        control_url, service_type = find_igd_control_url(location)
        if not control_url or not service_type:
            return None, None, None, None

        ext_ip = get_external_ip(control_url, service_type)

        # random external port; retry on conflict
        for _ in range(retries):
            ext_port = random.randint(20000, 60000)
            try:
                add_port_mapping(control_url, service_type, ext_port, local_ip, local_port, desc, lease)
                return ext_ip, ext_port, control_url, service_type
            except Exception:
                continue
        return ext_ip, None, control_url, service_type

    return await asyncio.to_thread(_work)

async def upnp_unmap(control_url: str, service_type: str, external_port: int) -> None:
    def _work():
        try:
            delete_port_mapping(control_url, service_type, external_port)
        except Exception:
            pass
    await asyncio.to_thread(_work)

async def main_async():
    db_init()

    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0", help="Bind address (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=0, help="Local port (0=random)")
    ap.add_argument("--upnp", action="store_true", help="Enable UPnP IGD mapping (REQUIRED for public forwarding)")
    ap.add_argument("--lease", type=int, default=0, help="UPnP lease duration seconds (0=router default)")
    ap.add_argument("--desc", default="ollama-mobile-chat", help="UPnP port mapping description")
    args = ap.parse_args()

    app = make_app()
    runner, site, bound_port = await start_aiohttp(app, args.bind, args.port)

    local_ip = get_local_ip()
    print(f"[{_now()}] Local bind: {args.bind}:{bound_port}")
    print(f"[{_now()}] Local URL:  http://127.0.0.1:{bound_port}/")
    print(f"[{_now()}] LAN URL:    http://{local_ip}:{bound_port}/")
    print(f"[{_now()}] Ollama:      {OLLAMA_BASE}")

    mapped = False
    control_url = None
    service_type = None
    external_ip = None
    external_port = None

    if args.upnp:
        print(f"[{_now()}] UPnP: discovering IGD and creating random port mapping...")
        external_ip, external_port, control_url, service_type = await upnp_map_random(
            local_ip=local_ip,
            local_port=bound_port,
            desc=args.desc,
            lease=args.lease,
            retries=18,
        )
        if external_port:
            mapped = True
            print(f"[{_now()}] UPnP: mapping OK -> {external_port}/TCP -> {local_ip}:{bound_port}")
            if external_ip:
                print(f"[{_now()}] PUBLIC URL: http://{external_ip}:{external_port}/")
            else:
                print(f"[{_now()}] PUBLIC PORT: {external_port} (external IP unavailable from IGD)")
        else:
            print(f"[{_now()}] UPnP: FAILED to create mapping (UPnP disabled / unsupported / blocked / CGNAT?)")

    # Keep running until cancelled
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        pass
    finally:
        if mapped and control_url and service_type and external_port:
            print(f"[{_now()}] UPnP: removing mapping {external_port}/TCP ...")
            await upnp_unmap(control_url, service_type, external_port)
        await runner.cleanup()

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
