#!/usr/bin/env python3
"""
UPnP-exposed, auth-gated Ollama chat portal (single-file, Python 3 stdlib):
- UPnP IGD port mapping (optional) to expose public HTTP endpoint
- SQLite user DB (signup/login) + server session tokens
- Token stored client-side (localStorage)
- Chat sessions/messages stored client-side (IndexedDB) for persistence across visits
- Mobile-first dark UI w/ slide-out sidebar, accent #ffae00, 8px radius, monospace
- Proxies a SAFE allowlist of Ollama endpoints (streaming where applicable):
    GET  /api/tags        -> /ollama/tags
    GET  /api/version     -> /ollama/version
    POST /api/chat        -> /ollama/chat      (NDJSON streaming)
    POST /api/generate    -> /ollama/generate  (NDJSON streaming)
    POST /api/embeddings  -> /ollama/embeddings

NOT exposed: pull/delete/create/copy/push/etc.
"""

from __future__ import annotations

import argparse
import atexit
import datetime as _dt
import hashlib
import hmac
import http.client
import json
import random
import secrets
import socket
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple


# ==========================
# Config / constants
# ==========================

USER_AGENT = "python-upnp-ollama-portal/2.1"
DEFAULT_MAX_BODY = 12 * 1024 * 1024  # 12MB

SSDP_ADDR = ("239.255.255.250", 1900)
SSDP_ST = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"

ALLOWED_OLLAMA = {
    ("GET", "/api/tags"),
    ("GET", "/api/version"),
    ("POST", "/api/chat"),
    ("POST", "/api/generate"),
    ("POST", "/api/embeddings"),
}

DB_LOCK = threading.Lock()


def now_human() -> str:
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


def pick_free_port(bind_host: str) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((bind_host, 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ==========================
# UPnP IGD helpers
# ==========================

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


# ==========================
# Auth DB (SQLite)
# ==========================

def db_connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    with conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          salt BLOB NOT NULL,
          pw_hash BLOB NOT NULL,
          created_at INTEGER NOT NULL
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
          token TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL,
          created_at INTEGER NOT NULL,
          last_seen INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """)
    return conn


def pbkdf2_hash(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def create_user(conn: sqlite3.Connection, username: str, password: str) -> None:
    username = username.strip()
    if not username or len(username) > 40:
        raise ValueError("invalid_username")
    if len(password) < 10:
        raise ValueError("password_too_short")
    salt = secrets.token_bytes(16)
    pw_hash = pbkdf2_hash(password, salt)
    with DB_LOCK, conn:
        conn.execute(
            "INSERT INTO users (username, salt, pw_hash, created_at) VALUES (?,?,?,?)",
            (username, salt, pw_hash, int(time.time()))
        )


def verify_user(conn: sqlite3.Connection, username: str, password: str) -> Optional[int]:
    with DB_LOCK:
        row = conn.execute("SELECT id, salt, pw_hash FROM users WHERE username = ?", (username.strip(),)).fetchone()
    if not row:
        return None
    salt = bytes(row["salt"])
    expected = bytes(row["pw_hash"])
    got = pbkdf2_hash(password, salt)
    if hmac.compare_digest(got, expected):
        return int(row["id"])
    return None


def new_session(conn: sqlite3.Connection, user_id: int, ttl_seconds: int = 7 * 24 * 3600) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    expires = now + ttl_seconds
    with DB_LOCK, conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, last_seen, expires_at) VALUES (?,?,?,?,?)",
            (token, user_id, now, now, expires)
        )
    return token


def get_session(conn: sqlite3.Connection, token: str) -> Optional[sqlite3.Row]:
    if not token:
        return None
    now = int(time.time())
    with DB_LOCK:
        row = conn.execute(
            """SELECT s.token, s.user_id, s.expires_at, u.username
               FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.token = ?""",
            (token,)
        ).fetchone()
    if not row:
        return None
    if int(row["expires_at"]) < now:
        with DB_LOCK, conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        return None
    with DB_LOCK, conn:
        conn.execute("UPDATE sessions SET last_seen = ? WHERE token = ?", (now, token))
    return row


def delete_session(conn: sqlite3.Connection, token: str) -> None:
    with DB_LOCK, conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


# ==========================
# Ollama proxy
# ==========================

def parse_ollama_base(url: str) -> Tuple[str, int, str]:
    u = urllib.parse.urlparse(url)
    scheme = u.scheme or "http"
    if scheme != "http":
        raise ValueError("Only http:// Ollama base supported.")
    host = u.hostname or "127.0.0.1"
    port = u.port or 11434
    return host, port, scheme


def log_proxy(username: str, api_path: str, body_bytes: int, note: str = "") -> None:
    msg = f"[{now_human()}] proxy user={username} path={api_path} bytes={body_bytes}"
    if note:
        msg += f" note={note}"
    print(msg)


# ==========================
# Web UI (mobile-first)
# ==========================

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
<title>Ollama Portal</title>
<style>
  :root{
    --bg:#070707; --bg2:#0d0d0d;
    --panel:#111111; --panel2:#151515;
    --border:#232323;
    --text:#e8e8e8; --muted:#b0b0b0;
    --accent:#ffae00; --danger:#ff3b3b;
    --r:8px;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  }
  *{ box-sizing:border-box; }
  html,body{ height:100%; }
  body{ margin:0; background:linear-gradient(180deg,var(--bg),var(--bg2)); color:var(--text); font-family:var(--mono); }

  .app{ height:100%; display:flex; flex-direction:column; }
  .topbar{
    position:sticky; top:0; z-index:20;
    display:flex; align-items:center; gap:10px; flex-wrap:wrap;
    padding:10px 12px; background:rgba(10,10,10,0.92);
    border-bottom:1px solid var(--border);
    backdrop-filter: blur(8px);
  }
  .brand{ display:flex; align-items:center; gap:10px; min-width:180px; }
  .hamburger{
    width:40px; height:36px; border-radius:var(--r);
    border:1px solid var(--border); background:var(--panel);
    color:var(--text); cursor:pointer;
    display:flex; align-items:center; justify-content:center;
  }
  .title{ font-weight:700; letter-spacing:0.4px; }
  .badge{
    border:1px solid var(--border); background:var(--panel);
    padding:6px 9px; border-radius:var(--r);
    font-size:12px; color:var(--muted);
    display:flex; align-items:center; gap:8px;
  }
  .dot{ width:8px; height:8px; border-radius:999px; background:var(--muted); }
  .dot.ok{ background:var(--accent); }
  .dot.bad{ background:var(--danger); }
  .spacer{ flex:1; }

  .btn{
    border:1px solid var(--border); background:var(--panel);
    color:var(--text); border-radius:var(--r);
    padding:9px 11px; cursor:pointer; font-family:var(--mono);
  }
  .btn.primary{ background:var(--accent); border-color:#c98700; color:#111; font-weight:700; }
  .btn.danger{ background:#1a0f0f; border-color:#3a1b1b; color:#ffd0d0; }
  .btn:active{ transform: translateY(1px); }

  .select,.input,.textarea{
    width:100%; border:1px solid var(--border);
    background:var(--panel); color:var(--text);
    border-radius:var(--r); padding:10px 11px; font-family:var(--mono);
  }
  .textarea{ min-height:54px; resize:vertical; }

  .shell{ flex:1; display:flex; min-height:0; }
  .sidebar{
    width:300px; max-width:86vw;
    background:linear-gradient(180deg,#0c0c0c,#0a0a0a);
    border-right:1px solid var(--border);
    padding:12px; display:flex; flex-direction:column; gap:12px;
  }
  .sidebarOverlay{ position:fixed; inset:0; background:rgba(0,0,0,0.55); z-index:30; display:none; }
  .sidebarSheet{
    position:fixed; top:0; left:0; bottom:0;
    width:300px; max-width:86vw;
    background:linear-gradient(180deg,#0c0c0c,#0a0a0a);
    border-right:1px solid var(--border);
    padding:12px; display:flex; flex-direction:column; gap:12px;
    transform:translateX(-105%); transition:transform 180ms ease-out;
    z-index:40;
  }
  .sidebarOverlay.open{ display:block; }
  .sidebarSheet.open{ transform:translateX(0); }
  .closeRow{ display:flex; align-items:center; gap:8px; }

  .card{
    border:1px solid var(--border);
    background:rgba(17,17,17,0.92);
    border-radius:var(--r);
    padding:10px;
  }
  .card h3{
    margin:0 0 8px 0;
    font-size:12px; color:var(--muted);
    font-weight:700; letter-spacing:0.5px;
    text-transform:uppercase;
  }
  .row{ display:flex; gap:10px; flex-wrap:wrap; }
  .row > *{ flex:1 1 auto; min-width:120px; }
  .hint{ font-size:12px; color:var(--muted); line-height:1.35; }
  .pill{
    border:1px solid #3b2a00;
    background:rgba(255,174,0,0.08);
    color:var(--accent);
    padding:4px 8px; border-radius:var(--r);
    font-size:12px;
  }

  .sessions{ display:flex; flex-direction:column; gap:8px; overflow:auto; min-height:0; }
  .session{
    border:1px solid var(--border);
    border-radius:var(--r); padding:10px;
    background:var(--panel); cursor:pointer;
  }
  .session.active{
    border-color:#3b2a00;
    box-shadow: 0 0 0 2px rgba(255,174,0,0.18) inset;
  }
  .sessionTitle{ font-weight:700; font-size:13px; }
  .sessionMeta{ font-size:12px; color:var(--muted); margin-top:4px; }

  .main{ flex:1; display:flex; flex-direction:column; min-width:0; min-height:0; }
  .chat{ flex:1; overflow:auto; padding:12px; display:flex; flex-direction:column; gap:10px; }
  .msg{
    max-width:920px; width:100%;
    border:1px solid var(--border);
    background:rgba(17,17,17,0.92);
    border-radius:var(--r);
    padding:10px 11px;
  }
  .msg.user{ background:rgba(20,20,20,0.92); }
  .msg.assistant{ background:rgba(14,14,14,0.92); }
  .meta{ display:flex; gap:10px; flex-wrap:wrap; font-size:11px; color:var(--muted); margin-bottom:6px; }
  .roleTag{
    border:1px solid var(--border);
    border-radius:var(--r);
    padding:3px 7px; background:#0f0f0f;
  }
  .content{ white-space:pre-wrap; word-break:break-word; line-height:1.35; font-size:13px; }
  .imgStrip{ display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }
  .thumb{
    width:64px; height:64px; border-radius:var(--r);
    border:1px solid var(--border); object-fit:cover; background:#000;
  }

  .composer{
    border-top:1px solid var(--border);
    background:rgba(10,10,10,0.92);
    padding:10px 12px;
    display:flex; flex-direction:column; gap:10px;
  }
  .composeRow{ display:flex; gap:10px; flex-wrap:wrap; align-items:stretch; }
  .composeRow .grow{ flex:1 1 260px; min-width:200px; }
  .composeRow .actions{ display:flex; gap:10px; flex-wrap:wrap; }
  .fileRow{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
  .fileNote{ font-size:12px; color:var(--muted); }

  /* Modal */
  .modalOverlay{
    position:fixed; inset:0;
    background:rgba(0,0,0,0.66);
    display:none; align-items:center; justify-content:center;
    padding:18px; z-index:100;
  }
  .modalOverlay.open{ display:flex; }
  .modal{
    width:min(520px,100%);
    border:1px solid var(--border);
    background:linear-gradient(180deg,#101010,#0b0b0b);
    border-radius:var(--r);
    padding:14px;
    display:flex; flex-direction:column; gap:12px;
  }
  .modalHeader{ display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap; }
  .tabs{ display:flex; gap:10px; flex-wrap:wrap; }
  .tabs .btn{ flex:1 1 140px; }
  .msgBox{
    border:1px solid var(--border);
    background:rgba(17,17,17,0.92);
    border-radius:var(--r);
    padding:10px; font-size:12px; color:var(--muted); line-height:1.35;
  }
  .toast{
    position:fixed; left:50%; bottom:16px; transform:translateX(-50%);
    z-index:200;
    padding:10px 12px; border-radius:var(--r);
    border:1px solid var(--border);
    background:rgba(17,17,17,0.94);
    color:var(--text); max-width:min(720px,92vw);
    display:none;
  }
  .toast.open{ display:block; }

  @media (min-width:980px){
    .hamburger{ display:none; }
    .sidebarOverlay,.sidebarSheet{ display:none !important; }
    .sidebar{ display:flex; }
  }
  @media (max-width:979px){
    .sidebar{ display:none; }
  }
</style>
</head>
<body>
<div class="app">

  <div class="topbar">
    <div class="brand">
      <button class="hamburger" id="openSide" aria-label="Open sidebar">☰</button>
      <div class="title">Ollama Portal</div>
    </div>
    <div class="badge"><span class="dot bad" id="authDot"></span><span id="authText">logged out</span></div>
    <div class="badge"><span class="dot bad" id="ollamaDot"></span><span id="ollamaText">ollama: ?</span></div>
    <div class="badge"><span id="statusText">idle</span></div>
    <div class="spacer"></div>
    <button class="btn" id="logoutBtn">Logout</button>
  </div>

  <div class="sidebarOverlay" id="sideOverlay"></div>
  <div class="sidebarSheet" id="sideSheet">
    <div class="closeRow">
      <div class="pill">Settings</div>
      <div class="spacer"></div>
      <button class="btn" id="closeSide">Close</button>
    </div>
    <div id="sidebarInnerMobile" style="display:flex; flex-direction:column; gap:12px; min-height:0;"></div>
  </div>

  <div class="shell">
    <div class="sidebar" id="sidebarInnerDesktop"></div>

    <div class="main">
      <div class="chat" id="chat"></div>

      <div class="composer">
        <div class="composeRow">
          <textarea class="textarea grow" id="input" placeholder="Type a message... (Enter = send, Shift+Enter = newline)"></textarea>
          <div class="actions">
            <button class="btn danger" id="stopBtn">Stop</button>
            <button class="btn primary" id="sendBtn">Send</button>
          </div>
        </div>
        <div class="fileRow">
          <input type="file" id="file" accept="image/*" multiple />
          <div class="fileNote" id="fileNote">No images attached.</div>
        </div>
        <div class="imgStrip" id="attachStrip"></div>
      </div>
    </div>
  </div>

</div>

<div class="modalOverlay" id="authModal">
  <div class="modal">
    <div class="modalHeader">
      <div class="pill">Authentication</div>
      <div class="hint">Token in <b>localStorage</b>. Sessions/messages in <b>IndexedDB</b>.</div>
    </div>
    <div class="tabs">
      <button class="btn" id="tabLogin">Login</button>
      <button class="btn" id="tabSignup">Sign up</button>
    </div>

    <div id="loginPane" style="display:flex; flex-direction:column; gap:10px;">
      <input class="input" id="loginUser" placeholder="username" autocomplete="username" />
      <input class="input" id="loginPass" placeholder="password" type="password" autocomplete="current-password" />
      <button class="btn primary" id="loginBtn">Login</button>
      <div class="msgBox" id="loginMsg"></div>
    </div>

    <div id="signupPane" style="display:none; flex-direction:column; gap:10px;">
      <input class="input" id="signupUser" placeholder="username" autocomplete="username" />
      <input class="input" id="signupPass" placeholder="password (min 10 chars)" type="password" autocomplete="new-password" />
      <button class="btn primary" id="signupBtn">Create account</button>
      <div class="msgBox" id="signupMsg"></div>
    </div>

    <div class="msgBox">
      Proxies only safe Ollama endpoints: tags/version/chat/generate/embeddings. No pull/delete/create.
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
(() => {
  const $ = (id) => document.getElementById(id);
  const esc = (s) => (s||"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;");

  // UUID v4 fallback for Safari/old WebViews
  function uuidv4(){
    // Prefer crypto.getRandomValues
    const cryptoObj = window.crypto || window.msCrypto;
    if (cryptoObj && cryptoObj.getRandomValues){
      const b = new Uint8Array(16);
      cryptoObj.getRandomValues(b);
      b[6] = (b[6] & 0x0f) | 0x40;
      b[8] = (b[8] & 0x3f) | 0x80;
      const hex = [...b].map(x => x.toString(16).padStart(2,"0")).join("");
      return (
        hex.slice(0,8) + "-" +
        hex.slice(8,12) + "-" +
        hex.slice(12,16) + "-" +
        hex.slice(16,20) + "-" +
        hex.slice(20)
      );
    }
    // Weak fallback (still unique-ish)
    const s4 = () => Math.floor((1+Math.random())*0x10000).toString(16).slice(1);
    return `${s4()}${s4()}-${s4()}-${s4()}-${s4()}-${s4()}${s4()}${s4()}`;
  }

  // Toast / status
  function toast(msg, ms=3200){
    const t = $("toast");
    t.textContent = msg;
    t.classList.add("open");
    setTimeout(() => t.classList.remove("open"), ms);
  }
  function setStatus(s){ $("statusText").textContent = s; }
  function setAuth(ok, text){
    $("authText").textContent = text;
    $("authDot").className = "dot " + (ok ? "ok" : "bad");
  }
  function setOllama(ok, text){
    $("ollamaText").textContent = text;
    $("ollamaDot").className = "dot " + (ok ? "ok" : "bad");
  }

  // Mobile sidebar open/close
  function openSide(){ $("sideOverlay").classList.add("open"); $("sideSheet").classList.add("open"); }
  function closeSide(){ $("sideOverlay").classList.remove("open"); $("sideSheet").classList.remove("open"); }
  $("openSide").onclick = openSide;
  $("closeSide").onclick = closeSide;
  $("sideOverlay").onclick = closeSide;

  // Auth
  const TOKEN_KEY = "ollamaPortalToken_v2";
  function getToken(){ return localStorage.getItem(TOKEN_KEY) || ""; }
  function setToken(t){ localStorage.setItem(TOKEN_KEY, t); }
  function clearToken(){ localStorage.removeItem(TOKEN_KEY); }

  async function api(path, opts={}){
    const headers = Object.assign({}, opts.headers || {});
    const token = getToken();
    if (token) headers["Authorization"] = "Bearer " + token;
    headers["Cache-Control"] = "no-store";
    return fetch(path, Object.assign({}, opts, { headers }));
  }

  async function whoAmI(){
    try{
      const r = await api("/auth/me");
      if (!r.ok) return null;
      return await r.json();
    } catch { return null; }
  }

  // IndexedDB
  const DB_NAME = "ollamaPortalDB_v2";
  const DB_VER = 1;

  function openDB(){
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VER);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains("sessions")){
          db.createObjectStore("sessions", { keyPath:"id" });
        }
        if (!db.objectStoreNames.contains("messages")){
          const ms = db.createObjectStore("messages", { keyPath:"id", autoIncrement:true });
          ms.createIndex("by_session", "sessionId", { unique:false });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function tx(storeNames, mode, fn){
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const t = db.transaction(storeNames, mode);
      const stores = storeNames.map(n => t.objectStore(n));
      let out;
      t.oncomplete = () => resolve(out);
      t.onerror = () => reject(t.error);
      fn(stores, (v) => out = v);
    });
  }

  async function listSessions(){
    return tx(["sessions"], "readonly", ([st], done) => {
      const r = st.getAll();
      r.onsuccess = () => {
        const rows = r.result || [];
        rows.sort((a,b) => (b.updatedAt||0)-(a.updatedAt||0));
        done(rows);
      };
    });
  }
  async function putSession(s){
    return tx(["sessions"], "readwrite", ([st], done) => { st.put(s); done(true); });
  }
  async function deleteSession(sessionId){
    return tx(["sessions","messages"], "readwrite", ([ss, ms], done) => {
      ss.delete(sessionId);
      const idx = ms.index("by_session");
      const cur = idx.openCursor(IDBKeyRange.only(sessionId));
      cur.onsuccess = () => {
        const c = cur.result;
        if (c){ ms.delete(c.primaryKey); c.continue(); }
      };
      done(true);
    });
  }
  async function getMessages(sessionId){
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const t = db.transaction(["messages"], "readonly");
      const idx = t.objectStore("messages").index("by_session");
      const r = idx.getAll(IDBKeyRange.only(sessionId));
      r.onsuccess = () => {
        const rows = r.result || [];
        rows.sort((a,b) => (a.ts||0)-(b.ts||0));
        resolve(rows);
      };
      r.onerror = () => reject(r.error);
    });
  }
  async function addMessage(m){
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const t = db.transaction(["messages"], "readwrite");
      const st = t.objectStore("messages");
      const r = st.add(m);
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }
  async function updateMessage(id, patch){
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const t = db.transaction(["messages"], "readwrite");
      const st = t.objectStore("messages");
      const g = st.get(id);
      g.onsuccess = () => {
        const obj = g.result;
        if (!obj) return resolve(false);
        Object.assign(obj, patch);
        st.put(obj);
        resolve(true);
      };
      g.onerror = () => reject(g.error);
    });
  }

  // Sidebar content (duplicated desktop/mobile)
  function sidebarContent(){
    const wrap = document.createElement("div");
    wrap.style.display="flex";
    wrap.style.flexDirection="column";
    wrap.style.gap="12px";
    wrap.style.minHeight="0";

    const settings = document.createElement("div");
    settings.className="card";
    settings.innerHTML = `
      <h3>Settings</h3>
      <div class="row" style="margin-bottom:10px;">
        <div style="min-width:180px;">
          <div class="hint" style="margin-bottom:6px;">Model</div>
          <select class="select" id="modelSelect"></select>
        </div>
        <div style="min-width:120px;">
          <div class="hint" style="margin-bottom:6px;">Mode</div>
          <select class="select" id="modeSelect">
            <option value="chat">chat</option>
            <option value="generate">generate</option>
            <option value="embed">embed</option>
          </select>
        </div>
      </div>
      <div class="hint" style="margin-bottom:6px;">System prompt (chat/generate)</div>
      <textarea class="textarea" id="systemPrompt" placeholder="Optional system prompt..."></textarea>
      <div class="row" style="margin-top:10px;">
        <div>
          <div class="hint" style="margin-bottom:6px;">temperature</div>
          <input class="input" id="temp" type="number" min="0" max="2" step="0.05" value="0.7" />
        </div>
        <div>
          <div class="hint" style="margin-bottom:6px;">top_p</div>
          <input class="input" id="topP" type="number" min="0" max="1" step="0.05" value="0.9" />
        </div>
        <div>
          <div class="hint" style="margin-bottom:6px;">num_predict</div>
          <input class="input" id="numPredict" type="number" min="-2" max="4096" step="32" value="512" />
        </div>
      </div>
      <div class="row" style="margin-top:10px;">
        <button class="btn" id="refreshModelsBtn">Refresh models</button>
        <button class="btn" id="newSessionBtn">New session</button>
        <button class="btn danger" id="delSessionBtn">Delete session</button>
      </div>
      <div class="hint" id="modelHint" style="margin-top:8px;">—</div>
    `;
    wrap.appendChild(settings);

    const sess = document.createElement("div");
    sess.className="card";
    sess.style.minHeight="0";
    sess.innerHTML = `
      <h3>Sessions</h3>
      <div class="sessions" id="sessions"></div>
      <div class="hint" style="margin-top:10px;">
        Sessions + messages persist on this device (IndexedDB).
      </div>
    `;
    wrap.appendChild(sess);

    return wrap;
  }

  function mountSidebar(){
    $("sidebarInnerDesktop").innerHTML = "";
    $("sidebarInnerDesktop").appendChild(sidebarContent());
    $("sidebarInnerMobile").innerHTML = "";
    $("sidebarInnerMobile").appendChild(sidebarContent());
  }

  function getSidebarRoot(){
    const desktopVisible = window.matchMedia("(min-width: 980px)").matches;
    return desktopVisible ? $("sidebarInnerDesktop") : $("sidebarInnerMobile");
  }
  function q(id){
    const root = getSidebarRoot();
    return root.querySelector("#" + id);
  }

  // App state
  let currentUser = null;
  let currentSessionId = null;
  let aborter = null;
  let attached = []; // {name,mime,b64,dataUrl}

  function prettyTime(ts){ try { return new Date(ts).toLocaleString(); } catch { return ""; } }

  function renderSessions(list){
    const root = q("sessions");
    root.innerHTML = "";
    for (const s of list){
      const div = document.createElement("div");
      div.className = "session" + (s.id === currentSessionId ? " active" : "");
      div.onclick = () => { selectSession(s.id); closeSide(); };
      div.innerHTML = `
        <div class="sessionTitle">${esc(s.title || "Untitled")}</div>
        <div class="sessionMeta">${esc(s.model || "")} • ${esc(prettyTime(s.updatedAt || s.createdAt))}</div>
      `;
      root.appendChild(div);
    }
  }

  function msgEl(m){
    const div = document.createElement("div");
    div.className = "msg " + (m.role === "user" ? "user" : "assistant");
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.innerHTML = `<span class="roleTag">${esc(m.role)}</span><span>${esc(prettyTime(m.ts))}</span>`;
    const content = document.createElement("div");
    content.className = "content";
    content.textContent = m.content || "";
    div.appendChild(meta);
    div.appendChild(content);

    if (m.images && m.images.length){
      const strip = document.createElement("div");
      strip.className = "imgStrip";
      for (const im of m.images){
        const img = document.createElement("img");
        img.className = "thumb";
        img.src = im.dataUrl || "";
        strip.appendChild(img);
      }
      div.appendChild(strip);
    }
    return div;
  }

  async function renderChat(){
    const chat = $("chat");
    chat.innerHTML = "";
    if (!currentSessionId) return;
    const msgs = await getMessages(currentSessionId);
    for (const m of msgs) chat.appendChild(msgEl(m));
    chat.scrollTop = chat.scrollHeight;
  }

  async function selectSession(id){
    currentSessionId = id;
    renderSessions(await listSessions());
    await renderChat();
    // sync model selector to session
    const ss = await listSessions();
    const cur = ss.find(x => x.id === currentSessionId);
    if (cur?.model){
      q("modelSelect").value = cur.model;
    }
  }

  async function createNewSession(model){
    const id = uuidv4();
    const s = { id, title:"New session", model, createdAt:Date.now(), updatedAt:Date.now() };
    await putSession(s);
    currentSessionId = id;
    renderSessions(await listSessions());
    await renderChat();
  }

  async function deleteCurrentSession(){
    if (!currentSessionId) return;
    await deleteSession(currentSessionId);
    currentSessionId = null;
    const ss = await listSessions();
    renderSessions(ss);
    if (ss.length) await selectSession(ss[0].id);
    else $("chat").innerHTML = "";
  }

  function setAttachUI(){
    const strip = $("attachStrip");
    strip.innerHTML = "";
    for (const a of attached){
      const img = document.createElement("img");
      img.className = "thumb";
      img.src = a.dataUrl;
      strip.appendChild(img);
    }
    $("fileNote").textContent = attached.length ? `${attached.length} image(s) attached.` : "No images attached.";
  }

  async function fileToDownscaledBase64(file, maxSide=1024, quality=0.86){
    const dataUrl = await new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = () => reject(r.error);
      r.readAsDataURL(file);
    });

    const img = await new Promise((resolve, reject) => {
      const i = new Image();
      i.onload = () => resolve(i);
      i.onerror = () => reject(new Error("image_decode_failed"));
      i.src = dataUrl;
    });

    const w = img.width, h = img.height;
    const scale = Math.min(1, maxSide / Math.max(w,h));
    const cw = Math.max(1, Math.round(w * scale));
    const ch = Math.max(1, Math.round(h * scale));
    const canvas = document.createElement("canvas");
    canvas.width = cw; canvas.height = ch;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(img, 0, 0, cw, ch);

    const outDataUrl = canvas.toDataURL("image/jpeg", quality);
    const b64 = outDataUrl.split(",")[1] || "";
    return { name:file.name, mime:"image/jpeg", b64, dataUrl: outDataUrl };
  }

  $("file").onchange = async (ev) => {
    const files = Array.from(ev.target.files || []);
    attached = [];
    for (const f of files.slice(0,4)){
      try{
        if (f.size > 8*1024*1024){ toast(`Skipping ${f.name}: too large`); continue; }
        attached.push(await fileToDownscaledBase64(f, 1024, 0.86));
      } catch { toast(`Failed to attach ${f.name}`); }
    }
    setAttachUI();
    $("file").value = "";
  };

  // Ollama
  async function loadOllamaVersion(){
    try{
      const r = await api("/ollama/version");
      if (!r.ok){ setOllama(false, "ollama: error"); return; }
      const d = await r.json();
      setOllama(true, "ollama: " + (d.version || "?"));
    } catch { setOllama(false, "ollama: offline"); }
  }

  async function loadModels(){
    q("modelHint").textContent = "Loading models…";
    try{
      const r = await api("/ollama/tags");
      if (!r.ok){
        q("modelHint").textContent = "Model load failed";
        return;
      }
      const d = await r.json();
      const models = (d.models || []).map(m => m.name).sort();
      const sel = q("modelSelect");
      sel.innerHTML = "";
      for (const name of models){
        const opt = document.createElement("option");
        opt.value = name;
        opt.textContent = name;
        sel.appendChild(opt);
      }
      q("modelHint").textContent = models.length ? `${models.length} model(s)` : "No models found.";

      const ss = await listSessions();
      if (!ss.length && models.length){
        await createNewSession(models[0]);
      } else if (ss.length && !currentSessionId){
        await selectSession(ss[0].id);
      }

      if (currentSessionId){
        const ss2 = await listSessions();
        const cur = ss2.find(x => x.id === currentSessionId);
        if (cur?.model) sel.value = cur.model;
        else if (models.length){
          sel.value = models[0];
          if (cur){
            cur.model = models[0];
            cur.updatedAt = Date.now();
            await putSession(cur);
            renderSessions(await listSessions());
          }
        }
      }
    } catch {
      q("modelHint").textContent = "Failed to load models.";
    }
  }

  async function readNdjsonStream(resp, onObj){
    if (!resp.body || !resp.body.getReader){
      const text = await resp.text();
      for (const line of text.split("\n")){
        const s = line.trim();
        if (!s) continue;
        try{ onObj(JSON.parse(s)); } catch {}
      }
      return;
    }
    const reader = resp.body.getReader();
    const dec = new TextDecoder("utf-8");
    let buf = "";
    while (true){
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream:true });
      let idx;
      while ((idx = buf.indexOf("\n")) >= 0){
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx+1);
        if (!line) continue;
        try{ onObj(JSON.parse(line)); } catch {}
      }
    }
    const tail = buf.trim();
    if (tail){
      try{ onObj(JSON.parse(tail)); } catch {}
    }
  }

  function optionsFromUI(){
    const t = parseFloat(q("temp").value || "0.7");
    const tp = parseFloat(q("topP").value || "0.9");
    const np = parseInt(q("numPredict").value || "512", 10);
    const o = {};
    if (!isNaN(t)) o.temperature = t;
    if (!isNaN(tp)) o.top_p = tp;
    if (!isNaN(np)) o.num_predict = np;
    return o;
  }

  async function send(){
    if (!currentSessionId){ toast("No session selected"); return; }

    const mode = q("modeSelect").value;
    const model = q("modelSelect").value;
    const sys = (q("systemPrompt").value || "").trim();
    const input = $("input");
    const text = input.value;

    if (!text.trim() && !attached.length){
      toast("Nothing to send");
      return;
    }

    // persist user message
    const userMsg = {
      sessionId: currentSessionId,
      role: "user",
      content: text,
      ts: Date.now(),
      images: attached.map(x => ({ name:x.name, mime:x.mime, b64:x.b64, dataUrl:x.dataUrl })),
    };
    input.value = "";
    attached = [];
    setAttachUI();
    await addMessage(userMsg);

    // update session meta
    const ss = await listSessions();
    const cur = ss.find(x => x.id === currentSessionId);
    if (cur){
      cur.model = model;
      cur.updatedAt = Date.now();
      if (cur.title === "New session") cur.title = (text.trim() || "Image").slice(0,40) || "Session";
      await putSession(cur);
    }
    renderSessions(await listSessions());
    await renderChat();

    // stop previous
    if (aborter) aborter.abort();
    aborter = new AbortController();

    setStatus("sending…");

    // assistant placeholder
    const assistant = { sessionId: currentSessionId, role:"assistant", content:"", ts: Date.now(), images: [] };
    const assistantId = await addMessage(assistant);
    await renderChat();

    function updateAssistantText(s){
      updateMessage(assistantId, { content: s });
      const chat = $("chat");
      const last = chat.lastElementChild;
      if (last){
        const contentEl = last.querySelector(".content");
        if (contentEl) contentEl.textContent = s;
      }
      chat.scrollTop = chat.scrollHeight;
    }

    try{
      if (mode === "embed"){
        const body = { model, prompt: text.trim() };
        const r = await api("/ollama/embeddings", {
          method:"POST",
          headers: {"Content-Type":"application/json"},
          body: JSON.stringify(body),
          signal: aborter.signal
        });
        if (!r.ok) throw new Error(await r.text());
        const d = await r.json();
        updateAssistantText(JSON.stringify(d, null, 2));
        setStatus("idle");
        return;
      }

      if (mode === "generate"){
        const body = { model, prompt: text, stream:true, options: optionsFromUI() };
        if (sys) body.system = sys;
        const r = await api("/ollama/generate", {
          method:"POST",
          headers: {"Content-Type":"application/json"},
          body: JSON.stringify(body),
          signal: aborter.signal
        });
        if (!r.ok) throw new Error(await r.text());

        let acc = "";
        await readNdjsonStream(r, (obj) => {
          if (obj?.response){
            acc += obj.response;
            updateAssistantText(acc);
          }
          if (obj?.error) throw new Error(obj.error);
        });
        setStatus("idle");
        return;
      }

      // chat mode
      const msgs = await getMessages(currentSessionId);
      const out = [];
      if (sys) out.push({ role:"system", content: sys });

      for (const m of msgs){
        if (m.id === assistantId) continue; // skip placeholder
        const o = { role: m.role, content: (m.content || "") };
        if (m.role === "user" && m.images && m.images.length){
          o.images = m.images.map(x => x.b64);
        }
        out.push(o);
      }

      const body = { model, messages: out, stream:true, options: optionsFromUI() };
      const r = await api("/ollama/chat", {
        method:"POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify(body),
        signal: aborter.signal
      });
      if (!r.ok) throw new Error(await r.text());

      let acc = "";
      await readNdjsonStream(r, (obj) => {
        const chunk = obj?.message?.content || "";
        if (chunk){
          acc += chunk;
          updateAssistantText(acc);
        }
        if (obj?.error) throw new Error(obj.error);
      });
      setStatus("idle");
    } catch(e){
      setStatus("error");
      const msg = "Error: " + (e?.message || e);
      updateAssistantText(msg);
      toast(msg);
    }
  }

  function stop(){
    if (aborter) aborter.abort();
    setStatus("stopped");
    toast("Stopped");
  }

  $("sendBtn").onclick = send;
  $("stopBtn").onclick = stop;
  $("input").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey){
      e.preventDefault();
      send();
    }
  });

  // Auth modal
  function openAuthModal(){ $("authModal").classList.add("open"); }
  function closeAuthModal(){ $("authModal").classList.remove("open"); }
  function showPane(which){
    $("loginPane").style.display = (which==="login") ? "flex" : "none";
    $("signupPane").style.display = (which==="signup") ? "flex" : "none";
  }
  $("tabLogin").onclick = () => showPane("login");
  $("tabSignup").onclick = () => showPane("signup");
  showPane("login");

  async function doLogin(username, password){
    const r = await fetch("/auth/login", {
      method:"POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ username, password })
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || "login_failed");
    setToken(d.token);
  }

  async function doSignup(username, password){
    const r = await fetch("/auth/signup", {
      method:"POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ username, password })
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || "signup_failed");
  }

  $("loginBtn").onclick = async () => {
    $("loginMsg").textContent = "…";
    try{
      await doLogin($("loginUser").value, $("loginPass").value);
      $("loginMsg").textContent = "Logged in.";
      await bootAuthed();
      closeAuthModal();
    } catch(e){
      $("loginMsg").textContent = "Login error: " + (e?.message || e);
    }
  };

  $("signupBtn").onclick = async () => {
    $("signupMsg").textContent = "…";
    try{
      await doSignup($("signupUser").value, $("signupPass").value);
      await doLogin($("signupUser").value, $("signupPass").value);
      $("signupMsg").textContent = "Account created + logged in.";
      await bootAuthed();
      closeAuthModal();
    } catch(e){
      $("signupMsg").textContent = "Signup error: " + (e?.message || e);
    }
  };

  $("logoutBtn").onclick = async () => {
    try{ await api("/auth/logout", { method:"POST" }); } catch {}
    clearToken();
    setAuth(false, "logged out");
    toast("Logged out");
    openAuthModal();
  };

  // Wire sidebar (duplicated IDs -> use q())
  function wireSidebar(){
    q("refreshModelsBtn").onclick = async () => { await loadModels(); await loadOllamaVersion(); toast("Refreshed"); };
    q("newSessionBtn").onclick = async () => {
      const model = q("modelSelect").value || "";
      await createNewSession(model);
      toast("New session created");
      closeSide();
    };
    q("delSessionBtn").onclick = async () => { await deleteCurrentSession(); toast("Session deleted"); closeSide(); };

    q("modelSelect").onchange = async () => {
      if (!currentSessionId) return;
      const ss = await listSessions();
      const cur = ss.find(x => x.id === currentSessionId);
      if (cur){
        cur.model = q("modelSelect").value;
        cur.updatedAt = Date.now();
        await putSession(cur);
        renderSessions(await listSessions());
      }
    };
  }

  async function bootAuthed(){
    const me = await whoAmI();
    if (!me){
      setAuth(false, "logged out");
      openAuthModal();
      return;
    }
    setAuth(true, "user: " + (me.username || "?"));
    await loadOllamaVersion();
    await loadModels();

    const ss = await listSessions();
    renderSessions(ss);
    if (ss.length){
      if (!currentSessionId) await selectSession(ss[0].id);
    } else {
      const ms = Array.from(q("modelSelect").options).map(o => o.value);
      if (ms.length) await createNewSession(ms[0]);
    }
  }

  async function boot(){
    mountSidebar();
    wireSidebar();
    setAttachUI();
    const me = await whoAmI();
    if (!me){
      setAuth(false, "logged out");
      openAuthModal();
      return;
    }
    setAuth(true, "user: " + (me.username || "?"));
    await bootAuthed();
  }

  window.addEventListener("resize", () => { try{ wireSidebar(); } catch {} });

  boot();
})();
</script>
</body>
</html>
"""


# ==========================
# HTTP server
# ==========================

class AppServer(ThreadingHTTPServer):
    def __init__(self, server_address, handler_cls, conn, ollama_base, max_body):
        super().__init__(server_address, handler_cls)
        self.db = conn
        self.ollama_base = ollama_base
        self.max_body = max_body


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _headers_common(self) -> Dict[str, str]:
        return {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }

    def _send(self, code: int, ctype: str, data: bytes, extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in self._headers_common().items():
            self.send_header(k, v)
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code: int, obj: Any) -> None:
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send(code, "application/json; charset=utf-8", data)

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length > self.server.max_body:
            raise ValueError("body_too_large")
        return self.rfile.read(length) if length else b""

    def _read_json(self) -> Dict[str, Any]:
        raw = self._read_body()
        try:
            return json.loads(raw.decode("utf-8", errors="strict") or "{}")
        except Exception:
            raise ValueError("bad_json")

    def _bearer_token(self) -> str:
        h = self.headers.get("Authorization", "")
        if h.lower().startswith("bearer "):
            return h.split(" ", 1)[1].strip()
        return ""

    def _require_session(self) -> sqlite3.Row:
        token = self._bearer_token()
        row = get_session(self.server.db, token)
        if not row:
            raise PermissionError("unauthorized")
        return row

    # Chunked streaming
    def _start_chunked(self, status: int, ctype: str, extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Transfer-Encoding", "chunked")
        for k, v in self._headers_common().items():
            self.send_header(k, v)
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()

    def _write_chunk(self, data: bytes) -> None:
        if not data:
            return
        self.wfile.write(("%X\r\n" % len(data)).encode("ascii"))
        self.wfile.write(data)
        self.wfile.write(b"\r\n")
        self.wfile.flush()

    def _end_chunked(self) -> None:
        try:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except Exception:
            pass

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path

        if path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", INDEX_HTML.encode("utf-8"))
            return

        if path == "/health":
            self._send(200, "text/plain; charset=utf-8", b"ok\n")
            return

        if path == "/auth/me":
            try:
                s = self._require_session()
                self._json(200, {"username": s["username"]})
            except PermissionError:
                self._json(401, {"error": "unauthorized"})
            return

        if path == "/ollama/tags":
            return self._ollama_simple("GET", "/api/tags")

        if path == "/ollama/version":
            return self._ollama_simple("GET", "/api/version")

        self._send(404, "text/plain; charset=utf-8", b"not found\n")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/auth/signup":
            try:
                obj = self._read_json()
                username = str(obj.get("username", "")).strip()
                password = str(obj.get("password", ""))
                create_user(self.server.db, username, password)
                self._json(200, {"ok": True})
            except ValueError as e:
                self._json(400, {"error": str(e)})
            except sqlite3.IntegrityError:
                self._json(409, {"error": "username_taken"})
            except Exception:
                self._json(500, {"error": "server_error"})
            return

        if path == "/auth/login":
            try:
                obj = self._read_json()
                username = str(obj.get("username", "")).strip()
                password = str(obj.get("password", ""))
                uid = verify_user(self.server.db, username, password)
                if not uid:
                    self._json(401, {"error": "bad_credentials"})
                    return
                token = new_session(self.server.db, uid)
                self._json(200, {"token": token})
            except ValueError as e:
                self._json(400, {"error": str(e)})
            except Exception:
                self._json(500, {"error": "server_error"})
            return

        if path == "/auth/logout":
            token = self._bearer_token()
            if token:
                delete_session(self.server.db, token)
            self._json(200, {"ok": True})
            return

        if path == "/ollama/chat":
            try:
                s = self._require_session()
            except PermissionError:
                self._json(401, {"error": "unauthorized"})
                return
            return self._ollama_stream("POST", "/api/chat", s)

        if path == "/ollama/generate":
            try:
                s = self._require_session()
            except PermissionError:
                self._json(401, {"error": "unauthorized"})
                return
            return self._ollama_stream("POST", "/api/generate", s)

        if path == "/ollama/embeddings":
            try:
                _ = self._require_session()
            except PermissionError:
                self._json(401, {"error": "unauthorized"})
                return
            return self._ollama_simple_proxy("POST", "/api/embeddings")

        self._json(404, {"error": "not_found"})

    def _ollama_simple(self, method: str, api_path: str) -> None:
        try:
            _ = self._require_session()
        except PermissionError:
            self._json(401, {"error": "unauthorized"})
            return

        if (method, api_path) not in ALLOWED_OLLAMA:
            self._json(403, {"error": "forbidden"})
            return

        host, port, _ = self.server.ollama_base
        try:
            conn = http.client.HTTPConnection(host, port, timeout=15)
            conn.request(method, api_path, headers={"User-Agent": USER_AGENT})
            resp = conn.getresponse()
            data = resp.read()
            ctype = resp.getheader("Content-Type") or "application/json; charset=utf-8"
            self.send_response(resp.status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in self._headers_common().items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            self._json(502, {"error": "ollama_unreachable"})

    def _ollama_simple_proxy(self, method: str, api_path: str) -> None:
        if (method, api_path) not in ALLOWED_OLLAMA:
            self._json(403, {"error": "forbidden"})
            return

        try:
            body = self._read_body()
        except ValueError as e:
            self._json(413, {"error": str(e)})
            return

        host, port, _ = self.server.ollama_base
        try:
            conn = http.client.HTTPConnection(host, port, timeout=60)
            conn.request(method, api_path, body=body, headers={
                "Content-Type": self.headers.get("Content-Type", "application/json"),
                "User-Agent": USER_AGENT,
            })
            resp = conn.getresponse()
            data = resp.read()
            ctype = resp.getheader("Content-Type") or "application/json; charset=utf-8"
            self.send_response(resp.status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in self._headers_common().items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            self._json(502, {"error": "ollama_unreachable"})

    def _ollama_stream(self, method: str, api_path: str, session_row: sqlite3.Row) -> None:
        if (method, api_path) not in ALLOWED_OLLAMA:
            self._json(403, {"error": "forbidden"})
            return

        try:
            body = self._read_body()
        except ValueError as e:
            self._json(413, {"error": str(e)})
            return

        username = str(session_row["username"])
        log_proxy(username, api_path, len(body))

        host, port, _ = self.server.ollama_base
        try:
            conn = http.client.HTTPConnection(host, port, timeout=3600)
            conn.request(method, api_path, body=body, headers={
                "Content-Type": self.headers.get("Content-Type", "application/json"),
                "User-Agent": USER_AGENT,
            })
            resp = conn.getresponse()
            status = resp.status
            ctype = resp.getheader("Content-Type") or "application/x-ndjson; charset=utf-8"

            self._start_chunked(status, ctype, extra={"Connection": "close"})

            while True:
                chunk = resp.read(4096)
                if not chunk:
                    break
                self._write_chunk(chunk)

            self._end_chunked()

        except Exception:
            try:
                self._start_chunked(502, "application/x-ndjson; charset=utf-8", extra={"Connection": "close"})
                self._write_chunk(b'{"error":"ollama_unreachable"}\n')
                self._end_chunked()
            except Exception:
                pass

    def log_message(self, fmt, *args):
        return


# ==========================
# Main
# ==========================

def main():
    ap = argparse.ArgumentParser(description="UPnP-exposed Ollama portal (mobile-first UI, auth, streaming proxy).")
    ap.add_argument("--bind", default="0.0.0.0", help="Bind address (default 0.0.0.0)")
    ap.add_argument("--local-port", type=int, default=0, help="Local port (0=auto)")
    ap.add_argument("--external-port", type=int, default=0, help="External port for UPnP (0=random high)")
    ap.add_argument("--lease", type=int, default=0, help="UPnP lease duration seconds (0=router default/indefinite)")
    ap.add_argument("--desc", default="python-ollama-portal", help="UPnP port mapping description")
    ap.add_argument("--db", default="ollama_portal.sqlite", help="SQLite db path for users/sessions")
    ap.add_argument("--ollama", default="http://127.0.0.1:11434", help="Ollama base URL (http only)")
    ap.add_argument("--max-body", type=int, default=DEFAULT_MAX_BODY, help="Max request body size bytes")
    ap.add_argument("--no-upnp", action="store_true", help="Disable UPnP mapping (LAN only)")
    args = ap.parse_args()

    conn = db_connect(args.db)
    ollama_base = parse_ollama_base(args.ollama)

    local_ip = get_local_ip()
    local_port = args.local_port or pick_free_port(args.bind)

    httpd = AppServer((args.bind, local_port), Handler, conn, ollama_base, args.max_body)

    print(f"[{now_human()}] Local URL: http://127.0.0.1:{local_port}/")
    print(f"[{now_human()}] Bind: {args.bind}:{local_port}  (LAN IP: {local_ip})")
    print(f"[{now_human()}] Ollama upstream: {ollama_base[0]}:{ollama_base[1]} (http)")
    print(f"[{now_human()}] DB: {args.db}")

    mapped = False
    control_url = None
    service_type = None
    external_port = args.external_port or random.randint(20000, 60000)
    ext_ip = None

    def cleanup():
        nonlocal mapped
        if mapped and control_url and service_type:
            try:
                delete_port_mapping(control_url, service_type, external_port)
                print(f"[{now_human()}] Cleaned up UPnP mapping {external_port}/TCP")
            except Exception as e:
                print(f"[{now_human()}] WARNING: Failed to delete port mapping: {e}")

    atexit.register(cleanup)

    if not args.no_upnp:
        try:
            location = ssdp_discover(timeout=3.0)
            if not location:
                raise RuntimeError("Could not discover UPnP IGD (SSDP). Is UPnP enabled on your router?")
            control_url, service_type = find_igd_control_url(location)
            if not control_url:
                raise RuntimeError("Found device description but no WANIPConnection/WANPPPConnection control URL.")

            for _ in range(8):
                try:
                    add_port_mapping(control_url, service_type, external_port, local_ip, local_port, args.desc, args.lease)
                    mapped = True
                    break
                except Exception:
                    external_port = random.randint(20000, 60000)

            if not mapped:
                raise RuntimeError("Unable to create UPnP port mapping after multiple attempts.")

            ext_ip = get_external_ip(control_url, service_type) or "UNKNOWN_PUBLIC_IP"
            print(f"[{now_human()}] UPnP mapping OK: http://{ext_ip}:{external_port}/")
            print(f"[{now_human()}] Login required. (Token stored in browser localStorage after login.)")

        except Exception as e:
            print(f"[{now_human()}] WARNING: UPnP failed: {e}")
            print(f"[{now_human()}] Server is LAN-only unless you manually forward the port.")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[{now_human()}] Shutting down…")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
