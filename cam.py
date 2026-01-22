#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Password-protected webcam MJPEG + chat (SSE) with UPnP port mapping + live camera switching.

Features
- Auto-generates .env on first run: APP_PASSWORD, APP_SECRET, DEFAULT_CAMERA
- Auto-bootstraps OpenCV (cv2) into local .venv and re-execs itself
- Login page -> session cookie (HMAC signed)
- /mjpeg streams live frames (token/cookie gated)
- Chat: terminal <-> browser, plus /0 /1 /2 /3 commands to switch camera live
- UPnP IGD mapping (best-effort) prints public URL

Run:
  python3 app.py --enable-camera

Switch camera live:
  In terminal or chat input: /0  /1  /2  /3
  Or: /cam 2
  Or: /cam /dev/video2

Linux hint:
  Your stable nodes are in /dev/v4l/by-path/* and /dev/v4l/by-id/*
"""

# -------------------- SELF-BOOTSTRAP VENV + DEPS --------------------
import os
import sys
import subprocess
import venv
from pathlib import Path

def _venv_python_path(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"

def _in_venv() -> bool:
    return (
        hasattr(sys, "real_prefix")
        or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)
        or bool(os.environ.get("VIRTUAL_ENV"))
    )

def ensure_deps_bootstrap(packages):
    # prevent infinite loop
    if os.environ.get("APP_BOOTSTRAPPED") == "1":
        return

    # If cv2 already available, no need
    try:
        import cv2  # noqa: F401
        return
    except Exception:
        pass

    script_dir = Path(__file__).resolve().parent
    venv_dir = script_dir / ".venv"

    if _in_venv():
        # install into current env
        print("[bootstrap] cv2 missing; installing into current environment…", flush=True)
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"])
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", *packages])
        except subprocess.CalledProcessError:
            # fallback
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "opencv-python-headless"])
        return

    # create venv + install + exec
    if not venv_dir.exists():
        print(f"[bootstrap] creating venv at {venv_dir}", flush=True)
        venv.create(venv_dir, with_pip=True)

    vpy = _venv_python_path(venv_dir)
    if not vpy.exists():
        raise RuntimeError(f"[bootstrap] venv python not found at {vpy}")

    print("[bootstrap] installing deps into .venv…", flush=True)
    subprocess.check_call([str(vpy), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"])
    try:
        subprocess.check_call([str(vpy), "-m", "pip", "install", "--upgrade", *packages])
    except subprocess.CalledProcessError:
        print("[bootstrap] opencv-python failed; trying opencv-python-headless…", flush=True)
        subprocess.check_call([str(vpy), "-m", "pip", "install", "--upgrade", "opencv-python-headless"])

    print("[bootstrap] re-executing under venv…", flush=True)
    os.environ["APP_BOOTSTRAPPED"] = "1"
    os.execv(str(vpy), [str(vpy), *sys.argv])

# You asked for cv2 to install automatically:
ensure_deps_bootstrap(["opencv-python"])
# -------------------- END BOOTSTRAP --------------------

# -------------------- Standard libs (rest of app) --------------------
import argparse
import atexit
import base64
import datetime as _dt
import hmac
import hashlib
import json
import queue
import random
import secrets
import socket
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Import cv2 after bootstrap
import cv2  # type: ignore


# -------------------- .env handling --------------------
ENV_PATH = Path(__file__).resolve().parent / ".env"

def _parse_env(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        out[k] = v
    return out

def load_or_create_env() -> dict:
    if ENV_PATH.exists():
        data = _parse_env(ENV_PATH.read_text(encoding="utf-8", errors="ignore"))
        return data

    # Create new .env with secure defaults
    password = secrets.token_urlsafe(18)  # ~24 chars
    secret = secrets.token_urlsafe(32)
    default_camera = "0"  # /dev/video0

    content = (
        "# Auto-generated on first run\n"
        "# Change APP_PASSWORD to whatever you want.\n"
        "APP_USERNAME=viewer\n"
        f"APP_PASSWORD={password}\n"
        f"APP_SECRET={secret}\n"
        f"DEFAULT_CAMERA={default_camera}\n"
        "# Optional: session TTL in seconds\n"
        "SESSION_TTL=43200\n"
    )
    ENV_PATH.write_text(content, encoding="utf-8")
    return _parse_env(content)


# -------------------- UPnP IGD constants/helpers --------------------
SSDP_ADDR = ("239.255.255.250", 1900)
SSDP_ST = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
USER_AGENT = "python-upnp-chat-stream/1.0"

def now_human():
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())

def pick_free_port(bind_host="0.0.0.0"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((bind_host, 0))
    port = s.getsockname()[1]
    s.close()
    return port

def ssdp_discover(timeout=3.0):
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

def http_get(url, timeout=6.0):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()

def find_igd_control_url(device_desc_url):
    raw = http_get(device_desc_url)
    xml = ET.fromstring(raw)

    def strip_ns(tag):
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

def escape_xml(s):
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&apos;")
    )

def soap_call(control_url, service_type, action, body_xml, timeout=8.0):
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

def get_external_ip(control_url, service_type):
    resp = soap_call(control_url, service_type, "GetExternalIPAddress", "")
    xml = ET.fromstring(resp)
    for el in xml.iter():
        if el.tag.endswith("NewExternalIPAddress") and el.text:
            return el.text.strip()
    return None

def add_port_mapping(control_url, service_type, external_port, internal_ip, internal_port, desc, lease_seconds=0):
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

def delete_port_mapping(control_url, service_type, external_port):
    body = f"""
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{external_port}</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
""".strip()
    soap_call(control_url, service_type, "DeletePortMapping", body)


# -------------------- Auth/session --------------------
def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))

def sign(secret: bytes, msg: bytes) -> str:
    return b64url(hmac.new(secret, msg, hashlib.sha256).digest())

def make_session(secret: bytes, username: str, ttl_seconds: int) -> str:
    payload = {
        "u": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + int(ttl_seconds),
        "n": secrets.token_urlsafe(10),
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    mac = sign(secret, raw).encode("ascii")
    token = b64url(raw) + "." + mac.decode("ascii")
    return token

def verify_session(secret: bytes, token: str) -> bool:
    try:
        parts = token.split(".", 1)
        if len(parts) != 2:
            return False
        raw = b64url_decode(parts[0])
        sig = parts[1]
        if not hmac.compare_digest(sign(secret, raw), sig):
            return False
        payload = json.loads(raw.decode("utf-8", errors="strict"))
        if int(payload.get("exp", 0)) < int(time.time()):
            return False
        return True
    except Exception:
        return False

def parse_cookies(cookie_header: str) -> dict:
    out = {}
    if not cookie_header:
        return out
    for part in cookie_header.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# -------------------- Chat state --------------------
CLIENTS_LOCK = threading.Lock()
CLIENTS = set()  # set[queue.Queue]

HISTORY_LOCK = threading.Lock()
HISTORY = []
HISTORY_MAX = 300

def add_history(msg: dict):
    with HISTORY_LOCK:
        HISTORY.append(msg)
        if len(HISTORY) > HISTORY_MAX:
            del HISTORY[:len(HISTORY) - HISTORY_MAX]

def broadcast(msg: dict):
    add_history(msg)
    dead = []
    with CLIENTS_LOCK:
        for q in list(CLIENTS):
            try:
                q.put_nowait(msg)
            except Exception:
                dead.append(q)
        for q in dead:
            CLIENTS.discard(q)

def terminal_print(msg: dict):
    print(f"[{msg.get('ts', now_human())}] {msg.get('sender','?')}: {msg.get('text','')}", flush=True)


# -------------------- Camera switching + frames --------------------
CAM_ENABLED = False
CAM_DEVICE_LOCK = threading.Lock()
CAM_DEVICE = 0  # int index or str path
CAM_SWITCH_EVENT = threading.Event()

FRAME_COND = threading.Condition()
LATEST_JPEG = None
LATEST_TS = 0.0

def set_camera_device(dev):
    global CAM_DEVICE
    with CAM_DEVICE_LOCK:
        CAM_DEVICE = dev
    CAM_SWITCH_EVENT.set()

def get_camera_device():
    with CAM_DEVICE_LOCK:
        return CAM_DEVICE

def _dev_to_opencv_source(dev):
    # dev can be int index, "/dev/video2", or "/dev/v4l/by-path/..."
    if isinstance(dev, int):
        return dev
    s = str(dev).strip()
    # allow numeric strings
    if s.isdigit():
        return int(s)
    return s

def camera_loop(stop_event: threading.Event, fps: float, jpeg_quality: int, width: int, height: int):
    global LATEST_JPEG, LATEST_TS

    delay = 1.0 / max(1.0, fps)
    encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), int(max(10, min(95, jpeg_quality)))]

    cap = None
    current = None

    def open_cap(dev):
        source = _dev_to_opencv_source(dev)
        # Prefer V4L2 on Linux (harmless elsewhere)
        try:
            c = cv2.VideoCapture(source, cv2.CAP_V4L2)
        except Exception:
            c = cv2.VideoCapture(source)

        # best-effort set size
        if width > 0:
            c.set(cv2.CAP_PROP_FRAME_WIDTH, float(width))
        if height > 0:
            c.set(cv2.CAP_PROP_FRAME_HEIGHT, float(height))

        # Helps with grayscale/Y16 devices sometimes
        c.set(cv2.CAP_PROP_CONVERT_RGB, 1)
        return c, source

    def close_cap(c):
        try:
            c.release()
        except Exception:
            pass

    while not stop_event.is_set():
        desired = get_camera_device()

        if cap is None or desired != current or CAM_SWITCH_EVENT.is_set():
            CAM_SWITCH_EVENT.clear()
            if cap is not None:
                close_cap(cap)

            cap, opened_source = open_cap(desired)
            current = desired

            if not cap or not cap.isOpened():
                msg = {"ts": now_human(), "sender": "server", "text": f"Camera open failed for {desired}"}
                terminal_print(msg); broadcast(msg)
                cap = None
                time.sleep(0.8)
                continue

            msg = {"ts": now_human(), "sender": "server", "text": f"Camera switched to {opened_source}"}
            terminal_print(msg); broadcast(msg)

        ok, frame = cap.read()
        if not ok or frame is None:
            # transient read error: retry a bit; if persistent, force reopen
            time.sleep(0.1)
            continue

        ok2, buf = cv2.imencode(".jpg", frame, encode_params)
        if not ok2:
            time.sleep(0.05)
            continue

        jpg = buf.tobytes()
        ts = time.time()
        with FRAME_COND:
            LATEST_JPEG = jpg
            LATEST_TS = ts
            FRAME_COND.notify_all()

        time.sleep(delay)

    if cap is not None:
        close_cap(cap)


# -------------------- Commands (/0 /1 /2 /3 etc) --------------------
def handle_command(text: str) -> bool:
    """
    Returns True if it was a recognized command.
    """
    s = text.strip()

    if s in ("/help", "/?"):
        broadcast({"ts": now_human(), "sender": "server",
                   "text": "Commands: /0 /1 /2 /3 (switch camera), /cam <n|/dev/videoX>, /cams"})
        return True

    if s == "/cams":
        vids = sorted([p.name for p in Path("/dev").glob("video*") if p.name[5:].isdigit()], key=lambda x: int(x[5:]))
        byp = list(Path("/dev/v4l/by-path").glob("*")) if Path("/dev/v4l/by-path").exists() else []
        byid = list(Path("/dev/v4l/by-id").glob("*")) if Path("/dev/v4l/by-id").exists() else []
        lines = []
        if vids:
            lines.append("Devices: " + ", ".join(f"/dev/{v}" for v in vids))
        if byp:
            lines.append("by-path: " + ", ".join(str(p) for p in byp))
        if byid:
            lines.append("by-id: " + ", ".join(str(p) for p in byid))
        if not lines:
            lines.append("No /dev/video* found.")
        broadcast({"ts": now_human(), "sender": "server", "text": "\n".join(lines)})
        return True

    # "/0" "/1" etc
    if s.startswith("/") and s[1:].isdigit() and len(s) <= 4:
        idx = int(s[1:])
        set_camera_device(idx)
        return True

    if s.startswith("/cam "):
        arg = s[5:].strip()
        if arg.isdigit():
            set_camera_device(int(arg))
        else:
            # allow full device path
            set_camera_device(arg)
        return True

    return False


# -------------------- Web UI --------------------
LOGIN_HTML = r"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Login</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:#0b0f14; color:#e7eef7; margin:0; }
    .wrap { max-width: 520px; margin: 10vh auto; padding: 16px; }
    .panel { background:#0f1620; border:1px solid #1e2a3a; border-radius:12px; padding:16px; }
    label { display:block; margin-top:12px; color:#9bb0c7; font-size:12px; }
    input { width:100%; padding:10px 12px; border-radius:10px; border:1px solid #2a3a52; background:#0b0f14; color:#e7eef7; }
    button { margin-top:14px; width:100%; padding:10px 14px; border-radius:10px; border:1px solid #2a3a52; background:#18212d; color:#e7eef7; cursor:pointer; }
    button:hover { background:#1d2a3b; }
    .err { margin-top:10px; color:#ffb4b4; font-size:12px; }
    .hint { margin-top:12px; color:#9bb0c7; font-size:12px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="panel">
      <h2 style="margin:0 0 6px 0;">Login</h2>
      <form method="POST" action="/login">
        <label>Password</label>
        <input name="password" type="password" autofocus />
        <button type="submit">Enter</button>
      </form>
      <div class="hint">Password is stored in <code>.env</code> as <code>APP_PASSWORD</code>.</div>
      {ERROR}
    </div>
  </div>
</body>
</html>
"""

INDEX_HTML = r"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Stream + Chat</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin:0; background:#0b0f14; color:#e7eef7; }
    .wrap { max-width: 1200px; margin:0 auto; padding:16px; display:grid; gap:12px; }
    .top { display:flex; gap:12px; align-items:baseline; flex-wrap:wrap; }
    .badge { font-size:12px; padding:4px 8px; border-radius:999px; background:#18212d; color:#bcd; }
    .grid { display:grid; grid-template-columns: 1.2fr 1fr; gap:12px; }
    .panel { background:#0f1620; border:1px solid #1e2a3a; border-radius:12px; overflow:hidden; }
    .video { padding:12px; }
    .video img { width:100%; border-radius:10px; border:1px solid #1e2a3a; background:#000; }
    #log { height: 52vh; overflow:auto; padding:12px; }
    .row { display:grid; grid-template-columns:1fr auto; gap:8px; padding:12px; border-top:1px solid #1e2a3a; }
    input { width:100%; padding:10px 12px; border-radius:10px; border:1px solid #2a3a52; background:#0b0f14; color:#e7eef7; }
    button { padding:10px 14px; border-radius:10px; border:1px solid #2a3a52; background:#18212d; color:#e7eef7; cursor:pointer; }
    button:hover { background:#1d2a3b; }
    .msg { margin:8px 0; }
    .meta { font-size:12px; color:#9bb0c7; }
    .text { white-space:pre-wrap; word-wrap:break-word; }
    .hint { font-size:12px; color:#9bb0c7; margin-top:8px; }
    a { color:#bcd; text-decoration:none; }
    @media (max-width: 950px) { .grid { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <h2 style="margin:0;">Stream + Chat</h2>
      <span id="status" class="badge">connecting…</span>
      <span id="camstat" class="badge">camera: ?</span>
      <a class="badge" href="/logout">logout</a>
    </div>

    <div class="grid">
      <div class="panel">
        <div class="video">
          <img id="cam" alt="camera stream"/>
          <div class="hint">
            Switch camera by sending <code>/0</code> <code>/1</code> <code>/2</code> <code>/3</code> (terminal or chat).
            Try <code>/cams</code> to list devices. Camera must be started with <code>--enable-camera</code>.
          </div>
        </div>
      </div>

      <div class="panel">
        <div id="log"></div>
        <div class="row">
          <input id="inp" placeholder="message… (try /1 to switch camera)" autocomplete="off"/>
          <button id="send">Send</button>
        </div>
      </div>
    </div>
  </div>

<script>
(() => {
  const log = document.getElementById("log");
  const status = document.getElementById("status");
  const camstat = document.getElementById("camstat");
  const cam = document.getElementById("cam");
  const inp = document.getElementById("inp");
  const btn = document.getElementById("send");

  function appendMsg(m) {
    const div = document.createElement("div");
    div.className = "msg";
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = `[${m.ts || ""}] ${m.sender || "?"}`;
    const text = document.createElement("div");
    text.className = "text";
    text.textContent = m.text || "";
    div.appendChild(meta);
    div.appendChild(text);
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }

  async function loadHistory() {
    try {
      const r = await fetch("/history");
      if (!r.ok) return;
      const data = await r.json();
      (data.history || []).forEach(appendMsg);
    } catch {}
  }

  async function getStatus() {
    try {
      const r = await fetch("/status");
      if (!r.ok) return;
      const s = await r.json();
      camstat.textContent = "camera: " + (s.camera ?? "?");
      if (s.camera_enabled) {
        cam.src = "/mjpeg";
      } else {
        cam.removeAttribute("src");
        cam.alt = "camera disabled on server";
      }
    } catch {}
  }

  async function sendMessage() {
    const text = (inp.value || "").trim();
    if (!text) return;
    inp.value = "";
    try {
      await fetch("/send", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({sender:"web", text})
      });
    } catch {}
  }

  btn.addEventListener("click", sendMessage);
  inp.addEventListener("keydown", (e) => { if (e.key === "Enter") sendMessage(); });

  function startSSE() {
    const es = new EventSource("/events");
    es.onopen = () => { status.textContent = "connected"; };
    es.onerror = () => { status.textContent = "reconnecting…"; };
    es.onmessage = (ev) => {
      try {
        const m = JSON.parse(ev.data);
        appendMsg(m);
        // if server announces camera switch, refresh status text
        if ((m.sender || "") === "server" && (m.text || "").startsWith("Camera switched")) {
          getStatus();
        }
      } catch {}
    };
  }

  loadHistory().then(() => { getStatus(); startSSE(); });
})();
</script>
</body>
</html>
"""


# -------------------- HTTP handler --------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "UPnPStreamChat/1.0"

    def _auth_ok(self) -> bool:
        secret = self.server.app_secret
        cookies = parse_cookies(self.headers.get("Cookie", ""))
        sess = cookies.get("session", "")
        if not sess:
            return False
        return verify_session(secret, sess)

    def _send(self, code: int, content_type: str, data: bytes, extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/health":
            self._send(200, "text/plain; charset=utf-8", b"ok\n")
            return

        if path == "/login":
            err = ""
            if "e=1" in self.path:
                err = '<div class="err">Invalid password</div>'
            html = LOGIN_HTML.replace("{ERROR}", err)
            self._send(200, "text/html; charset=utf-8", html.encode("utf-8"))
            return

        if path == "/logout":
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header("Set-Cookie", "session=; HttpOnly; Max-Age=0; Path=/")
            self.end_headers()
            return

        # Require auth for everything else
        if not self._auth_ok():
            if path in ("/", "/index.html"):
                self._redirect("/login")
            else:
                self._send(401, "text/plain; charset=utf-8", b"Unauthorized\n")
            return

        if path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", INDEX_HTML.encode("utf-8"))
            return

        if path == "/status":
            cam = get_camera_device()
            payload = json.dumps({
                "camera": cam,
                "camera_enabled": bool(self.server.camera_enabled),
            }, ensure_ascii=False).encode("utf-8")
            self._send(200, "application/json; charset=utf-8", payload)
            return

        if path == "/history":
            with HISTORY_LOCK:
                payload = json.dumps({"history": HISTORY}, ensure_ascii=False).encode("utf-8")
            self._send(200, "application/json; charset=utf-8", payload)
            return

        if path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            q = queue.Queue(maxsize=200)
            with CLIENTS_LOCK:
                CLIENTS.add(q)

            hello = {"ts": now_human(), "sender": "server", "text": "SSE connected."}
            try:
                self.wfile.write(f"data: {json.dumps(hello, ensure_ascii=False)}\n\n".encode("utf-8"))
                self.wfile.flush()
            except Exception:
                with CLIENTS_LOCK:
                    CLIENTS.discard(q)
                return

            try:
                while True:
                    try:
                        msg = q.get(timeout=20.0)
                        self.wfile.write(f"data: {json.dumps(msg, ensure_ascii=False)}\n\n".encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
            except Exception:
                pass
            finally:
                with CLIENTS_LOCK:
                    CLIENTS.discard(q)
            return

        if path == "/mjpeg":
            # Log viewer connection
            print(f"[{now_human()}] Viewer connected to /mjpeg from {self.client_address[0]}:{self.client_address[1]}", flush=True)

            if not self.server.camera_enabled:
                self._send(503, "text/plain; charset=utf-8",
                           b"Camera disabled. Start server with --enable-camera.\n")
                return

            boundary = "frame"
            self.send_response(200)
            self.send_header("Content-Type", f"multipart/x-mixed-replace; boundary={boundary}")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()

            last_ts = 0.0
            try:
                while True:
                    with FRAME_COND:
                        FRAME_COND.wait(timeout=2.0)
                        jpg = LATEST_JPEG
                        ts = LATEST_TS

                    if jpg is None:
                        time.sleep(0.05)
                        continue
                    if ts <= last_ts:
                        time.sleep(0.02)
                        continue
                    last_ts = ts

                    header = (
                        f"--{boundary}\r\n"
                        "Content-Type: image/jpeg\r\n"
                        f"Content-Length: {len(jpg)}\r\n"
                        "\r\n"
                    ).encode("utf-8")
                    self.wfile.write(header)
                    self.wfile.write(jpg)
                    self.wfile.write(b"\r\n")
                    self.wfile.flush()
            except Exception:
                return

        self._send(404, "text/plain; charset=utf-8", b"not found\n")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/login":
            # Accept x-www-form-urlencoded
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            body = self.rfile.read(length) if length > 0 else b""
            qs = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))

            pw = (qs.get("password", [""])[0] or "").strip()
            if pw != self.server.app_password:
                self._redirect("/login?e=1")
                return

            token = make_session(self.server.app_secret, self.server.app_username, self.server.session_ttl)
            self.send_response(302)
            self.send_header("Location", "/")
            # HttpOnly cookie; SameSite=Lax is decent default
            self.send_header("Set-Cookie", f"session={token}; HttpOnly; Path=/; SameSite=Lax")
            self.end_headers()
            return

        # Require auth for everything else
        if not self._auth_ok():
            self._send(401, "text/plain; charset=utf-8", b"Unauthorized\n")
            return

        if path == "/send":
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            body = self.rfile.read(length) if length > 0 else b""

            sender = "web"
            text = ""
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            try:
                if ctype == "application/json":
                    obj = json.loads(body.decode("utf-8", errors="ignore") or "{}")
                    sender = str(obj.get("sender", "web"))
                    text = str(obj.get("text", ""))
                else:
                    text = body.decode("utf-8", errors="ignore")
            except Exception:
                self._send(400, "application/json; charset=utf-8", b'{"error":"bad_request"}\n')
                return

            sender = sender.strip()[:40] or "web"
            text = (text or "").strip()
            if not text:
                self._send(400, "application/json; charset=utf-8", b'{"error":"empty"}\n')
                return
            if len(text) > 2000:
                text = text[:2000] + "…"

            # Commands first
            if text.startswith("/"):
                if handle_command(text):
                    # also show the command as a message (optional). Comment next two lines to hide.
                    msg = {"ts": now_human(), "sender": sender, "text": text}
                    terminal_print(msg); broadcast(msg)
                    self._send(200, "application/json; charset=utf-8", b'{"ok":true}\n')
                    return

            msg = {"ts": now_human(), "sender": sender, "text": text}
            terminal_print(msg)
            broadcast(msg)
            self._send(200, "application/json; charset=utf-8", b'{"ok":true}\n')
            return

        self._send(404, "text/plain; charset=utf-8", b"not found\n")

    def log_message(self, fmt, *args):
        return


# -------------------- Terminal input loop --------------------
def terminal_input_loop(stop_event: threading.Event):
    print(f"[{now_human()}] Terminal input enabled. Type and press Enter to send. Ctrl+C to quit.", flush=True)
    while not stop_event.is_set():
        try:
            line = sys.stdin.readline()
            if line == "":
                time.sleep(0.2)
                continue
            line = line.rstrip("\n")
            if not line.strip():
                continue

            text = line.strip()
            if text.startswith("/") and handle_command(text):
                msg = {"ts": now_human(), "sender": "terminal", "text": text}
                terminal_print(msg); broadcast(msg)
                continue

            msg = {"ts": now_human(), "sender": "terminal", "text": text[:2000]}
            terminal_print(msg)
            broadcast(msg)
        except Exception:
            time.sleep(0.2)


# -------------------- Main --------------------
def main():
    env = load_or_create_env()

    app_username = env.get("APP_USERNAME", "viewer")
    app_password = env.get("APP_PASSWORD", "")
    app_secret = env.get("APP_SECRET", "")
    default_camera = env.get("DEFAULT_CAMERA", "0")
    session_ttl = int(env.get("SESSION_TTL", "43200") or "43200")

    if not app_password or not app_secret:
        print(f"[{now_human()}] ERROR: .env missing APP_PASSWORD or APP_SECRET", flush=True)
        sys.exit(1)

    secret_bytes = app_secret.encode("utf-8")

    ap = argparse.ArgumentParser(description="Password-protected stream+chat with UPnP + live camera switching.")
    ap.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    ap.add_argument("--local-port", type=int, default=0, help="Local TCP port (0=auto)")
    ap.add_argument("--external-port", type=int, default=0, help="External TCP port (0=random high port)")
    ap.add_argument("--lease", type=int, default=0, help="UPnP lease seconds (0=router default)")
    ap.add_argument("--desc", default="python-upnp-stream-chat", help="UPnP mapping description")

    ap.add_argument("--enable-camera", action="store_true", help="Enable webcam MJPEG streaming")
    ap.add_argument("--camera", default=default_camera, help="Default camera device (index like 2 or path like /dev/video2)")
    ap.add_argument("--fps", type=float, default=10.0, help="Capture FPS (default 10)")
    ap.add_argument("--jpeg-quality", type=int, default=75, help="JPEG quality 10-95 (default 75)")
    ap.add_argument("--width", type=int, default=0, help="Optional capture width")
    ap.add_argument("--height", type=int, default=0, help="Optional capture height")
    args = ap.parse_args()

    # initial camera selection
    cam_init = args.camera.strip()
    if cam_init.isdigit():
        set_camera_device(int(cam_init))
    else:
        set_camera_device(cam_init)

    internal_ip = get_local_ip()
    local_port = args.local_port or pick_free_port(args.bind)

    httpd = ThreadingHTTPServer((args.bind, local_port), Handler)
    httpd.app_username = app_username
    httpd.app_password = app_password
    httpd.app_secret = secret_bytes
    httpd.session_ttl = session_ttl
    httpd.camera_enabled = bool(args.enable_camera)

    if not ENV_PATH.exists():
        # (shouldn't happen because we create it), but keep safe
        pass

    if ENV_PATH.exists():
        # On first run, show generated password prominently
        # If it already existed, this still prints what you’re using
        print(f"[{now_human()}] .env: {ENV_PATH}", flush=True)
        print(f"[{now_human()}] APP_USERNAME={app_username}", flush=True)
        print(f"[{now_human()}] APP_PASSWORD={app_password}", flush=True)

    print(f"[{now_human()}] Local login: http://127.0.0.1:{local_port}/login", flush=True)
    print(f"[{now_human()}] Local IP:    {internal_ip}", flush=True)

    # Start terminal thread
    stop_event = threading.Event()
    term_thread = threading.Thread(target=terminal_input_loop, args=(stop_event,), daemon=True)
    term_thread.start()

    # Start camera thread if enabled
    cam_stop = threading.Event()
    cam_thread = None
    if args.enable_camera:
        cam_thread = threading.Thread(
            target=camera_loop,
            args=(cam_stop, args.fps, args.jpeg_quality, args.width, args.height),
            daemon=True
        )
        cam_thread.start()
        msg = {"ts": now_human(), "sender": "server", "text": "Camera streaming ENABLED (MJPEG at /mjpeg)."}
        terminal_print(msg); broadcast(msg)
    else:
        msg = {"ts": now_human(), "sender": "server", "text": "Camera streaming DISABLED (start with --enable-camera)."}
        terminal_print(msg); broadcast(msg)

    # UPnP mapping best-effort
    mapped = False
    external_port = args.external_port or random.randint(20000, 60000)
    ext_ip = None
    control_url = None
    service_type = None

    def cleanup():
        nonlocal mapped
        stop_event.set()
        cam_stop.set()
        if mapped and control_url and service_type:
            try:
                delete_port_mapping(control_url, service_type, external_port)
                print(f"[{now_human()}] Cleaned up port mapping {external_port}/TCP", flush=True)
            except Exception as e:
                print(f"[{now_human()}] WARNING: Failed to delete port mapping: {e}", flush=True)

    atexit.register(cleanup)

    try:
        location = ssdp_discover(timeout=3.0)
        if not location:
            raise RuntimeError("Could not discover UPnP IGD (SSDP). Is UPnP enabled on your router?")

        control_url, service_type = find_igd_control_url(location)
        if not control_url:
            raise RuntimeError("Found device description but no WANIPConnection/WANPPPConnection control URL.")

        for _ in range(8):
            try:
                add_port_mapping(
                    control_url, service_type,
                    external_port=external_port,
                    internal_ip=internal_ip,
                    internal_port=local_port,
                    desc=args.desc,
                    lease_seconds=args.lease
                )
                mapped = True
                break
            except Exception:
                external_port = random.randint(20000, 60000)

        if not mapped:
            raise RuntimeError("Unable to create UPnP port mapping after multiple attempts.")

        ext_ip = get_external_ip(control_url, service_type) or "UNKNOWN_PUBLIC_IP"
        print(f"[{now_human()}] UPnP mapping OK: {ext_ip}:{external_port} -> {internal_ip}:{local_port}", flush=True)
        print(f"[{now_human()}] Public login:   http://{ext_ip}:{external_port}/login", flush=True)

    except Exception as e:
        print(f"[{now_human()}] WARNING: UPnP setup failed: {e}", flush=True)
        print(f"[{now_human()}] Server is running LOCALLY only.", flush=True)

    ready = {"ts": now_human(), "sender": "server",
             "text": "Ready. Login, then view stream+chat at /. Switch camera with /0 /1 /2 /3 or /cam <...>."}
    terminal_print(ready); broadcast(ready)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[{now_human()}] Shutting down…", flush=True)
    finally:
        stop_event.set()
        cam_stop.set()
        httpd.server_close()


if __name__ == "__main__":
    main()
