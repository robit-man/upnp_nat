#!/usr/bin/env python3
"""
UPnP-exposed bi-directional chat:
- Terminal <-> Web UI
- Public port mapping via UPnP IGD
- Server-Sent Events (SSE) for live updates
- Token required (?token=... or X-Auth-Token)

Works best on home routers with UPnP enabled.
Won't work behind CGNAT / strict enterprise NAT / UPnP disabled.

Run:
  python3 upnp_bidir_chat.py

Then open (from outside your LAN):
  http://PUBLIC_IP:EXTERNAL_PORT/?token=TOKEN
"""

import argparse
import atexit
import datetime as _dt
import html
import json
import os
import queue
import random
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SSDP_ADDR = ("239.255.255.250", 1900)
SSDP_ST = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
USER_AGENT = "python-upnp-bidir-chat/1.0"

# --- Chat state ---
CLIENTS_LOCK = threading.Lock()
CLIENTS = set()  # set[queue.Queue]
HISTORY_LOCK = threading.Lock()
HISTORY = []     # list[dict], bounded
HISTORY_MAX = 300

SERVER_START = time.time()


def now_iso():
    return _dt.datetime.now().isoformat(timespec="seconds")


def now_human():
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def clamp(s: str, max_len: int) -> str:
    if s is None:
        return ""
    s = s.replace("\r", "")
    if len(s) > max_len:
        return s[:max_len] + "…"
    return s


def get_local_ip():
    # Find the interface used for outbound traffic
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


# --- UPnP IGD helpers (SSDP + SOAP) ---

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


# --- Chat bus ---

def add_history(msg: dict):
    with HISTORY_LOCK:
        HISTORY.append(msg)
        if len(HISTORY) > HISTORY_MAX:
            del HISTORY[:len(HISTORY) - HISTORY_MAX]


def broadcast(msg: dict):
    """Send message to all SSE clients and store in history."""
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


def terminal_print_message(msg: dict):
    sender = msg.get("sender", "?")
    text = msg.get("text", "")
    ts = msg.get("ts", now_human())
    print(f"[{ts}] {sender}: {text}")


# --- HTTP server ---

INDEX_HTML = r"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>UPnP Bi-directional Chat</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0; background: #0b0f14; color: #e7eef7; }
    .wrap { max-width: 900px; margin: 0 auto; padding: 16px; }
    .top { display: flex; gap: 12px; align-items: baseline; flex-wrap: wrap; }
    .badge { font-size: 12px; padding: 4px 8px; border-radius: 999px; background: #18212d; color: #bcd; }
    .panel { margin-top: 12px; background: #0f1620; border: 1px solid #1e2a3a; border-radius: 12px; overflow: hidden; }
    #log { height: 60vh; overflow: auto; padding: 12px; }
    .row { display: grid; grid-template-columns: 1fr auto; gap: 8px; padding: 12px; border-top: 1px solid #1e2a3a; }
    input[type="text"] { width: 100%; padding: 10px 12px; border-radius: 10px; border: 1px solid #2a3a52; background: #0b0f14; color: #e7eef7; }
    button { padding: 10px 14px; border-radius: 10px; border: 1px solid #2a3a52; background: #18212d; color: #e7eef7; cursor: pointer; }
    button:hover { background: #1d2a3b; }
    .msg { margin: 8px 0; }
    .meta { font-size: 12px; color: #9bb0c7; }
    .text { white-space: pre-wrap; word-wrap: break-word; }
    .sys { color: #9bd; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <h2 style="margin:0;">UPnP Bi-directional Chat</h2>
      <span id="status" class="badge">connecting…</span>
      <span class="badge">token-gated</span>
    </div>

    <div class="panel">
      <div id="log"></div>
      <div class="row">
        <input id="inp" type="text" placeholder="Type a message…" autocomplete="off" />
        <button id="send">Send</button>
      </div>
    </div>
  </div>

<script>
(() => {
  const qs = new URLSearchParams(location.search);
  const token = qs.get("token") || "";
  const log = document.getElementById("log");
  const status = document.getElementById("status");
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

  function appendSys(s) {
    const div = document.createElement("div");
    div.className = "msg sys";
    div.textContent = s;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }

  async function loadHistory() {
    try {
      const r = await fetch(`/history?token=${encodeURIComponent(token)}`);
      if (!r.ok) return;
      const data = await r.json();
      (data.history || []).forEach(appendMsg);
    } catch {}
  }

  async function sendMessage() {
    const text = inp.value.trim();
    if (!text) return;
    inp.value = "";
    try {
      const r = await fetch(`/send?token=${encodeURIComponent(token)}`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ sender: "web", text })
      });
      if (!r.ok) appendSys(`send failed (${r.status})`);
    } catch (e) {
      appendSys("send error: " + e);
    }
  }

  btn.addEventListener("click", sendMessage);
  inp.addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMessage();
  });

  // Start SSE stream
  function startSSE() {
    if (!token) {
      status.textContent = "missing token";
      appendSys("Missing token in URL. Use /?token=YOURTOKEN");
      return;
    }
    const es = new EventSource(`/events?token=${encodeURIComponent(token)}`);
    es.onopen = () => {
      status.textContent = "connected";
      appendSys("Connected.");
    };
    es.onerror = () => {
      status.textContent = "reconnecting…";
    };
    es.onmessage = (ev) => {
      try {
        const m = JSON.parse(ev.data);
        appendMsg(m);
      } catch {}
    };
  }

  loadHistory().then(startSSE);
})();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "UPnPBiDirChat/1.0"

    def _token(self):
        return getattr(self.server, "token", "")

    def _authorized(self):
        token = self._token()
        if not token:
            return True
        # Header token OR query token
        hdr = self.headers.get("X-Auth-Token")
        if hdr and hdr.strip() == token:
            return True
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        return qs.get("token", [""])[0] == token

    def _send(self, code, content_type, data: bytes):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            if not self._authorized():
                self._send(401, "text/plain; charset=utf-8", b"Unauthorized (missing/invalid token)\n")
                return
            data = INDEX_HTML.encode("utf-8")
            self._send(200, "text/html; charset=utf-8", data)
            return

        if path == "/health":
            self._send(200, "text/plain; charset=utf-8", b"ok\n")
            return

        if path == "/history":
            if not self._authorized():
                self._send(401, "application/json; charset=utf-8", b'{"error":"unauthorized"}\n')
                return
            with HISTORY_LOCK:
                payload = json.dumps({"history": HISTORY}, ensure_ascii=False).encode("utf-8")
            self._send(200, "application/json; charset=utf-8", payload)
            return

        if path == "/events":
            if not self._authorized():
                self.send_response(401)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Unauthorized\n")
                return

            # SSE stream
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            q = queue.Queue(maxsize=200)
            with CLIENTS_LOCK:
                CLIENTS.add(q)

            # Send a hello event
            hello = {"ts": now_human(), "sender": "server", "text": "SSE stream established."}
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
                        payload = json.dumps(msg, ensure_ascii=False)
                        self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        # keepalive comment
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
            except Exception:
                # client disconnected
                pass
            finally:
                with CLIENTS_LOCK:
                    CLIENTS.discard(q)
            return

        self._send(404, "text/plain; charset=utf-8", b"not found\n")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path != "/send":
            self._send(404, "text/plain; charset=utf-8", b"not found\n")
            return

        if not self._authorized():
            self._send(401, "application/json; charset=utf-8", b'{"error":"unauthorized"}\n')
            return

        # Read body
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
            elif ctype == "application/x-www-form-urlencoded":
                qs = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
                sender = qs.get("sender", ["web"])[0]
                text = qs.get("text", [""])[0]
            else:
                # Accept raw text
                text = body.decode("utf-8", errors="ignore")
        except Exception:
            self._send(400, "application/json; charset=utf-8", b'{"error":"bad_request"}\n')
            return

        sender = clamp(sender, 40)
        text = clamp(text.strip(), 2000)
        if not text:
            self._send(400, "application/json; charset=utf-8", b'{"error":"empty"}\n')
            return

        msg = {"ts": now_human(), "sender": sender, "text": text}
        terminal_print_message(msg)
        broadcast(msg)

        self._send(200, "application/json; charset=utf-8", b'{"ok":true}\n')

    def log_message(self, fmt, *args):
        # Silence default logging
        return


def terminal_input_loop(stop_event: threading.Event):
    """
    Read stdin lines and broadcast as sender='terminal'.
    """
    print(f"[{now_human()}] Terminal input enabled. Type and press Enter to send. Ctrl+C to quit.")
    while not stop_event.is_set():
        try:
            line = sys.stdin.readline()
            if line == "":
                # stdin closed
                time.sleep(0.2)
                continue
            line = line.rstrip("\n")
            if not line.strip():
                continue
            msg = {"ts": now_human(), "sender": "terminal", "text": clamp(line.strip(), 2000)}
            terminal_print_message(msg)
            broadcast(msg)
        except Exception:
            time.sleep(0.2)


def main():
    ap = argparse.ArgumentParser(description="Expose a bi-directional chat server via UPnP IGD port mapping.")
    ap.add_argument("--bind", default="0.0.0.0", help="Bind address for local server (default: 0.0.0.0)")
    ap.add_argument("--local-port", type=int, default=0, help="Local TCP port (0 = auto)")
    ap.add_argument("--external-port", type=int, default=0, help="External TCP port (0 = random high port)")
    ap.add_argument("--lease", type=int, default=0, help="Lease duration seconds (0 = indefinite if router allows)")
    ap.add_argument("--desc", default="python-upnp-bidir-chat", help="Port mapping description")
    ap.add_argument("--token", default="", help="Require this token (or auto-generate if empty)")
    args = ap.parse_args()

    token = (args.token or os.environ.get("CHAT_TOKEN", "")).strip()
    if not token:
        token = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(24))

    internal_ip = get_local_ip()
    local_port = args.local_port or pick_free_port(args.bind)

    httpd = ThreadingHTTPServer((args.bind, local_port), Handler)
    httpd.token = token

    print(f"[{now_human()}] Local server: http://127.0.0.1:{local_port}/?token={token}")
    print(f"[{now_human()}] Local IP: {internal_ip}")
    print(f"[{now_human()}] Token: {token}")

    # Start terminal input thread
    stop_event = threading.Event()
    t = threading.Thread(target=terminal_input_loop, args=(stop_event,), daemon=True)
    t.start()

    # UPnP setup
    mapped = False
    external_port = args.external_port or random.randint(20000, 60000)
    ext_ip = None
    control_url = None
    service_type = None

    def cleanup():
        nonlocal mapped
        stop_event.set()
        if mapped and control_url and service_type:
            try:
                delete_port_mapping(control_url, service_type, external_port)
                print(f"[{now_human()}] Cleaned up port mapping {external_port}/TCP")
            except Exception as e:
                print(f"[{now_human()}] WARNING: Failed to delete port mapping: {e}")

    atexit.register(cleanup)

    try:
        location = ssdp_discover(timeout=3.0)
        if not location:
            raise RuntimeError("Could not discover UPnP IGD (SSDP). Is UPnP enabled on your router?")

        control_url, service_type = find_igd_control_url(location)
        if not control_url:
            raise RuntimeError("Found device description but no WANIPConnection/WANPPPConnection control URL.")

        # Try a few ports in case of conflict
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
        print(f"[{now_human()}] UPnP mapping OK: {ext_ip}:{external_port} -> {internal_ip}:{local_port}")
        print(f"[{now_human()}] Public chat URL: http://{ext_ip}:{external_port}/?token={token}")

    except Exception as e:
        print(f"[{now_human()}] WARNING: UPnP setup failed: {e}")
        print(f"[{now_human()}] The chat server is still running LOCALLY only.")

    # Announce ready
    ready = {"ts": now_human(), "sender": "server", "text": "Chat server ready."}
    terminal_print_message(ready)
    broadcast(ready)

    # Run server
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[{now_human()}] Shutting down…")
    finally:
        stop_event.set()
        httpd.server_close()


if __name__ == "__main__":
    main()
