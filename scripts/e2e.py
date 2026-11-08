#!/usr/bin/env python3
"""End-to-end test of a real emberd, driving real Minecraft servers.

Needs root. Tailscale itself is replaced by a fake tailscaled on the same local API
that answers with fixed identities, because a CI runner is not on a tailnet. Only the
identity source is faked: the auth code path, sandbox and firewall are all real.
"""

import argparse
import base64
import http.client
import http.server
import json
import os
import pathlib
import shutil
import signal
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

NODE_IP = "127.0.0.2"
OWNER_IP = "127.0.0.5"
STRANGER_IP = "127.0.0.6"
TAGGED_IP = "127.0.0.7"
API_PORT = 8787
EXT_NS = "ember-e2e-ext"
HOST_VETH_IP = "10.214.0.1"
OWNER = "owner@example.com"
LOGINS = {OWNER_IP: OWNER, STRANGER_IP: "stranger@example.com", TAGGED_IP: "tagged-devices", NODE_IP: OWNER}

failures = []


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'} {name}{f' ({detail})' if detail else ''}", flush=True)
    if not ok:
        failures.append(name)


class FakeTailscaled(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def address_string(self):
        return "unix"

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path == "/localapi/v0/status":
            body = {"Self": {"TailscaleIPs": [NODE_IP], "DNSName": "e2e.tail.ts.net.", "HostName": "e2e"}}
        elif url.path == "/localapi/v0/whois":
            ip = urllib.parse.parse_qs(url.query)["addr"][0].rsplit(":", 1)[0]
            login = LOGINS.get(ip)
            if login is None:
                self.send_error(404)
                return
            body = {"Node": {}, "UserProfile": {"LoginName": login}}
        else:
            self.send_error(404)
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def api(method, path, body=None, source=OWNER_IP, headers=None, raw=None, client_header=True, timeout=60):
    conn = http.client.HTTPConnection(NODE_IP, API_PORT, timeout=timeout, source_address=(source, 0))
    h = dict(headers or {})
    if client_header:
        h.setdefault("x-ember-client", "e2e")
    payload = raw
    if body is not None:
        payload = json.dumps(body)
        h["Content-Type"] = "application/json"
    conn.request(method, path, body=payload, headers=h)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    try:
        return resp.status, json.loads(data) if data else None
    except ValueError:
        return resp.status, data


def wait_state(sid, want, timeout):
    deadline = time.time() + timeout
    state = None
    while time.time() < deadline:
        _, info = api("GET", f"/v1/servers/{sid}")
        state = info["state"]
        if state in want:
            return state, info
        if state in ("install_failed", "crashed") and state not in want:
            return state, info
        time.sleep(2)
    return state, None


def ws_console(sid, commands, expect, timeout=30):
    """A small RFC 6455 client. Returns True once a line containing `expect` arrives."""
    s = socket.create_connection((NODE_IP, API_PORT), timeout=timeout, source_address=(OWNER_IP, 0))
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(
        (
            f"GET /v1/servers/{sid}/console HTTP/1.1\r\nHost: {NODE_IP}:{API_PORT}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nx-ember-client: e2e\r\n\r\n"
        ).encode()
    )
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    head, buf = buf.split(b"\r\n\r\n", 1)
    if b" 101 " not in head.split(b"\r\n")[0]:
        return False

    def send_text(text):
        data = text.encode()
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        length = len(data)
        if length < 126:
            s.sendall(bytes([0x81, 0x80 | length]) + mask + masked)
        else:
            s.sendall(bytes([0x81, 0x80 | 126]) + struct.pack(">H", length) + mask + masked)

    for c in commands:
        send_text(json.dumps({"command": c}))

    deadline = time.time() + timeout
    while time.time() < deadline:
        while len(buf) < 2:
            buf += s.recv(65536)
        length = buf[1] & 0x7F
        offset = 2
        if length == 126:
            while len(buf) < 4:
                buf += s.recv(65536)
            length = struct.unpack(">H", buf[2:4])[0]
            offset = 4
        elif length == 127:
            while len(buf) < 10:
                buf += s.recv(65536)
            length = struct.unpack(">Q", buf[2:10])[0]
            offset = 10
        while len(buf) < offset + length:
            buf += s.recv(65536)
        payload, buf = buf[offset : offset + length], buf[offset + length :]
        try:
            event = json.loads(payload)
        except ValueError:
            continue
        if event.get("type") == "line" and expect in event.get("text", ""):
            s.close()
            return True
    s.close()
    return False


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


PING_SNIPPET = r"""
import json, socket, sys
def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: return bytes(out)
def read_varint(s):
    n = shift = 0
    while True:
        b = s.recv(1)[0]
        n |= (b & 0x7F) << shift; shift += 7
        if not b & 0x80: return n
host, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((host, port), timeout=15)
addr = host.encode()
hs = varint(0) + varint(765) + varint(len(addr)) + addr + port.to_bytes(2, "big") + varint(1)
s.sendall(varint(len(hs)) + hs + varint(1) + varint(0))
read_varint(s); read_varint(s); n = read_varint(s)
buf = b""
while len(buf) < n: buf += s.recv(65536)
print(json.loads(buf)["version"]["name"])
"""


def ext_ping(port):
    """Server List Ping from a separate network namespace, like a real player."""
    r = subprocess.run(
        ["ip", "netns", "exec", EXT_NS, sys.executable, "-c", PING_SNIPPET, HOST_VETH_IP, str(port)],
        capture_output=True, text=True, timeout=30,
    )
    return r.returncode == 0, (r.stdout.strip() or r.stderr.strip()[-300:])


def sh(*args):
    subprocess.run(args, check=True)


def setup_ext_ns():
    subprocess.run(["ip", "netns", "del", EXT_NS], capture_output=True)
    subprocess.run(["ip", "link", "del", "e2eh"], capture_output=True)
    sh("ip", "netns", "add", EXT_NS)
    sh("ip", "link", "add", "e2eh", "type", "veth", "peer", "name", "e2ep")
    sh("ip", "link", "set", "e2ep", "netns", EXT_NS)
    sh("ip", "addr", "add", f"{HOST_VETH_IP}/30", "dev", "e2eh")
    sh("ip", "link", "set", "e2eh", "up")
    sh("ip", "-n", EXT_NS, "addr", "add", "10.214.0.2/30", "dev", "e2ep")
    sh("ip", "-n", EXT_NS, "link", "set", "e2ep", "up")
    sh("ip", "-n", EXT_NS, "link", "set", "lo", "up")
    sh("ip", "-n", EXT_NS, "route", "add", "default", "via", HOST_VETH_IP)


def test_auth():
    print("=== authentication", flush=True)
    check("owner is accepted", api("GET", "/v1/node")[0] == 200)
    check("stranger on the tailnet is refused", api("GET", "/v1/node", source=STRANGER_IP)[0] == 403)
    check("tagged device is refused", api("GET", "/v1/node", source=TAGGED_IP)[0] == 403)
    check("unknown source is refused", api("GET", "/v1/node", source="127.0.0.9")[0] == 403)
    check("the node itself is refused", api("GET", "/v1/node", source=NODE_IP)[0] == 403)
    check("request without client header is refused", api("GET", "/v1/node", client_header=False)[0] == 403)
    check("browser Origin is refused", api("GET", "/v1/node", headers={"Origin": "https://evil.example"})[0] == 403)
    check("DNS rebinding Host is refused", api("GET", "/v1/node", headers={"Host": "evil.example:8787"})[0] == 403)
    check("every route is guarded", api("GET", "/v1/servers", source=STRANGER_IP)[0] == 403)
    check("nothing listens on loopback", _refused("127.0.0.1"))


def _refused(ip):
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((ip, API_PORT))
        return False
    except OSError:
        return True
    finally:
        s.close()


LIMITS = {"memory_mb": 2048, "cpu_percent": 200, "disk_mb": 10240, "pids": 1024}


def test_validation(version):
    print("=== input validation", flush=True)
    base = {"name": "x", "flavor": "vanilla", "version": version, "limits": LIMITS, "port": 25570, "eula_accepted": True}
    check("EULA must be accepted", api("POST", "/v1/servers", {**base, "eula_accepted": False})[0] == 400)
    check("low port is refused", api("POST", "/v1/servers", {**base, "port": 22})[0] == 400)
    check("daemon port is refused", api("POST", "/v1/servers", {**base, "port": API_PORT})[0] == 400)
    check("URL injection in version is refused", api("POST", "/v1/servers", {**base, "version": "../../evil"})[0] == 400)
    check("bad limits are refused", api("POST", "/v1/servers", {**base, "limits": {**LIMITS, "memory_mb": 1}})[0] == 400)
    evil = {**base, "flavor": "bedrock", "bedrock_url": "https://evil.example/bedrock-server-1.zip"}
    check("non-Mojang Bedrock link is refused", api("POST", "/v1/servers", evil)[0] == 400)


def test_full_server(version, data_root):
    print(f"=== full lifecycle on vanilla {version}", flush=True)
    req = {"name": "E2E Vanilla", "flavor": "vanilla", "version": version, "limits": LIMITS, "port": 25565, "eula_accepted": True}
    code, info = api("POST", "/v1/servers", req)
    check("server is created", code == 201, str(code))
    sid = info["id"]
    state, _ = wait_state(sid, ("offline",), 420)
    check("install finishes", state == "offline", str(state))
    if state != "offline":
        print(api("GET", f"/v1/servers/{sid}"))
        return
    dup = api("POST", "/v1/servers", {**req, "name": "dup"})
    check("port conflict is refused", dup[0] == 409, str(dup[0]))

    check("start is accepted", api("POST", f"/v1/servers/{sid}/power", {"action": "start"})[0] == 202)
    state, _ = wait_state(sid, ("running",), 300)
    check("Minecraft reaches running", state == "running", str(state))
    if state != "running":
        print(ws_console_dump(data_root, sid))
        return

    ok, detail = ext_ping(25565)
    check("real player can reach it from outside", ok, detail)
    check("console round trip works", ws_console(sid, ["list"], "players online"))

    time.sleep(3)
    _, stats = api("GET", f"/v1/servers/{sid}/stats")
    check("memory usage is reported", stats["memory_bytes"] > 100 << 20, str(stats["memory_bytes"]))
    check("memory limit is reported", stats["memory_limit_bytes"] == 2048 << 20)

    data = pathlib.Path(data_root) / "servers" / sid / "data"
    expected_uid = data.stat().st_uid
    check("server has a dedicated unprivileged uid", expected_uid >= 200000, str(expected_uid))
    procs = pathlib.Path(f"/sys/fs/cgroup/ember/{sid}/cgroup.procs").read_text().split()
    owners = {p: os.stat(f"/proc/{p}").st_uid for p in procs if os.path.exists(f"/proc/{p}")}
    check("game processes run as that uid", set(owners.values()) - {0} == {expected_uid}, str(owners))
    # The helper that waits outside the namespaces joins the cgroup as root. It must be the
    # only root process, and it must not share the sandbox's PID namespace.
    roots = [p for p, uid in owners.items() if uid == 0]
    inside = [p for p, uid in owners.items() if uid == expected_uid]
    check("only the outer helper is root", len(roots) == 1, str(roots))
    if roots and inside:
        cmdline = pathlib.Path(f"/proc/{roots[0]}/cmdline").read_bytes()
        check("the root process is the sandbox helper", b"__sandbox-init" in cmdline, cmdline[:60].decode(errors="replace"))
        helper_ns = os.readlink(f"/proc/{roots[0]}/ns/pid")
        game_ns = os.readlink(f"/proc/{inside[0]}/ns/pid")
        check("the root helper is outside the sandbox PID namespace", helper_ns != game_ns, f"{helper_ns} vs {game_ns}")
    limit = pathlib.Path(f"/sys/fs/cgroup/ember/{sid}/memory.max").read_text().strip()
    check("memory cgroup is enforced", limit == str(2048 << 20), limit)

    test_files(sid, data, expected_uid)
    test_backups_and_power(sid, data)


def ws_console_dump(data_root, sid):
    log = pathlib.Path(data_root) / "servers" / sid / "data" / "logs" / "latest.log"
    return log.read_text()[-3000:] if log.exists() else "(no log)"


def test_files(sid, data, uid):
    print("=== file API against a hostile tree", flush=True)
    base = f"/v1/servers/{sid}/files"
    shadow = pathlib.Path("/etc/shadow")
    before = shadow.read_bytes()
    os.symlink("/etc/shadow", data / "evil")
    os.symlink("/etc", data / "evildir")
    os.mkfifo(data / "pipe")
    q = lambda p: urllib.parse.quote(p, safe="")

    check("read through a file symlink is refused", api("GET", f"{base}/content?path=evil")[0] == 400)
    check("read through a dir symlink is refused", api("GET", f"{base}/content?path=evildir/shadow")[0] == 400)
    check("list through a dir symlink is refused", api("GET", f"{base}?path=evildir")[0] == 400)
    check("write through a symlink is refused", api("PUT", f"{base}/content", {"path": "evil", "content": "x"})[0] == 400)
    check("write through a dir symlink is refused", api("PUT", f"{base}/content", {"path": "evildir/pwn", "content": "x"})[0] == 400)
    check("download through a symlink is refused", api("GET", f"{base}/download?path=evil")[0] == 400)
    check("FIFO cannot hang a read", api("GET", f"{base}/content?path=pipe", timeout=10)[0] == 400)
    check("path traversal is refused", api("GET", f"{base}/content?path={q('../server.json')}")[0] == 400)
    check("absolute path stays inside", api("GET", f"{base}/content?path={q('/etc/passwd')}")[0] == 400)
    check("/etc/shadow is untouched", shadow.read_bytes() == before)
    check("nothing was created in /etc", not pathlib.Path("/etc/pwn").exists())
    check("root cannot be deleted", api("DELETE", f"{base}?path=")[0] == 400)

    code, _ = api("DELETE", f"{base}?path=evildir")
    check("deleting a dir symlink works", code == 204 and pathlib.Path("/etc/passwd").exists())
    os.unlink(data / "evil")
    os.unlink(data / "pipe")

    check("files can be written", api("PUT", f"{base}/content", {"path": "plugins/a.txt", "content": "hello"})[0] == 204)
    check("files can be read", api("GET", f"{base}/content?path=plugins/a.txt")[1]["content"] == "hello")
    check("new files belong to the server", (data / "plugins/a.txt").stat().st_uid == uid)
    check("new folders belong to the server", (data / "plugins").stat().st_uid == uid)

    blob = os.urandom(1 << 20)
    check("upload works", api("PUT", f"{base}/upload?path=mods/blob.bin", raw=blob)[0] == 204)
    check("uploads belong to the server", (data / "mods/blob.bin").stat().st_uid == uid)
    check("download round-trips", api("GET", f"{base}/download?path=mods/blob.bin")[1] == blob)
    os.symlink("/etc/shadow", data / "upload-evil")
    check("upload replaces a symlink instead of following it", api("PUT", f"{base}/upload?path=upload-evil", raw=b"safe")[0] == 204)
    check("/etc/shadow survives the upload", shadow.read_bytes() == before)
    check("the link was replaced", stat.S_ISREG(os.lstat(data / "upload-evil").st_mode))
    os.unlink(data / "upload-evil")
    check("rename works", api("POST", f"{base}/rename", {"from": "mods/blob.bin", "to": "mods/b2.bin"})[0] == 204)
    check("delete works", api("DELETE", f"{base}?path=mods")[0] == 204)


def test_backups_and_power(sid, data):
    print("=== schedules, backups and power", flush=True)
    base = f"/v1/servers/{sid}"
    check("bad cron is refused", api("POST", f"{base}/schedules", {"name": "s", "cron": "nope", "action": {"type": "restart"}, "enabled": True})[0] == 400)
    code, sched = api("POST", f"{base}/schedules", {"name": "tick", "cron": "*/5 * * * * *", "action": {"type": "command", "value": "say scheduled-tick"}, "enabled": True})
    check("schedule is created", code == 201)
    check("schedule fires", ws_console(sid, [], "scheduled-tick", timeout=30))
    check("schedule is deleted", api("DELETE", f"{base}/schedules/{sched['id']}")[0] == 204)

    (data / "marker.txt").write_text("original")
    code, backup = api("POST", f"{base}/backups", {"name": "before"}, timeout=300)
    check("backup is created", code == 201, str(code))
    check("restore refuses a running server", api("POST", f"{base}/backups/{backup['id']}/restore")[0] == 409)

    check("stop is accepted", api("POST", f"{base}/power", {"action": "stop"})[0] == 202)
    state, _ = wait_state(sid, ("offline",), 90)
    check("graceful stop reaches offline", state == "offline", str(state))
    check("cgroup is removed", not pathlib.Path(f"/sys/fs/cgroup/ember/{sid}").exists())
    netns = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
    check("network namespace is removed", "ember-" not in netns.replace(EXT_NS, ""), netns.strip())

    (data / "marker.txt").write_text("changed")
    code, _ = api("POST", f"{base}/backups/{backup['id']}/restore", timeout=300)
    check("backup restores", code == 204, str(code))
    check("restored content is correct", (data / "marker.txt").read_text() == "original")

    props = api("GET", f"{base}/files/content?path=server.properties")[1]["content"]
    api("PUT", f"{base}/files/content", {"path": "server.properties", "content": props.replace("server-port=25565", "server-port=1")})
    check("restart is accepted from offline", api("POST", f"{base}/power", {"action": "start"})[0] == 202)
    state, _ = wait_state(sid, ("running",), 240)
    check("second boot works", state == "running", str(state))
    ok, detail = ext_ping(25565)
    check("the configured port is enforced after a bad edit", ok, detail)

    test_startup(sid, base)

    check("kill is accepted", api("POST", f"{base}/power", {"action": "kill"})[0] == 202)
    state, _ = wait_state(sid, ("offline",), 30)
    check("kill reaches offline", state == "offline", str(state))

    code, _ = api("DELETE", base)
    check("server deletes", code == 204, str(code))
    check("server files are gone", not data.exists())
    check("host is intact after delete", pathlib.Path("/etc/passwd").exists())


def test_startup(sid, base):
    print("=== startup options", flush=True)
    code, info = api("GET", f"{base}/startup")
    check("startup shows the real command", code == 200 and "-jar server.jar nogui" in info["command"], str(info))
    check("startup reports the default Java", info["default_java"] == 25 or info["default_java"] is not None)
    opts = info["options"]
    bad = [{**opts, "max_heap_mb": 999999}, {**opts, "java_major": 99}, {**opts, "jar": "../../etc/passwd"}, {**opts, "jvm_args": ["nope"]}, {**opts, "env": [{"name": "BAD NAME", "value": "x"}]}]
    check("invalid startup options are refused", all(api("PUT", f"{base}/startup", {"options": b})[0] == 400 for b in bad))
    busy = api("PUT", f"{base}/startup", {"options": opts, "version": "1.21.1"})
    check("version cannot change while running", busy[0] == 409, str(busy[0]))

    api("POST", f"{base}/power", {"action": "kill"})
    wait_state(sid, ("offline",), 30)
    chosen = {**opts, "min_heap_mb": 600, "max_heap_mb": 1200, "jvm_args": ["-XX:+UseG1GC", "-Dember.e2e=yes"], "env": [{"name": "EMBER_E2E", "value": "works"}]}
    code, saved = api("PUT", f"{base}/startup", {"options": chosen})
    check("startup options save", code == 200, str(code))
    check("the preview shows the new command", "-Xmx1200M" in saved["command"] and "-Dember.e2e=yes" in saved["command"], saved["command"])

    api("POST", f"{base}/power", {"action": "start"})
    state, _ = wait_state(sid, ("running",), 240)
    check("server boots with custom options", state == "running", str(state))
    pids = pathlib.Path(f"/sys/fs/cgroup/ember/{sid}/cgroup.procs").read_text().split()
    java = [p for p in pids if os.path.exists(f"/proc/{p}/exe") and os.readlink(f"/proc/{p}/exe").endswith("/bin/java")]
    check("a Java process is running", bool(java))
    if java:
        cmd = pathlib.Path(f"/proc/{java[0]}/cmdline").read_bytes().split(b"\0")
        environ = pathlib.Path(f"/proc/{java[0]}/environ").read_bytes().split(b"\0")
        check("the JVM really got the heap flags", b"-Xms600M" in cmd and b"-Xmx1200M" in cmd)
        check("the JVM really got the custom flags", b"-Dember.e2e=yes" in cmd and b"-XX:+UseG1GC" in cmd)
        check("the JVM really got the environment", b"EMBER_E2E=works" in environ)


def test_flavor(flavor, port):
    print(f"=== boot {flavor}", flush=True)
    code, versions = api("GET", f"/v1/versions/{flavor}")
    stable = [v["id"] for v in versions if v["stable"]] if code == 200 else []
    check(f"{flavor} lists versions", bool(stable), str(code))
    if not stable:
        return
    req = {"name": f"E2E {flavor}", "flavor": flavor, "version": stable[0], "limits": LIMITS, "port": port, "eula_accepted": True}
    code, info = api("POST", "/v1/servers", req)
    check(f"{flavor} {stable[0]} is created", code == 201, str(code))
    if code != 201:
        return
    sid = info["id"]
    state, detail = wait_state(sid, ("offline",), 600)
    check(f"{flavor} installs", state == "offline", f"{state} {detail and detail.get('last_error')}")
    if state != "offline":
        return
    api("POST", f"/v1/servers/{sid}/power", {"action": "start"})
    state, _ = wait_state(sid, ("running",), 420)
    check(f"{flavor} reaches running", state == "running", str(state))
    if state == "running":
        ok, detail = ext_ping(port)
        check(f"{flavor} answers a player", ok, detail)
    api("POST", f"/v1/servers/{sid}/power", {"action": "stop"})
    wait_state(sid, ("offline",), 90)
    api("DELETE", f"/v1/servers/{sid}")


def wait_for_api():
    for _ in range(60):
        try:
            if api("GET", "/v1/node", timeout=2)[0] == 200:
                return True
        except OSError:
            pass
        time.sleep(1)
    return False


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--emberd", required=True)
    p.add_argument("--flavors", default="")
    a = p.parse_args()
    if os.geteuid() != 0:
        sys.exit("e2e.py must run as root")

    work = tempfile.mkdtemp(prefix="ember-e2e-")
    os.chmod(work, 0o711)
    sock_path = os.path.join(work, "tailscaled.sock")
    server = UnixServer(sock_path, FakeTailscaled)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    data_root = os.path.join(work, "data")
    config = os.path.join(work, "config.toml")
    with open(config, "w") as f:
        f.write(f'owners = ["{OWNER}"]\nport = {API_PORT}\ndata_dir = "{data_root}"\ntailscale_socket = "{sock_path}"\nstop_timeout_secs = 45\n')

    setup_ext_ns()
    log_path = os.path.join(work, "emberd.log")
    log = open(log_path, "w")
    daemon = subprocess.Popen([os.path.abspath(a.emberd), "run", "--config", config], stdout=log, stderr=subprocess.STDOUT)
    try:
        check("daemon comes up on the Tailscale address", wait_for_api())
        if failures:
            return
        test_auth()
        _, versions = api("GET", "/v1/versions/vanilla")
        version = next(v["id"] for v in versions if v["stable"])
        test_validation(version)
        test_full_server(version, data_root)
        for i, flavor in enumerate(f for f in a.flavors.split(",") if f):
            test_flavor(flavor, 25600 + i)

        print("=== graceful daemon shutdown", flush=True)
        daemon.send_signal(signal.SIGTERM)
        check("daemon exits cleanly on SIGTERM", daemon.wait(timeout=120) == 0)
    finally:
        if daemon.poll() is None:
            daemon.kill()
            daemon.wait()
        log.close()
        print("--- emberd log (tail) ---")
        print(pathlib.Path(log_path).read_text()[-6000:])
        subprocess.run(["ip", "netns", "del", EXT_NS], capture_output=True)
        subprocess.run(["ip", "link", "del", "e2eh"], capture_output=True)
        server.shutdown()
        shutil.rmtree(work, ignore_errors=True)
    print(f"\n{len(failures)} failure(s)" + (": " + "; ".join(failures) if failures else ""))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
