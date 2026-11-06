"""GPS fleet tracker server: JT/T 808 listener + SQLite + HTTP API/dashboard.

Env vars:
  DASH_PASSWORD      required, password for the dashboard (user name: anything)
  TRACKER_UTC_OFFSET hours the tracker's clock is ahead of UTC (default 8)
  DB_PATH            default /opt/tracker/positions.db
"""
import base64, hmac, json, os, socket, sqlite3, threading, time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

TCP_PORT, HTTP_PORT = 8881, 8080
OFFSET = int(os.environ.get("TRACKER_UTC_OFFSET", "8"))
DB_PATH = os.environ.get("DB_PATH", "/opt/tracker/positions.db")
PASSWORD = os.environ.get("DASH_PASSWORD")
if not PASSWORD:
    raise SystemExit("Set DASH_PASSWORD before starting.")
HERE = os.path.dirname(os.path.abspath(__file__))

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.execute("""CREATE TABLE IF NOT EXISTS positions(
    device TEXT, ts TEXT, lat REAL, lon REAL, speed REAL, course INTEGER,
    PRIMARY KEY (device, ts))""")
db.commit()
lock = threading.Lock()
last_seen = {}
seq = 0


# ---- JT/T 808 helpers ------------------------------------------------------
def unescape(b):
    out, i = bytearray(), 0
    while i < len(b):
        if b[i] == 0x7D and i + 1 < len(b):
            out.append(0x7E if b[i + 1] == 2 else 0x7D)
            i += 2
        else:
            out.append(b[i])
            i += 1
    return bytes(out)


def escape(b):
    return b.replace(b"\x7d", b"\x7d\x01").replace(b"\x7e", b"\x7d\x02")


def xor(b):
    c = 0
    for x in b:
        c ^= x
    return c


def send(conn, mid, phone, body):
    global seq
    seq = (seq + 1) & 0xFFFF
    msg = mid.to_bytes(2, "big") + len(body).to_bytes(2, "big") + phone + seq.to_bytes(2, "big") + body
    conn.sendall(b"\x7e" + escape(msg + bytes([xor(msg)])) + b"\x7e")


def parse_pos(b):
    """Decode a 0x0200 body. Returns (lat, lon, speed, course, utc_iso) or None."""
    if len(b) < 28:
        return None
    status = int.from_bytes(b[4:8], "big")
    if not status & 2:  # no GPS fix
        return None
    lat = int.from_bytes(b[8:12], "big") / 1e6
    lon = int.from_bytes(b[12:16], "big") / 1e6
    if status & 4:
        lat = -lat
    if status & 8:
        lon = -lon
    if lat == 0 and lon == 0:
        return None
    speed = int.from_bytes(b[18:20], "big") / 10
    course = int.from_bytes(b[20:22], "big")
    t = datetime.strptime(b[22:28].hex(), "%y%m%d%H%M%S").replace(tzinfo=timezone(timedelta(hours=OFFSET)))
    return lat, lon, speed, course, t.astimezone(timezone.utc).isoformat(timespec="seconds")


def store(dev, p):
    with lock:
        db.execute("INSERT OR IGNORE INTO positions VALUES (?,?,?,?,?,?)", (dev, p[4], p[0], p[1], p[2], p[3]))
        db.commit()


def handle(conn, addr):
    print("connected", addr, flush=True)
    conn.settimeout(300)
    buf = b""
    try:
        while True:
            d = conn.recv(4096)
            if not d:
                break
            buf += d
            while True:
                s = buf.find(b"\x7e")
                if s < 0:
                    buf = b""
                    break
                e = buf.find(b"\x7e", s + 1)
                if e < 0:
                    buf = buf[s:]
                    break
                if e == s + 1:
                    buf = buf[e:]
                    continue
                f = unescape(buf[s + 1:e])
                buf = buf[e + 1:]
                if len(f) < 13:
                    continue
                mid, phone, serial, body = int.from_bytes(f[0:2], "big"), f[4:10], f[10:12], f[12:-1]
                dev = phone.hex()
                last_seen[dev] = time.time()
                if mid == 0x0100:  # registration -> hand out an auth code
                    send(conn, 0x8100, phone, serial + b"\x00" + dev.lstrip("0").encode())
                else:  # everything else: general "OK"
                    send(conn, 0x8001, phone, serial + f[0:2] + b"\x00")
                if mid == 0x0200:
                    p = parse_pos(body)
                    if p:
                        store(dev, p)
                elif mid == 0x0704 and len(body) >= 3:  # batch of buffered positions
                    n, i = int.from_bytes(body[0:2], "big"), 3
                    for _ in range(n):
                        if i + 2 > len(body):
                            break
                        ln = int.from_bytes(body[i:i + 2], "big")
                        p = parse_pos(body[i + 2:i + 2 + ln])
                        if p:
                            store(dev, p)
                        i += 2 + ln
    except Exception as ex:
        print("error:", addr, ex, flush=True)
    finally:
        conn.close()
        print("disconnected", addr, flush=True)


def tcp_loop():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", TCP_PORT))
    srv.listen(50)
    print("tracker port", TCP_PORT, flush=True)
    while True:
        c, a = srv.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()


# ---- HTTP API + dashboard --------------------------------------------------
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def authed(self):
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                pw = base64.b64decode(h[6:]).decode().partition(":")[2]
                return hmac.compare_digest(pw, PASSWORD)
            except Exception:
                return False
        return False

    def reply(self, code, ctype, data):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self.authed():
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Fleet"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/api/devices":
            with lock:
                rows = db.execute("SELECT device, MAX(ts), lat, lon, speed, course FROM positions GROUP BY device").fetchall()
            now = time.time()
            out = [{"id": r[0], "ts": r[1], "lat": r[2], "lon": r[3], "speed": r[4], "course": r[5],
                    "online": now - last_seen.get(r[0], 0) < 120} for r in rows]
            self.reply(200, "application/json", json.dumps(out).encode())
        elif u.path == "/api/track":
            dev = q.get("device", [""])[0]
            hours = min(float(q.get("hours", ["24"])[0]), 24 * 31)
            since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
            with lock:
                rows = db.execute("SELECT ts, lat, lon, speed FROM positions WHERE device=? AND ts>=? ORDER BY ts",
                                  (dev, since)).fetchall()
            self.reply(200, "application/json", json.dumps(rows).encode())
        elif u.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as fh:
                self.reply(200, "text/html; charset=utf-8", fh.read())
        else:
            self.reply(404, "text/plain", b"not found")


if __name__ == "__main__":
    threading.Thread(target=tcp_loop, daemon=True).start()
    print("dashboard port", HTTP_PORT, flush=True)
    ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), H).serve_forever()
