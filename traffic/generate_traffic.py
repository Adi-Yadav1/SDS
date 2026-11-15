"""Safe local traffic generator (lab use only). Loopback / RFC1918 private targets only.

server: TCP echo-sink that discards data.   client: sends TCP data to the server.
  normal = small messages at ~10/s      burst = tight loop of larger messages (a high-rate
  *load pattern* for telemetry demos; bounded by --duration; not an exploit or flood tool).
"""
import argparse
import ipaddress
import socket
import sys
import time


def check_target(host):
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    if not (ip.is_private or ip.is_loopback):
        sys.exit(f"Refusing non-private target {ip}: this tool is for local labs only.")


def server(port, duration):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(5); s.settimeout(1)
    end = time.time() + duration
    while time.time() < end:
        try:
            c, _ = s.accept()
        except socket.timeout:
            continue
        c.settimeout(2)
        try:
            while c.recv(65536):
                pass
        except OSError:
            pass
        c.close()


def client(target, port, mode, duration):
    check_target(target)
    size, delay = (200, 0.1) if mode == "normal" else (1400, 0.0005)
    payload = b"x" * size
    sent = msgs = 0
    s = socket.create_connection((target, port), timeout=5)
    start = time.time(); end = start + duration
    try:
        while time.time() < end:
            s.sendall(payload); sent += size; msgs += 1
            time.sleep(delay)
    except OSError as e:  # e.g. the controller installed a drop rule and the connection stalled
        print(f"[{mode}] connection stalled/blocked after {time.time()-start:.1f}s: {e!r}")
    finally:
        s.close()
    print(f"[{mode}] sent {msgs} messages / {sent} bytes to {target}:{port} (planned {duration}s)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=["server", "client"])
    ap.add_argument("--target", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5001)
    ap.add_argument("--mode", choices=["normal", "burst"], default="normal")
    ap.add_argument("--duration", type=int, default=10)
    a = ap.parse_args()
    server(a.port, a.duration) if a.role == "server" else client(a.target, a.port, a.mode, a.duration)
