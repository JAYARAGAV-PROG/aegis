"""
AEGIS Firewall Agent v1.0
─────────────────────────
Run this on EVERY machine you want to monitor.
Needs: pip install psutil requests
Run as Administrator for firewall blocking to work.

Usage: python agent.py
"""

import psutil
import socket
import requests
import subprocess
import platform
import time
import os
import sys
import json
import logging
from datetime import datetime

# ── CONFIG ────────────────────────────────────────
# Change this to your deployed backend URL
BACKEND_URL = os.getenv("AEGIS_BACKEND", "http://localhost:8000")
SCAN_INTERVAL = 5        # seconds between scans
MAX_RETRY     = 5        # connection retries on startup
AGENT_VERSION = "1.0"

logging.basicConfig(
    level=logging.INFO,
    format="[AEGIS %(asctime)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("aegis")

# ── State ─────────────────────────────────────────
ENDPOINT_ID   = None
blocked_rules = set()   # IPs we've already added firewall rules for

# ── Helpers ───────────────────────────────────────

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def resolve_host(ip: str) -> str:
    """Reverse DNS — gives us human-readable hostname"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def is_private(ip: str) -> bool:
    private = ("192.168.", "10.", "172.16.", "127.", "0.0.0.0", "::")
    return any(ip.startswith(p) for p in private)

# ── Registration ──────────────────────────────────

def register(retries: int = MAX_RETRY) -> bool:
    """Register this machine with the central AEGIS server"""
    global ENDPOINT_ID
    payload = {
        "name":          "RAHUL-LAPTOP",
        "hostname":      "RAHUL-LAPTOP",
        "ip_address":    "192.168.1.108",
        "os_info":       "Windows 11 x86_64",
        "agent_version": AGENT_VERSION,
    }
    for attempt in range(1, retries + 1):
        try:
            r = requests.post(
                f"{BACKEND_URL}/api/endpoint/register",
                json=payload, timeout=10
            )
            r.raise_for_status()
            ENDPOINT_ID = r.json()["endpoint_id"]
            log.info(f"✅  Registered → endpoint_id: {ENDPOINT_ID}")
            return True
        except Exception as e:
            log.warning(f"Registration attempt {attempt}/{retries} failed: {e}")
            time.sleep(3 * attempt)
    return False

# ── Connection Scanning ───────────────────────────

def scan_connections() -> list:
    """
    Use psutil to get REAL established connections on this machine.
    Returns list of dicts with process + network info.
    """
    results = []
    seen    = set()

    try:
        # Get all established TCP connections
        for conn in psutil.net_connections(kind="inet"):
            if conn.status not in ("ESTABLISHED", "SYN_SENT"):
                continue
            if not conn.raddr:
                continue

            remote_ip   = conn.raddr.ip
            remote_port = conn.raddr.port

            # Deduplicate pid+remote
            key = (conn.pid, remote_ip, remote_port)
            if key in seen:
                continue
            seen.add(key)

            # Get process name and path
            proc_name = "Unknown"
            proc_path = ""
            try:
                if conn.pid:
                    p = psutil.Process(conn.pid)
                    proc_name = p.name()
                    try:
                        proc_path = p.exe()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            results.append({
                "process_name": proc_name,
                "process_pid":  conn.pid,
                "process_path": proc_path,
                "local_ip":     conn.laddr.ip  if conn.laddr else "",
                "local_port":   conn.laddr.port if conn.laddr else None,
                "remote_ip":    remote_ip,
                "remote_port":  remote_port,
                "remote_host":  resolve_host(remote_ip) if not is_private(remote_ip) else "",
                "protocol":     "TCP",
                "conn_status":  conn.status,
            })

    except psutil.AccessDenied:
        log.warning("⚠️  Access denied on some connections — run as Administrator for full visibility")
    except Exception as e:
        log.error(f"Scan error: {e}")

    return results

# ── Windows Firewall Integration ──────────────────

def block_ip(ip: str) -> bool:
    """
    Add a REAL Windows Firewall outbound block rule.
    Requires running as Administrator.
    """
    if ip in blocked_rules or is_private(ip):
        return False

    rule_name = f"AEGIS_BLOCK_{ip}"
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}",
             "dir=out",
             "action=block",
             f"remoteip={ip}",
             "protocol=any",
             "enable=yes"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            blocked_rules.add(ip)
            log.warning(f"🚫  BLOCKED {ip} via Windows Firewall")
            return True
        else:
            log.error(f"Firewall block failed for {ip}: {result.stderr}")
            return False
    except Exception as e:
        log.error(f"Could not block {ip}: {e}")
        return False

def unblock_ip(ip: str) -> bool:
    """Remove an AEGIS block rule"""
    rule_name = f"AEGIS_BLOCK_{ip}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={rule_name}"],
            capture_output=True, text=True, timeout=10
        )
        blocked_rules.discard(ip)
        log.info(f"✅  UNBLOCKED {ip}")
        return True
    except Exception as e:
        log.error(f"Could not unblock {ip}: {e}")
        return False

def cleanup_rules():
    """Remove all AEGIS firewall rules on shutdown"""
    log.info("Cleaning up AEGIS firewall rules...")
    for ip in list(blocked_rules):
        unblock_ip(ip)

# ── Send to Backend ───────────────────────────────

def fetch_policy() -> dict:
    """Fetch the effective firewall policy for this endpoint."""
    if not ENDPOINT_ID:
        return None

    try:
        r = requests.get(
            f"{BACKEND_URL}/api/endpoint/{ENDPOINT_ID}/policy",
            timeout=10
        )
        r.raise_for_status()
        return r.json()
    except requests.ConnectionError:
        log.warning("Policy sync failed: backend unreachable")
        return None
    except Exception as e:
        log.error(f"Policy sync failed: {e}")
        return None


def sync_firewall_policy():
    """
    Reconcile Windows Firewall with central console rules.
    Manual blocks from the dashboard should apply even if the
    connection has already disappeared from the next telemetry batch.
    """
    policy = fetch_policy()
    if policy is None:
        return

    desired = {
        ip for ip in policy.get("block_ips", [])
        if ip and not is_private(ip)
    }

    if not desired and not blocked_rules:
        return

    for ip in sorted(desired - blocked_rules):
        block_ip(ip)
    for ip in sorted(blocked_rules - desired):
        unblock_ip(ip)


def send_batch(connections: list) -> dict:
    """
    POST real connections to AEGIS backend.
    Response tells us which IPs to block.
    """
    if not ENDPOINT_ID or not connections:
        return {}

    try:
        r = requests.post(
            f"{BACKEND_URL}/api/connections/batch",
            json={"endpoint_id": ENDPOINT_ID, "connections": connections},
            timeout=15
        )
        r.raise_for_status()
        return r.json()
    except requests.ConnectionError:
        log.warning("Backend unreachable — will retry next cycle")
        return {}
    except Exception as e:
        log.error(f"Send failed: {e}")
        return {}

# ── Main Loop ─────────────────────────────────────

def main():
    log.info("=" * 50)
    log.info("  AEGIS Firewall Agent v1.0")
    log.info(f"  Host    : {socket.gethostname()}")
    log.info(f"  OS      : {platform.system()} {platform.release()}")
    log.info(f"  Backend : {BACKEND_URL}")
    log.info("=" * 50)

    # Check admin rights (needed for full firewall control)
    if platform.system() == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            log.warning("⚠️  Not running as Administrator.")
            log.warning("   Monitoring works but firewall BLOCKING requires Admin.")

    # Register with central server
    if not register():
        log.error("❌  Could not register with AEGIS server. Exiting.")
        sys.exit(1)

    log.info(f"👁️  Monitoring started — scanning every {SCAN_INTERVAL}s")
    sync_firewall_policy()
    log.info("   Dashboard: open your AEGIS web console to see live data")

    cycle = 0
    try:
        while True:
            cycle += 1
            sync_firewall_policy()
            connections = scan_connections()

            log.info(f"[Cycle {cycle}] Found {len(connections)} active connections")

            if connections:
                result = send_batch(connections)

                flagged = result.get("flagged", [])
                if flagged:
                    log.warning(f"  ⚠️  Flagged IPs this cycle: {list(set(flagged))}")

            time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:
        log.info("\nShutting down AEGIS agent...")
        cleanup_rules()
        # Notify server we're going offline
        try:
            requests.post(
                f"{BACKEND_URL}/api/endpoint/{ENDPOINT_ID}/offline",
                timeout=5
            )
        except Exception:
            pass
        log.info("Agent stopped cleanly.")

if __name__ == "__main__":
    main()
