"""
AEGIS Firewall — FastAPI Backend
Real data: AbuseIPDB + Gemini AI + Supabase
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
import asyncio
import httpx
import os
import json
import socket
from datetime import datetime
from supabase import create_client, Client
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

# ── Init ──────────────────────────────────────────
app = FastAPI(title="AEGIS Firewall API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Supabase
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Gemini
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
gemini = genai.GenerativeModel("gemini-1.5-flash")

# AbuseIPDB key
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")

# ── WebSocket Manager ─────────────────────────────
class WSManager:
    def __init__(self):
        self.connections: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

ws_manager = WSManager()

# ── IP Cache (saves AbuseIPDB quota) ─────────────
ip_cache: Dict[str, int] = {}

PRIVATE_PREFIXES = ("192.168.", "10.", "172.16.", "172.17.",
                    "172.18.", "172.19.", "172.20.", "172.21.",
                    "172.22.", "172.23.", "172.24.", "172.25.",
                    "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "127.", "::1", "0.0.0.0")

def is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)

async def check_abuse(ip: str) -> int:
    """Hit AbuseIPDB — returns real abuse confidence score 0-100"""
    if not ip or is_private(ip):
        return 0
    if ip in ip_cache:
        return ip_cache[ip]
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            )
            score = r.json()["data"]["abuseConfidenceScore"]
            ip_cache[ip] = score
            return score
    except Exception:
        return 0

async def gemini_analyze(endpoint_name: str, process: str, conns: list) -> str:
    """Ask Gemini to analyse real connection pattern"""
    summary = "\n".join(
        f"  → {c['remote_ip']}:{c['remote_port']}  "
        f"host={c.get('remote_host','-')}  "
        f"abuse={c.get('abuse_score',0)}/100"
        for c in conns[:8]
    )
    prompt = f"""You are a cybersecurity SOC analyst reviewing live endpoint telemetry.

Endpoint : {endpoint_name}
Process  : {process}
Live connections captured right now:
{summary}

Give a 2-sentence professional threat assessment:
1. Is this behaviour normal or suspicious?
2. What specific action should the security team take?

Be precise, technical, and direct. No fluff."""
    try:
        resp = gemini.generate_content(prompt)
        return resp.text.strip()
    except Exception as e:
        return f"Gemini analysis unavailable: {e}"

# ── Pydantic Models ───────────────────────────────
class EndpointIn(BaseModel):
    name: str
    hostname: str
    ip_address: str
    os_info: str
    agent_version: str = "1.0"

class ConnEntry(BaseModel):
    process_name: str
    process_pid: Optional[int] = None
    process_path: Optional[str] = ""
    local_ip: Optional[str] = ""
    local_port: Optional[int] = None
    remote_ip: str
    remote_port: Optional[int] = None
    remote_host: Optional[str] = ""
    protocol: Optional[str] = "TCP"
    conn_status: Optional[str] = "ESTABLISHED"

class BatchIn(BaseModel):
    endpoint_id: str
    connections: List[ConnEntry]

class RuleIn(BaseModel):
    endpoint_id: Optional[str] = None
    process_name: Optional[str] = None
    remote_ip: Optional[str] = None
    remote_host: Optional[str] = None
    action: str   # 'block' | 'allow'
    reason: Optional[str] = None


def get_effective_rules(endpoint_id: str) -> dict:
    """
    Resolve the effective policy for one endpoint.
    Endpoint-specific rules override global reach, and allow rules take precedence.
    """
    rules_raw = supabase.table("rules").select("*").execute().data
    scoped_rules = [
        r for r in rules_raw
        if r.get("endpoint_id") is None or r.get("endpoint_id") == endpoint_id
    ]

    allow_ips = {
        r["remote_ip"]
        for r in scoped_rules
        if r["action"] == "allow" and r.get("remote_ip")
    }
    allow_processes = {
        r["process_name"]
        for r in scoped_rules
        if r["action"] == "allow" and r.get("process_name")
    }
    block_ips = {
        r["remote_ip"]
        for r in scoped_rules
        if r["action"] == "block" and r.get("remote_ip")
        and r["remote_ip"] not in allow_ips
    }
    block_processes = {
        r["process_name"]
        for r in scoped_rules
        if r["action"] == "block" and r.get("process_name")
        and r["process_name"] not in allow_processes
    }

    return {
        "block_ips": sorted(block_ips),
        "block_processes": sorted(block_processes),
        "allow_ips": sorted(allow_ips),
        "allow_processes": sorted(allow_processes),
    }

# ── Routes ────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "AEGIS online", "version": "1.0"}

# ── Endpoint Management ──
@app.post("/api/endpoint/register")
async def register_endpoint(data: EndpointIn):
    """Agent calls this on startup to register the machine"""
    existing = supabase.table("endpoints").select("id").eq(
        "hostname", data.hostname
    ).execute().data

    if existing:
        eid = existing[0]["id"]
        supabase.table("endpoints").update({
            "ip_address": data.ip_address,
            "os_info": data.os_info,
            "status": "online",
            "last_seen": datetime.utcnow().isoformat(),
        }).eq("id", eid).execute()
    else:
        row = supabase.table("endpoints").insert({
            "name": data.name,
            "hostname": data.hostname,
            "ip_address": data.ip_address,
            "os_info": data.os_info,
            "agent_version": data.agent_version,
            "status": "online",
            "last_seen": datetime.utcnow().isoformat(),
        }).execute().data[0]
        eid = row["id"]

    endpoint = supabase.table("endpoints").select("*").eq("id", eid).execute().data[0]
    await ws_manager.broadcast({"type": "endpoint_online", "data": endpoint})
    return {"endpoint_id": eid}

@app.get("/api/endpoints")
def get_endpoints():
    return supabase.table("endpoints").select("*").order(
        "last_seen", desc=True
    ).execute().data

@app.post("/api/endpoint/{eid}/offline")
async def mark_offline(eid: str):
    supabase.table("endpoints").update({"status": "offline"}).eq("id", eid).execute()
    await ws_manager.broadcast({"type": "endpoint_offline", "endpoint_id": eid})
    return {"ok": True}


@app.get("/api/endpoint/{endpoint_id}/policy")
def get_endpoint_policy(endpoint_id: str):
    return get_effective_rules(endpoint_id)

# ── Connection Ingestion ──
@app.post("/api/connections/batch")
async def ingest_connections(data: BatchIn):
    """
    Agent POSTs real connections every 5 seconds.
    We check each IP against AbuseIPDB, apply rules,
    store in Supabase, and push to dashboard via WebSocket.
    """
    if not data.connections:
        return {"received": 0, "blocked": [], "flagged": []}

    policy = get_effective_rules(data.endpoint_id)
    block_ips = set(policy["block_ips"])
    block_processes = set(policy["block_processes"])
    allow_ips = set(policy["allow_ips"])
    allow_processes = set(policy["allow_processes"])

    # Fetch endpoint name for Gemini prompts
    ep = supabase.table("endpoints").select("name").eq(
        "id", data.endpoint_id
    ).execute().data
    endpoint_name = ep[0]["name"] if ep else "Unknown"

    processed = []
    new_alerts = []
    flagged_ips = []
    blocked_ips = []

    # Check each connection
    abuse_tasks = [check_abuse(c.remote_ip) for c in data.connections]
    abuse_scores = await asyncio.gather(*abuse_tasks)

    for conn, score in zip(data.connections, abuse_scores):
        is_blocked = (
            (conn.remote_ip in block_ips and conn.remote_ip not in allow_ips) or
            (conn.process_name in block_processes and conn.process_name not in allow_processes)
        )
        is_flagged = score > 25 or is_blocked

        row = {
            "endpoint_id": data.endpoint_id,
            "process_name": conn.process_name,
            "process_pid": conn.process_pid,
            "process_path": conn.process_path,
            "local_ip": conn.local_ip,
            "local_port": conn.local_port,
            "remote_ip": conn.remote_ip,
            "remote_port": conn.remote_port,
            "remote_host": conn.remote_host or conn.remote_ip,
            "protocol": conn.protocol,
            "conn_status": conn.conn_status,
            "abuse_score": score,
            "is_flagged": is_flagged,
            "is_blocked": is_blocked,
            "created_at": datetime.utcnow().isoformat(),
        }
        processed.append(row)

        if is_flagged:
            flagged_ips.append(conn.remote_ip)
        if is_blocked:
            blocked_ips.append(conn.remote_ip)

        # Generate alert for suspicious IPs
        if score > 50 and not is_blocked:
            severity = "critical" if score > 80 else "high"
            new_alerts.append({
                "endpoint_id": data.endpoint_id,
                "process_name": conn.process_name,
                "remote_ip": conn.remote_ip,
                "alert_type": "suspicious_ip",
                "severity": severity,
                "description": (
                    f"[{conn.process_name}] connecting to {conn.remote_ip} "
                    f"(port {conn.remote_port}) — AbuseIPDB score: {score}/100"
                ),
            })

    # Batch insert connections
    supabase.table("connections").insert(processed).execute()

    # Process alerts with Gemini analysis
    for alert in new_alerts:
        # Get connections for this process to give Gemini context
        proc_conns = [p for p in processed if p["process_name"] == alert["process_name"]]
        alert["gemini_analysis"] = await gemini_analyze(
            endpoint_name, alert["process_name"], proc_conns
        )
        supabase.table("alerts").insert(alert).execute()

    # Update endpoint heartbeat
    supabase.table("endpoints").update({
        "last_seen": datetime.utcnow().isoformat(),
        "status": "online",
    }).eq("id", data.endpoint_id).execute()

    # Push live update to all dashboard viewers
    await ws_manager.broadcast({
        "type": "connections",
        "endpoint_id": data.endpoint_id,
        "endpoint_name": endpoint_name,
        "data": processed,
        "alerts": new_alerts,
        "stats": {
            "total": len(processed),
            "flagged": len(flagged_ips),
            "blocked": len(blocked_ips),
        },
    })

    return {
        "received": len(processed),
        "blocked": list(set(blocked_ips)),
        "flagged": list(set(flagged_ips)),
    }

# ── Connections Query ──
@app.get("/api/connections/{endpoint_id}")
def get_connections(endpoint_id: str, limit: int = 200):
    return supabase.table("connections").select("*").eq(
        "endpoint_id", endpoint_id
    ).order("created_at", desc=True).limit(limit).execute().data

@app.get("/api/connections/{endpoint_id}/flagged")
def get_flagged(endpoint_id: str):
    return supabase.table("connections").select("*").eq(
        "endpoint_id", endpoint_id
    ).eq("is_flagged", True).order("created_at", desc=True).limit(100).execute().data

# ── Rules ──
@app.get("/api/rules")
def get_rules():
    return supabase.table("rules").select(
        "*, endpoints(name)"
    ).order("created_at", desc=True).execute().data

@app.post("/api/rules")
async def create_rule(rule: RuleIn):
    inserted = supabase.table("rules").insert(rule.model_dump()).execute().data[0]
    row = supabase.table("rules").select(
        "*, endpoints(name)"
    ).eq("id", inserted["id"]).execute().data[0]
    await ws_manager.broadcast({"type": "rule_added", "data": row})
    return row

@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: str):
    supabase.table("rules").delete().eq("id", rule_id).execute()
    await ws_manager.broadcast({"type": "rule_deleted", "rule_id": rule_id})
    return {"deleted": True}

# ── Alerts ──
@app.get("/api/alerts")
def get_alerts(resolved: bool = False):
    return supabase.table("alerts").select(
        "*, endpoints(name)"
    ).eq("is_resolved", resolved).order(
        "created_at", desc=True
    ).limit(100).execute().data

@app.patch("/api/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str):
    supabase.table("alerts").update({"is_resolved": True}).eq(
        "id", alert_id
    ).execute()
    await ws_manager.broadcast({"type": "alert_resolved", "alert_id": alert_id})
    return {"resolved": True}

# ── Stats ──
@app.get("/api/stats")
def get_stats():
    endpoints   = supabase.table("endpoints").select("id,status").execute().data
    total_conns = supabase.table("connections").select("id", count="exact").execute()
    flagged     = supabase.table("connections").select("id", count="exact").eq(
        "is_flagged", True
    ).execute()
    alerts      = supabase.table("alerts").select("id", count="exact").eq(
        "is_resolved", False
    ).execute()
    return {
        "total_endpoints": len(endpoints),
        "online_endpoints": sum(1 for e in endpoints if e["status"] == "online"),
        "total_connections": total_conns.count or 0,
        "flagged_connections": flagged.count or 0,
        "open_alerts": alerts.count or 0,
    }

# ── WebSocket ──
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            # Keep alive ping
            await asyncio.sleep(30)
            await ws.send_json({"type": "ping"})
    except (WebSocketDisconnect, Exception):
        ws_manager.disconnect(ws)
