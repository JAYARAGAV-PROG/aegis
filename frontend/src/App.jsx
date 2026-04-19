import { useState, useEffect, useRef, useCallback } from "react"
import "./index.css"

const API    = import.meta.env.VITE_API_URL || ""
const WS_URL = (import.meta.env.VITE_WS_URL || "ws://localhost:8000") + "/ws"

// ── API helpers ────────────────────────────────────
const http = {
  get:    path       => fetch(API + path).then(r => r.json()),
  post:   (path, b)  => fetch(API + path, { method:"POST",   headers:{"Content-Type":"application/json"}, body:JSON.stringify(b) }).then(r => r.json()),
  del:    path       => fetch(API + path, { method:"DELETE" }).then(r => r.json()),
  patch:  path       => fetch(API + path, { method:"PATCH"  }).then(r => r.json()),
}

// ── Helpers ────────────────────────────────────────
function timeAgo(ts) {
  if (!ts) return "—"
  const d = new Date(ts)
  if (isNaN(d.getTime())) return "—"
  const s = (Date.now() - d.getTime()) / 1000
  if (s < 5)     return "just now"
  if (s < 60)    return `${Math.floor(s)}s ago`
  if (s < 3600)  return `${Math.floor(s/60)}m ago`
  if (s < 86400) return `${Math.floor(s/3600)}h ago`
  return `${Math.floor(s/86400)}d ago`
}

function isPrivate(ip) {
  if (!ip) return true
  return (
    ip.startsWith("192.168.") || ip.startsWith("10.") ||
    ip.startsWith("172.")     || ip.startsWith("127.") ||
    ip === "::1"              || ip === "0.0.0.0"      ||
    ip.startsWith("fe80:")
  )
}

function getScoreClass(n) {
  if (!n || n === 0) return "s0"
  if (n < 25) return "slo"
  if (n < 60) return "smd"
  return "shi"
}

// ── Toast ──────────────────────────────────────────
function Toast({ toast }) {
  if (!toast) return null
  return (
    <div className={`toast ${toast.type}`}>
      <span>{toast.msg}</span>
    </div>
  )
}

// ── Stat Box ───────────────────────────────────────
function StatBox({ label, value, color, sub }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${color}`}>{value ?? 0}</div>
      {sub && <div style={{ fontSize: 9, color: "var(--text-3)", marginTop: 4 }}>{sub}</div>}
    </div>
  )
}

// ── Endpoint Card ──────────────────────────────────
function EndpointCard({ ep, selected, onSelect }) {
  return (
    <div
      className={`endpoint-row ${selected?.id === ep.id ? "selected" : ""}`}
      onClick={() => onSelect(ep)}
    >
      <div className={`pulse ${ep.status !== "online" ? "offline" : ""}`} />
      <div className="ep-info">
        <div className="ep-name">{ep.name}</div>
        <div className="ep-meta">{ep.ip_address} · {ep.os_info}</div>
      </div>
      <span className={`badge badge-${ep.status === "online" ? "online" : "offline"}`}>
        {ep.status}
      </span>
      <span style={{ color:"var(--text-3)", fontSize:10, marginLeft:8, whiteSpace:"nowrap" }}>
        {timeAgo(ep.last_seen)}
      </span>
    </div>
  )
}

// ── Score Cell ─────────────────────────────────────
function ScoreCell({ ip, score }) {
  if (isPrivate(ip)) return <span style={{ color:"var(--text-3)", fontSize:10 }}>local</span>
  const cls = getScoreClass(score)
  const pct  = Math.min(score ?? 0, 100)
  return (
    <div className="score-wrap">
      <div className="score-bar">
        <div className={`score-fill ${cls}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`score-val ${cls}`}>{score ?? 0}</span>
    </div>
  )
}

// ── Connections Table ──────────────────────────────
function ConnectionsTable({ connections, localBlocked, onBlock }) {
  if (!connections.length) return (
    <div className="empty">
      No connections yet.<br/>
      Waiting for agent data…
    </div>
  )

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Process</th>
            <th>PID</th>
            <th>Remote IP</th>
            <th>Host</th>
            <th>Port</th>
            <th>Proto</th>
            <th>Abuse Score</th>
            <th>Status</th>
            <th>Seen</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {connections.map((c, i) => {
            const blocked = c.is_blocked || localBlocked.has(c.remote_ip)
            const cls = blocked ? "blocked" : c.is_flagged ? "flagged" : ""
            return (
              <tr key={c.id || i} className={cls}>
                <td><span className="proc">{c.process_name}</span></td>
                <td style={{ color:"var(--text-3)" }}>{c.process_pid}</td>
                <td>
                  <span className={`ip ${isPrivate(c.remote_ip) ? "private" : ""}`}>
                    {c.remote_ip}
                  </span>
                </td>
                <td className="host-cell">{c.remote_host || "—"}</td>
                <td><span className="port-badge">{c.remote_port}</span></td>
                <td style={{ color:"var(--text-3)", fontSize:10 }}>{c.protocol || "TCP"}</td>
                <td><ScoreCell ip={c.remote_ip} score={c.abuse_score} /></td>
                <td>
                  {blocked ? (
                    <span className="badge badge-blocked">🚫 blocked</span>
                  ) : c.is_flagged ? (
                    <span className="badge badge-flagged">⚠ flagged</span>
                  ) : (
                    <span className="badge badge-ok">ok</span>
                  )}
                </td>
                <td style={{ color:"var(--text-3)", fontSize:10 }}>{timeAgo(c.created_at)}</td>
                <td>
                  {!blocked && !isPrivate(c.remote_ip) ? (
                    <button
                      className="btn btn-block-ip"
                      onClick={() => onBlock(c)}
                    >
                      block
                    </button>
                  ) : blocked ? (
                    <span style={{ color:"var(--red)", fontSize:10 }}>✓ blocked</span>
                  ) : null}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ── Alerts Panel ───────────────────────────────────
function AlertsPanel({ alerts, onResolve }) {
  if (!alerts.length) return (
    <div className="empty">
      ✓ No open alerts<br/>
      <span style={{ fontSize:10 }}>Alerts appear when suspicious IPs are detected (AbuseIPDB score &gt; 30)</span>
    </div>
  )
  return (
    <div>
      {alerts.map(a => (
        <div key={a.id} className={`alert-item ${a.severity || "medium"} fade-in`}>
          <div className="alert-head">
            <span className={`badge badge-${a.severity || "medium"}`}>
              {a.severity || "medium"}
            </span>
            <span className="proc">{a.process_name}</span>
            <span className="ip">{a.remote_ip}</span>
            {a.endpoints?.name && (
              <span style={{ color:"var(--text-3)", fontSize:10 }}>@ {a.endpoints.name}</span>
            )}
            <span className="alert-time">{timeAgo(a.created_at)}</span>
          </div>
          <div className="alert-desc">{a.description}</div>
          {a.gemini_analysis && (
            <div className="alert-ai">
              <span className="ai-tag">✦ Gemini AI Analysis</span>
              {a.gemini_analysis}
            </div>
          )}
          <button className="btn btn-resolve" onClick={() => onResolve(a.id)}>
            ✓ mark resolved
          </button>
        </div>
      ))}
    </div>
  )
}

// ── Rules Panel ────────────────────────────────────
function RulesPanel({ rules, onAdd, onDelete }) {
  const [form, setForm] = useState({
    process_name: "", remote_ip: "", action: "block", reason: ""
  })
  const [adding, setAdding] = useState(false)

  function set(k, v) { setForm(f => ({ ...f, [k]: v })) }

  async function submit() {
    if (!form.remote_ip && !form.process_name) return
    setAdding(true)
    await onAdd({ ...form })
    setForm({ process_name:"", remote_ip:"", action:"block", reason:"" })
    setAdding(false)
  }

  return (
    <div>
      {/* Add Rule Form */}
      <div style={{ marginBottom:16 }}>
        <div className="card-title" style={{ marginBottom:12 }}>
          <div className="dot-accent" /> Add Firewall Rule
        </div>
        <div className="form-row">
          <div className="field">
            <label>Process Name</label>
            <input className="input" placeholder="chrome.exe (optional)"
              value={form.process_name} onChange={e => set("process_name", e.target.value)} />
          </div>
          <div className="field">
            <label>Remote IP</label>
            <input className="input" placeholder="185.220.101.45"
              value={form.remote_ip} onChange={e => set("remote_ip", e.target.value)} />
          </div>
          <div className="field">
            <label>Reason</label>
            <input className="input" placeholder="Malicious C2 server"
              value={form.reason} onChange={e => set("reason", e.target.value)} />
          </div>
          <div className="field">
            <label>Action</label>
            <select className="select" value={form.action} onChange={e => set("action", e.target.value)}>
              <option value="block">block</option>
              <option value="allow">allow</option>
            </select>
          </div>
          <div style={{ display:"flex", alignItems:"flex-end" }}>
            <button className="btn btn-primary" onClick={submit} disabled={adding}>
              {adding ? "adding…" : "+ Add Rule"}
            </button>
          </div>
        </div>
      </div>

      {/* Rules Table */}
      {rules.length === 0 ? (
        <div className="empty">
          No rules yet.<br/>
          Add a rule above to block an app or IP across all endpoints.
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Action</th>
                <th>Process</th>
                <th>Remote IP</th>
                <th>Reason</th>
                <th>Scope</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rules.map(r => (
                <tr key={r.id}>
                  <td>
                    <span className={`badge badge-${r.action === "block" ? "blocked" : "online"}`}>
                      {r.action}
                    </span>
                  </td>
                  <td><span className="proc">{r.process_name || "*"}</span></td>
                  <td><span className="ip">{r.remote_ip || "*"}</span></td>
                  <td style={{ color:"var(--text-2)", fontSize:11 }}>{r.reason || "—"}</td>
                  <td style={{ color:"var(--text-3)", fontSize:10 }}>
                    {r.endpoints?.name || "global"}
                  </td>
                  <td style={{ color:"var(--text-3)", fontSize:10 }}>{timeAgo(r.created_at)}</td>
                  <td>
                    <button className="btn btn-remove" onClick={() => onDelete(r.id)}>remove</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="ticker" style={{ marginTop:12 }}>
        <div className="ticker-dot" />
        <span>
          Rules sync to all agents every 5s · Block rules add real Windows Firewall rules via netsh ·
          Global rules apply to all {rules.filter(r => !r.endpoint_id).length} endpoints
        </span>
      </div>
    </div>
  )
}

// ── Dashboard Tab ──────────────────────────────────
function Dashboard({ stats, endpoints, alerts, rules, onSelect, onResolve }) {
  return (
    <div>
      {/* Stats */}
      <div className="stat-row">
        <StatBox label="Endpoints" value={stats.total_endpoints} color="cyan" />
        <StatBox label="Online"    value={stats.online_endpoints} color="green" sub="agents active" />
        <StatBox label="Connections" value={(stats.total_connections||0).toLocaleString()} color="white" />
        <StatBox label="Flagged"   value={stats.flagged_connections} color="amber" />
        <StatBox label="Alerts"    value={stats.open_alerts} color="red" sub="open" />
        <StatBox label="Block Rules" value={stats.active_rules} color="purple" />
      </div>

      <div className="grid-2">
        {/* Endpoints */}
        <div className="card">
          <div className="card-header">
            <div className="card-title"><div className="dot-accent" /> Monitored Endpoints</div>
          </div>
          {endpoints.length === 0 ? (
            <div className="empty">No agents connected.<br/>Run agent.py on each machine to start.</div>
          ) : (
            <div className="endpoint-list">
              {endpoints.map(ep => (
                <EndpointCard
                  key={ep.id} ep={ep} selected={null}
                  onSelect={ep => onSelect(ep)}
                />
              ))}
            </div>
          )}
        </div>

        {/* Recent Alerts */}
        <div className="card">
          <div className="card-header">
            <div className="card-title"><div className="dot-accent" /> Recent Alerts</div>
            {alerts.length > 0 && (
              <span className="badge badge-critical">{alerts.length} open</span>
            )}
          </div>
          <AlertsPanel alerts={alerts.slice(0, 4)} onResolve={onResolve} />
        </div>
      </div>

      {/* Active Rules Summary */}
      <div className="card">
        <div className="card-header">
          <div className="card-title"><div className="dot-accent" /> Active Block Rules</div>
          <span className="count-badge">{rules.filter(r => r.action === "block").length} rules</span>
        </div>
        {rules.filter(r => r.action === "block").length === 0 ? (
          <div className="empty" style={{ padding:"16px 0" }}>
            No active block rules. Go to Rules tab to add.
          </div>
        ) : (
          <div className="rule-chips">
            {rules.filter(r => r.action === "block").map(r => (
              <span key={r.id} className="rule-chip">
                {r.process_name && <span>{r.process_name}</span>}
                {r.process_name && r.remote_ip && <span>→</span>}
                {r.remote_ip && <span>{r.remote_ip}</span>}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Live Ticker */}
      <div className="ticker">
        <div className="ticker-dot" />
        <span>
          WebSocket live · Agents report every 5s · AbuseIPDB real-time threat scoring ·
          Gemini AI analysis on suspicious connections · netsh Windows Firewall enforcement
        </span>
      </div>
    </div>
  )
}

// ── Main App ───────────────────────────────────────
export default function App() {
  const [tab,         setTab]         = useState("dashboard")
  const [endpoints,   setEndpoints]   = useState([])
  const [selected,    setSelected]    = useState(null)
  const [connections, setConnections] = useState([])
  const [alerts,      setAlerts]      = useState([])
  const [rules,       setRules]       = useState([])
  const [stats,       setStats]       = useState({})
  const [wsStatus,    setWsStatus]    = useState("connecting")
  const [liveCount,   setLiveCount]   = useState(0)
  const [toast,       setToast]       = useState(null)
  const [localBlocked,setLocalBlocked]= useState(new Set())
  const ws = useRef(null)

  // ── Toast helper ──
  function showToast(msg, type = "success") {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 4000)
  }

  // ── Load all data ──
  const loadAll = useCallback(async () => {
    try {
      const [ep, al, ru, st] = await Promise.all([
        http.get("/api/endpoints"),
        http.get("/api/alerts"),
        http.get("/api/rules"),
        http.get("/api/stats"),
      ])
      setEndpoints(Array.isArray(ep) ? ep : [])
      setAlerts(Array.isArray(al) ? al : [])
      setRules(Array.isArray(ru) ? ru : [])
      if (st && !st.detail) setStats(st)
      if (!selected && Array.isArray(ep) && ep.length > 0) setSelected(ep[0])
    } catch (e) {
      console.error("Load error:", e)
    }
  }, [])

  const loadConnections = useCallback(async (ep) => {
    if (!ep) return
    try {
      const data = await http.get(`/api/connections/${ep.id}`)
      setConnections(Array.isArray(data) ? data : [])
    } catch (e) {
      console.error("Connections error:", e)
    }
  }, [])

  // ── WebSocket ──
  useEffect(() => {
    function connect() {
      try {
        ws.current = new WebSocket(WS_URL)
        ws.current.onopen = () => setWsStatus("connected")

        ws.current.onmessage = (e) => {
          try {
            const msg = JSON.parse(e.data)
            if (msg.type === "ping") return

            if (msg.type === "connections") {
              setConnections(prev => {
                const merged = [...msg.data, ...prev]
                // Deduplicate by id, keep latest 200
                const seen = new Set()
                return merged.filter(c => {
                  const key = c.id || `${c.process_name}-${c.remote_ip}-${c.remote_port}`
                  if (seen.has(key)) return false
                  seen.add(key)
                  return true
                }).slice(0, 200)
              })
              setLiveCount(n => n + msg.data.length)
              if (msg.alerts?.length) {
                setAlerts(prev => [...msg.alerts, ...prev].slice(0, 100))
                setStats(s => ({ ...s, open_alerts: (s.open_alerts || 0) + msg.alerts.length }))
              }
            }

            if (msg.type === "endpoint_online") {
              setEndpoints(prev => {
                const exists = prev.find(e => e.id === msg.data.id)
                return exists
                  ? prev.map(e => e.id === msg.data.id ? msg.data : e)
                  : [msg.data, ...prev]
              })
            }

            if (msg.type === "endpoint_offline") {
              setEndpoints(prev => prev.map(e =>
                e.id === msg.endpoint_id ? { ...e, status: "offline" } : e
              ))
            }

            if (msg.type === "rule_added") {
              setRules(prev => [msg.data, ...prev])
              setStats(s => ({ ...s, active_rules: (s.active_rules || 0) + 1 }))
            }

            if (msg.type === "rule_deleted") {
              setRules(prev => prev.filter(r => r.id !== msg.rule_id))
              setStats(s => ({ ...s, active_rules: Math.max(0, (s.active_rules || 1) - 1) }))
            }

            if (msg.type === "alert_resolved") {
              setAlerts(prev => prev.filter(a => a.id !== msg.alert_id))
              setStats(s => ({ ...s, open_alerts: Math.max(0, (s.open_alerts || 1) - 1) }))
            }
          } catch (err) {
            console.error("WS parse error:", err)
          }
        }

        ws.current.onclose = () => {
          setWsStatus("reconnecting…")
          setTimeout(connect, 3000)
        }

        ws.current.onerror = () => setWsStatus("error")
      } catch (e) {
        setTimeout(connect, 3000)
      }
    }

    connect()
    loadAll()
    const interval = setInterval(loadAll, 30000)
    return () => {
      clearInterval(interval)
      ws.current?.close()
    }
  }, [loadAll])

  // Reload connections when endpoint changes
  useEffect(() => {
    if (selected) loadConnections(selected)
    const interval = setInterval(() => {
      if (selected) loadConnections(selected)
    }, 6000)
    return () => clearInterval(interval)
  }, [selected, loadConnections])

  // ── Actions ──
  async function blockConnection(conn) {
    try {
      // Instant local visual feedback
      setLocalBlocked(prev => new Set([...prev, conn.remote_ip]))
      setConnections(prev => prev.map(c =>
        c.remote_ip === conn.remote_ip ? { ...c, is_blocked: true } : c
      ))
      await http.post("/api/rules", {
        remote_ip:    conn.remote_ip,
        process_name: conn.process_name,
        action:       "block",
        reason:       `Manual block — abuse score ${conn.abuse_score ?? 0} — via dashboard`,
      })
      showToast(`🚫 Blocked ${conn.remote_ip} (${conn.process_name}) — firewall rule active within 5s`, "success")
    } catch (e) {
      showToast(`❌ Block failed — check backend`, "error")
    }
  }

  async function addRule(ruleData) {
    try {
      await http.post("/api/rules", ruleData)
      showToast(`✓ Rule added — syncing to agents within 5s`, "success")
    } catch (e) {
      showToast(`❌ Failed to add rule`, "error")
    }
  }

  async function deleteRule(id) {
    try {
      await http.del(`/api/rules/${id}`)
      showToast(`✓ Rule removed`, "info")
    } catch (e) {
      showToast(`❌ Failed to remove rule`, "error")
    }
  }

  async function resolveAlert(id) {
    try {
      await http.patch(`/api/alerts/${id}/resolve`)
      showToast("✓ Alert resolved", "info")
    } catch (e) {
      showToast("❌ Failed to resolve alert", "error")
    }
  }

  function selectEndpoint(ep) {
    setSelected(ep)
    setConnections([])
    loadConnections(ep)
    setTab("connections")
  }

  // ── Render ──
  return (
    <div className="layout">
      <Toast toast={toast} />

      {/* Nav */}
      <nav className="nav">
        <div className="nav-logo">AEGIS<span> //</span></div>
        <div className="nav-tabs">
          {["dashboard", "connections", "alerts", "rules"].map(t => (
            <button
              key={t}
              className={`nav-tab ${tab === t ? "active" : ""}`}
              onClick={() => setTab(t)}
            >
              {t}
              {t === "alerts" && alerts.length > 0 && (
                <span style={{ marginLeft:5, color:"var(--red)", fontSize:9 }}>
                  [{alerts.length}]
                </span>
              )}
              {t === "rules" && rules.filter(r => r.action === "block").length > 0 && (
                <span style={{ marginLeft:5, color:"var(--purple)", fontSize:9 }}>
                  [{rules.filter(r => r.action === "block").length}]
                </span>
              )}
            </button>
          ))}
        </div>
        <div className="nav-status">
          <div className={`pulse ${wsStatus !== "connected" ? "offline" : ""}`}
               style={{ width:6, height:6 }} />
          <span style={{ fontSize:10 }}>
            {wsStatus === "connected"
              ? `live · ${liveCount.toLocaleString()} events`
              : wsStatus}
          </span>
        </div>
      </nav>

      {/* Main */}
      <main className="main">

        {/* ── DASHBOARD ── */}
        {tab === "dashboard" && (
          <Dashboard
            stats={stats}
            endpoints={endpoints}
            alerts={alerts}
            rules={rules}
            onSelect={selectEndpoint}
            onResolve={resolveAlert}
          />
        )}

        {/* ── CONNECTIONS ── */}
        {tab === "connections" && (
          <div>
            {/* Endpoint Selector */}
            <div className="card" style={{ marginBottom:16 }}>
              <div className="card-header">
                <div className="card-title"><div className="dot-accent" /> Select Endpoint</div>
                <span className="count-badge">
                  {endpoints.filter(e => e.status === "online").length} online
                </span>
              </div>
              {endpoints.length === 0 ? (
                <div className="empty">No endpoints. Run agent.py on a machine.</div>
              ) : (
                <div className="endpoint-list">
                  {endpoints.map(ep => (
                    <EndpointCard
                      key={ep.id} ep={ep} selected={selected}
                      onSelect={ep => { setSelected(ep); loadConnections(ep) }}
                    />
                  ))}
                </div>
              )}
            </div>

            {/* Connections Table */}
            {selected && (
              <div className="card">
                <div className="card-header">
                  <div className="card-title">
                    <div className="dot-accent" />
                    Live Connections —&nbsp;
                    <span style={{ color:"var(--cyan)" }}>{selected.name}</span>
                    <span className="count-badge">{connections.length}</span>
                  </div>
                  <div style={{ display:"flex", gap:8, alignItems:"center" }}>
                    <span style={{
                      fontSize:9, letterSpacing:1.5, textTransform:"uppercase",
                      color:"var(--green)", border:"1px solid rgba(0,255,136,0.2)",
                      padding:"2px 8px", borderRadius:3
                    }}>✦ AbuseIPDB Scored</span>
                    <button className="btn btn-primary"
                      onClick={() => loadConnections(selected)} style={{ fontSize:10 }}>
                      ↻ refresh
                    </button>
                  </div>
                </div>

                <ConnectionsTable
                  connections={connections}
                  localBlocked={localBlocked}
                  onBlock={blockConnection}
                />

                <div className="ticker">
                  <div className="ticker-dot" />
                  <span>
                    Auto-refreshes every 6s · Click "block" to add Windows Firewall rule instantly ·
                    Red rows = blocked · Amber rows = flagged by AbuseIPDB
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── ALERTS ── */}
        {tab === "alerts" && (
          <div className="card">
            <div className="card-header">
              <div className="card-title">
                <div className="dot-accent" />
                Security Alerts
                <span className="count-badge">{alerts.length} open</span>
              </div>
              <span style={{
                fontSize:9, letterSpacing:1.5, textTransform:"uppercase",
                color:"var(--cyan)", border:"1px solid rgba(0,212,255,0.2)",
                padding:"2px 8px", borderRadius:3
              }}>✦ Gemini AI Analysis</span>
            </div>
            <AlertsPanel alerts={alerts} onResolve={resolveAlert} />
            <div className="ticker">
              <div className="ticker-dot" />
              <span>
                Alerts trigger when AbuseIPDB score &gt; 30 · Gemini AI writes analysis for each ·
                Click "mark resolved" to dismiss
              </span>
            </div>
          </div>
        )}

        {/* ── RULES ── */}
        {tab === "rules" && (
          <div className="card">
            <div className="card-header">
              <div className="card-title">
                <div className="dot-accent" /> Firewall Rules
              </div>
              <span className="count-badge">
                {rules.filter(r => r.action === "block").length} block rules active
              </span>
            </div>
            <RulesPanel rules={rules} onAdd={addRule} onDelete={deleteRule} />
          </div>
        )}

      </main>
    </div>
  )
}
