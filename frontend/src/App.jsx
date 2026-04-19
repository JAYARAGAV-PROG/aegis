import { useState, useEffect, useRef, useCallback } from "react"

const API = import.meta.env.VITE_API_URL || ""
const WS_URL = (import.meta.env.VITE_WS_URL || "ws://localhost:8000") + "/ws"

// ── API Helpers ───────────────────────────────────
const api = {
  get:    (path)       => fetch(API + path).then(r => r.json()),
  post:   (path, body) => fetch(API + path, { method: "POST",   headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(r => r.json()),
  delete: (path)       => fetch(API + path, { method: "DELETE" }).then(r => r.json()),
  patch:  (path)       => fetch(API + path, { method: "PATCH"  }).then(r => r.json()),
}

// ── Score helpers ─────────────────────────────────
function scoreClass(n) {
  if (n === 0)  return "score-0"
  if (n < 25)   return "score-lo"
  if (n < 60)   return "score-md"
  return "score-hi"
}

function scoreColor(n) {
  if (n === 0)  return "var(--text-3)"
  if (n < 25)   return "var(--green)"
  if (n < 60)   return "var(--amber)"
  return "var(--red)"
}

function timeAgo(ts) {
  const diff = (Date.now() - new Date(ts + "Z").getTime()) / 1000
  if (diff < 60)    return `${Math.floor(diff)}s ago`
  if (diff < 3600)  return `${Math.floor(diff/60)}m ago`
  return `${Math.floor(diff/3600)}h ago`
}

function isPrivate(ip) {
  return !ip || ip.startsWith("192.168.") || ip.startsWith("10.") ||
    ip.startsWith("172.") || ip.startsWith("127.") || ip === "::1"
}

// ── Components ────────────────────────────────────

function StatRow({ stats }) {
  return (
    <div className="stat-row">
      <div className="stat">
        <div className="stat-label">Endpoints</div>
        <div className="stat-value cyan">{stats.total_endpoints ?? 0}</div>
      </div>
      <div className="stat">
        <div className="stat-label">Online</div>
        <div className="stat-value green">{stats.online_endpoints ?? 0}</div>
      </div>
      <div className="stat">
        <div className="stat-label">Total Connections</div>
        <div className="stat-value white">{(stats.total_connections ?? 0).toLocaleString()}</div>
      </div>
      <div className="stat">
        <div className="stat-label">Flagged IPs</div>
        <div className="stat-value amber">{stats.flagged_connections ?? 0}</div>
      </div>
      <div className="stat">
        <div className="stat-label">Open Alerts</div>
        <div className="stat-value red">{stats.open_alerts ?? 0}</div>
      </div>
    </div>
  )
}

function EndpointList({ endpoints, selected, onSelect }) {
  if (!endpoints.length) return (
    <div className="empty">No endpoints online yet.<br/>Run the agent on a machine to start monitoring.</div>
  )
  return (
    <div className="endpoint-list">
      {endpoints.map(ep => (
        <div
          key={ep.id}
          className={`endpoint-row ${selected?.id === ep.id ? "selected" : ""}`}
          onClick={() => onSelect(ep)}
        >
          <div className="dot" style={ep.status !== "online" ? { background: "var(--red)", boxShadow: "0 0 8px var(--red)", animation: "none" } : {}} />
          <div>
            <div className="endpoint-name">{ep.name}</div>
            <div className="endpoint-meta">{ep.ip_address} · {ep.os_info}</div>
          </div>
          <span className={`badge badge-${ep.status === "online" ? "online" : "offline"}`}>
            {ep.status}
          </span>
          <div className="endpoint-meta" style={{ marginLeft: "auto" }}>
            {timeAgo(ep.last_seen)}
          </div>
        </div>
      ))}
    </div>
  )
}

function ConnectionTable({ connections, onBlock }) {
  if (!connections.length) return (
    <div className="empty">Waiting for connections from agent…</div>
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
            <th>AbuseIPDB</th>
            <th>Status</th>
            <th>Time</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {connections.map((c, i) => (
            <tr
              key={c.id || i}
              className={c.is_blocked ? "blocked" : c.is_flagged ? "flagged" : ""}
            >
              <td><span className="proc-name">{c.process_name}</span></td>
              <td style={{ color: "var(--text-3)" }}>{c.process_pid}</td>
              <td>
                <span className={isPrivate(c.remote_ip) ? "ip-private" : "ip-addr"}>
                  {c.remote_ip}
                </span>
              </td>
              <td style={{ color: "var(--text-2)", maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {c.remote_host || "—"}
              </td>
              <td><span className="port">{c.remote_port}</span></td>
              <td>
                {isPrivate(c.remote_ip) ? (
                  <span style={{ color: "var(--text-3)" }}>private</span>
                ) : (
                  <div className="score-bar">
                    <div
                      className={`score-fill ${scoreClass(c.abuse_score)}`}
                      style={{ width: Math.max(c.abuse_score, 2) + "px" }}
                    />
                    <span style={{ color: scoreColor(c.abuse_score), fontSize: 11 }}>
                      {c.abuse_score}
                    </span>
                  </div>
                )}
              </td>
              <td>
                {c.is_blocked ? (
                  <span className="badge badge-high">blocked</span>
                ) : c.is_flagged ? (
                  <span className="badge badge-medium">flagged</span>
                ) : (
                  <span style={{ color: "var(--text-3)" }}>ok</span>
                )}
              </td>
              <td style={{ color: "var(--text-3)", fontSize: 11 }}>{timeAgo(c.created_at)}</td>
              <td>
                {!c.is_blocked && !isPrivate(c.remote_ip) && (
                  <button
                    className="btn btn-block"
                    onClick={() => onBlock({ remote_ip: c.remote_ip, process_name: c.process_name, action: "block", reason: `Manual block — abuse score ${c.abuse_score}` })}
                  >
                    block
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AlertsPanel({ alerts, onResolve }) {
  if (!alerts.length) return (
    <div className="empty">No open alerts. System is clean.</div>
  )
  return (
    <div>
      {alerts.map(a => (
        <div key={a.id} className={`alert-item ${a.severity}`}>
          <div className="alert-head">
            <span className={`badge badge-${a.severity}`}>{a.severity}</span>
            <span style={{ color: "var(--text-2)", fontSize: 11 }}>{a.alert_type}</span>
            <span className="proc-name">{a.process_name}</span>
            <span className="ip-addr">{a.remote_ip}</span>
            {a.endpoints?.name && (
              <span style={{ color: "var(--text-3)", fontSize: 11 }}>
                @ {a.endpoints.name}
              </span>
            )}
            <span className="alert-time">{timeAgo(a.created_at)}</span>
          </div>
          <div className="alert-desc">{a.description}</div>
          {a.gemini_analysis && (
            <div className="alert-ai">
              <span className="gemini-tag" style={{ marginBottom: 4, display: "inline-flex" }}>
                ✦ GEMINI AI
              </span>
              <br />
              {a.gemini_analysis}
            </div>
          )}
          <div style={{ marginTop: 8 }}>
            <button className="btn btn-resolve" onClick={() => onResolve(a.id)}>
              mark resolved
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}

function RulesPanel({ rules, onAdd, onDelete }) {
  const [form, setForm] = useState({
    process_name: "", remote_ip: "", remote_host: "", action: "block", reason: ""
  })

  function update(k, v) { setForm(f => ({ ...f, [k]: v })) }

  function submit() {
    if (!form.remote_ip && !form.process_name) return
    onAdd({ ...form })
    setForm({ process_name: "", remote_ip: "", remote_host: "", action: "block", reason: "" })
  }

  return (
    <div>
      {/* Add rule form */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-title">✦ Add Rule</div>
        <div className="rule-form">
          <div>
            <div className="input-label">Process Name</div>
            <input
              className="input"
              placeholder="chrome.exe"
              value={form.process_name}
              onChange={e => update("process_name", e.target.value)}
            />
          </div>
          <div>
            <div className="input-label">Remote IP</div>
            <input
              className="input"
              placeholder="185.220.101.45"
              value={form.remote_ip}
              onChange={e => update("remote_ip", e.target.value)}
            />
          </div>
          <div>
            <div className="input-label">Reason</div>
            <input
              className="input"
              placeholder="Malicious C2 server"
              value={form.reason}
              onChange={e => update("reason", e.target.value)}
            />
          </div>
          <div>
            <div className="input-label">Action</div>
            <select className="select" value={form.action} onChange={e => update("action", e.target.value)}>
              <option value="block">block</option>
              <option value="allow">allow</option>
            </select>
          </div>
          <div style={{ alignSelf: "flex-end" }}>
            <button className="btn btn-primary" onClick={submit}>+ Add</button>
          </div>
        </div>
      </div>

      {/* Existing rules */}
      {!rules.length ? (
        <div className="empty">No rules configured. Add a rule above to block apps or IPs.</div>
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
                    <span className={`badge badge-${r.action === "block" ? "high" : "online"}`}>
                      {r.action}
                    </span>
                  </td>
                  <td className="proc-name">{r.process_name || "*"}</td>
                  <td className="ip-addr">{r.remote_ip || "*"}</td>
                  <td style={{ color: "var(--text-2)" }}>{r.reason || "—"}</td>
                  <td style={{ color: "var(--text-3)" }}>
                    {r.endpoints?.name || "global"}
                  </td>
                  <td style={{ color: "var(--text-3)", fontSize: 11 }}>{timeAgo(r.created_at)}</td>
                  <td>
                    <button className="btn btn-block" onClick={() => onDelete(r.id)}>
                      remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── App ───────────────────────────────────────────
export default function App() {
  const [tab, setTab]               = useState("dashboard")
  const [endpoints, setEndpoints]   = useState([])
  const [selected, setSelected]     = useState(null)
  const [connections, setConnections] = useState([])
  const [alerts, setAlerts]         = useState([])
  const [rules, setRules]           = useState([])
  const [stats, setStats]           = useState({})
  const [wsStatus, setWsStatus]     = useState("connecting")
  const [liveCount, setLiveCount]   = useState(0)
  const ws = useRef(null)
  const selectedRef = useRef(null)

  useEffect(() => {
    selectedRef.current = selected
  }, [selected])

  // ── Data fetching ──
  const loadAll = useCallback(async () => {
    const [ep, al, ru, st] = await Promise.all([
      api.get("/api/endpoints"),
      api.get("/api/alerts"),
      api.get("/api/rules"),
      api.get("/api/stats"),
    ])
    setEndpoints(ep)
    setAlerts(al)
    setRules(ru)
    setStats(st)
    if (!selected && ep.length) setSelected(ep[0])
  }, [])

  const loadConnections = useCallback(async (ep) => {
    if (!ep) return
    const data = await api.get(`/api/connections/${ep.id}`)
    setConnections(data)
  }, [])

  // ── WebSocket ──
  useEffect(() => {
    function connect() {
      ws.current = new WebSocket(WS_URL)

      ws.current.onopen = () => {
        setWsStatus("connected")
      }

      ws.current.onmessage = (e) => {
        const msg = JSON.parse(e.data)
        if (msg.type === "ping") return

        if (msg.type === "connections") {
          if (selectedRef.current?.id === msg.endpoint_id) {
            setConnections(prev => [...msg.data.slice(0, 20), ...prev].slice(0, 200))
          }
          setLiveCount(c => c + msg.data.length)
          // Update stats
          setStats(s => ({
            ...s,
            total_connections: (s.total_connections || 0) + msg.data.length,
            flagged_connections: (s.flagged_connections || 0) + (msg.stats?.flagged || 0),
          }))
        }

        if (msg.type === "endpoint_online") {
          setEndpoints(prev => {
            const exists = prev.find(e => e.id === msg.data.id)
            return exists
              ? prev.map(e => e.id === msg.data.id ? msg.data : e)
              : [msg.data, ...prev]
          })
          setStats(s => ({ ...s, online_endpoints: (s.online_endpoints || 0) + 1 }))
        }

        if (msg.type === "endpoint_offline") {
          setEndpoints(prev => prev.map(e =>
            e.id === msg.endpoint_id ? { ...e, status: "offline" } : e
          ))
        }

        if (msg.type === "rule_added") {
          setRules(prev => [msg.data, ...prev])
        }

        if (msg.type === "rule_deleted") {
          setRules(prev => prev.filter(r => r.id !== msg.rule_id))
        }

        if (msg.type === "alert_resolved") {
          setAlerts(prev => prev.filter(a => a.id !== msg.alert_id))
          setStats(s => ({ ...s, open_alerts: Math.max(0, (s.open_alerts || 1) - 1) }))
        }

        // New alert from agent
        if (msg.alerts?.length) {
          setAlerts(prev => [...msg.alerts, ...prev].slice(0, 100))
          setStats(s => ({ ...s, open_alerts: (s.open_alerts || 0) + msg.alerts.length }))
        }
      }

      ws.current.onclose = () => {
        setWsStatus("reconnecting")
        setTimeout(connect, 3000)
      }

      ws.current.onerror = () => {
        setWsStatus("error")
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

  // Load connections when endpoint selected
  useEffect(() => {
    if (selected) loadConnections(selected)
  }, [selected, loadConnections])

  // ── Actions ──
  async function blockIP(ruleData) {
    if (!selected) return

    await api.post("/api/rules", {
      ...ruleData,
      endpoint_id: selected.id,
    })

    setConnections(prev => prev.map(c =>
      c.remote_ip === ruleData.remote_ip && c.process_name === ruleData.process_name
        ? { ...c, is_blocked: true, is_flagged: true }
        : c
    ))
  }

  async function addRule(ruleData) {
    await api.post("/api/rules", ruleData)
  }

  async function deleteRule(id) {
    await api.delete(`/api/rules/${id}`)
  }

  async function resolveAlert(id) {
    await api.patch(`/api/alerts/${id}/resolve`)
  }

  // ── Render ──
  return (
    <div className="layout">
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
                <span style={{ marginLeft: 6, color: "var(--red)", fontSize: 10 }}>
                  [{alerts.length}]
                </span>
              )}
            </button>
          ))}
        </div>
        <div className="nav-status">
          <div className={`dot ${wsStatus !== "connected" ? "offline" : ""}`} />
          {wsStatus === "connected" ? `live · ${liveCount.toLocaleString()} events` : wsStatus}
        </div>
      </nav>

      {/* Main */}
      <main className="main">

        {/* ── DASHBOARD ── */}
        {tab === "dashboard" && (
          <div>
            <StatRow stats={stats} />
            <div className="grid-2">
              <div className="card">
                <div className="card-title">⬡ Monitored Endpoints</div>
                <EndpointList
                  endpoints={endpoints}
                  selected={selected}
                  onSelect={ep => { setSelected(ep); setTab("connections") }}
                />
              </div>
              <div className="card">
                <div className="card-title">⚡ Recent Alerts</div>
                <AlertsPanel
                  alerts={alerts.slice(0, 5)}
                  onResolve={resolveAlert}
                />
              </div>
            </div>

            {/* Active rules summary */}
            <div className="card">
              <div className="card-title">⊘ Active Block Rules ({rules.filter(r=>r.action==="block").length})</div>
              {rules.filter(r => r.action === "block").length === 0 ? (
                <div className="empty">No block rules. Go to Rules tab to add.</div>
              ) : (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                  {rules.filter(r => r.action === "block").map(r => (
                    <span key={r.id} className="badge badge-high" style={{ fontSize: 11, padding: "4px 10px" }}>
                      {r.process_name || ""}{r.process_name && r.remote_ip ? " → " : ""}{r.remote_ip || ""}
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div className="ticker">
              <div className="ticker-dot" />
              <span>
                WebSocket live · {endpoints.filter(e=>e.status==="online").length} endpoint(s) actively sending data ·
                AbuseIPDB threat intel · Gemini AI analysis on suspicious connections
              </span>
            </div>
          </div>
        )}

        {/* ── CONNECTIONS ── */}
        {tab === "connections" && (
          <div>
            {/* Endpoint selector */}
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title">Select Endpoint</div>
              <EndpointList
                endpoints={endpoints}
                selected={selected}
                onSelect={setSelected}
              />
            </div>

            {selected && (
              <div className="card">
                <div className="card-title" style={{ justifyContent: "space-between" }}>
                  <span>
                    ⬡ Live Connections — <span style={{ color: "var(--cyan)" }}>{selected.name}</span>
                    <span style={{ color: "var(--text-3)", marginLeft: 8 }}>({connections.length})</span>
                  </span>
                  <span className="gemini-tag">✦ ABUSEIPDB SCORED</span>
                </div>
                <ConnectionTable connections={connections} onBlock={blockIP} />
                <div className="ticker">
                  <div className="ticker-dot" />
                  <span>
                    Updating every 5s · Each IP scored against AbuseIPDB in real time ·
                    Alerts are automatic; blocking is manual from this console and syncs to the endpoint every 5s
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── ALERTS ── */}
        {tab === "alerts" && (
          <div className="card">
            <div className="card-title" style={{ justifyContent: "space-between" }}>
              <span>⚡ Security Alerts ({alerts.length} open)</span>
              <span className="gemini-tag">✦ GEMINI AI ANALYSIS</span>
            </div>
            <AlertsPanel alerts={alerts} onResolve={resolveAlert} />
          </div>
        )}

        {/* ── RULES ── */}
        {tab === "rules" && (
          <div className="card">
            <div className="card-title">⊘ Firewall Rules</div>
            <RulesPanel rules={rules} onAdd={addRule} onDelete={deleteRule} />
            <div className="ticker" style={{ marginTop: 12 }}>
              <div className="ticker-dot" />
              <span>
                Rules sync to all agents every 5s · Block rules add real Windows Firewall entries ·
                Global rules apply to all endpoints
              </span>
            </div>
          </div>
        )}

      </main>
    </div>
  )
}
