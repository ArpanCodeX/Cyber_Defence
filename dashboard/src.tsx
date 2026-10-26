import React, { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const api = import.meta.env.VITE_API_URL || "";

type Event = {
  id?: number;
  timestamp: string;
  site_id: string;
  source_ip: string;
  path: string;
  alerts: string[];
  action: "allow" | "flag" | "block" | string;
  severity: string;
  reason?: string;
};

type Health = {
  status: "healthy" | "degraded" | string;
  enforcement: boolean;
  database: "ok" | "error" | string;
  redis: "ok" | "disabled" | "unavailable" | string;
};

type Site = { site_id: string; name: string; created_at: string };
type Block = { site_id: string; source_ip: string; expires_at: string; reason: string };

function statusClass(status: string): string {
  return status === "healthy" || status === "ok" || status === "enabled" ? "healthy" : "warning";
}

function StatusPill({ label, status }: { label: string; status: string }) {
  return (
    <div className="status-item">
      <span className={`status-dot ${statusClass(status)}`} />
      <span>{label}</span>
      <strong>{status}</strong>
    </div>
  );
}

async function readJson<T>(response: Response, endpoint: string): Promise<T> {
  const contentType = response.headers.get("content-type") || "";
  if (!response.ok) throw new Error(`${endpoint} failed (${response.status})`);
  if (!contentType.includes("application/json")) {
    throw new Error(`${endpoint} returned HTML instead of JSON. Restart the dashboard server.`);
  }
  return response.json() as Promise<T>;
}

function App() {
  const [events, setEvents] = useState<Event[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [health, setHealth] = useState<Health | null>(null);
  const [token, setToken] = useState(localStorage.getItem("admin") || "");
  const [tokenInput, setTokenInput] = useState(token);
  const [error, setError] = useState("");
  const [lastChecked, setLastChecked] = useState<Date | null>(null);
  const [loading, setLoading] = useState(false);
  const [now, setNow] = useState(new Date());

  const headers = useMemo(() => ({ Authorization: `Bearer ${token}` }), [token]);

  const loadHealth = useCallback(async () => {
    const response = await fetch(`${api}/health`);
    return readJson<Health>(response, "Health check");
  }, []);

  const loadProtectedData = useCallback(async () => {
    const [eventsResponse, sitesResponse] = await Promise.all([
      fetch(`${api}/api/v1/events?limit=100`, { headers }),
      fetch(`${api}/api/v1/sites`, { headers }),
    ]);
    const nextEvents = await readJson<Event[]>(eventsResponse, "Events request");
    const nextSites = await readJson<Site[]>(sitesResponse, "Sites request");
    const blockResults = await Promise.all(
      nextSites.map(async (site) => {
        const response = await fetch(`${api}/api/v1/sites/${encodeURIComponent(site.site_id)}/blocks`, { headers });
        return readJson<Block[]>(response, "Blocks request");
      }),
    );
    return { events: nextEvents, sites: nextSites, blocks: blockResults.flat() };
  }, [headers]);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const [nextHealth, protectedData] = await Promise.all([loadHealth(), loadProtectedData()]);
      setHealth(nextHealth);
      setEvents(protectedData.events);
      setSites(protectedData.sites);
      setBlocks(protectedData.blocks);
      setLastChecked(new Date());
      setError("");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to load server health");
    } finally {
      setLoading(false);
    }
  }, [loadHealth, loadProtectedData, token]);

  useEffect(() => {
    if (!token) return;
    void load();
    const timer = window.setInterval(() => void load(), 10000);
    return () => window.clearInterval(timer);
  }, [load, token]);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const submitToken = (event: FormEvent) => {
    event.preventDefault();
    const nextToken = tokenInput.trim();
    if (!nextToken) return;
    localStorage.setItem("admin", nextToken);
    setToken(nextToken);
  };

  const logout = () => {
    localStorage.removeItem("admin");
    setToken("");
    setHealth(null);
    setEvents([]);
    setSites([]);
    setBlocks([]);
  };

  const alerts = events.flatMap((event) => event.alerts);
  const alertCounts = alerts.reduce<Record<string, number>>((counts, alert) => {
    counts[alert] = (counts[alert] || 0) + 1;
    return counts;
  }, {});
  const topAlerts = Object.entries(alertCounts).sort(([, a], [, b]) => b - a).slice(0, 5);
  const recentBuckets = Array.from({ length: 12 }, (_, index) => {
    const end = Date.now() - index * 5 * 60 * 1000;
    const start = end - 5 * 60 * 1000;
    return events.filter((event) => {
      const timestamp = Date.parse(event.timestamp);
      return timestamp >= start && timestamp < end;
    }).length;
  }).reverse();
  const maxBucket = Math.max(...recentBuckets, 1);

  return (
    <main>
      <header className="page-header">
        <div>
          <p className="eyebrow">Cyber Defense Control Plane</p>
          <h1>Protected server health</h1>
          <span>Live security posture, service health, and recent activity</span>
        </div>
        {token && <button className="secondary-button" onClick={logout}>Sign out</button>}
      </header>
      {!token ? (
        <section className="card login-card">
          <h2>Administrator sign-in</h2>
          <p>Use the configured administrator token to view protected server metrics.</p>
          <form onSubmit={submitToken}>
            <input
              aria-label="Administrator token"
              placeholder="Administrator token"
              type="password"
              value={tokenInput}
              onChange={(event) => setTokenInput(event.target.value)}
            />
            <button type="submit">Open dashboard</button>
          </form>
        </section>
      ) : (
        <>
          <section className="toolbar">
            <span className={`live-indicator ${health ? statusClass(health.status) : "warning"}`}>
              <span className="status-dot" />
              {loading ? "Updating..." : health?.status === "healthy" ? "Monitoring live" : "Health attention required"}
            </span>
            <span className="muted">
              {lastChecked ? `Last checked ${lastChecked.toLocaleTimeString()}` : "Waiting for health check"}
            </span>
            <button onClick={() => void load} disabled={loading}>Refresh now</button>
          </section>

          {error && <p className="error banner">{error}</p>}

          <section className="time-card">
            <div>
              <span className="card-label">Current local time</span>
              <strong>{now.toLocaleTimeString()}</strong>
              <small>{now.toLocaleDateString(undefined, { weekday: "long", year: "numeric", month: "long", day: "numeric" })}</small>
            </div>
            <div className="time-detail">
              <span className="card-label">UTC</span>
              <strong>{now.toISOString().slice(11, 19)}</strong>
              <small>{now.toISOString().slice(0, 10)}</small>
            </div>
            <div className="time-detail">
              <span className="card-label">Last API check</span>
              <strong>{lastChecked ? lastChecked.toLocaleTimeString() : "Not checked"}</strong>
              <small>{lastChecked ? "Backend health response received" : "Waiting for connection"}</small>
            </div>
          </section>

          <section className="health-grid">
            <div className={`health-card ${statusClass(health?.status || "unknown")}`}>
              <span className="card-label">Overall status</span>
              <strong>{health?.status || "unknown"}</strong>
              <small>FastAPI health endpoint</small>
            </div>
            <div className="health-card">
              <span className="card-label">Protection mode</span>
              <strong>{health?.enforcement ? "Enforcing" : "Detection only"}</strong>
              <small>{health?.enforcement ? "Blocking policy violations" : "Recording alerts without blocking"}</small>
            </div>
            <div className="health-card">
              <span className="card-label">Active blocks</span>
              <strong>{blocks.length}</strong>
              <small>Temporary IP blocks</small>
            </div>
            <div className="health-card">
              <span className="card-label">Protected sites</span>
              <strong>{sites.length}</strong>
              <small>Configured tenants</small>
            </div>
          </section>

          <section className="content-grid">
            <div className="card">
              <div className="row"><h2>Service health</h2><span className="muted">Auto-refresh: 10s</span></div>
              <div className="status-list">
                <StatusPill label="FastAPI service" status={health?.status || "unknown"} />
                <StatusPill label="SQLite database" status={health?.database || "unknown"} />
                <StatusPill label="Redis counters" status={health?.redis || "unknown"} />
                <StatusPill label="Enforcement" status={health?.enforcement ? "enabled" : "disabled"} />
              </div>
            </div>
            <div className="card">
              <div className="row"><h2>Request activity</h2><span className="muted">Last hour</span></div>
              <div className="activity-chart" aria-label="Requests per five-minute interval">
                {recentBuckets.map((count, index) => (
                  <div className="bar-column" key={`${index}-${count}`}>
                    <span className="bar-value">{count || ""}</span>
                    <div className="bar" style={{ height: `${Math.max((count / maxBucket) * 100, count ? 8 : 2)}%` }} />
                  </div>
                ))}
              </div>
              <div className="chart-axis"><span>60 min ago</span><span>Now</span></div>
            </div>
          </section>

          <section className="content-grid">
            <div className="card">
              <div className="row"><h2>Detection summary</h2><span className="muted">{alerts.length} alerts</span></div>
              {topAlerts.length ? <div className="alert-list">{topAlerts.map(([name, count]) => (
                <div className="alert-row" key={name}><span>{name.replaceAll("_", " ")}</span><strong>{count}</strong></div>
              ))}</div> : <p className="empty">No attack alerts in the loaded event history.</p>}
            </div>
            <div className="card">
              <div className="row"><h2>Active blocks</h2><span className="muted">All sites</span></div>
              {blocks.length ? <div className="block-list">{blocks.slice(0, 5).map((block) => (
                <div className="block-row" key={`${block.site_id}-${block.source_ip}`}>
                  <div><strong>{block.source_ip}</strong><small>{block.site_id} · {block.reason}</small></div>
                  <span>{new Date(block.expires_at).toLocaleTimeString()}</span>
                </div>
              ))}</div> : <p className="empty">No active IP blocks.</p>}
            </div>
          </section>

          <section className="card">
            <div className="row"><h2>Recent security events</h2><span className="muted">{events.length} loaded</span></div>
            <div className="table-wrap">
              <table><thead><tr><th>Time</th><th>Site</th><th>Source</th><th>Path</th><th>Alerts</th><th>Action</th></tr></thead>
                <tbody>{events.length ? events.map((event, index) => (
                  <tr key={event.id ?? `${event.timestamp}-${index}`}><td>{new Date(event.timestamp).toLocaleString()}</td><td>{event.site_id}</td><td>{event.source_ip}</td><td>{event.path}</td><td>{event.alerts.join(", ") || "—"}</td><td className={event.action}>{event.action}</td></tr>
                )) : <tr><td colSpan={6} className="empty">No events recorded yet.</td></tr>}</tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
