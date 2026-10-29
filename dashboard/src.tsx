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
  method?: string;
  event_type?: string;
  alerts: string[];
  action: "allow" | "flag" | "block" | string;
  severity: string;
  reason?: string;
  scan_type?: string;
};

type Health = {
  status: string;
  enforcement: boolean;
  database: string;
  redis: string;
};

type Site = { site_id: string; name: string; created_at: string };
type Block = { site_id: string; source_ip: string; expires_at: string; reason: string };

const platformServices = [
  { key: "gateway", name: "Nginx Gateway", detail: "First line of request inspection and policy checks.", tone: "coral", tag: "EDGE" },
  { key: "api", name: "FastAPI Policy API", detail: "Evaluates events, thresholds, blocks, and site policies.", tone: "blue", tag: "CONTROL" },
  { key: "sensor", name: "Network Sensor", detail: "Reports authorized TCP and UDP probe telemetry.", tone: "yellow", tag: "TELEMETRY" },
  { key: "demo", name: "Protected Origin", detail: "The configured backend that receives allowed traffic.", tone: "green", tag: "ORIGIN" },
  { key: "redis", name: "Redis Counters", detail: "Optional distributed request and block counters.", tone: "pink", tag: "STATE" },
  { key: "database", name: "Event Store", detail: "Persists security evidence for the report view.", tone: "purple", tag: "EVIDENCE" },
];

const attackInfo: Record<string, { label: string; short: string; icon: string; tone: string }> = {
  sql_injection: { label: "SQL Injection", short: "SQLi payloads", icon: "01", tone: "coral" },
  xss: { label: "Cross-Site Scripting", short: "XSS payloads", icon: "02", tone: "yellow" },
  request_flood: { label: "Request Flood", short: "Rate abuse", icon: "03", tone: "blue" },
  brute_force: { label: "Brute Force", short: "Failed logins", icon: "04", tone: "pink" },
  port_scan: { label: "Port Scan", short: "Network probes", icon: "05", tone: "green" },
  modsecurity: { label: "ModSecurity CRS", short: "WAF rules", icon: "06", tone: "purple" },
};

const attackRoutes = [
  { path: "/sql-injection", key: "sql_injection" },
  { path: "/xss", key: "xss" },
  { path: "/brute-force", key: "brute_force" },
  { path: "/dos", key: "request_flood" },
  { path: "/nmap", key: "port_scan" },
  { path: "/modsecurity", key: "modsecurity" },
];

function statusClass(status: string) {
  return status === "healthy" || status === "ok" || status === "enabled" ? "healthy" : "warning";
}

async function readJson<T>(response: Response, endpoint: string): Promise<T> {
  const contentType = response.headers.get("content-type") || "";
  if (!response.ok) throw new Error(`${endpoint} failed (${response.status})`);
  if (!contentType.includes("application/json")) throw new Error(`${endpoint} returned HTML instead of JSON.`);
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
  const [eventSearch, setEventSearch] = useState("");
  const [eventAction, setEventAction] = useState("all");
  const [eventDate, setEventDate] = useState("");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [route, setRoute] = useState(window.location.pathname || "/");

  const headers = useMemo(() => ({ Authorization: `Bearer ${token}` }), [token]);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const [healthResponse, eventsResponse, sitesResponse] = await Promise.all([
        fetch(`${api}/health`),
        fetch(`${api}/api/v1/events?limit=100`, { headers }),
        fetch(`${api}/api/v1/sites`, { headers }),
      ]);
      const nextHealth = await readJson<Health>(healthResponse, "Health check");
      const nextEvents = await readJson<Event[]>(eventsResponse, "Events request");
      const nextSites = await readJson<Site[]>(sitesResponse, "Sites request");
      const blockResults = await Promise.all(nextSites.map(async (site) => {
        const response = await fetch(`${api}/api/v1/sites/${encodeURIComponent(site.site_id)}/blocks`, { headers });
        return readJson<Block[]>(response, "Blocks request");
      }));
      setHealth(nextHealth);
      setEvents(nextEvents);
      setSites(nextSites);
      setBlocks(blockResults.flat());
      setLastChecked(new Date());
      setError("");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to load dashboard data");
    } finally {
      setLoading(false);
    }
  }, [headers, token]);

  useEffect(() => {
    if (!token) return;
    void load();
    const timer = window.setInterval(() => void load(), 10000);
    return () => window.clearInterval(timer);
  }, [load, token]);

  useEffect(() => {
    const onPopState = () => setRoute(window.location.pathname || "/");
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const navigate = (path: string) => {
    window.history.pushState({}, "", path);
    setRoute(path);
    setMobileMenuOpen(false);
  };

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

  const alertCounts = events.flatMap((event) => event.alerts).reduce<Record<string, number>>((counts, alert) => {
    counts[alert] = (counts[alert] || 0) + 1;
    return counts;
  }, {});
  const blockedCount = events.filter((event) => event.action === "block").length;
  const flaggedCount = events.filter((event) => event.action === "flag").length;
  const attackCount = Object.values(alertCounts).reduce((sum, count) => sum + count, 0);
  const attackKeys = Object.keys(attackInfo);
  const filteredEvents = events.filter((event) => {
    const query = eventSearch.trim().toLowerCase();
    const searchable = `${event.source_ip} ${event.path} ${event.site_id} ${event.alerts.join(" ")} ${event.reason || ""}`.toLowerCase();
    return (!query || searchable.includes(query))
      && (eventAction === "all" || event.action === eventAction)
      && (!eventDate || event.timestamp.slice(0, 10) === eventDate);
  });
  const recentBuckets = Array.from({ length: 10 }, (_, index) => {
    const end = Date.now() - index * 6 * 60 * 1000;
    const start = end - 6 * 60 * 1000;
    return events.filter((event) => Date.parse(event.timestamp) >= start && Date.parse(event.timestamp) < end).length;
  }).reverse();
  const maxBucket = Math.max(...recentBuckets, 1);
  const focusedAttacks = [
    { key: "xss", title: "XSS monitor", description: "Cross-site scripting payloads detected at the edge.", tone: "yellow" },
    { key: "brute_force", title: "Brute-force monitor", description: "Repeated failed login activity and temporary blocks.", tone: "pink" },
    { key: "port_scan", title: "Nmap / port scan monitor", description: "TCP and UDP probe telemetry from the network sensor.", tone: "green" },
    { key: "request_flood", title: "DoS / request flood monitor", description: "Application-layer request bursts over the policy window.", tone: "blue" },
  ];
  const attackRoute = attackRoutes.find((item) => item.path === route);

  if (!token) {
    return <main className="auth-page"><section className="login-card">
      <div className="brand-mark">CD</div>
      <p className="eyebrow">Cyber Defense / Control room</p>
      <h1>Keep the bad stuff out.</h1>
      <p className="intro">Sign in to see every protected request, alert, and active block in one place.</p>
      <form onSubmit={submitToken}>
        <input aria-label="Administrator token" placeholder="Administrator token" type="password" value={tokenInput} onChange={(event) => setTokenInput(event.target.value)} />
        <button type="submit">Open control room <span>→</span></button>
      </form>
    </section></main>;
  }

  return <main aria-busy={loading}>
    <header className="site-header">
      <div className="brand"><div className="brand-mark">CD</div><div><strong>Cyber Defense</strong><small>website security control room</small></div></div>
      <button className="menu-toggle" aria-expanded={mobileMenuOpen} aria-controls="primary-nav" onClick={() => setMobileMenuOpen(!mobileMenuOpen)}>Menu <span>☰</span></button>
      <nav id="primary-nav" aria-label="Primary navigation" className={mobileMenuOpen ? "open" : ""}><button className={route === "/" ? "nav-active" : "nav-link"} onClick={() => navigate("/")}>Overview</button><button className="nav-link" onClick={() => navigate("/platform")}>Platform</button><span className="nav-group-label">Attacks</span>{attackRoutes.map((item) => <button className={route === item.path ? "nav-active" : "nav-link"} key={item.path} onClick={() => navigate(item.path)}>{attackInfo[item.key].label}</button>)}<button className={route === "/reports" ? "nav-active" : "nav-link"} onClick={() => navigate("/reports")}>Reports</button><button className="logout" onClick={logout}>Sign out</button></nav>
    </header>

    <section className="hero" id="overview">
      <div><p className="eyebrow">Live protection dashboard</p><h1>Your website is<br /><em>being watched.</em></h1><p className="hero-copy">A clear view of what Cyber Defense is detecting, stopping, and learning from.</p></div>
      <div className="hero-bricks" aria-hidden="true"><i /><i /><i /><i /><i /></div>
      <div className="hero-sticker"><span>LIVE</span><strong>{health?.enforcement ? "ENFORCING" : "DETECTION ONLY"}</strong><small>{loading ? "Updating now" : `Checked ${lastChecked?.toLocaleTimeString() || "—"}`}</small></div>
    </section>

    {error && <p className="error banner" role="alert">{error}</p>}

    <section className="stat-grid">
      <div className="stat-card featured"><span className="stat-number">{blockedCount}</span><span className="stat-label">Requests prevented</span><small>Blocked by security policy</small><b>↗</b></div>
      <div className="stat-card"><span className="stat-number">{events.length}</span><span className="stat-label">Requests reviewed</span><small>Last 100 events loaded</small></div>
      <div className="stat-card"><span className="stat-number">{attackCount}</span><span className="stat-label">Threat signals</span><small>{flaggedCount} flagged for review</small></div>
      <div className="stat-card"><span className="stat-number">{blocks.length}</span><span className="stat-label">Active blocks</span><small>{sites.length} protected site{sites.length === 1 ? "" : "s"}</small></div>
    </section>

    {route === "/reports" ? <section className="report-page">
      <div className="report-page-heading"><p className="eyebrow">All reports / evidence workspace</p><h1>Everything the shield<br /><em>has seen.</em></h1><p>Search, filter, and review every real security event returned by the API.</p></div>
      <div className="report-chart-grid"><div className="chart-card"><div className="chart-top"><strong>Traffic volume</strong><span>Last hour</span></div><div className="activity-chart">{recentBuckets.map((count, index) => <div className="bar-column" key={`report-${index}-${count}`}><span>{count || ""}</span><div className="bar" style={{ height: `${Math.max((count / maxBucket) * 100, count ? 10 : 3)}%` }} /></div>)}</div><div className="chart-axis"><span>60 min ago</span><span>Now</span></div></div><div className="report-card report-main"><div className="report-kicker">LIVE SUMMARY</div><h3>{blockedCount} prevented / {events.length} reviewed</h3><p>Counts are calculated from the currently loaded API events. No statistics are fabricated.</p><div className="report-line"><span>Flagged signals</span><strong>{attackCount}</strong></div></div></div>
      <div className="report-breakdown">{Object.entries(attackInfo).map(([key, info]) => <div className={`breakdown-row ${info.tone}`} key={`report-${key}`}><span>{info.label}</span><strong>{alertCounts[key] || 0}</strong><div><i style={{ width: `${attackCount ? `${Math.max(((alertCounts[key] || 0) / attackCount) * 100, 2)}%` : "2%"}` }} /></div></div>)}</div>
      <div className="section-heading report-events-heading"><div><p className="eyebrow">Complete evidence</p><h2>All reports</h2></div><span className="muted">{filteredEvents.length} shown</span></div>
      <div className="event-filters"><input aria-label="Search reports" placeholder="Search IP, path, alert..." value={eventSearch} onChange={(event) => setEventSearch(event.target.value)} /><select aria-label="Filter reports by action" value={eventAction} onChange={(event) => setEventAction(event.target.value)}><option value="all">All actions</option><option value="block">Blocked</option><option value="flag">Flagged</option><option value="allow">Allowed</option></select><input aria-label="Filter reports by date" type="date" value={eventDate} onChange={(event) => setEventDate(event.target.value)} /><button className="clear-filter" onClick={() => { setEventSearch(""); setEventAction("all"); setEventDate(""); }}>Clear</button></div>
      <div className="event-list">{filteredEvents.length ? filteredEvents.map((event, index) => <details className="event-item" key={`report-event-${event.id ?? `${event.timestamp}-${index}`}`}><summary><span className="event-index">{String(events.length - index).padStart(2, "0")}</span><span className={`event-status ${event.action}`}>{event.action}</span><span className="event-alert">{event.alerts.join(" · ") || "Normal traffic"}</span><span className="event-path">{event.path}</span><time>{new Date(event.timestamp).toLocaleString()}</time><span className="chevron">+</span></summary><div className="event-details"><div><label>Source IP</label><strong>{event.source_ip}</strong></div><div><label>Site</label><strong>{event.site_id}</strong></div><div><label>Method</label><strong>{event.method || "HTTP"}</strong></div><div><label>Reason</label><strong>{event.reason || "No policy violation"}</strong></div></div></details>) : <p className="empty">No reports match these filters.</p>}</div>
    </section> : attackRoute ? <section className="attack-page">
      <button className="back-link" onClick={() => navigate("/")}>← Back to overview</button>
      <div className={`attack-page-hero ${attackInfo[attackRoute.key].tone}`}><span className="attack-page-index">{attackInfo[attackRoute.key].icon}</span><p className="eyebrow">Dedicated protection route</p><h1>{attackInfo[attackRoute.key].label}</h1><p>{attackInfo[attackRoute.key].short}. This page shows the real matching events returned by the security API.</p></div>
      <div className="attack-page-stats"><div><strong>{alertCounts[attackRoute.key] || 0}</strong><span>Detected signals</span></div><div><strong>{events.filter((event) => event.alerts.includes(attackRoute.key) && event.action === "block").length}</strong><span>Prevented requests</span></div><div><strong>{health?.enforcement ? "ON" : "OFF"}</strong><span>Enforcement mode</span></div></div>
      <div className="attack-page-grid"><div className="chart-card"><div className="chart-top"><strong>Activity for this attack</strong><span>Loaded events</span></div><div className="attack-mini-chart">{Array.from({ length: 10 }, (_, index) => { const count = events.filter((event) => event.alerts.includes(attackRoute.key)).slice(index * 10, index * 10 + 10).length; return <div className="mini-bar" key={index}><i style={{ height: `${Math.max(count * 18, 4)}px` }} /></div>; })}</div></div><div className="report-card report-main"><div className="report-kicker">HOW IT WORKS</div><h3>{attackInfo[attackRoute.key].label} protection</h3><p>{attackRoute.key === "port_scan" ? "The authorized network sensor classifies TCP and UDP probes before policy enforcement." : "The gateway and policy API inspect request telemetry, record the signal, and enforce the configured site policy."}</p></div></div>
      <div className="section-heading attack-events-heading"><div><p className="eyebrow">Evidence</p><h2>Matching requests</h2></div><span className="muted">{events.filter((event) => event.alerts.includes(attackRoute.key)).length} total</span></div>
      <div className="event-list">{events.filter((event) => event.alerts.includes(attackRoute.key)).map((event, index) => <details className="event-item" key={`attack-${event.id ?? `${event.timestamp}-${index}`}`}><summary><span className="event-index">{String(index + 1).padStart(2, "0")}</span><span className={`event-status ${event.action}`}>{event.action}</span><span className="event-alert">{event.alerts.join(" · ")}</span><span className="event-path">{event.path}</span><time>{new Date(event.timestamp).toLocaleString()}</time><span className="chevron">+</span></summary><div className="event-details"><div><label>Source IP</label><strong>{event.source_ip}</strong></div><div><label>Site</label><strong>{event.site_id}</strong></div><div><label>Method</label><strong>{event.method || "HTTP"}</strong></div><div><label>Reason</label><strong>{event.reason || "Policy signal"}</strong></div></div></details>)}</div>
      {!events.some((event) => event.alerts.includes(attackRoute.key)) && <p className="empty">No {attackInfo[attackRoute.key].label} events recorded yet.</p>}
    </section> : route === "/platform" ? <section className="platform-page"><button className="back-link" onClick={() => navigate("/")}>← Back to overview</button><div className="report-page-heading"><p className="eyebrow">Connected services</p><h1>The platform,<br /><em>block by block.</em></h1><p>Each service has a distinct role in the protection pipeline.</p></div><div className="service-grid">{platformServices.map((service, index) => <article className={`service-card ${service.tone}`} key={`platform-${service.key}`}><span className="service-number">{String(index + 1).padStart(2, "0")}</span><span className="service-tag">{service.tag}</span><h3>{service.name}</h3><p>{service.detail}</p><span className="service-state">● {service.key === "redis" ? health?.redis || "optional" : service.key === "database" ? health?.database || "—" : health?.status || "connected"}</span></article>)}</div></section> : <>
    <section className="split-section">
      <div className="section-heading"><p className="eyebrow">At a glance</p><h2>Traffic activity</h2><span className={`health-text ${statusClass(health?.status || "unknown")}`}>● {health?.status || "unknown"} / API</span></div>
      <div className="chart-card" aria-label="Requests in the last hour"><div className="chart-top"><strong>Requests in the last hour</strong><span>Auto-refreshes every 10s</span></div><div className="activity-chart">{recentBuckets.map((count, index) => <div className="bar-column" key={`${index}-${count}`}><span>{count || ""}</span><div className="bar" style={{ height: `${Math.max((count / maxBucket) * 100, count ? 10 : 3)}%` }} /></div>)}</div><div className="chart-axis"><span>60 min ago</span><span>Now</span></div></div>
    </section>

    <section id="attacks" className="section-block"><div className="section-heading"><p className="eyebrow">What we stop</p><h2>Protection, in boxes.</h2><span className="muted">{attackCount} signals found</span></div>
      <div className="attack-grid">{attackKeys.map((key) => { const info = attackInfo[key]; const count = alertCounts[key] || 0; return <article className={`attack-card ${info.tone}`} key={key}><div className="attack-icon">{info.icon}</div><div><h3>{info.label}</h3><p>{info.short}</p></div><strong>{count}</strong><small>{count ? "detected" : "ready to detect"}</small></article>; })}</div>
    </section>

    <section className="section-block attack-monitors"><div className="section-heading"><p className="eyebrow">Dedicated monitors</p><h2>See each attack clearly.</h2><span className="muted">Real event data only</span></div>
      <div className="monitor-grid">{focusedAttacks.map((monitor) => {
        const info = attackInfo[monitor.key];
        const matched = events.filter((event) => event.alerts.includes(monitor.key));
        const latest = matched[0];
        return <article className={`monitor-card ${monitor.tone}`} key={monitor.key}><div className="monitor-top"><span className="attack-icon">{info.icon}</span><strong>{matched.length}</strong></div><h3>{monitor.title}</h3><p>{monitor.description}</p><div className="monitor-meter"><i style={{ width: `${matched.length ? `${Math.min(matched.length * 12, 100)}%` : "2%"}` }} /></div><small>{latest ? `Last seen ${new Date(latest.timestamp).toLocaleString()}` : "No matching events recorded"}</small></article>;
      })}</div>
    </section>

    <section className="section-block" id="platform"><div className="section-heading"><p className="eyebrow">The platform</p><h2>Every block has a job.</h2><span className="muted">Connected services</span></div>
      <div className="service-grid">{platformServices.map((service, index) => <article className={`service-card ${service.tone}`} key={service.key}><span className="service-number">{String(index + 1).padStart(2, "0")}</span><span className="service-tag">{service.tag}</span><h3>{service.name}</h3><p>{service.detail}</p><span className="service-state">● {service.key === "redis" ? health?.redis || "optional" : service.key === "database" ? health?.database || "—" : health?.status || "connected"}</span></article>)}</div>
    </section>

    <section className="section-block" id="report"><div className="section-heading"><p className="eyebrow">Security report</p><h2>What happened?</h2><button className="outline-button" onClick={() => void load()} disabled={loading}>{loading ? "Refreshing..." : "Refresh report ↻"}</button></div>
      <div className="report-grid"><div className="report-card report-main"><div className="report-kicker">PROTECTION SUMMARY</div><h3>{blockedCount ? `${blockedCount} request${blockedCount === 1 ? "" : "s"} kept away.` : "No blocked requests yet."}</h3><p>{blockedCount ? "Your gateway identified these requests as unsafe and stopped them before they reached the protected application." : "Run the local demo tests to generate blocked requests and see the report populate."}</p><div className="report-line"><span>Prevention rate</span><strong>{events.length ? `${Math.round((blockedCount / events.length) * 100)}%` : "0%"}</strong></div></div><div className="report-card"><div className="report-kicker">SERVICES</div><div className="service-row"><span>FastAPI</span><b className={statusClass(health?.status || "")}>● {health?.status || "—"}</b></div><div className="service-row"><span>Database</span><b className={statusClass(health?.database || "")}>● {health?.database || "—"}</b></div><div className="service-row"><span>Redis counters</span><b className={statusClass(health?.redis || "")}>● {health?.redis || "—"}</b></div><div className="service-row"><span>Mode</span><b>{health?.enforcement ? "Enforcing" : "Detection only"}</b></div></div></div>
    </section>

    <section className="section-block events-section"><div className="section-heading"><div><p className="eyebrow">Evidence log</p><h2>Protected requests</h2></div><span className="muted">Click a row for details</span></div>
      <div className="event-filters"><input aria-label="Search events" placeholder="Search IP, path, alert..." value={eventSearch} onChange={(event) => setEventSearch(event.target.value)} /><select aria-label="Filter by action" value={eventAction} onChange={(event) => setEventAction(event.target.value)}><option value="all">All actions</option><option value="block">Blocked</option><option value="flag">Flagged</option><option value="allow">Allowed</option></select><input aria-label="Filter by date" type="date" value={eventDate} onChange={(event) => setEventDate(event.target.value)} /><button className="clear-filter" onClick={() => { setEventSearch(""); setEventAction("all"); setEventDate(""); }}>Clear</button></div>
      <div className="event-list">{filteredEvents.length ? filteredEvents.map((event, index) => <details className="event-item" key={event.id ?? `${event.timestamp}-${index}`}><summary><span className="event-index">{String(events.length - index).padStart(2, "0")}</span><span className={`event-status ${event.action}`}>{event.action}</span><span className="event-alert">{event.alerts.join(" · ") || "Normal traffic"}</span><span className="event-path">{event.path}</span><time>{new Date(event.timestamp).toLocaleTimeString()}</time><span className="chevron">+</span></summary><div className="event-details"><div><label>Source IP</label><strong>{event.source_ip}</strong></div><div><label>Site</label><strong>{event.site_id}</strong></div><div><label>Method</label><strong>{event.method || "HTTP"}</strong></div><div><label>Reason</label><strong>{event.reason || "No policy violation"}</strong></div></div></details>) : <p className="empty">{events.length ? "No events match these filters." : "No events recorded yet."}</p>}</div>
    </section>
    </>}

    <footer><span>Cyber Defense Control Room</span><span>Built for safer websites · {new Date().getFullYear()}</span></footer>
  </main>;
}

createRoot(document.getElementById("root")!).render(<App />);
