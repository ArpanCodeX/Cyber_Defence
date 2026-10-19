import React, {useEffect, useState} from "react";
import {createRoot} from "react-dom/client";
import "./style.css";
const api = import.meta.env.VITE_API_URL || "http://localhost:8000";
type Event = {id:number; timestamp:string; site_id:string; source_ip:string; path:string; alerts:string[]; action:string; severity:string};
function App() {
  const [events,setEvents]=useState<Event[]>([]); const [token,setToken]=useState(localStorage.getItem("admin")||""); const [error,setError]=useState("");
  const load=()=>fetch(`${api}/api/v1/events?limit=50`,{headers:{Authorization:`Bearer ${token}`}}).then(async r=>{if(!r.ok) throw new Error(`API request failed (${r.status})`); return r.json()}).then(data=>{setEvents(data);setError("")}).catch(e=>setError(e.message));
  useEffect(()=>{if(token) load()},[token]);
  return <main><header><h1>Universal Website Security</h1><span>Detection and enforcement control plane</span></header>
    {!token?<section className="card"><h2>Administrator sign-in</h2><input placeholder="Bearer token" type="password" onChange={e=>{localStorage.setItem("admin",e.target.value);setToken(e.target.value)}}/></section>:
    <><section className="stats"><div><b>{events.length}</b><small>Recent events</small></div><div><b>{events.filter(e=>e.action==="block").length}</b><small>Blocked</small></div><div><b>{new Set(events.map(e=>e.site_id)).size}</b><small>Protected sites</small></div></section>
    <section className="card"><div className="row"><h2>Event history</h2><button onClick={load}>Refresh</button></div>{error&&<p className="error">{error}</p>}<table><thead><tr><th>Time</th><th>Site</th><th>Source</th><th>Path</th><th>Alerts</th><th>Action</th></tr></thead><tbody>{events.length?events.map(e=><tr key={e.id}><td>{new Date(e.timestamp).toLocaleString()}</td><td>{e.site_id}</td><td>{e.source_ip}</td><td>{e.path}</td><td>{e.alerts.join(", ")||"—"}</td><td className={e.action}>{e.action}</td></tr>):<tr><td colSpan={6}>No events recorded yet.</td></tr>}</tbody></table></section></>}</main>
}
createRoot(document.getElementById("root")!).render(<App/>);
