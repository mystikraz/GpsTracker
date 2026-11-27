import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation, useNavigate, useParams } from "react-router-dom";
import maplibregl, { Map as MapLibreMap, Marker, Popup } from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import "./styles.css";
import { api, ApiError, readAndClearFragmentToken, Role } from "./api";

type Me = { user_id: string; email: string; status: string };
type Organization = { organization_id: string; role: Role };
type Vehicle = { id: string; name: string; plate_number: string | null; color?: string };
type Device = { id: string; terminal_id: string; vehicle_id: string };
type Latest = { vehicle_id: string; vehicle_name: string; plate_number: string | null; terminal_id: string | null; color: string | null; status: "moving" | "stopped" | "offline" | "no_fix"; latitude: number | null; longitude: number | null; gps_timestamp: string | null; speed_kmh: number | null };

function ErrorNotice({ error }: { error: unknown }) {
  if (!error) return null;
  return <p className="notice error" role="alert">{error instanceof ApiError ? error.message : "Something went wrong. Try again."}</p>;
}

function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState(""); const [password, setPassword] = useState(""); const [error, setError] = useState<unknown>(); const [busy, setBusy] = useState(false); const [bootstrapAvailable, setBootstrapAvailable] = useState(false);
  useEffect(() => { api.get<{ available: boolean }>("/api/v1/auth/bootstrap/status").then((result) => setBootstrapAvailable(result.available)).catch(() => undefined); }, []);
  async function submit(event: React.FormEvent) { event.preventDefault(); setBusy(true); setError(undefined); try { const csrf = await api.get<{ csrf_token: string }>("/api/v1/auth/login/csrf"); api.setCsrf(csrf.csrf_token); await api.post("/api/v1/auth/login", { email, password, csrf_token: csrf.csrf_token }); navigate("/organizations"); } catch (cause) { setError(cause); } finally { setBusy(false); } }
  if (bootstrapAvailable) return <main className="auth-page"><section className="auth-card"><p className="eyebrow">Fleet operations</p><h1>Welcome back</h1><p className="muted">Sign in to see your organizationâ€™s vehicles.</p><ErrorNotice error={error} /><form onSubmit={submit}><label>Email<input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required /></label><label>Password<input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label><button className="primary" disabled={busy}>{busy ? "Signing inâ€¦" : "Sign in"}</button></form><Link to="/forgot-password">Forgot password?</Link><p className="auth-secondary"><Link to="/create-account">Create the first account</Link></p></section></main>;
  return <main className="auth-page"><section className="auth-card"><p className="eyebrow">Fleet operations</p><h1>Welcome back</h1><p className="muted">Sign in to see your organization’s vehicles.</p><ErrorNotice error={error} /><form onSubmit={submit}><label>Email<input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required /></label><label>Password<input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label><button className="primary" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button></form><Link to="/forgot-password">Forgot password?</Link></section></main>;
}

function CreateAccount() {
  const navigate = useNavigate();
  const [email, setEmail] = useState(""); const [password, setPassword] = useState(""); const [confirm, setConfirm] = useState(""); const [error, setError] = useState<unknown>(); const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) { event.preventDefault(); setError(undefined); if (password !== confirm) { setError(new Error("Passwords do not match")); return; } setBusy(true); try { const csrf = await api.get<{ csrf_token: string }>("/api/v1/auth/login/csrf"); const response = await fetch("/api/v1/auth/bootstrap-owner", { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json", "X-CSRF-Token": csrf.csrf_token }, credentials: "include", body: JSON.stringify({ email, password }) }); const body = await response.json().catch(() => ({})); if (!response.ok) throw new ApiError(response.status, body.detail ?? "Account creation rejected"); const replacement = response.headers.get("X-CSRF-Token"); if (replacement) api.setCsrf(replacement); navigate("/organizations"); } catch (cause) { setError(cause); } finally { setBusy(false); } }
  return <main className="auth-page"><section className="auth-card"><p className="eyebrow">First-run setup</p><h1>Create your account</h1><p className="muted">You’ll become the owner of a new default organization.</p><ErrorNotice error={error} /><form onSubmit={submit}><label>Email<input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required /></label><label>Password<input type="password" minLength={12} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} required /><small>Use at least 12 characters.</small></label><label>Confirm password<input type="password" minLength={12} autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required /></label><button className="primary" disabled={busy}>{busy ? "Creating account…" : "Create owner account"}</button></form><Link to="/login">Back to sign in</Link></section></main>;
}

function FragmentTokenPage({ invitation = false }: { invitation?: boolean }) {
  const [token, setToken] = useState(""); const [password, setPassword] = useState(""); const [message, setMessage] = useState(""); const [error, setError] = useState<unknown>();
  useEffect(() => setToken(readAndClearFragmentToken()), []);
  async function submit(event: React.FormEvent) { event.preventDefault(); setError(undefined); try { await api.post(invitation ? "/api/v1/auth/invitations/accept" : "/api/v1/auth/reset/consume", { token, password, new_password: password }); setMessage(invitation ? "Invitation accepted. You can now sign in." : "Password reset. You can now sign in."); } catch (cause) { setError(cause); } }
  return <main className="auth-page"><section className="auth-card"><p className="eyebrow">Fleet operations</p><h1>{invitation ? "Accept invitation" : "Choose a new password"}</h1><ErrorNotice error={error} />{message ? <p className="notice success">{message}</p> : <form onSubmit={submit}><label>New password<input type="password" minLength={12} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label><button className="primary">{invitation ? "Accept invitation" : "Reset password"}</button></form>}</section></main>;
}

function ForgotPassword() { const [email, setEmail] = useState(""); const [link, setLink] = useState(""); const [error, setError] = useState<unknown>(); async function submit(event: React.FormEvent) { event.preventDefault(); try { const result = await api.post<{ reset_token?: string; message: string }>("/api/v1/auth/reset/request", { email }); setLink(result.reset_token ? `${window.location.origin}/reset-password#${encodeURIComponent(result.reset_token)}` : ""); } catch (cause) { setError(cause); } } return <main className="auth-page"><section className="auth-card"><p className="eyebrow">Account recovery</p><h1>Reset your password</h1><p className="muted">If the account exists, reset instructions will be provided.</p><ErrorNotice error={error} />{link && <p className="notice success"><a href={link}>Open the one-time reset link</a></p>}<form onSubmit={submit}><label>Email<input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required /></label><button className="primary">Request reset</button></form><Link to="/login">Back to sign in</Link></section></main>; }

function Sessions() { const [rows, setRows] = useState<{ id: string; created_at: string; last_seen_at: string }[]>([]); const [error, setError] = useState<unknown>(); const load = () => api.get<typeof rows>("/api/v1/auth/sessions").then(setRows).catch(setError); useEffect(() => { void load(); }, []); return <Page title="Active sessions"><ErrorNotice error={error} /><div className="stack">{rows.map((row) => <div className="list-row" key={row.id}><span><strong>Session {row.id.slice(0, 8)}</strong><small>Last seen {new Date(row.last_seen_at).toLocaleString()}</small></span><button onClick={() => api.post(`/api/v1/auth/sessions/${row.id}/revoke`, {}).then(load).catch(setError)}>Revoke</button></div>)}</div></Page>; }

function ChangePassword() { const [current, setCurrent] = useState(""); const [next, setNext] = useState(""); const [message, setMessage] = useState(""); const [error, setError] = useState<unknown>(); async function submit(event: React.FormEvent) { event.preventDefault(); try { await api.post("/api/v1/auth/password/change", { current_password: current, new_password: next, csrf_token: "" }); setMessage("Password changed. Other sessions were signed out."); setCurrent(""); setNext(""); } catch (cause) { setError(cause); } } return <Page title="Change password"><ErrorNotice error={error} />{message && <p className="notice success">{message}</p>}<form className="narrow-form" onSubmit={submit}><label>Current password<input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required /></label><label>New password<input type="password" minLength={12} autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required /></label><button className="primary">Change password</button></form></Page>; }

function History() { const { orgId = "" } = useParams(); const [vehicles, setVehicles] = useState<Vehicle[]>([]); const [selected, setSelected] = useState(""); const [points, setPoints] = useState<{ gps_timestamp: string; latitude: number; longitude: number; speed_kmh: number }[]>([]); const [error, setError] = useState<unknown>(); useEffect(() => { api.get<Vehicle[]>(`/api/v1/orgs/${orgId}/vehicles`).then((rows) => { setVehicles(rows); if (rows[0]) setSelected(rows[0].id); }).catch(setError); }, [orgId]); async function loadHistory() { if (!selected) return; const to = new Date(); const from = new Date(to.getTime() - 60 * 60 * 1000); try { const result = await api.get<{ points: typeof points }>(`/api/v1/orgs/${orgId}/vehicles/${selected}/history?from=${encodeURIComponent(from.toISOString())}&to=${encodeURIComponent(to.toISOString())}`); setPoints(result.points); } catch (cause) { setError(cause); } } return <Page title="History playback"><ErrorNotice error={error} /><div className="toolbar"><label>Vehicle<select value={selected} onChange={(e) => setSelected(e.target.value)}>{vehicles.map((vehicle) => <option key={vehicle.id} value={vehicle.id}>{vehicle.name}</option>)}</select></label><button className="primary" onClick={loadHistory}>Load last hour</button></div><p className="muted">{points.length} points loaded. Use the table as the accessible playback view.</p><div className="table-wrap"><table><thead><tr><th scope="col">Time</th><th scope="col">Latitude</th><th scope="col">Longitude</th><th scope="col">Speed</th></tr></thead><tbody>{points.map((point) => <tr key={point.gps_timestamp}><td>{new Date(point.gps_timestamp).toLocaleString()}</td><td>{point.latitude}</td><td>{point.longitude}</td><td>{point.speed_kmh} km/h</td></tr>)}</tbody></table></div></Page>; }

function OrgSection() { const { orgId = "", section = "" } = useParams(); const [data, setData] = useState<unknown[]>([]); const [error, setError] = useState<unknown>(); const [name, setName] = useState(""); const [inviteEmail, setInviteEmail] = useState(""); const [inviteRole, setInviteRole] = useState("viewer"); const [inviteLink, setInviteLink] = useState(""); const [vehicles, setVehicles] = useState<Vehicle[]>([]); const [terminalId, setTerminalId] = useState(""); const [selectedVehicle, setSelectedVehicle] = useState(""); const [provisionPassword, setProvisionPassword] = useState(""); const [existingAuthCode, setExistingAuthCode] = useState(""); const [authCode, setAuthCode] = useState(""); const endpoint = section === "vehicles" ? "vehicles" : section === "devices" ? "devices" : section === "members" ? "members" : section === "invitations" ? "invitations" : section === "audit" ? "audit" : section === "groups" ? "groups" : ""; const load = () => { if (endpoint) api.get<unknown[]>(`/api/v1/orgs/${orgId}/${endpoint}`).then(setData).catch(setError); }; useEffect(load, [orgId, endpoint]); useEffect(() => { if (endpoint === "devices") api.get<Vehicle[]>(`/api/v1/orgs/${orgId}/vehicles`).then((rows) => { setVehicles(rows); if (rows[0]) setSelectedVehicle(rows[0].id); }).catch(setError); }, [orgId, endpoint]); async function create() { try { await api.post(`/api/v1/orgs/${orgId}/${endpoint}`, { name }); setName(""); load(); } catch (cause) { setError(cause); } } async function invite() { try { const result = await api.post<{ invite_token?: string }>(`/api/v1/orgs/${orgId}/invitations`, { email: inviteEmail, role: inviteRole }); setInviteLink(result.invite_token ? `${window.location.origin}/accept-invitation#${encodeURIComponent(result.invite_token)}` : ""); setInviteEmail(""); load(); } catch (cause) { setError(cause); } } async function provision() { try { await api.post("/api/v1/auth/reauthenticate", { password: provisionPassword, purpose: "device.provision", csrf_token: "" }); const result = await api.post<{ device_id: string; auth_code: string }>(`/api/v1/orgs/${orgId}/devices`, { vehicle_id: selectedVehicle, terminal_id: terminalId, ...(existingAuthCode ? { auth_code: existingAuthCode } : {}) }); setAuthCode(result.auth_code); setTerminalId(""); setExistingAuthCode(""); setProvisionPassword(""); load(); } catch (cause) { setError(cause); } } async function memberAction(userId: string, action: "active" | "suspended" | "removed") { try { await api.post(`/api/v1/orgs/${orgId}/members/${userId}/${action}`, {}); load(); } catch (cause) { setError(cause); } } async function changeRole(userId: string, role: string) { try { await api.patch(`/api/v1/orgs/${orgId}/members/${userId}/role`, { role }); load(); } catch (cause) { setError(cause); } } const action = ["vehicles", "groups"].includes(endpoint) ? <div className="inline-form"><input aria-label={`New ${endpoint.slice(0, -1)} name`} value={name} onChange={(e) => setName(e.target.value)} placeholder={`New ${endpoint.slice(0, -1)} name`} /><button className="primary" onClick={create} disabled={!name}>Create</button></div> : endpoint === "devices" ? <div className="device-form"><input aria-label="Terminal ID" inputMode="numeric" value={terminalId} onChange={(e) => setTerminalId(e.target.value)} placeholder="12-digit terminal ID" /><select aria-label="Vehicle" value={selectedVehicle} onChange={(e) => setSelectedVehicle(e.target.value)}><option value="" disabled>Vehicle</option>{vehicles.map((vehicle) => <option key={vehicle.id} value={vehicle.id}>{vehicle.name}</option>)}</select><input aria-label="Existing device auth code" inputMode="numeric" value={existingAuthCode} onChange={(e) => setExistingAuthCode(e.target.value)} placeholder="Existing 11-digit code" /><input aria-label="Password confirmation" type="password" autoComplete="current-password" value={provisionPassword} onChange={(e) => setProvisionPassword(e.target.value)} placeholder="Confirm password" /><button className="primary" onClick={provision} disabled={!terminalId || !selectedVehicle || !provisionPassword}>Add device</button></div> : endpoint === "invitations" ? <div className="inline-form"><input aria-label="Invite email" type="email" value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} placeholder="Email" /><select aria-label="Invite role" value={inviteRole} onChange={(e) => setInviteRole(e.target.value)}><option value="viewer">Viewer</option><option value="dispatcher">Dispatcher</option><option value="admin">Admin</option></select><button className="primary" onClick={invite} disabled={!inviteEmail}>Invite</button></div> : undefined; return <Page title={section[0].toUpperCase() + section.slice(1)} action={action}><ErrorNotice error={error} />{authCode && <p className="notice success">Device added. Save this one-time device authentication code: <code>{authCode}</code></p>}{inviteLink && <p className="notice success"><a href={inviteLink}>Copy or open the one-time invitation link</a></p>}{endpoint ? <div className="table-wrap"><table><caption className="sr-only">{section}</caption><thead><tr><th scope="col">Record</th><th scope="col">Details</th>{endpoint === "members" && <th scope="col">Actions</th>}</tr></thead><tbody>{data.map((item, index) => { const record = item as Record<string, unknown>; const userId = String(record.user_id ?? ""); return <tr key={index}><th scope="row">{String(record.name ?? record.email ?? `Record ${index + 1}`)}</th><td><code>{JSON.stringify(item)}</code></td>{endpoint === "members" && <td className="action-row"><select aria-label={`Role for ${String(record.email ?? userId)}`} value={String(record.role ?? "viewer")} onChange={(e) => changeRole(userId, e.target.value)}><option value="viewer">Viewer</option><option value="dispatcher">Dispatcher</option><option value="admin">Admin</option><option value="owner">Owner</option></select><button onClick={() => memberAction(userId, "suspended")}>Suspend</button><button onClick={() => memberAction(userId, "active")}>Restore</button><button onClick={() => memberAction(userId, "removed")}>Remove</button></td>}</tr>; })}</tbody></table></div> : <div className="empty-panel"><p>Choose an organization workflow from the navigation.</p></div>}</Page>; }

function Shell({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate(); const location = useLocation(); const [me, setMe] = useState<Me | null>(null); const [orgs, setOrgs] = useState<Organization[]>([]);
  useEffect(() => { Promise.all([api.get<Me>("/api/v1/auth/me"), api.get<Organization[]>("/api/v1/orgs")]).then(([user, memberships]) => { setMe(user); setOrgs(memberships); }).catch(() => navigate("/login")); }, [navigate]);
  if (!me) return <main className="loading" aria-live="polite">Loading your workspace…</main>;
  const active = location.pathname.match(/\/organizations\/([^/]+)/)?.[1] ?? orgs[0]?.organization_id;
  return <div className="app-shell"><a className="skip-link" href="#main">Skip to content</a><header className="topbar"><Link className="brand" to="/organizations">Fleet<span>Tracker</span></Link><div className="topbar-actions"><span className="user-email">{me.email}</span><button onClick={async () => { await api.post("/api/v1/auth/logout", {}); navigate("/login"); }}>Log out</button></div></header><div className="workspace"><aside className="sidebar"><label className="org-select">Organization<select value={active ?? ""} onChange={(e) => navigate(`/organizations/${e.target.value}/map`)}>{orgs.map((org) => <option key={org.organization_id} value={org.organization_id}>{org.organization_id.slice(0, 8)} · {org.role}</option>)}</select></label>{active && <nav aria-label="Organization navigation"><Link className={location.pathname.endsWith("/map") ? "active" : ""} to={`/organizations/${active}/map`}>Live map</Link><Link to={`/organizations/${active}/history`}>History</Link><Link to={`/organizations/${active}/vehicles`}>Vehicles</Link><Link to={`/organizations/${active}/devices`}>Devices</Link><Link to={`/organizations/${active}/groups`}>Groups</Link><Link to={`/organizations/${active}/members`}>Members</Link><Link to={`/organizations/${active}/invitations`}>Invitations</Link><Link to={`/organizations/${active}/audit`}>Audit log</Link></nav>}<Link to="/account/sessions">Active sessions</Link><Link to="/change-password">Change password</Link></aside><main id="main" className="content">{children}</main></div></div>;
}

function Organizations() { const navigate = useNavigate(); const [orgs, setOrgs] = useState<Organization[]>([]); const [name, setName] = useState(""); const [timezone, setTimezone] = useState("Asia/Kathmandu"); const [error, setError] = useState<unknown>(); const [busy, setBusy] = useState(false); const load = () => api.get<Organization[]>("/api/v1/orgs").then(setOrgs).catch(setError); useEffect(() => { void load(); }, []); async function create(event: React.FormEvent) { event.preventDefault(); setBusy(true); setError(undefined); try { const result = await api.post<{ organization_id: string }>("/api/v1/orgs", { name, timezone }); navigate(`/organizations/${result.organization_id}/map`); } catch (cause) { setError(cause); } finally { setBusy(false); } } return <Page title="Your organizations"><ErrorNotice error={error} /><section className="panel org-create"><div><h2>Create an organization</h2><p className="muted">Set up a separate fleet workspace and become its owner.</p></div><form className="inline-form" onSubmit={create}><label>Organization name<input value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. Kathmandu Fleet" required maxLength={256} /></label><label>Timezone<select value={timezone} onChange={(event) => setTimezone(event.target.value)}><option>Asia/Kathmandu</option><option>Asia/Kolkata</option><option>UTC</option></select></label><button className="primary" disabled={busy || !name.trim()}>{busy ? "Creating…" : "Create organization"}</button></form></section><div className="stack">{orgs.map((org) => <button className="list-row" key={org.organization_id} onClick={() => navigate(`/organizations/${org.organization_id}/map`)}><span><strong>Organization</strong><small>{org.organization_id}</small></span><strong>{org.role}</strong></button>)}</div></Page>; }

type TrailPoint = { latitude: number; longitude: number };

function terminalLabel(terminalId: string | null) {
  return terminalId ? `Tracker · ${terminalId.slice(-6)}` : "Tracker ID unavailable";
}

function FleetMapCanvas({ vehicles, selectedVehicleId, trail, colors, onSelect, onError }: { vehicles: Latest[]; selectedVehicleId: string; trail: TrailPoint[]; colors: Record<string, string>; onSelect: (vehicleId: string) => void; onError: (message: string) => void }) {
  const mapNode = React.useRef<HTMLDivElement>(null);
  const map = React.useRef<MapLibreMap | null>(null);
  const markers = React.useRef<Marker[]>([]);
  const [mapReady, setMapReady] = React.useState(false);

  useEffect(() => {
    if (!mapNode.current) return;
    const instance = new maplibregl.Map({ container: mapNode.current, style: import.meta.env.VITE_MAP_STYLE_URL ?? "https://tiles.openfreemap.org/styles/liberty", center: [85.324, 27.7172], zoom: 7, attributionControl: {} });
    const handleError = (event: { error?: Error }) => onError(event.error?.message ?? "Map tiles could not be loaded");
    instance.on("load", () => setMapReady(true));
    instance.on("error", handleError);
    instance.addControl(new maplibregl.NavigationControl(), "top-left");
    map.current = instance;
    return () => { instance.off("error", handleError); markers.current.forEach((marker) => marker.remove()); markers.current = []; instance.remove(); map.current = null; setMapReady(false); };
  }, [onError]);

  useEffect(() => {
    const instance = map.current;
    if (!instance || !mapReady) return;
    markers.current.forEach((marker) => marker.remove());
    markers.current = vehicles.map((vehicle) => {
      const color = colors[vehicle.vehicle_id] ?? "#0f766e";
      const element = document.createElement("div");
      element.className = `fleet-marker${vehicle.vehicle_id === selectedVehicleId ? " selected" : ""}`;
      element.style.backgroundColor = color;
      element.setAttribute("role", "button");
      element.setAttribute("tabindex", "0");
      element.setAttribute("aria-label", `${vehicle.vehicle_name}, ${terminalLabel(vehicle.terminal_id)}`);
      element.setAttribute("aria-current", vehicle.vehicle_id === selectedVehicleId ? "true" : "false");
      element.title = `${vehicle.vehicle_name} · ${terminalLabel(vehicle.terminal_id)}`;
      element.addEventListener("click", () => onSelect(vehicle.vehicle_id));
      element.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onSelect(vehicle.vehicle_id); } });
      return new maplibregl.Marker({ element }).setLngLat([vehicle.longitude!, vehicle.latitude!]).setPopup(new Popup({ offset: 14 }).setHTML(`<strong>${vehicle.vehicle_name}</strong><br />${terminalLabel(vehicle.terminal_id)}<br />${vehicle.status.replace("_", " ")}`)).addTo(instance);
    });
    if (vehicles.length > 0) {
      const bounds = new maplibregl.LngLatBounds();
      vehicles.forEach((vehicle) => bounds.extend([vehicle.longitude!, vehicle.latitude!]));
      instance.fitBounds(bounds, { padding: 56, maxZoom: 16, duration: 0 });
    }
    return () => { markers.current.forEach((marker) => marker.remove()); };
  }, [mapReady, vehicles, selectedVehicleId, colors, onSelect]);

  useEffect(() => {
    const instance = map.current;
    if (!instance || !mapReady) return;
    const data = { type: "Feature", geometry: { type: "LineString", coordinates: trail.map((point) => [point.longitude, point.latitude]) }, properties: {} } as GeoJSON.Feature<GeoJSON.LineString>;
    const source = instance.getSource("vehicle-trail") as maplibregl.GeoJSONSource | undefined;
    if (source) source.setData(data);
    else {
      instance.addSource("vehicle-trail", { type: "geojson", data });
      instance.addLayer({ id: "vehicle-trail", type: "line", source: "vehicle-trail", paint: { "line-color": colors[selectedVehicleId] ?? "#0f766e", "line-width": 5, "line-opacity": 0.9, "line-blur": 0.1 } });
    }
    if (instance.getLayer("vehicle-trail")) instance.setPaintProperty("vehicle-trail", "line-color", colors[selectedVehicleId] ?? "#0f766e");
  }, [mapReady, trail, selectedVehicleId, colors]);

  return <div ref={mapNode} className="fleet-map" aria-label={selectedVehicleId ? "Live vehicle map with selected vehicle trail" : "Live vehicle map"} />;
}

function FleetMap() { const { orgId = "" } = useParams(); const [vehicles, setVehicles] = useState<Latest[]>([]); const [selectedVehicleId, setSelectedVehicleId] = useState(""); const [trail, setTrail] = useState<TrailPoint[]>([]); const [state, setState] = useState("connecting"); const [error, setError] = useState(""); const reportMapError = React.useCallback((message: string) => setError(message), []); const selectVehicle = React.useCallback((vehicleId: string) => setSelectedVehicleId(vehicleId), []); const positioned = vehicles.filter((vehicle) => vehicle.latitude !== null && vehicle.longitude !== null); const colors = React.useMemo(() => Object.fromEntries(vehicles.map((vehicle) => [vehicle.vehicle_id, vehicle.color ?? "#0f766e"])), [vehicles]); useEffect(() => { let alive = true; api.get<Latest[]>(`/api/v1/orgs/${orgId}/vehicles/latest-state`).then((rows) => { setVehicles(rows); setSelectedVehicleId((current) => current || rows.find((row) => row.latitude !== null && row.longitude !== null)?.vehicle_id || ""); }).catch((cause) => { if (alive) { setState("offline"); setError(cause instanceof Error ? cause.message : "Vehicle data could not be loaded"); } }); const source = new EventSource(`/api/v1/orgs/${orgId}/vehicles/stream`, { withCredentials: true }); source.onopen = () => alive && setState("connected"); source.onerror = () => alive && setState("reconnecting"); source.addEventListener("vehicle-state", (event) => { const next = JSON.parse((event as MessageEvent).data) as Latest; setVehicles((current) => [...current.filter((item) => item.vehicle_id !== next.vehicle_id), next]); }); return () => { alive = false; source.close(); }; }, [orgId]); useEffect(() => { if (selectedVehicleId || !vehicles.length) return; const positionedVehicle = vehicles.find((vehicle) => vehicle.latitude !== null && vehicle.longitude !== null); if (positionedVehicle) setSelectedVehicleId(positionedVehicle.vehicle_id); }, [selectedVehicleId, vehicles]); useEffect(() => { if (!selectedVehicleId) { setTrail([]); return; } const to = new Date(); const from = new Date(to.getTime() - 24 * 60 * 60 * 1000); api.get<{ points: TrailPoint[] }>(`/api/v1/orgs/${orgId}/vehicles/${selectedVehicleId}/history?from=${encodeURIComponent(from.toISOString())}&to=${encodeURIComponent(to.toISOString())}`).then((result) => setTrail(result.points)).catch((cause) => setError(cause instanceof Error ? cause.message : "Vehicle trail could not be loaded")); }, [orgId, selectedVehicleId]); return <Page title="Live fleet" action={<span className={`connection ${state}`}>{state}</span>}><ErrorNotice error={error} /><div className="fleet-grid"><section className="map-wrap" aria-label="Fleet map"><FleetMapCanvas vehicles={positioned} selectedVehicleId={selectedVehicleId} trail={trail} colors={colors} onSelect={selectVehicle} onError={reportMapError} /><div className="map-legend" aria-label="Vehicle trail legend"><strong>Trails</strong>{positioned.map((vehicle) => <button className={`legend-item${vehicle.vehicle_id === selectedVehicleId ? " selected" : ""}`} key={vehicle.vehicle_id} onClick={() => selectVehicle(vehicle.vehicle_id)} aria-pressed={vehicle.vehicle_id === selectedVehicleId}><span className="legend-swatch" style={{ backgroundColor: colors[vehicle.vehicle_id] }} aria-hidden="true" /><span><strong>{vehicle.vehicle_name}</strong><small>{terminalLabel(vehicle.terminal_id)}</small></span></button>)}</div><p className="map-caption">{positioned.length} vehicles with a current fix. Click a marker or legend item to show its matching 24-hour trail.</p></section><section aria-labelledby="vehicles-heading"><h2 id="vehicles-heading">Vehicle status</h2><div className="stack">{vehicles.map((vehicle) => <button className={`list-row${vehicle.vehicle_id === selectedVehicleId ? " selected" : ""}`} key={vehicle.vehicle_id} onClick={() => selectVehicle(vehicle.vehicle_id)} aria-pressed={vehicle.vehicle_id === selectedVehicleId}><span className="vehicle-row-label"><span className="legend-swatch" style={{ backgroundColor: colors[vehicle.vehicle_id] }} aria-hidden="true" /><span><strong>{vehicle.vehicle_name}</strong><small>{vehicle.plate_number ?? "No plate"} · {terminalLabel(vehicle.terminal_id)}</small></span></span><span className={`status ${vehicle.status}`}>{vehicle.status.replace("_", " ")}</span></button>)}</div></section></div></Page>; }

function GenericOrgPage({ title }: { title: string }) { return <Page title={title}><div className="empty-panel"><h2>{title}</h2><p className="muted">This workspace is ready for the authorized organization workflow.</p></div></Page>; }
function Page({ title, action, children }: { title: string; action?: React.ReactNode; children: React.ReactNode }) { return <><div className="page-heading"><div><p className="eyebrow">Organization workspace</p><h1>{title}</h1></div>{action}</div>{children}</>; }

function OrgRoute() { const { section = "" } = useParams(); return section === "devices" ? <DeviceSection /> : <OrgSection />; }
function App() { return <Routes><Route path="/login" element={<Login />} /><Route path="/create-account" element={<CreateAccount />} /><Route path="/reset-password" element={<FragmentTokenPage />} /><Route path="/accept-invitation" element={<FragmentTokenPage invitation />} /><Route path="/forgot-password" element={<ForgotPassword />} /><Route path="/" element={<Navigate to="/organizations" replace />} /><Route path="/organizations" element={<Shell><Organizations /></Shell>} /><Route path="/organizations/:orgId/map" element={<Shell><FleetMap /></Shell>} /><Route path="/organizations/:orgId/history" element={<Shell><History /></Shell>} /><Route path="/organizations/:orgId/:section" element={<Shell><OrgRoute /></Shell>} /><Route path="/account/sessions" element={<Shell><Sessions /></Shell>} /><Route path="/change-password" element={<Shell><ChangePassword /></Shell>} /><Route path="*" element={<Navigate to="/organizations" replace />} /></Routes>; }

function DeviceSection() {
  const { orgId = "" } = useParams();
  const [devices, setDevices] = useState<Device[]>([]);
  const [vehicles, setVehicles] = useState<Vehicle[]>([]);
  const [error, setError] = useState<unknown>();
  const [terminalId, setTerminalId] = useState("");
  const [selectedVehicle, setSelectedVehicle] = useState("");
  const [existingAuthCode, setExistingAuthCode] = useState("");
  const [provisionPassword, setProvisionPassword] = useState("");
  const [authCode, setAuthCode] = useState("");
  const [provisioning, setProvisioning] = useState(false);
  const [editing, setEditing] = useState<Device | null>(null);
  const [editVehicleId, setEditVehicleId] = useState("");
  const [editAuthCode, setEditAuthCode] = useState("");
  const [editPassword, setEditPassword] = useState("");

  const load = () => Promise.all([
    api.get<Device[]>(`/api/v1/orgs/${orgId}/devices`),
    api.get<Vehicle[]>(`/api/v1/orgs/${orgId}/vehicles`),
  ]).then(([deviceRows, vehicleRows]) => {
    setDevices(deviceRows);
    setVehicles(vehicleRows);
    if (!selectedVehicle && vehicleRows[0]) setSelectedVehicle(vehicleRows[0].id);
  }).catch(setError);
  useEffect(() => { void load(); }, [orgId]);

  async function provision() {
    setProvisioning(true);
    setError(undefined);
    try {
      await api.post("/api/v1/auth/reauthenticate", { password: provisionPassword, purpose: "device.provision", csrf_token: "" });
      const result = await api.post<{ device_id: string; auth_code: string }>(`/api/v1/orgs/${orgId}/devices`, {
        vehicle_id: selectedVehicle,
        terminal_id: terminalId,
        ...(existingAuthCode ? { auth_code: existingAuthCode } : {}),
      });
      setAuthCode(result.auth_code);
      setTerminalId(""); setExistingAuthCode(""); setProvisionPassword("");
      await load();
    } catch (cause) { setError(cause); }
    finally { setProvisioning(false); }
  }

  function beginEdit(device: Device) {
    setEditing(device); setEditVehicleId(device.vehicle_id); setEditAuthCode(""); setEditPassword(""); setError(undefined);
  }

  async function saveEdit() {
    if (!editing) return;
    try {
      await api.post("/api/v1/auth/reauthenticate", { password: editPassword, purpose: "device.edit", csrf_token: "" });
      if (editVehicleId !== editing.vehicle_id) await api.post(`/api/v1/orgs/${orgId}/devices/${editing.id}/assign`, { vehicle_id: editVehicleId });
      if (editAuthCode) await api.post(`/api/v1/orgs/${orgId}/devices/${editing.id}/rotate-secret`, { auth_code: editAuthCode });
      setEditing(null); await load();
    } catch (cause) { setError(cause); }
  }

  async function deleteDevice(device: Device) {
    if (!window.confirm(`Remove tracker ${device.terminal_id}? Its history will be retained, but it will stop authenticating.`)) return;
    const password = window.prompt("Enter your password to confirm removal:");
    if (!password) return;
    try {
      await api.post("/api/v1/auth/reauthenticate", { password, purpose: "device.delete", csrf_token: "" });
      await api.delete(`/api/v1/orgs/${orgId}/devices/${device.id}`);
      if (editing?.id === device.id) setEditing(null);
      await load();
    } catch (cause) { setError(cause); }
  }

  const vehicleName = (id: string) => vehicles.find((vehicle) => vehicle.id === id)?.name ?? "Unassigned";
  return <Page title="Devices" action={<div className="device-form" aria-busy={provisioning}><input aria-label="Terminal ID" inputMode="numeric" value={terminalId} onChange={(e) => setTerminalId(e.target.value)} placeholder="12-digit terminal ID" disabled={provisioning} /><select aria-label="Vehicle" value={selectedVehicle} onChange={(e) => setSelectedVehicle(e.target.value)} disabled={provisioning}><option value="" disabled>Vehicle</option>{vehicles.map((vehicle) => <option key={vehicle.id} value={vehicle.id}>{vehicle.name}</option>)}</select><input aria-label="Existing device auth code" inputMode="numeric" value={existingAuthCode} onChange={(e) => setExistingAuthCode(e.target.value)} placeholder="Existing 11-digit code" disabled={provisioning} /><input aria-label="Password confirmation" type="password" autoComplete="current-password" value={provisionPassword} onChange={(e) => setProvisionPassword(e.target.value)} placeholder="Confirm password" disabled={provisioning} /><button className="primary" onClick={provision} disabled={provisioning || !terminalId || !selectedVehicle || !provisionPassword}>{provisioning ? "Adding device…" : "Add device"}</button></div>}>
    <ErrorNotice error={error} />
    {provisioning && <p className="notice" role="status" aria-live="polite">Adding device and securing its authentication. Please wait…</p>}
    {authCode && <p className="notice success">Device added. Save this one-time device authentication code: <code>{authCode}</code></p>}
    {editing && <section className="panel" aria-label={`Edit device ${editing.terminal_id}`}><h2>Edit {editing.terminal_id}</h2><div className="inline-form"><label>Vehicle<select value={editVehicleId} onChange={(e) => setEditVehicleId(e.target.value)}>{vehicles.map((vehicle) => <option key={vehicle.id} value={vehicle.id}>{vehicle.name}</option>)}</select></label><label>New authentication code<input inputMode="numeric" value={editAuthCode} onChange={(e) => setEditAuthCode(e.target.value)} placeholder="11 digits, optional" /></label><label>Confirm password<input type="password" autoComplete="current-password" value={editPassword} onChange={(e) => setEditPassword(e.target.value)} required /></label><button className="primary" onClick={saveEdit} disabled={!editPassword}>Save changes</button><button onClick={() => setEditing(null)}>Cancel</button></div><p className="muted">Terminal IDs cannot be edited. Leave the authentication field empty to change only the vehicle assignment.</p></section>}
    <div className="table-wrap"><table><caption className="sr-only">Devices</caption><thead><tr><th scope="col">Terminal ID</th><th scope="col">Vehicle</th><th scope="col">Actions</th></tr></thead><tbody>{devices.map((device) => <tr key={device.id}><th scope="row"><code>{device.terminal_id}</code></th><td>{vehicleName(device.vehicle_id)}</td><td className="action-row"><button onClick={() => beginEdit(device)}>Edit</button><button onClick={() => deleteDevice(device)}>Delete</button></td></tr>)}</tbody></table></div>
  </Page>;
}

createRoot(document.getElementById("root")!).render(<React.StrictMode><BrowserRouter><App /></BrowserRouter></React.StrictMode>);
