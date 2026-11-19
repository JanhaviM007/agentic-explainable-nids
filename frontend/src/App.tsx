import { useCallback, useEffect, useMemo, useState } from "react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000").replace(/\/$/, "");

type Feature = {
  name: string;
  value?: string | number | null;
  shap_value: number;
  description?: string | null;
};

type Alert = {
  flow_id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  predicted_label: string;
  confidence: number;
  top_features: Feature[];
  metadata: Record<string, unknown>;
  expected_techniques?: string[] | null;
  expected_severity?: string | null;
};

type Technique = {
  technique_id: string;
  technique_name: string;
  tactic_name: string;
  description: string;
  url?: string | null;
  mitigations?: { id: string; name: string; description: string }[];
};

type Proposal = {
  action_id: string;
  action_type: string;
  target: string;
  priority: number;
  rationale: string;
  estimated_impact: string;
  approval_status: string;
  execution_command_preview?: string | null;
};

type Investigation = {
  alert_id: string;
  execution_time_seconds: number;
  plan: { objective: string; reasoning: string; steps: string[] };
  investigation: {
    matched_techniques: Technique[];
    assessed_severity: string;
    attack_chain_context: string;
    key_evidence: string[];
    confidence_assessment: string;
  };
  response_proposals: Proposal[];
  report: {
    executive_summary: string;
    technical_analysis: string;
    mitre_summary: string;
  };
};

type AuditEntry = {
  audit_id: string;
  action_id: string;
  decision: string;
  analyst_id: string;
  analyst_notes?: string | null;
  timestamp: string;
};

type Page = "overview" | "alerts" | "matrix" | "audit";

const navigation: { id: Page; label: string; icon: string }[] = [
  { id: "overview", label: "Overview", icon: "◫" },
  { id: "alerts", label: "Alert stream", icon: "⌁" },
  { id: "matrix", label: "ATT&CK map", icon: "▦" },
  { id: "audit", label: "Decision log", icon: "◎" },
];

function App() {
  const [page, setPage] = useState<Page>("overview");
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [health, setHealth] = useState<{ status: string; service: string; mitre_database_techniques_count: number; agents_active?: string[] } | null>(null);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [techniques, setTechniques] = useState<Technique[]>([]);
  const [techniqueQuery, setTechniqueQuery] = useState("");
  const [alertQuery, setAlertQuery] = useState("");
  const [filter, setFilter] = useState("All events");
  const [reviewFilter, setReviewFilter] = useState("all");
  const [sortOrder, setSortOrder] = useState("latest");
  const [timeRange, setTimeRange] = useState("all");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [analyst, setAnalyst] = useState("");
  const [notes, setNotes] = useState("");
  const [notice, setNotice] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const request = useCallback(async <T,>(path: string, init?: RequestInit): Promise<T> => {
    const response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...init?.headers },
    });
    if (!response.ok) {
      let detail = `Request failed (${response.status})`;
      try {
        const body = await response.json();
        detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
      } catch {
        // Keep the HTTP status as a useful fallback when the server response is not JSON.
      }
      throw new Error(detail);
    }
    return response.json() as Promise<T>;
  }, []);

  const refresh = useCallback(async (background = false) => {
    if (!background) setLoading(true);
    if (!background) setError("");
    const results = await Promise.allSettled([
      request<Alert[]>("/api/v1/alerts/mock"),
      request<{ status: string; service: string; mitre_database_techniques_count: number; agents_active?: string[] }>("/api/v1/health"),
      request<{ logs: AuditEntry[] }>("/api/v1/audit/logs"),
    ]);
    const messages: string[] = [];
    if (results[0].status === "fulfilled") {
      const fixtureAlerts = results[0].value;
      setAlerts((current) => [
        ...current.filter((alert) => alert.metadata.prediction_source === "CSV prediction · this browser session"),
        ...fixtureAlerts,
      ]);
      setLastUpdated(new Date());
    }
    else messages.push(`Could not load alerts: ${results[0].reason instanceof Error ? results[0].reason.message : "unknown error"}`);
    if (results[1].status === "fulfilled") setHealth(results[1].value);
    else messages.push("Backend health is unavailable.");
    if (results[2].status === "fulfilled") {
      const auditEntries = results[2].value.logs;
      setAudit(auditEntries);
      setInvestigation((current) => syncInvestigationDecisions(current, auditEntries));
    }
    else messages.push("Decision log is unavailable.");
    setError(messages.join(" "));
    if (!background) setLoading(false);
  }, [request]);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(true), 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const filteredAlerts = useMemo(() => {
    const query = alertQuery.trim().toLowerCase();
    const timeCutoff = timeRange === "24h"
      ? Date.now() - 24 * 60 * 60 * 1000
      : timeRange === "7d"
        ? Date.now() - 7 * 24 * 60 * 60 * 1000
        : timeRange === "30d"
          ? Date.now() - 30 * 24 * 60 * 60 * 1000
          : null;
    return alerts.filter((alert) => {
      const matchesQuery = !query || [
        alert.flow_id, alert.src_ip, alert.dst_ip, alert.predicted_label,
        String(alert.metadata.hostname ?? ""), String(alert.metadata.process_name ?? ""),
      ].some((value) => value.toLowerCase().includes(query));
      const hasDecision = hasAnalystDecision(alert, audit);
      const matchesFilter = filter === "All events"
        || (filter === "Threats" && severityOf(alert) !== "BENIGN")
        || (filter === "Critical" && severityOf(alert) === "CRITICAL")
        || (filter === "High" && severityOf(alert) === "HIGH")
        || (filter === "Benign" && severityOf(alert) === "BENIGN")
        || (filter === "Undecided" && severityOf(alert) !== "BENIGN" && !hasDecision);
      const matchesReview = reviewFilter === "all"
        || (reviewFilter === "undecided" && severityOf(alert) !== "BENIGN" && !hasDecision)
        || (reviewFilter === "decided" && hasDecision);
      const timestamp = Date.parse(alert.timestamp);
      const matchesTime = timeCutoff === null || (Number.isFinite(timestamp) && timestamp >= timeCutoff);
      return matchesQuery && matchesFilter && matchesReview && matchesTime;
    }).sort((left, right) => {
      const leftTime = Date.parse(left.timestamp);
      const rightTime = Date.parse(right.timestamp);
      if (!Number.isFinite(leftTime) || !Number.isFinite(rightTime)) return 0;
      return sortOrder === "latest" ? rightTime - leftTime : leftTime - rightTime;
    });
  }, [alertQuery, alerts, audit, filter, reviewFilter, sortOrder, timeRange]);

  const openAlert = (alert: Alert) => {
    setSelected(alert);
    setInvestigation(null);
    setNotes("");
    setError("");
  };

  const investigate = async () => {
    if (!selected) return;
    setBusy("investigate");
    setError("");
    try {
      const result = await request<Investigation>("/api/v1/investigate", {
        method: "POST",
        body: JSON.stringify(selected),
      });
      setInvestigation(syncInvestigationDecisions(result, audit));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Investigation failed.");
    } finally {
      setBusy("");
    }
  };

  const decide = async (proposal: Proposal, decision: "APPROVED" | "REJECTED") => {
    if (!analyst.trim()) {
      setError("Enter an analyst ID before recording a decision.");
      return;
    }
    setBusy(proposal.action_id);
    setError("");
    try {
      await request("/api/v1/actions/decision", {
        method: "POST",
        body: JSON.stringify({
          action_id: proposal.action_id,
          decision,
          analyst_id: analyst.trim(),
          analyst_notes: notes || null,
        }),
      });
      setInvestigation((current) => current && ({
        ...current,
        response_proposals: current.response_proposals.map((item) => item.action_id === proposal.action_id
          ? { ...item, approval_status: decision }
          : item),
      }));
      setNotice(`Action ${decision.toLowerCase()} and recorded in the audit log.`);
      window.setTimeout(() => setNotice(""), 3800);
      const result = await request<{ logs: AuditEntry[] }>("/api/v1/audit/logs");
      setAudit(result.logs);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not record this decision.");
    } finally {
      setBusy("");
    }
  };

  const searchTechniques = async (query: string) => {
    setTechniqueQuery(query);
    setError("");
    try {
      const path = query.trim()
        ? `/api/v1/mitre/search?query=${encodeURIComponent(query.trim())}`
        : "/api/v1/mitre/techniques";
      setTechniques(await request<Technique[]>(path));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not search the ATT&CK catalog.");
    }
  };

  useEffect(() => {
    if (page === "matrix" && techniques.length === 0) void searchTechniques("");
    // Load the catalog only when the page is opened for the first time.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page]);

  const criticalCount = alerts.filter((alert) => severityOf(alert) === "CRITICAL").length;
  const highCount = alerts.filter((alert) => severityOf(alert) === "HIGH").length;
  const benignCount = alerts.filter((alert) => severityOf(alert) === "BENIGN").length;
  const threatCount = alerts.length - benignCount;
  const newest = [...alerts].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  const apiOnline = health?.status === "online";
  const openFilteredAlerts = (severity: string) => {
    setFilter(severity === "Undecided" ? "All events" : severity);
    setReviewFilter(severity === "Undecided" ? "undecided" : "all");
    setTimeRange("all");
    setSortOrder("latest");
    setAlertQuery("");
    setPage("alerts");
  };

  const unreviewedThreatCount = alerts.filter(
    (alert) => severityOf(alert) !== "BENIGN" && !hasAnalystDecision(alert, audit),
  ).length;
  const decidedThreatCount = threatCount - unreviewedThreatCount;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#" onClick={(event) => { event.preventDefault(); setPage("overview"); }}>
          <span className="brand-mark"><span /></span>
          <span className="brand-name">NIDS<span className="brand-period">/</span><small>AGENTIC SECURITY OPERATIONS</small></span>
        </a>
        <div className="workspace-label">PROJECT</div>
        <div className="workspace-switch"><span className="workspace-glyph">A</span><span><b>Explainable NIDS</b><small>Threat detection · response</small></span></div>
        <div className="nav-heading">COMMAND</div>
        <nav className="nav-list" aria-label="Main navigation">
          {navigation.map((item) => (
            <button key={item.id} className={`nav-item ${page === item.id ? "active" : ""}`} onClick={() => setPage(item.id)}>
              <span className="nav-icon">{item.icon}</span><span>{item.label}</span>
              {item.id === "alerts" && unreviewedThreatCount > 0 && <span className="nav-count" title="Threat alerts with no recorded analyst decision">{unreviewedThreatCount}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="sensor-card">
            <div className="sensor-heading"><span className={`sensor-dot ${apiOnline ? "" : "offline"}`} /> API SERVICE</div>
            <div className="sensor-state">{apiOnline ? "Backend connected" : "Backend unavailable"}</div>
            <div className="sensor-meta">{apiOnline ? `${health?.mitre_database_techniques_count.toLocaleString()} ATT&CK techniques indexed` : "Start the API to load project data"}</div>
          </div>
          <div className="approval-status"><span className="approval-icon">✓</span><span><b>Human approval gate</b><small>Required before response</small></span></div>
          <div className="sidebar-footer">AGENTIC EXPLAINABLE NIDS <span>v1.0.0</span></div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumb"><span>{health?.service ?? "Agentic Explainable NIDS"}</span><span className="crumb-slash">/</span><b>{navigation.find((item) => item.id === page)?.label}</b></div>
          <div className="topbar-right">
            <span className="api-indicator"><i className={apiOnline ? "" : "offline"} />{apiOnline ? "API connected" : "API disconnected"}</span>
            <button className="icon-button" aria-label="Refresh data" title="Refresh data" disabled={loading} onClick={() => void refresh()}>↻</button>
            <span className="data-chip">SAMPLE + MODEL · 5S SYNC</span>
          </div>
        </header>

        <div className="content">
          {error && <div className="error-banner" role="alert"><span>!</span><p>{error}</p><button onClick={() => void refresh()}>Retry</button><button className="dismiss" onClick={() => setError("")}>×</button></div>}
          {notice && <div className="notice-banner" role="status"><span>✓</span>{notice}<button className="dismiss" onClick={() => setNotice("")}>×</button></div>}
          {lastUpdated && <div className="data-updated">ALERT FEED LAST SYNCED <b>{lastUpdated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</b></div>}
          {page === "overview" && (
            <Overview
              loading={loading}
              alerts={newest}
              criticalCount={criticalCount}
              highCount={highCount}
              threatCount={threatCount}
              unreviewedThreatCount={unreviewedThreatCount}
              decidedThreatCount={decidedThreatCount}
              benignCount={benignCount}
              audit={audit}
              agentsActive={health?.agents_active ?? []}
              techniqueCount={health?.mitre_database_techniques_count ?? 0}
              onOpen={openAlert}
              onNavigate={setPage}
              onOpenQueue={openFilteredAlerts}
            />
          )}
          {page === "alerts" && (
            <AlertStream
              alerts={filteredAlerts}
              query={alertQuery}
              filter={filter}
              reviewFilter={reviewFilter}
              sortOrder={sortOrder}
              timeRange={timeRange}
              audit={audit}
              loading={loading}
              onQuery={setAlertQuery}
              onFilter={setFilter}
              onReviewFilter={setReviewFilter}
              onSortOrder={setSortOrder}
              onTimeRange={setTimeRange}
              onOpen={openAlert}
            />
          )}
          {page === "matrix" && (
            <AttackMap
              techniques={techniques}
              query={techniqueQuery}
              onQuery={(value) => void searchTechniques(value)}
            />
          )}
          {page === "audit" && <AuditLog entries={audit} />}
          <footer className="page-footer"><span>AGENTIC EXPLAINABLE NIDS <b>·</b> SOC CONSOLE</span><span>DETECT <b>·</b> EXPLAIN <b>·</b> INVESTIGATE <b>·</b> REVIEW</span></footer>
        </div>
      </main>

      {selected && (
        <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setSelected(null); }}>
          <section className="detail-panel" role="dialog" aria-modal="true" aria-labelledby="detail-title">
            <div className="detail-topline"><span>ALERT DOSSIER</span><button className="icon-button close-button" aria-label="Close alert" onClick={() => setSelected(null)}>×</button></div>
            <div className="detail-id mono">{selected.flow_id}</div>
            <h2 id="detail-title">{humanize(selected.predicted_label)}</h2>
            <div className={`detail-severity ${severityClass(severityOf(selected))}`}>{severityOf(selected)} PRIORITY <span>·</span> {(selected.confidence * 100).toFixed(0)}% CONFIDENCE</div>
            <div className="detail-endpoints"><div><small>SOURCE</small><b>{selected.src_ip}</b><span>{selected.src_port} · {selected.protocol}</span></div><i>→</i><div><small>DESTINATION</small><b>{selected.dst_ip}</b><span>{selected.dst_port} · {selected.protocol}</span></div></div>
            <p className="flow-explanation">A flow is one network conversation: {selected.src_ip}:{selected.src_port} sent traffic to {selected.dst_ip}:{selected.dst_port} over {selected.protocol}.</p>
            <div className="detail-meta"><span>MODEL SOURCE</span><b>{selected.metadata.prediction_source ? "Model prediction" : String(selected.metadata.model_source ?? "Provided fixture")}</b><span>HOST</span><b>{String(selected.metadata.hostname ?? "Unidentified host")}</b><span>PROCESS</span><b>{String(selected.metadata.process_name ?? "Not reported")}</b><span>DETECTED</span><b>{formatDate(selected.timestamp)}</b></div>
            <div className="section-rule"><span>WHY THE MODEL FLAGGED THIS FLOW</span><i /></div>
            <p className="model-explanation">The model classified this connection as {humanize(selected.predicted_label)} with {(selected.confidence * 100).toFixed(1)}% confidence. These traffic details show what supported or weakened that result.</p>
            {selected.top_features.length ? <div className="feature-list">{selected.top_features.slice(0, 5).map((feature) => <FeatureRow key={feature.name} feature={feature} predictedLabel={selected.predicted_label} />)}</div> : <p className="empty-copy">No traffic details were included with this alert.</p>}
            {!investigation ? (
              <div className="run-investigation">
                <p>Ask the agent team to correlate this evidence with ATT&CK and prepare response options.</p>
                <button className="primary-button full-button" disabled={busy === "investigate"} onClick={() => void investigate()}>
                  {busy === "investigate" ? <><span className="button-spinner" /> Investigating…</> : <>Run agent investigation <span>↗</span></>}
                </button>
              </div>
            ) : (
              <InvestigationView
                alert={selected}
                result={investigation}
                analyst={analyst}
                notes={notes}
                busy={busy}
                onAnalyst={setAnalyst}
                onNotes={setNotes}
                onDecision={(proposal, decision) => void decide(proposal, decision)}
              />
            )}
          </section>
        </div>
      )}
    </div>
  );
}

function Overview(props: {
  loading: boolean;
  alerts: Alert[];
  criticalCount: number;
  highCount: number;
  threatCount: number;
  unreviewedThreatCount: number;
  decidedThreatCount: number;
  benignCount: number;
  audit: AuditEntry[];
  agentsActive: string[];
  techniqueCount: number;
  onOpen: (alert: Alert) => void;
  onNavigate: (page: Page) => void;
  onOpenQueue: (filter: string) => void;
}) {
  const { loading, alerts, criticalCount, highCount, threatCount, unreviewedThreatCount, decidedThreatCount, benignCount, audit, agentsActive, techniqueCount, onOpen, onNavigate, onOpenQueue } = props;
  const recent = alerts.slice(0, 5);
  const latestDecision = [...audit].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))[0];
  const topSeverity = criticalCount ? "Critical" : highCount ? "High" : threatCount ? "Review" : "Clear";
  return (
    <>
      <div className="page-heading">
        <div><div className="eyebrow"><span className="eyebrow-line" /> {new Date().toLocaleDateString([], { weekday: "long", month: "long", day: "numeric", year: "numeric" }).toUpperCase()}</div><h1>Detect early.<br />Respond with <em>context.</em></h1><p>Explainable network detection, agent-led investigation, and human-approved response.</p></div>
        <div className="heading-stamp"><span>⌘</span><b>AGENTIC<br />DEFENSE</b><small>EXPLAIN · INVESTIGATE</small></div>
      </div>
      <section className="demo-guide" aria-labelledby="demo-guide-title">
        <div className="demo-guide-heading"><div><div className="eyebrow small-eyebrow">PROJECT WORKFLOW</div><h2 id="demo-guide-title">What each stage does</h2></div><span>SELECT A STEP TO EXPLORE</span></div>
        <div className="demo-guide-steps">
          <button onClick={() => onOpenQueue("Threats")}><span>01 · DETECT</span><b>Model flags traffic</b><small>Finds suspicious network flows in the sample alerts.</small><i>Open threat alerts ↗</i></button>
          <button disabled={!alerts.length} onClick={() => alerts[0] && onOpen(alerts[0])}><span>02 · EXPLAIN</span><b>The model explains why</b><small>See which traffic patterns influenced a detection.</small><i>{alerts.length ? "Inspect alert evidence ↗" : "Waiting for alert data"}</i></button>
          <button disabled={!alerts.length} onClick={() => alerts[0] && onOpen(alerts[0])}><span>03 · INVESTIGATE</span><b>Agents add context</b><small>Correlates evidence with the MITRE ATT&CK catalog.</small><i>{alerts.length ? "Open investigation dossier ↗" : "Waiting for alert data"}</i></button>
          <button onClick={() => onNavigate("audit")}><span>04 · HUMAN REVIEW</span><b>Analyst decides</b><small>Response proposals require an approval or rejection.</small><i>View decision log ↗</i></button>
        </div>
      </section>
      <div className="metric-grid">
        <MetricCard label="ALERTS IN FEED" value={loading ? "—" : alerts.length.toLocaleString()} note="Sample fixtures + model runs" icon="⌁" color="sage" onClick={() => onOpenQueue("All events")} />
        <MetricCard label="UNDECIDED THREATS" value={loading ? "—" : unreviewedThreatCount.toLocaleString()} note={`${decidedThreatCount} with decisions · ${threatCount} total`} icon="!" color="peach" onClick={() => onOpenQueue("Undecided")} />
        <MetricCard label="BENIGN CLASSIFICATIONS" value={loading ? "—" : benignCount.toLocaleString()} note="Classified by detection model" icon="✓" color="lilac" onClick={() => onOpenQueue("Benign")} />
        <button className="metric-card risk-card metric-card-button" onClick={() => onOpenQueue(criticalCount ? "Critical" : highCount ? "High" : "Threats")} aria-label="Open highest-priority alerts">
          <div className="metric-top"><span>HIGHEST PRIORITY</span><span className="metric-icon risk-icon">↗</span></div>
          <div className="risk-card-value">{loading ? "—" : topSeverity}</div>
          <div className="metric-foot"><span className={`tiny-dot ${criticalCount || highCount ? "red" : "green"}`} />{loading ? "Waiting for API data" : unreviewedThreatCount ? `${unreviewedThreatCount} threat${unreviewedThreatCount === 1 ? "" : "s"} without a decision` : "No threats await a decision"}</div>
          <div className="risk-halo"><i /></div>
        </button>
      </div>
      <div className="overview-grid">
        <section className="card activity-card">
          <div className="card-head"><div><div className="eyebrow small-eyebrow">OBSERVED TELEMETRY</div><h2>Detection timeline</h2><p className="card-description">Alert counts grouped by their recorded event times.</p></div><span className="chart-legend"><i /> API alert events</span></div>
          <div className="chart-wrap"><SignalChart alerts={alerts} /></div>
          <div className="chart-axis"><span>{alerts.length ? formatShortDate(alerts[alerts.length - 1].timestamp) : "—"}</span><span>EVENT TIME</span><span>{alerts.length ? formatShortDate(alerts[0].timestamp) : "—"}</span></div>
          <div className="chart-foot"><span>{alerts.length.toLocaleString()} ALERT EVENTS <b>·</b> TIME DISTRIBUTION</span><span><i className={`status-dot ${loading ? "offline" : ""}`} />{loading ? "LOADING API DATA" : "SAMPLE + MODEL RUNS"}</span></div>
        </section>
        <section className="card pulse-card">
          <div className="card-head"><div><div className="eyebrow small-eyebrow">MODEL OUTPUT</div><h2>Classification mix</h2><p className="card-description">Share of sample alerts labeled as threats.</p></div><span className="pulse-ring"><i /></span></div>
          <div className="pulse-gauge"><div className="gauge-center"><strong>{alerts.length ? `${Math.round((threatCount / alerts.length) * 100)}%` : "—"}</strong><span>FLAGGED IN DATASET</span></div><div className="gauge-label gauge-label-left">BENIGN</div><div className="gauge-label gauge-label-right">FLAGGED</div></div>
          <div className="pulse-stats"><div><span>CRITICAL</span><b className="text-red">{criticalCount.toString().padStart(2, "0")}</b></div><i /><div><span>HIGH</span><b>{highCount.toString().padStart(2, "0")}</b></div><i /><div><span>BENIGN</span><b className="text-green">{benignCount.toString().padStart(2, "0")}</b></div></div>
          <button className="text-link" onClick={() => onNavigate("alerts")}>Review classifications <span>↗</span></button>
        </section>
      </div>
      <div className="section-title-row"><div><div className="eyebrow small-eyebrow">MODEL EXPLANATION</div><h2>Recent detections <span className="count-pill">{alerts.length}</span></h2><p className="section-description">Select a row to inspect the network flow and its explanation.</p></div><button className="text-link" onClick={() => onNavigate("alerts")}>Open all alerts <span>↗</span></button></div>
      <section className="card detections-card">
        <div className="table-scroll"><table><thead><tr><th>DETECTION</th><th>SOURCE → DESTINATION</th><th>CONFIDENCE</th><th>WHEN</th><th>SEVERITY</th><th /></tr></thead>
          <tbody>{recent.map((alert) => <AlertRow key={alert.flow_id} alert={alert} decisionLogged={hasAnalystDecision(alert, audit)} onClick={() => onOpen(alert)} />)}</tbody>
        </table></div>
        {!loading && alerts.length === 0 && <EmptyState title="No detections to display" detail="Start the backend or refresh to load alert data." />}
        <div className="table-bottom"><span>Showing {recent.length} of {alerts.length} recorded events</span><button onClick={() => onNavigate("alerts")}>VIEW ALERT STREAM <span>→</span></button></div>
      </section>
      <div className="lower-grid">
        <section className="card sequence-card">
          <div className="card-head"><div><div className="eyebrow small-eyebrow">API HEALTH RESPONSE</div><h2>Investigation agents</h2><p className="card-description">Agents available to analyze an opened alert.</p></div><span className="chain-tag">{agentsActive.length} ACTIVE</span></div>
          {agentsActive.length ? <div className="agent-list">{agentsActive.map((agent) => <div className="agent-item" key={agent}><span className="agent-status"><i /></span><span>{agent}</span><b>ACTIVE</b></div>)}</div> : <EmptyState title="Agent status unavailable" detail="Connect to the API health endpoint to load the agent roster." />}
          <div className="sequence-note"><span>↗</span> Alerts can be investigated by the multi-agent pipeline on demand.</div>
        </section>
        <section className="card attention-card">
          <div className="eyebrow small-eyebrow">HUMAN-IN-THE-LOOP</div><div className="attention-mark">◎</div>
          <h2 className="oversight-title">Response stays<br /><em>in human hands.</em></h2>
          <p>Agent recommendations are proposals, not commands. An analyst reviews every response action before approval.</p>
          {latestDecision ? <div className="latest-decision"><span className={`decision-dot ${latestDecision.decision === "APPROVED" ? "approved" : "rejected"}`} /><span><b>Latest decision · {latestDecision.decision.toLowerCase()}</b><small>{latestDecision.analyst_id} · {timeAgo(latestDecision.timestamp)}</small></span><button onClick={() => onNavigate("audit")}>View log ↗</button></div> : <div className="latest-decision empty-decision"><span className="decision-dot" /><span><b>No decisions recorded</b><small>Analyst actions will appear here.</small></span><button onClick={() => onNavigate("audit")}>Open log ↗</button></div>}
        </section>
      </div>
      <div className="activity-strip"><span><i className={`status-dot ${agentsActive.length ? "" : "offline"}`} /> API-REPORTED AGENTS</span><b>{agentsActive.length}</b><span>·</span><b>{techniqueCount.toLocaleString()} ATT&CK techniques indexed</b><span>·</span><b>{audit.length} recorded decisions</b><button onClick={() => onNavigate("audit")}>View decision log →</button></div>
    </>
  );
}

function MetricCard({ label, value, note, icon, color, onClick }: { label: string; value: string; note: string; icon: string; color: string; onClick: () => void }) {
  return <button className={`metric-card metric-${color} metric-card-button`} onClick={onClick} aria-label={`${label}: ${value}. Open matching alerts`}><div className="metric-top"><span>{label}</span><span className="metric-icon">{icon}</span></div><div className="metric-value">{value}</div><div className="metric-bottom"><span>{note}</span></div></button>;
}

function syncInvestigationDecisions(investigation: Investigation | null, audit: AuditEntry[]) {
  if (!investigation) return investigation;
  const decisions = new Map(audit.map((entry) => [entry.action_id, entry.decision]));
  return {
    ...investigation,
    response_proposals: investigation.response_proposals.map((proposal) => ({
      ...proposal,
      approval_status: decisions.get(proposal.action_id) ?? proposal.approval_status,
    })),
  };
}

function AlertStream({ alerts, query, filter, reviewFilter, sortOrder, timeRange, audit, loading, onQuery, onFilter, onReviewFilter, onSortOrder, onTimeRange, onOpen }: {
  alerts: Alert[];
  query: string;
  filter: string;
  reviewFilter: string;
  sortOrder: string;
  timeRange: string;
  audit: AuditEntry[];
  loading: boolean;
  onQuery: (value: string) => void;
  onFilter: (value: string) => void;
  onReviewFilter: (value: string) => void;
  onSortOrder: (value: string) => void;
  onTimeRange: (value: string) => void;
  onOpen: (alert: Alert) => void;
}) {
  return <>
    <div className="subpage-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> INVESTIGATION QUEUE</div><h1>The alert <em>stream.</em></h1><p>Newest events first. Decisions are marked; alerts remain here as history.</p></div><div className="subpage-count"><b>{alerts.length.toLocaleString()}</b><span>EVENTS<br />IN VIEW</span></div></div>
    <section className="card stream-card">
      <div className="stream-toolbar">
        <label className="search-field"><span>⌕</span><input value={query} onChange={(event) => onQuery(event.target.value)} placeholder="Search IP, host, or detection…" /></label>
        <div className="stream-toolbar-controls">
          <div className="filter-group">{["All events", "Threats", "Critical", "High", "Benign"].map((item) => <button key={item} className={filter === item ? "selected" : ""} onClick={() => { onFilter(item); onReviewFilter("all"); }}>{item}</button>)}</div>
          <div className="stream-selects">
            <label>Review<select value={reviewFilter} onChange={(event) => onReviewFilter(event.target.value)}><option value="all">All</option><option value="undecided">No decision</option><option value="decided">Decision logged</option></select></label>
            <label>Time<select value={timeRange} onChange={(event) => onTimeRange(event.target.value)}><option value="all">All time</option><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option></select></label>
            <label>Sort<select value={sortOrder} onChange={(event) => onSortOrder(event.target.value)}><option value="latest">Latest first</option><option value="oldest">Oldest first</option></select></label>
          </div>
        </div>
      </div>
      <div className="table-scroll"><table><thead><tr><th>DETECTION / REVIEW</th><th>FLOW</th><th>HOST / PROCESS</th><th>CONFIDENCE</th><th>WHEN</th><th>SEVERITY</th><th /></tr></thead><tbody>{alerts.map((alert) => <AlertRow key={alert.flow_id} alert={alert} decisionLogged={hasAnalystDecision(alert, audit)} onClick={() => onOpen(alert)} expanded />)}</tbody></table></div>
      {!loading && alerts.length === 0 && <EmptyState title="Nothing matches this view" detail="Try another search or severity filter." />}
      <div className="table-bottom"><span>{loading ? "Loading alert fixtures…" : `${alerts.length} event${alerts.length === 1 ? "" : "s"} in this view`}</span><span>SELECT AN EVENT TO INVESTIGATE <b>↗</b></span></div>
    </section>
    <div className="stream-footnote"><span>ⓘ</span> Sample fixtures and uploaded model predictions are shown together. Live packet capture is not configured.</div>
  </>;
}

function AttackMap({ techniques, query, onQuery }: { techniques: Technique[]; query: string; onQuery: (query: string) => void }) {
  const tactics = [...new Set(techniques.map((technique) => technique.tactic_name))];
  return <>
    <div className="subpage-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> ADVERSARY KNOWLEDGE</div><h1>Map the <em>method.</em></h1><p>Explore the MITRE ATT&CK techniques mapped in this system.</p></div><div className="subpage-count"><b>{techniques.length.toString().padStart(2, "0")}</b><span>TECHNIQUES<br />IN VIEW</span></div></div>
    <div className="matrix-search-row"><label className="search-field matrix-search"><span>⌕</span><input value={query} onChange={(event) => onQuery(event.target.value)} placeholder="Search technique, ID, or tactic…" /></label><span className="matrix-source"><i className="status-dot" /> CURATED ATT&CK CATALOG</span></div>
    {techniques.length > 0 && <div className="tactic-pills">{tactics.map((tactic) => <span key={tactic}>{tactic}</span>)}</div>}
    {techniques.length ? <div className="technique-grid">{techniques.map((technique) => <article className="technique-card" key={technique.technique_id}><div className="technique-card-top"><span className="technique-id">{technique.technique_id}</span><span className="technique-arrow">↗</span></div><h3>{technique.technique_name}</h3><span className="tactic-label">{technique.tactic_name}</span><p>{technique.description}</p><div className="mitigation-footer"><span>{technique.mitigations?.length ?? 0} MITIGATIONS</span>{technique.url && <a href={technique.url} target="_blank" rel="noreferrer">ATT&CK REFERENCE ↗</a>}</div></article>)}</div> : <EmptyState title="No techniques found" detail="Try searching for a technique name, ID, or tactic." />}
  </>;
}

function AuditLog({ entries }: { entries: AuditEntry[] }) {
  return <>
    <div className="subpage-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> HUMAN-IN-THE-LOOP</div><h1>Decisions, <em>documented.</em></h1><p>A transparent record of analyst approvals and rejections.</p></div><div className="subpage-count"><b>{entries.length.toString().padStart(2, "0")}</b><span>RECORDED<br />DECISIONS</span></div></div>
    <section className="card audit-card"><div className="audit-intro"><span className="audit-seal">◎</span><div><b>A decision log built for accountability.</b><p>Each response action is reviewed by a person before it is approved or rejected.</p></div></div>
      {entries.length ? <div className="audit-list">{[...entries].reverse().map((entry) => <article className="audit-item" key={entry.audit_id}><span className={`audit-decision ${entry.decision === "APPROVED" ? "approved" : "rejected"}`}>{entry.decision === "APPROVED" ? "✓" : "×"}</span><div className="audit-main"><div><b>{entry.decision === "APPROVED" ? "Action approved" : "Action rejected"}</b><span className="audit-action mono">{entry.action_id}</span></div><p>{entry.analyst_notes || "No analyst note provided."}</p><small>{entry.audit_id}</small></div><div className="audit-who"><b>{entry.analyst_id}</b><span>{formatDate(entry.timestamp)}</span></div></article>)}</div> : <EmptyState title="No analyst decisions yet" detail="Investigate an alert and review a proposed action to begin the audit trail." />}
    </section>
  </>;
}

function InvestigationView({ alert, result, analyst, notes, busy, onAnalyst, onNotes, onDecision }: {
  alert: Alert; result: Investigation; analyst: string; notes: string; busy: string; onAnalyst: (value: string) => void; onNotes: (value: string) => void; onDecision: (proposal: Proposal, decision: "APPROVED" | "REJECTED") => void;
}) {
  const finding = result.investigation;
  return <div className="investigation-result">
    <div className="investigation-head"><span className="status-dot" /> INVESTIGATION COMPLETE <span>{result.execution_time_seconds.toFixed(2)}s</span></div>
    <div className="investigation-severity"><span>ASSESSED SEVERITY</span><b className={`severity-badge ${severityClass(finding.assessed_severity)}`}>{finding.assessed_severity}</b></div>
    <div className="investigation-block"><span>EXECUTIVE SUMMARY</span><p>{result.report.executive_summary}</p></div>
    <div className="investigation-block"><span>ATTACK CHAIN CONTEXT</span><p>{finding.attack_chain_context}</p></div>
    <div className="investigation-block"><span>WHY THIS CONNECTION WAS FLAGGED</span><p>The model identified {humanize(alert.predicted_label)} on traffic from {alert.src_ip}:{alert.src_port} to {alert.dst_ip}:{alert.dst_port} over {alert.protocol}, with {(alert.confidence * 100).toFixed(1)}% confidence.</p>
      {alert.top_features.length ? <ul>{alert.top_features.slice(0, 3).map((feature) => {
        const value = typeof feature.value === "number" ? feature.value.toLocaleString() : feature.value ?? "not reported";
        const impact = feature.shap_value >= 0 ? "supported" : "weighed against";
        return <li key={feature.name}><b>{feature.description || humanize(feature.name)}</b>{feature.description ? ` (value ${value})` : ` measured ${value}`}. This pattern {impact} the {humanize(alert.predicted_label)} result.</li>;
      })}</ul> : <p>No feature-level traffic details were included with this alert.</p>}
    </div>
    <div className="investigation-block"><span>MITRE ATT&CK</span>{finding.matched_techniques.map((technique) => <a className="matched-technique" href={technique.url ?? `https://attack.mitre.org/techniques/${technique.technique_id.replace(".", "/")}/`} target="_blank" rel="noreferrer" key={technique.technique_id}><b>{technique.technique_id}</b><span>{technique.technique_name}</span><i>↗</i></a>)}</div>
    <div className="investigation-block"><span>INVESTIGATION SUPPORT</span><p>The investigation matched this activity to {finding.matched_techniques.length} MITRE ATT&CK technique{finding.matched_techniques.length === 1 ? "" : "s"}. Model confidence for the detection is {(alert.confidence * 100).toFixed(1)}%.</p></div>
    <div className="investigation-block"><span>RESPONSE PROPOSALS · HUMAN REVIEW REQUIRED</span>
      {result.response_proposals.map((proposal) => <div className="proposal-card" key={proposal.action_id}><div className="proposal-top"><b>{proposal.action_type.replaceAll("_", " ")}</b><span>PRIORITY {proposal.priority}</span></div><p>{proposal.rationale}</p><div className="proposal-target">TARGET <b>{proposal.target}</b></div><p className="impact-copy">{proposal.estimated_impact}</p>
        {proposal.approval_status === "PENDING_APPROVAL" ? <><input className="analyst-input" value={analyst} onChange={(event) => onAnalyst(event.target.value)} placeholder="Analyst ID (required)" aria-label="Analyst ID (required)" /><textarea className="analyst-notes" value={notes} onChange={(event) => onNotes(event.target.value)} placeholder="Optional decision note…" aria-label="Decision note" /><div className="decision-buttons"><button disabled={busy === proposal.action_id || !analyst.trim()} onClick={() => onDecision(proposal, "REJECTED")}>Reject</button><button disabled={busy === proposal.action_id || !analyst.trim()} onClick={() => onDecision(proposal, "APPROVED")}>{busy === proposal.action_id ? "Saving…" : "Approve action"}</button></div></> : <div className={`decision-complete ${proposal.approval_status === "APPROVED" ? "approved" : "rejected"}`}>{proposal.approval_status === "APPROVED" ? "✓ Approved" : "× Rejected"} — decision logged</div>}
      </div>)}
    </div>
  </div>;
}

function AlertRow({ alert, onClick, expanded = false, decisionLogged = false }: { alert: Alert; onClick: () => void; expanded?: boolean; decisionLogged?: boolean }) {
  const severity = severityOf(alert);
  const reviewLabel = severity === "BENIGN" ? "BENIGN" : decisionLogged ? "DECISION LOGGED" : "NO DECISION";
  return <tr onClick={onClick} tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter") onClick(); }}>
    <td><div className="detection-name"><span className={`table-severity-dot ${severityClass(severity)}`} /><span><b>{humanize(alert.predicted_label)}</b><small className="mono">{alert.flow_id}</small><small className="prediction-source">{alert.metadata.prediction_source ? "MODEL PREDICTION" : "SAMPLE FIXTURE"}</small><small className={`review-label ${decisionLogged ? "decision-logged" : ""}`}>{reviewLabel}</small></span></div></td>
    <td><div className="flow-address"><b>{alert.src_ip}</b><span>→</span><b>{alert.dst_ip}</b><small>{alert.src_port} → {alert.dst_port} · {alert.protocol}</small></div></td>
    {expanded && <td><div className="host-cell"><b>{String(alert.metadata.hostname ?? "—")}</b><small>{String(alert.metadata.process_name ?? "—")}</small></div></td>}
    <td><div className="confidence-cell"><span className="confidence-track"><i style={{ width: `${Math.min(100, Math.max(0, alert.confidence * 100))}%` }} /></span><b>{(alert.confidence * 100).toFixed(0)}%</b></div></td>
    <td className="time-cell"><b>{timeAgo(alert.timestamp)}</b><small>{formatDate(alert.timestamp)}</small></td>
    <td><span className={`severity-badge ${severityClass(severity)}`}>{severity}</span></td>
    <td><button className="row-arrow" aria-label={`Inspect ${alert.flow_id}`} onClick={(event) => { event.stopPropagation(); onClick(); }}>↗</button></td>
  </tr>;
}

function FeatureRow({ feature, predictedLabel }: { feature: Feature; predictedLabel: string }) {
  const strength = Math.min(100, Math.round(Math.abs(feature.shap_value) * 150));
  const value = typeof feature.value === "number" ? feature.value.toLocaleString() : feature.value ?? "—";
  const impact = feature.shap_value >= 0 ? "supported" : "weighed against";
  return <div className="feature-row"><div className="feature-row-top"><b>{feature.description || humanize(feature.name)}</b><span>Value {value}</span></div><div className="feature-bar"><i className={feature.shap_value < 0 ? "negative" : ""} style={{ width: `${strength}%` }} /></div><small>This pattern {impact} the {humanize(predictedLabel)} result.</small></div>;
}

function SignalChart({ alerts }: { alerts: Alert[] }) {
  const timestamps = alerts.map((alert) => Date.parse(alert.timestamp)).filter(Number.isFinite).sort((a, b) => a - b);
  const bins = Array.from({ length: 12 }, () => 0);
  if (timestamps.length) {
    const first = timestamps[0];
    const span = timestamps[timestamps.length - 1] - first || 1;
    timestamps.forEach((timestamp) => {
      const bucket = Math.min(bins.length - 1, Math.floor(((timestamp - first) / span) * (bins.length - 1)));
      bins[bucket] += 1;
    });
  }
  const peak = Math.max(1, ...bins);
  const points = bins.map((count, index) => ({
    x: (index / (bins.length - 1)) * 700,
    y: 126 - (count / peak) * 92,
  }));
  const path = points.map((point, index) => `${index ? "L" : "M"}${point.x},${point.y}`).join(" ");
  const lastPoint = points[points.length - 1];
  return (
    <svg className="signal-chart" viewBox="0 0 700 150" preserveAspectRatio="none" role="img" aria-label={`Alert event counts across ${alerts.length} API-provided detections`}>
      <defs><linearGradient id="signal-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#748b6e" stopOpacity=".22" /><stop offset="100%" stopColor="#748b6e" stopOpacity="0" /></linearGradient></defs>
      <path className="chart-gridline" d="M0 30H700M0 70H700M0 110H700" />
      {timestamps.length > 0 && <>
        <path d={`${path} L700 145 L0 145 Z`} fill="url(#signal-fill)" />
        <path d={path} fill="none" stroke="#718568" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx={lastPoint.x} cy={lastPoint.y} r="5" fill="#718568" stroke="#fff" strokeWidth="3" />
      </>}
    </svg>
  );
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return <div className="empty-state"><span>⌁</span><b>{title}</b><p>{detail}</p></div>;
}

function humanize(value: string) {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function severityOf(alert: Alert) {
  if (alert.predicted_label.toLowerCase().includes("benign")) return "BENIGN";
  return alert.expected_severity?.toUpperCase() ?? (alert.confidence >= 0.94 ? "CRITICAL" : alert.confidence >= 0.84 ? "HIGH" : "MEDIUM");
}

function severityClass(value: string) {
  return value.toLowerCase();
}

function hasAnalystDecision(alert: Alert, audit: AuditEntry[]) {
  const actionPrefix = `ACT-${alert.flow_id}-`;
  return audit.some((entry) => entry.action_id.startsWith(actionPrefix));
}

function timeAgo(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  const minutes = Math.max(0, Math.floor((Date.now() - date.getTime()) / 60_000));
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function formatShortDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export default App;
