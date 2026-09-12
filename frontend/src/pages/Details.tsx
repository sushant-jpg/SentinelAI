import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  Sparkles,
  ShieldCheck,
  Plus,
  ExternalLink,
} from "lucide-react";
import { useResource } from "../hooks/useResource";
import { useAuth } from "../hooks/Auth";
import { post, patch } from "../services/api";
import type { Alert, Incident, Explanation, Status } from "../types";
import {
  PageHeading,
  Panel,
  Loading,
  ErrorBox,
  Badge,
  ActionButton,
  formatDate,
} from "../components/ui";
import { AlertTable } from "../components/AlertTable";
const statuses: Status[] = [
  "New",
  "Investigating",
  "Resolved",
  "False Positive",
];
function Assignee({
  value,
  onChange,
}: {
  value: string | null;
  onChange: (value: string | null) => void;
}) {
  const { data } = useResource<{ items: { id: string; name: string }[] }>(
    "/users/assignable",
  );
  return (
    <select
      aria-label="Assigned analyst"
      value={value || ""}
      onChange={(e) => onChange(e.target.value || null)}
    >
      <option value="">Unassigned</option>
      {data?.items.map((u) => (
        <option value={u.id} key={u.id}>
          {u.name}
        </option>
      ))}
    </select>
  );
}
export function ExplanationView({ data }: { data: Explanation }) {
  return (
    <div className="explanation">
      <span className="ai-provider">
        <Sparkles size={14} />
        {data.generated_by}
      </span>
      <h3>Observed evidence</h3>
      <div className="evidence-summary">
        <strong>{data.observed_evidence.matching_count}</strong> matching
        records · {data.observed_evidence.window_seconds}s window ·{" "}
        {data.observed_evidence.affected_accounts} accounts
      </div>
      <h3>Interpretation</h3>
      <p>{data.interpretation}</p>
      <h3>Possible impact</h3>
      <p>{data.possible_impact}</p>
      <h3>Recommended investigation</h3>
      <ol>
        {data.investigation.map((v) => (
          <li key={v}>{v}</li>
        ))}
      </ol>
      <h3>Defensive recommendations</h3>
      <ol>
        {data.recommendations.map((v) => (
          <li key={v}>{v}</li>
        ))}
      </ol>
      <div className="context-note">
        <ShieldCheck size={17} />
        {data.limitations}
      </div>
    </div>
  );
}
export function AlertDetails() {
  const { id } = useParams();
  const resource = useResource<Alert>("/alerts/" + id);
  const { user } = useAuth();
  const [note, setNote] = useState(""),
    [explanation, setExplanation] = useState<Explanation | null>(null),
    [error, setError] = useState("");
  const a = resource.data;
  async function update(body: unknown) {
    setError("");
    try {
      await patch("/alerts/" + id, body);
      resource.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  if (resource.loading && !a) return <Loading />;
  if (!a) return <ErrorBox message={resource.error} />;
  return (
    <>
      <Link className="back-link" to="/alerts">
        <ArrowLeft size={15} />
        Back to alerts
      </Link>
      <PageHeading
        eyebrow={`DETECTION / ${a.alert_id.slice(0, 8).toUpperCase()}`}
        title={a.title}
        description={`Detected ${formatDate(a.timestamp)} · ${a.detection_rule}`}
        action={<Badge value={a.severity} />}
      />
      <ErrorBox message={error || resource.error} />
      <div className="detail-grid">
        <div className="detail-main">
          <Panel title="Detection summary" action={<Badge value={a.status} />}>
            <div className="panel-body">
              <p>{a.description}</p>
              <div className="metadata-grid">
                {[
                  ["Source IP", a.source_ip],
                  ["Destination IP", a.destination_ip],
                  ["Affected host", a.affected_host],
                  ["Account", a.username],
                  ["Category", a.category],
                  ["Event type", a.event_type],
                ].map(([label, value]) => (
                  <div key={label}>
                    <small>{label}</small>
                    <strong className="mono">{value || "Not supplied"}</strong>
                  </div>
                ))}
              </div>
              <div className="mitre-card">
                <span className="mitre-mark">ATT&CK</span>
                <div>
                  <a
                    href={`https://attack.mitre.org/techniques/${a.technique_id.replace(".", "/")}/`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {a.technique_id} · {a.technique?.technique_name}
                    <ExternalLink size={12} />
                  </a>
                  <small>
                    {a.technique?.tactic} · Investigative mapping; validate
                    against evidence
                  </small>
                </div>
              </div>
            </div>
          </Panel>
          <Panel
            title="Observed event evidence"
            subtitle={`${a.evidence.event_ids.length} linked records · ${a.evidence.origin} source`}
          >
            <div className="event-evidence">
              {a.events?.map((e) => (
                <div key={e.event_id}>
                  <div>
                    <span className="mono">{e.event_type}</span>
                    <small>{formatDate(e.timestamp)}</small>
                  </div>
                  <p>{e.message || "No message supplied"}</p>
                  <small className="mono muted">{e.event_id}</small>
                </div>
              ))}
            </div>
          </Panel>
          <Panel
            title="Investigation notes"
            subtitle="Build a shared record of your findings"
          >
            <div className="panel-body">
              {a.notes?.length ? (
                a.notes.map((n) => (
                  <div className="note" key={n.id}>
                    <small>{formatDate(n.timestamp)}</small>
                    <p>{n.text}</p>
                  </div>
                ))
              ) : (
                <p className="muted">No analyst notes yet.</p>
              )}
              {user?.role !== "viewer" && (
                <>
                  <label className="sr-only" htmlFor="alert-note">
                    Investigation note
                  </label>
                  <textarea
                    id="alert-note"
                    placeholder="Document your findings…"
                    value={note}
                    maxLength={5000}
                    onChange={(e) => setNote(e.target.value)}
                  />
                  <ActionButton
                    action={async () => {
                      if (!note.trim()) throw new Error("Enter a note first");
                      await post(`/alerts/${id}/notes`, { text: note });
                      setNote("");
                    }}
                    onDone={resource.reload}
                  >
                    <Plus size={15} />
                    Add note
                  </ActionButton>
                </>
              )}
            </div>
          </Panel>
        </div>
        <div className="detail-side">
          <Panel title="Risk assessment">
            <div className="panel-body">
              <div className={`risk-score ${a.severity}`}>
                <strong>{a.risk_score}</strong>
                <span>
                  / 100<small>{a.severity} risk</small>
                </span>
              </div>
              <div className="risk-track">
                <i style={{ width: a.risk_score + "%" }} />
              </div>
              {a.risk_factors.map((f) => (
                <div className="factor" key={f.factor}>
                  <span>{f.factor}</span>
                  <strong>+{f.points}</strong>
                </div>
              ))}
              <small className="muted">Contributions are capped at 100.</small>
            </div>
          </Panel>
          {user?.role !== "viewer" && (
            <Panel title="Alert workflow">
              <div className="panel-body form-stack">
                <label>
                  Status
                  <select
                    aria-label="Status"
                    value={a.status}
                    onChange={(e) => update({ status: e.target.value })}
                  >
                    {statuses.map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Assigned analyst
                  <Assignee
                    value={a.assigned_to}
                    onChange={(v) => update({ assigned_to: v })}
                  />
                </label>
              </div>
            </Panel>
          )}
          <Panel title="AI analysis" action={<Sparkles size={17} />}>
            <div className="panel-body">
              {explanation ? (
                <ExplanationView data={explanation} />
              ) : (
                <p className="muted">
                  Understand this detection and get a starting point for
                  investigation.
                </p>
              )}
              <ActionButton
                action={async () =>
                  setExplanation(await post<Explanation>(`/ai/alerts/${id}`))
                }
                className="button ai-button"
              >
                <Sparkles size={15} />
                {explanation ? "Regenerate analysis" : "Explain this alert"}
              </ActionButton>
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}
export function IncidentDetails() {
  const { id } = useParams();
  const resource = useResource<Incident>("/incidents/" + id);
  const { user } = useAuth();
  const [note, setNote] = useState(""),
    [resolution, setResolution] = useState(""),
    [error, setError] = useState("");
  const a = resource.data;
  async function update(body: unknown) {
    setError("");
    try {
      await patch("/incidents/" + id, body);
      resource.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  if (resource.loading && !a) return <Loading />;
  if (!a) return <ErrorBox message={resource.error} />;
  return (
    <>
      <Link className="back-link" to="/incidents">
        <ArrowLeft size={15} />
        Back to incidents
      </Link>
      <PageHeading
        eyebrow={`INCIDENT / ${a.incident_id.slice(0, 8).toUpperCase()}`}
        title={a.title}
        description={a.description || `Opened ${formatDate(a.created_at)}`}
        action={<Badge value={a.severity} />}
      />
      <ErrorBox message={error || resource.error} />
      <div className="detail-grid">
        <div className="detail-main">
          <Panel
            title="Related alerts"
            subtitle={`Affected assets: ${a.affected_assets.join(", ")}`}
          >
            <AlertTable alerts={a.related_alerts || []} compact />
          </Panel>
          <Panel title="Incident timeline">
            <div className="panel-body timeline">
              {a.timeline?.map((t) => (
                <div key={t.id}>
                  <i />
                  <span className="muted">{formatDate(t.timestamp)}</span>
                  <h3>{t.action}</h3>
                  <p>{t.note}</p>
                </div>
              ))}
            </div>
          </Panel>
          {a.resolution && (
            <Panel title="Resolution">
              <div className="panel-body">
                <p>{a.resolution}</p>
              </div>
            </Panel>
          )}
        </div>
        <div className="detail-side">
          <Panel title="Incident workflow">
            <div className="panel-body form-stack">
              <Badge value={a.status} />
              {user?.role !== "viewer" && (
                <>
                  <label>
                    Assigned analyst
                    <Assignee
                      value={a.assigned_analyst}
                      onChange={(v) => update({ assigned_analyst: v })}
                    />
                  </label>
                  <label>
                    Resolution
                    <textarea
                      value={resolution}
                      placeholder={
                        a.resolution ||
                        "Describe containment, findings and closure…"
                      }
                      onChange={(e) => setResolution(e.target.value)}
                    />
                  </label>
                  <label>
                    Status
                    <select
                      aria-label="Status"
                      value={a.status}
                      onChange={(e) =>
                        update({
                          status: e.target.value,
                          ...(e.target.value === "Resolved"
                            ? { resolution: resolution || a.resolution }
                            : {}),
                        })
                      }
                    >
                      {statuses.map((s) => (
                        <option key={s}>{s}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Investigation note
                    <textarea
                      value={note}
                      onChange={(e) => setNote(e.target.value)}
                    />
                  </label>
                  <ActionButton
                    action={async () => {
                      if (!note.trim())
                        throw new Error("Enter an investigation note");
                      await patch("/incidents/" + id, { note });
                      setNote("");
                    }}
                    onDone={resource.reload}
                  >
                    Add timeline note
                  </ActionButton>
                </>
              )}
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}
