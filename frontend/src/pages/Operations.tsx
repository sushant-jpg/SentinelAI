import { useState } from "react";
import { Link } from "react-router-dom";
import {
  ArrowUpRight,
  Layers,
  Server,
  Search,
  ShieldCheck,
  Code2,
} from "lucide-react";
import { useResource } from "../hooks/useResource";
import { useAuth } from "../hooks/Auth";
import { patch } from "../services/api";
import type { Incident, Page, Asset, Rule } from "../types";
import {
  PageHeading,
  Panel,
  Loading,
  ErrorBox,
  Badge,
  Pagination,
  Empty,
  formatDate,
  Modal,
  ActionButton,
} from "../components/ui";
export function Incidents() {
  const [page, setPage] = useState(1);
  const { data, error, loading } = useResource<Page<Incident>>(
    `/incidents?page=${page}`,
  );
  return (
    <>
      <PageHeading
        title="Incident workspace"
        description="Connect related threats and guide investigations from signal to resolution."
        action={
          <Link className="button primary" to="/alerts">
            <Layers size={16} />
            Group alerts into incident
          </Link>
        }
      />
      <Panel
        title="All incidents"
        subtitle="Shared investigations and response tracking"
      >
        <ErrorBox message={error} />
        {loading ? (
          <Loading />
        ) : data?.items.length ? (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Incident</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Affected assets</th>
                    <th>Last updated</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((i) => (
                    <tr key={i.incident_id}>
                      <td>
                        <Link
                          to={"/incidents/" + i.incident_id}
                          className="alert-title"
                        >
                          <Layers size={18} />
                          <span>
                            {i.title}
                            <small className="mono">
                              INC-{i.incident_id.slice(0, 8).toUpperCase()}
                            </small>
                          </span>
                        </Link>
                      </td>
                      <td>
                        <Badge value={i.severity} />
                      </td>
                      <td>
                        <Badge value={i.status} />
                      </td>
                      <td>{i.affected_assets.join(", ")}</td>
                      <td className="muted">{formatDate(i.updated_at)}</td>
                      <td>
                        <Link
                          aria-label={`View ${i.title}`}
                          to={"/incidents/" + i.incident_id}
                        >
                          <ArrowUpRight size={17} />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={page}
              pageSize={20}
              total={data.total}
              onChange={setPage}
            />
          </>
        ) : (
          <Empty
            title="Your incident queue is clear"
            text="Select related alerts in the threat feed to open an investigation."
          />
        )}
      </Panel>
    </>
  );
}
export function Assets() {
  const { data, error, loading, reload } = useResource<{ items: Asset[] }>(
    "/assets",
  );
  const { user } = useAuth();
  const [search, setSearch] = useState(""),
    [edit, setEdit] = useState<Asset | null>(null);
  const items =
    data?.items.filter((a) =>
      `${a.hostname} ${a.ip_address}`
        .toLowerCase()
        .includes(search.toLowerCase()),
    ) || [];
  return (
    <>
      <PageHeading
        title="Asset inventory"
        description="Know what you protect. Track observed hosts and their security posture."
      />
      <div className="inventory-summary">
        <Server size={22} />
        <strong>{data?.items.length || 0}</strong>
        <span>observed assets</span>
        <span className="muted">
          Activity status is based on the latest received event.
        </span>
      </div>
      <Panel
        title="Monitored assets"
        action={
          <div className="search-input">
            <Search size={15} />
            <input
              aria-label="Search assets"
              placeholder="Find a host or IP…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        }
      >
        <ErrorBox message={error} />
        {loading ? (
          <Loading />
        ) : items.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>IP address</th>
                  <th>Activity</th>
                  <th>Open alerts</th>
                  <th>Highest risk</th>
                  <th>Last seen</th>
                  {user?.role === "admin" && <th />}
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <div className="alert-title">
                        <span className="asset-icon">
                          <Server size={18} />
                        </span>
                        <span>
                          {a.hostname}
                          <small>
                            {a.operating_system} · sensitivity {a.sensitivity}/3
                          </small>
                        </span>
                      </div>
                    </td>
                    <td className="mono">{a.ip_address || "Unknown"}</td>
                    <td>
                      <Badge value={a.agent_status} />
                    </td>
                    <td>
                      <Link
                        className="text-link"
                        to={"/alerts?host=" + encodeURIComponent(a.hostname)}
                      >
                        {a.number_of_alerts} alerts
                      </Link>
                    </td>
                    <td>
                      <div className="risk-inline">
                        <span>{a.risk_score}</span>
                        <div>
                          <i style={{ width: a.risk_score + "%" }} />
                        </div>
                      </div>
                    </td>
                    <td className="muted">{formatDate(a.last_seen)}</td>
                    {user?.role === "admin" && (
                      <td>
                        <button
                          className="text-button"
                          onClick={() => setEdit({ ...a })}
                        >
                          Edit
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            title="No assets to display"
            text="Hosts are discovered automatically when security events arrive."
          />
        )}
      </Panel>
      {edit && (
        <Modal title={"Edit " + edit.hostname} onClose={() => setEdit(null)}>
          <div className="modal-body form-stack">
            <label>
              Operating system
              <input
                value={edit.operating_system}
                onChange={(e) =>
                  setEdit({ ...edit, operating_system: e.target.value })
                }
              />
            </label>
            <label>
              Asset sensitivity
              <select
                value={edit.sensitivity}
                onChange={(e) =>
                  setEdit({ ...edit, sensitivity: Number(e.target.value) })
                }
              >
                <option value={1}>Standard</option>
                <option value={2}>Sensitive</option>
                <option value={3}>Critical</option>
              </select>
            </label>
            <p className="muted">
              Sensitivity affects risk scoring for future detections.
            </p>
            <ActionButton
              action={() =>
                patch("/assets/" + edit.id, {
                  operating_system: edit.operating_system,
                  sensitivity: edit.sensitivity,
                })
              }
              onDone={() => {
                setEdit(null);
                reload();
              }}
            >
              Save asset
            </ActionButton>
          </div>
        </Modal>
      )}
    </>
  );
}
export function Rules() {
  const { data, error, loading, reload } = useResource<{ items: Rule[] }>(
    "/rules",
  );
  const { user } = useAuth();
  const [selected, setSelected] = useState<Rule | null>(null);
  return (
    <>
      <PageHeading
        title="Detection rules"
        description="Transparent, configurable logic. Every alert starts with an explainable rule."
      />
      <div className="rules-banner">
        <ShieldCheck size={24} />
        <div>
          <strong>
            {data?.items.filter((r) => r.enabled).length || 0} active detections
          </strong>
          <p>
            Sigma selection syntax with bounded SentinelAI correlation. Rules
            analyze supplied logs only.
          </p>
        </div>
        <span className="mini-tag">SIGMA SUBSET</span>
      </div>
      <ErrorBox message={error} />
      {loading ? (
        <Loading />
      ) : (
        <div className="rules-grid">
          {data?.items.map((r) => (
            <section className="panel rule-card" key={r.id}>
              <div className="rule-card-top">
                <span className="rule-icon">
                  <Code2 size={20} />
                </span>
                <Badge value={r.definition.level} />
              </div>
              <button className="rule-title" onClick={() => setSelected(r)}>
                {r.title}
              </button>
              <p>{r.definition.description}</p>
              <div className="rule-tags">
                <span>{r.definition.sentinel.technique_id}</span>
                <span>{r.definition.sentinel.kind.replaceAll("_", " ")}</span>
              </div>
              <div className="rule-card-bottom">
                <span className={r.enabled ? "success-text" : "muted"}>
                  <i
                    className={r.enabled ? "status-light" : "inactive-light"}
                  />
                  {r.enabled ? "Enabled" : "Disabled"}
                </span>
                {user?.role === "admin" ? (
                  <ActionButton
                    className="text-button"
                    action={() =>
                      patch("/rules/" + r.id, { enabled: !r.enabled })
                    }
                    onDone={reload}
                  >
                    {r.enabled ? "Disable rule" : "Enable rule"}
                  </ActionButton>
                ) : (
                  <button
                    className="text-button"
                    onClick={() => setSelected(r)}
                  >
                    View rule
                  </button>
                )}
              </div>
            </section>
          ))}
        </div>
      )}
      {selected && (
        <Modal title={selected.title} onClose={() => setSelected(null)}>
          <div className="modal-body">
            <h3>Detection selection</h3>
            <pre>{JSON.stringify(selected.definition.detection, null, 2)}</pre>
            <h3>Correlation</h3>
            <p>
              {selected.definition.sentinel.threshold} matching records / values
              in {selected.definition.sentinel.window_seconds}s
            </p>
            <h3>Potential false positives</h3>
            <ul>
              {selected.definition.falsepositives.map((v) => (
                <li key={v}>{v}</li>
              ))}
            </ul>
            <p className="muted">
              Author: {selected.definition.author} · Configure definitions in
              rules/*.yml and restart the backend.
            </p>
          </div>
        </Modal>
      )}
    </>
  );
}
