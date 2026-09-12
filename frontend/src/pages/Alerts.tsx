import { useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { Search, SlidersHorizontal, Plus, Upload } from "lucide-react";
import { useResource } from "../hooks/useResource";
import { useAuth } from "../hooks/Auth";
import { api, post } from "../services/api";
import type { Alert, Page, Incident } from "../types";
import { AlertTable } from "../components/AlertTable";
import {
  PageHeading,
  Panel,
  Loading,
  ErrorBox,
  Pagination,
  Modal,
} from "../components/ui";
export function Alerts() {
  const [params, setParams] = useSearchParams(),
    navigate = useNavigate();
  const { user } = useAuth();
  const writable = user?.role !== "viewer";
  const [advanced, setAdvanced] = useState(false),
    [selected, setSelected] = useState<string[]>([]),
    [modal, setModal] = useState<"incident" | "import" | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [title, setTitle] = useState(""),
    [source, setSource] = useState("suricata"),
    [payload, setPayload] = useState(""),
    [result, setResult] = useState("");
  const page = Number(params.get("page") || 1);
  const query = new URLSearchParams(params);
  query.set("page_size", "20");
  for (const key of ["start", "end"]) {
    const value = query.get(key);
    if (value) {
      const date = new Date(value);
      if (!Number.isNaN(date.getTime())) query.set(key, date.toISOString());
    }
  }
  const resource = useResource<Page<Alert>>("/alerts?" + query);
  function filter(key: string, value: string) {
    const next = new URLSearchParams(params);
    value ? next.set(key, value) : next.delete(key);
    next.delete("page");
    setParams(next);
    setSelected([]);
  }
  return (
    <>
      <PageHeading
        title="Threat alerts"
        description="Investigate detections, connect the evidence, and take action."
        action={
          writable && (
            <>
              <button
                className="button"
                onClick={() => {
                  setModal("import");
                  setError("");
                }}
              >
                <Upload size={15} />
                Import logs
              </button>
              <button
                className="button primary"
                disabled={!selected.length}
                onClick={() => {
                  setModal("incident");
                  setError("");
                }}
              >
                <Plus size={16} />
                Create incident{selected.length ? ` (${selected.length})` : ""}
              </button>
            </>
          )
        }
      />
      <Panel
        title="Detection feed"
        subtitle={`${resource.data?.total || 0} matching alerts`}
      >
        <div className="filters">
          <div className="search-input">
            <Search size={16} />
            <input
              aria-label="Search alerts"
              placeholder="Search alerts, IP addresses, hosts…"
              value={params.get("q") || ""}
              onChange={(e) => filter("q", e.target.value)}
            />
          </div>
          <select
            aria-label="Severity filter"
            value={params.get("severity") || ""}
            onChange={(e) => filter("severity", e.target.value)}
          >
            <option value="">All severities</option>
            {["critical", "high", "medium", "low", "informational"].map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
          <select
            aria-label="Status filter"
            value={params.get("status") || ""}
            onChange={(e) => filter("status", e.target.value)}
          >
            <option value="">All statuses</option>
            {["New", "Investigating", "Resolved", "False Positive"].map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
          <button
            className={`button ${advanced ? "active" : ""}`}
            onClick={() => setAdvanced(!advanced)}
          >
            <SlidersHorizontal size={15} />
            Filters
          </button>
        </div>
        {advanced && (
          <div className="advanced-filters">
            {[
              ["ip", "Source IP"],
              ["host", "Hostname"],
              ["username", "Username"],
              ["event_type", "Event type"],
              ["technique", "MITRE technique"],
              ["min_risk", "Minimum risk"],
              ["max_risk", "Maximum risk"],
              ["start", "From"],
              ["end", "Until"],
            ].map(([key, label]) => (
              <label key={key}>
                {label}
                <input
                  aria-label={label}
                  type={
                    key.includes("risk")
                      ? "number"
                      : key === "start" || key === "end"
                        ? "datetime-local"
                        : "text"
                  }
                  min={0}
                  max={100}
                  value={params.get(key) || ""}
                  onChange={(e) => filter(key, e.target.value)}
                />
              </label>
            ))}
            <button className="text-button" onClick={() => setParams({})}>
              Reset filters
            </button>
          </div>
        )}
        <ErrorBox message={resource.error} />
        {resource.loading ? (
          <Loading />
        ) : (
          <>
            <AlertTable
              alerts={resource.data?.items || []}
              selected={selected}
              onSelect={
                writable
                  ? (id) =>
                      setSelected((list) =>
                        list.includes(id)
                          ? list.filter((v) => v !== id)
                          : [...list, id],
                      )
                  : undefined
              }
            />
            <Pagination
              page={page}
              total={resource.data?.total || 0}
              pageSize={20}
              onChange={(p) => {
                const next = new URLSearchParams(params);
                next.set("page", String(p));
                setParams(next);
              }}
            />
          </>
        )}
      </Panel>
      {modal && (
        <Modal
          title={
            modal === "incident"
              ? "Group alerts into an incident"
              : "Import sensor logs"
          }
          onClose={() => setModal(null)}
        >
          <form
            className="modal-body"
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              setError("");
              try {
                if (modal === "incident") {
                  const incident = await post<Incident>("/incidents", {
                    title,
                    related_alerts: selected,
                  });
                  navigate("/incidents/" + incident.incident_id);
                } else {
                  const data = await api<{
                    accepted: number;
                    duplicates: number;
                    alerts_created: number;
                  }>(`/events/import/${source}`, {
                    method: "POST",
                    body: payload,
                  });
                  setResult(
                    `${data.accepted} events imported · ${data.alerts_created} alerts created · ${data.duplicates} duplicates skipped`,
                  );
                  resource.reload();
                }
              } catch (e) {
                setError((e as Error).message);
              } finally {
                setBusy(false);
              }
            }}
          >
            {modal === "incident" ? (
              <>
                <p>
                  {selected.length} selected alerts will be linked to this
                  incident.
                </p>
                <label>
                  Incident title
                  <input
                    autoFocus
                    required
                    minLength={3}
                    maxLength={200}
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                  />
                </label>
              </>
            ) : (
              <>
                <p>
                  Paste a JSON object, array, or newline-delimited JSON. Maximum
                  500 events / 2 MB.
                </p>
                <label>
                  Sensor
                  <select
                    value={source}
                    onChange={(e) => setSource(e.target.value)}
                  >
                    <option value="suricata">Suricata EVE JSON</option>
                    <option value="wazuh">Wazuh alert JSON</option>
                  </select>
                </label>
                <label>
                  Log records
                  <textarea
                    required
                    rows={10}
                    className="mono"
                    value={payload}
                    onChange={(e) => setPayload(e.target.value)}
                  />
                </label>
                {result && (
                  <p className="success-text" role="status">
                    {result}
                  </p>
                )}
              </>
            )}
            <ErrorBox message={error} />
            <button className="button primary" disabled={busy}>
              {busy
                ? "Processing…"
                : modal === "incident"
                  ? "Create incident"
                  : "Import events"}
            </button>
          </form>
        </Modal>
      )}
    </>
  );
}
