import { useState } from "react";
import {
  ShieldCheck,
  Users as UsersIcon,
  Database,
  Lock,
  Plug,
  Sparkles,
} from "lucide-react";
import { useAuth } from "../hooks/Auth";
import { useResource } from "../hooks/useResource";
import { patch, post } from "../services/api";
import type { User, Settings as SettingsData, Audit, Page } from "../types";
import {
  PageHeading,
  Panel,
  Loading,
  ErrorBox,
  Badge,
  ActionButton,
  Pagination,
  formatDate,
} from "../components/ui";
export function AuditLogs() {
  const [page, setPage] = useState(1);
  const { data, error, loading } = useResource<Page<Audit>>(
    "/audit?page=" + page,
  );
  return (
    <>
      <PageHeading
        title="Audit trail"
        description="A traceable record of access, investigations, and administrative changes."
      />
      <Panel title="Activity log" action={<ShieldCheck size={19} />}>
        <ErrorBox message={error} />
        {loading ? (
          <Loading />
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Actor</th>
                    <th>Action</th>
                    <th>Target</th>
                    <th>Source IP</th>
                  </tr>
                </thead>
                <tbody>
                  {data?.items.map((a) => (
                    <tr key={a.id}>
                      <td className="nowrap muted">
                        {formatDate(a.timestamp)}
                      </td>
                      <td>{a.user}</td>
                      <td>
                        <span className="audit-action">{a.action}</span>
                      </td>
                      <td className="mono muted truncate" title={a.target}>
                        {a.target}
                      </td>
                      <td className="mono">{a.source_ip}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={page}
              total={data?.total || 0}
              pageSize={25}
              onChange={setPage}
            />
          </>
        )}
      </Panel>
    </>
  );
}
export function Users() {
  const { user } = useAuth();
  const { data, error, loading, reload } = useResource<{ items: User[] }>(
    "/users",
  );
  const [mutationError, setMutationError] = useState("");
  async function update(id: string, body: unknown) {
    setMutationError("");
    try {
      await patch("/users/" + id, body);
      reload();
    } catch (e) {
      setMutationError((e as Error).message);
    }
  }
  return (
    <>
      <PageHeading
        title="User management"
        description="Give your team the right access. New registrations begin with viewer permissions."
      />
      <Panel title="Workspace members" action={<UsersIcon size={19} />}>
        <ErrorBox message={error || mutationError} />
        {loading ? (
          <Loading />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Member</th>
                  <th>Role</th>
                  <th>Account status</th>
                  <th>Access</th>
                </tr>
              </thead>
              <tbody>
                {data?.items.map((u) => (
                  <tr key={u.id}>
                    <td>
                      <div className="alert-title">
                        <div className="avatar">
                          {u.name.slice(0, 2).toUpperCase()}
                        </div>
                        <span>
                          {u.name}
                          {u.id === user?.id ? " (you)" : ""}
                          <small>{u.email}</small>
                        </span>
                      </div>
                    </td>
                    <td>
                      <select
                        aria-label={`Role for ${u.name}`}
                        value={u.role}
                        disabled={u.id === user?.id}
                        onChange={(e) => update(u.id, { role: e.target.value })}
                      >
                        <option value="viewer">Viewer</option>
                        <option value="analyst">Analyst</option>
                        <option value="admin">Admin</option>
                      </select>
                    </td>
                    <td>
                      <Badge value={u.active ? "active" : "disabled"} />
                    </td>
                    <td>
                      {u.id !== user?.id && (
                        <button
                          className="text-button"
                          onClick={() => update(u.id, { active: !u.active })}
                        >
                          {u.active ? "Deactivate" : "Reactivate"}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <div className="context-note">
        <Lock size={18} />
        Changing a member’s permissions revokes their existing sessions. Your
        own administrator access cannot be changed here.
      </div>
    </>
  );
}
export function Settings() {
  const { user } = useAuth();
  const { data, error, loading } = useResource<SettingsData>("/settings");
  const [result, setResult] = useState("");
  return (
    <>
      <PageHeading
        title="Workspace settings"
        description="Review your environment, integrations, and security configuration."
      />
      <ErrorBox message={error} />
      {loading ? (
        <Loading />
      ) : (
        data && (
          <div className="settings-grid">
            <Panel title="Environment" action={<Database size={18} />}>
              <div className="panel-body settings-values">
                <div>
                  <span>Deployment</span>
                  <strong>{data.environment}</strong>
                </div>
                <div>
                  <span>Demo mode</span>
                  <Badge value={data.demo_mode ? "enabled" : "disabled"} />
                </div>
                <div>
                  <span>Self-registration</span>
                  <strong>
                    {data.registration_enabled
                      ? "Enabled · viewer role"
                      : "Disabled"}
                  </strong>
                </div>
                <p className="muted">
                  Server configuration is managed through environment variables.
                  Restart the backend after changes.
                </p>
                {user?.role === "admin" && data.demo_mode && (
                  <>
                    <ActionButton
                      action={async () => {
                        const r = await post<{
                          accepted: number;
                          alerts_created: number;
                        }>("/events/demo");
                        setResult(
                          `${r.accepted} simulated records ingested; ${r.alerts_created} detections created.`,
                        );
                      }}
                    >
                      Generate demo events
                    </ActionButton>
                    {result && (
                      <p role="status" className="success-text">
                        {result}
                      </p>
                    )}
                  </>
                )}
              </div>
            </Panel>
            <Panel title="Authentication" action={<Lock size={18} />}>
              <div className="panel-body settings-values">
                <div>
                  <span>Password hashing</span>
                  <strong>Argon2id</strong>
                </div>
                <div>
                  <span>Access token lifetime</span>
                  <strong>{data.access_token_minutes} minutes</strong>
                </div>
                <div>
                  <span>Refresh session</span>
                  <strong>7 days · rotating token</strong>
                </div>
                <div>
                  <span>Your role</span>
                  <strong>{user?.role}</strong>
                </div>
                <div>
                  <span>Login limits</span>
                  <strong>Account + source IP</strong>
                </div>
              </div>
            </Panel>
            <Panel title="Sensor integrations" action={<Plug size={18} />}>
              <div className="panel-body settings-values">
                {Object.entries(data.integrations).map(([name, state]) => (
                  <div key={name}>
                    <strong>{name}</strong>
                    <span>{state}</span>
                  </div>
                ))}
                <p className="muted">
                  Import logs from Threat alerts, or send authenticated
                  collector requests to the integration API. Sensor connectivity
                  is not inferred from API availability.
                </p>
              </div>
            </Panel>
            <Panel title="AI & detection" action={<Sparkles size={18} />}>
              <div className="panel-body settings-values">
                <div>
                  <span>Explanation provider</span>
                  <strong>{data.ai_provider}</strong>
                </div>
                <div>
                  <span>Rules</span>
                  <strong>{data.rule_format}</strong>
                </div>
                <p className="muted">
                  Local explanations are available without API credentials.
                  External AI is explicitly configured on the server;
                  deterministic evidence remains authoritative.
                </p>
              </div>
            </Panel>
          </div>
        )
      )}
    </>
  );
}
