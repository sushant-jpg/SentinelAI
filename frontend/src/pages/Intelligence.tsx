import { useState } from "react";
import {
  Sparkles,
  ChartNoAxesCombined,
  Timer,
  ShieldCheck,
} from "lucide-react";
import { useResource } from "../hooks/useResource";
import { post } from "../services/api";
import type { Analytics as Metrics, Alert, Page, Explanation } from "../types";
import {
  PageHeading,
  Panel,
  Loading,
  ErrorBox,
  ActionButton,
} from "../components/ui";
import { ActivityChart, SeverityChart, Ranking } from "../components/Charts";
import { ExplanationView } from "./Details";
export function Analytics() {
  const [days, setDays] = useState(7);
  const { data, error, loading } = useResource<Metrics>(
    "/analytics?days=" + days,
  );
  return (
    <>
      <PageHeading
        title="Threat analytics"
        description="Find recurring patterns and understand the shape of your threat landscape."
        action={
          <select
            aria-label="Analytics range"
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
          >
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </select>
        }
      />
      <ErrorBox message={error} />
      {loading ? (
        <Loading />
      ) : (
        data && (
          <>
            <div className="analytics-metrics">
              <div>
                <ChartNoAxesCombined />
                <span>
                  <small>Detected alerts</small>
                  <strong>{data.total_alerts}</strong>
                </span>
              </div>
              <div>
                <Timer />
                <span>
                  <small>Mean incident resolution time · all time</small>
                  <strong>
                    {data.mttr_hours === null
                      ? "No resolved incidents"
                      : `${data.mttr_hours} hours`}
                  </strong>
                </span>
              </div>
              <div>
                <ShieldCheck />
                <span>
                  <small>Resolved incidents · all time</small>
                  <strong>{data.resolved_incidents}</strong>
                </span>
              </div>
            </div>
            <div className="chart-grid">
              <Panel title="Security trends" subtitle="Alerts detected by day">
                <ActivityChart data={data.trend} />
              </Panel>
              <Panel title="Severity distribution">
                <SeverityChart
                  severity={data.severity}
                  total={data.total_alerts}
                />
              </Panel>
            </div>
            <div className="analytics-grid">
              {[
                ["Most common detections", data.detections],
                ["Top source IP addresses", data.top_ips],
                ["Most targeted hosts", data.top_hosts],
                ["Most affected accounts", data.top_users],
              ].map(([title, values]) => (
                <Panel title={title as string} key={title as string}>
                  <Ranking data={values as Metrics["top_ips"]} />
                </Panel>
              ))}
            </div>
          </>
        )
      )}
    </>
  );
}
export function AIAnalysis() {
  const { data, error, loading } = useResource<Page<Alert>>(
    "/alerts?page_size=100",
  );
  const [id, setId] = useState(""),
    [analysis, setAnalysis] = useState<Explanation | null>(null);
  return (
    <>
      <PageHeading
        eyebrow="ASSISTED INVESTIGATION"
        title="Your AI security analyst"
        description="Evidence first. Clear explanations and defensive guidance, with you in control."
      />
      <div className="ai-workspace">
        <Panel title="Choose a detection" action={<Sparkles size={18} />}>
          <div className="panel-body">
            <p className="muted">
              Analysis begins with an alert already identified by the
              deterministic engine. Select from the latest 100 detections, or
              open any alert to analyze it.
            </p>
            <ErrorBox message={error} />
            {loading ? (
              <Loading />
            ) : (
              <label>
                Security alert
                <select
                  value={id}
                  onChange={(e) => {
                    setId(e.target.value);
                    setAnalysis(null);
                  }}
                >
                  <option value="">Select an alert…</option>
                  {data?.items.map((a) => (
                    <option value={a.alert_id} key={a.alert_id}>
                      {a.title} · {a.affected_host} · {a.risk_score}/100
                    </option>
                  ))}
                </select>
              </label>
            )}
            <ActionButton
              action={async () => {
                if (!id) throw new Error("Select a detection to analyze");
                setAnalysis(await post<Explanation>("/ai/alerts/" + id));
              }}
              className="button ai-button"
            >
              <Sparkles size={16} />
              Generate analysis
            </ActionButton>
            <div className="context-note">
              <ShieldCheck size={18} />
              AI guidance cannot change alert severity, create evidence, or
              initiate a response.
            </div>
          </div>
        </Panel>
        <Panel
          title="Investigation brief"
          subtitle="Observed evidence · interpretation · recommendations"
        >
          {analysis ? (
            <div className="panel-body">
              <ExplanationView data={analysis} />
            </div>
          ) : (
            <div className="ai-empty">
              <div className="ai-card-icon">
                <Sparkles size={30} />
              </div>
              <h2>Context for your next move.</h2>
              <p>
                Select a detection to get an evidence summary, possible impact,
                and recommended investigation steps.
              </p>
              <div>
                <span>01 / Understand</span>
                <span>02 / Investigate</span>
                <span>03 / Respond</span>
              </div>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
