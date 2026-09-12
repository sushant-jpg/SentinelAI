import { Link } from "react-router-dom";
import { ArrowUpRight, Crosshair } from "lucide-react";
import type { Alert } from "../types";
import { Badge, Empty, formatDate } from "./ui";
export function AlertTable({
  alerts,
  compact = false,
  selected,
  onSelect,
}: {
  alerts: Alert[];
  compact?: boolean;
  selected?: string[];
  onSelect?: (id: string) => void;
}) {
  if (!alerts.length) return <Empty />;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {onSelect && <th>Select</th>}
            <th>Detection / source</th>
            <th>Severity</th>
            <th>Target host</th>
            {!compact && <th>Risk score</th>}
            <th>Status</th>
            <th>Detected</th>
            <th aria-label="Open" />
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.alert_id}>
              {onSelect && (
                <td>
                  <input
                    aria-label={`Select ${alert.title} ${alert.alert_id}`}
                    type="checkbox"
                    checked={selected?.includes(alert.alert_id)}
                    onChange={() => onSelect(alert.alert_id)}
                  />
                </td>
              )}
              <td>
                <Link className="alert-title" to={`/alerts/${alert.alert_id}`}>
                  <span className={`detection-icon ${alert.severity}`}>
                    <Crosshair size={16} />
                  </span>
                  <span>
                    {alert.title}
                    <small className="mono">
                      {alert.source_ip || "Local activity"}
                      <span className="dot-separator">·</span>
                      {alert.technique_id}
                    </small>
                  </span>
                </Link>
              </td>
              <td>
                <Badge value={alert.severity} />
              </td>
              <td className="mono muted">{alert.affected_host}</td>
              {!compact && (
                <td>
                  <div className="risk-inline">
                    <span>{alert.risk_score}</span>
                    <div>
                      <i style={{ width: `${alert.risk_score}%` }} />
                    </div>
                  </div>
                </td>
              )}
              <td>
                <Badge value={alert.status} />
              </td>
              <td className="muted nowrap">{formatDate(alert.timestamp)}</td>
              <td>
                <Link
                  aria-label={`View ${alert.title}`}
                  to={`/alerts/${alert.alert_id}`}
                >
                  <ArrowUpRight size={16} />
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
