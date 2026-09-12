import {
  fireEvent,
  render,
  screen,
  waitFor,
  cleanup,
} from "@testing-library/react";
import { describe, it, expect, vi, afterEach } from "vitest";
import { ActionButton, Pagination } from "./ui";
import { AlertTable } from "./AlertTable";
import { MemoryRouter } from "react-router-dom";
import type { Alert } from "../types";
afterEach(cleanup);
describe("Analyst UI", () => {
  it("reports failed mutations and permits retry", async () => {
    const action = vi
      .fn()
      .mockRejectedValueOnce(new Error("Permission denied"))
      .mockResolvedValueOnce({});
    render(<ActionButton action={action}>Save status</ActionButton>);
    fireEvent.click(screen.getByText("Save status"));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Permission denied",
    );
    fireEvent.click(screen.getByText("Save status"));
    await waitFor(() =>
      expect(screen.queryByRole("alert")).not.toBeInTheDocument(),
    );
    expect(action).toHaveBeenCalledTimes(2);
  });
  it("prevents pagination past either boundary", () => {
    const change = vi.fn();
    render(<Pagination page={1} total={2} pageSize={20} onChange={change} />);
    expect(screen.getByLabelText("Previous page")).toBeDisabled();
    expect(screen.getByLabelText("Next page")).toBeDisabled();
    expect(screen.getByText("1–2 of 2 records")).toBeInTheDocument();
  });
  it("renders untrusted alert text without executing HTML", () => {
    const alert = {
      alert_id: "a1",
      title: "<img src=x onerror=alert(1)>",
      source_ip: "198.51.100.1",
      affected_host: "host",
      technique_id: "T1110",
      severity: "high",
      status: "New",
      timestamp: "2026-01-01T00:00:00Z",
      risk_score: 70,
    } as Alert;
    render(
      <MemoryRouter>
        <AlertTable alerts={[alert]} />
      </MemoryRouter>,
    );
    expect(screen.getByText(alert.title)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByLabelText(`View ${alert.title}`)).toHaveAttribute(
      "href",
      "/alerts/a1",
    );
  });
  it("provides an empty state for an empty feed", () => {
    render(
      <MemoryRouter>
        <AlertTable alerts={[]} />
      </MemoryRouter>,
    );
    expect(screen.getByText("No records found")).toBeInTheDocument();
  });
});
