import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
const env = Object.fromEntries(
  readFileSync("../.env", "utf8")
    .split("\n")
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => {
      const at = line.indexOf("=");
      return [line.slice(0, at), line.slice(at + 1)];
    }),
);
test("SOC investigation from login through incident resolution", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/login");
  await page.getByLabel("Email address").fill(env.BOOTSTRAP_ADMIN_EMAIL);
  await page
    .getByLabel("Password", { exact: true })
    .fill(env.BOOTSTRAP_ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Sign in to workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
  const demoButton = page.getByRole("button", { name: "Generate demo events" });
  await expect(demoButton).toBeVisible();
  await expect(page.getByRole("status")).toHaveCount(0);
  if (
    !(await page
      .getByRole("link", { name: /SSH brute-force attempt/ })
      .first()
      .isVisible())
  ) {
    const [response] = await Promise.all([
      page.waitForResponse(
        (r) =>
          r.url().endsWith("/api/events/demo") &&
          r.request().method() === "POST",
      ),
      demoButton.click(),
    ]);
    expect(response.status()).toBe(201);
  }
  await expect(
    page.getByRole("link", { name: /SSH brute-force attempt/ }).first(),
  ).toBeVisible({ timeout: 30000 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(2500);
  await page.screenshot({
    path: "../docs/dashboard-desktop.png",
    fullPage: true,
  });
  await page.getByRole("link", { name: "View all alerts" }).click();
  await expect(
    page.getByRole("heading", { name: "Threat alerts", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("combobox", { name: "Severity filter" })
    .selectOption("critical");
  await expect(
    page.getByRole("link", { name: /Network intrusion signature/ }).first(),
  ).toBeVisible();
  await page
    .getByRole("link", { name: /Network intrusion signature/ })
    .first()
    .click();
  await expect(
    page.getByRole("heading", { name: "Observed event evidence" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Explain this alert" }).click();
  await expect(
    page.getByRole("heading", { name: "Observed evidence", exact: true }),
  ).toBeVisible();
  const note = `Browser verification: reviewed simulated evidence ${Date.now()}.`;
  await page.getByLabel("Investigation note").fill(note);
  await page.getByRole("button", { name: "Add note", exact: true }).click();
  await expect(page.getByLabel("Investigation note")).toHaveValue("");
  await expect(page.getByText(note, { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Back to alerts" }).click();
  await page.getByRole("checkbox").first().check();
  await page.getByRole("button", { name: /Create incident/ }).click();
  await page
    .getByLabel("Incident title")
    .fill("Simulated intrusion investigation");
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Create incident", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Incident timeline" }),
  ).toBeVisible();
  await page
    .getByLabel("Resolution", { exact: true })
    .fill("Simulated activity confirmed; no containment required.");
  await page
    .getByRole("combobox", { name: "Status", exact: true })
    .selectOption("Resolved");
  await expect(
    page.getByRole("heading", { name: "Resolution", exact: true }),
  ).toBeVisible();
  for (const [route, heading] of [
    ["/assets", "Asset inventory"],
    ["/rules", "Detection rules"],
    ["/analytics", "Threat analytics"],
    ["/ai", "Your AI security analyst"],
    ["/audit", "Audit trail"],
    ["/users", "User management"],
    ["/settings", "Workspace settings"],
  ]) {
    await page.goto(route);
    await expect(
      page.getByRole("heading", { name: heading, exact: true }),
    ).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);
  }
  await page.goto("/");
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Open navigation" }),
  ).toBeVisible();
  await page.waitForTimeout(2500);
  await page.screenshot({
    path: "../docs/dashboard-mobile.png",
    fullPage: true,
  });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
  await page.getByRole("button", { name: "Open navigation" }).click();
  await page.getByRole("link", { name: "Assets", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Asset inventory" }),
  ).toBeVisible();
  expect(errors).toEqual([]);
});
