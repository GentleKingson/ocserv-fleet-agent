const { test, expect } = require("@playwright/test");

test("dashboard loads read-only views and audit preview", async ({ page }) => {
  const consoleErrors = [];
  const writeRequests = [];
  page.on("console", message => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  page.on("request", request => {
    if (request.method() !== "GET") writeRequests.push(`${request.method()} ${request.url()}`);
  });

  const response = await page.goto("/");
  expect(response).not.toBeNull();
  expect(response.status()).toBe(200);
  expect(response.headers()["content-security-policy"]).toContain("default-src 'none'");
  await expect(page.getByRole("heading", { level: 1, name: "ocfleet" })).toBeVisible();
  await expect(page.getByRole("heading", { level: 2 })).toHaveCount(7);
  await expect(page.getByRole("status")).toContainText("Updated");
  await expect(page.locator("#nodes")).toContainText("No rows");
  await expect(page.locator("#jobs")).toContainText("No rows");
  await expect(page.locator("#alerts")).toContainText("No rows");

  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByRole("status")).toContainText("Updated");
  await page.getByRole("button", { name: "Preview" }).click();
  await expect(page.locator("#audit")).toContainText(/No rows|controller\.init/);

  expect(writeRequests).toEqual([]);
  expect(consoleErrors).toEqual([]);
});

test("dashboard remains usable at a narrow viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.getByRole("status")).toContainText("Updated");
  await expect(page.getByRole("button", { name: "Refresh" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Preview" })).toBeVisible();

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  expect(overflow).toBe(false);
});
