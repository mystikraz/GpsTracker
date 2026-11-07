import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("login is keyboard reachable and has no critical axe violations", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations.filter((item) => ["critical", "serious"].includes(item.impact ?? ""))).toEqual([]);
  await page.keyboard.press("Tab");
  await expect(page.locator(":focus")).toBeVisible();
});

test("reset page clears a fragment before submitting", async ({ page }) => {
  await page.goto("/reset-password#one-time-test-token");
  await expect(page).toHaveURL(/reset-password$/);
  await expect(page.getByRole("heading", { name: "Choose a new password" })).toBeVisible();
});
