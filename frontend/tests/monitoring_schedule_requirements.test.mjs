import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirements = readRecord("requirements", "operating-modes-scheduler.md");
const client = read("frontend/src/api/client.ts");
const control = read("frontend/src/components/ScheduleControl.tsx");
const detail = read("frontend/src/pages/EngagementDetail.tsx");
const wizard = read("frontend/src/pages/MonitorWizard.tsx");

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-MON-004 the monitor wizard turns automatic runs on, every 7 days, and shows the control in step 2", () => {
  record.match(requirements, /## REQ-MON-004:/);
  assert.match(wizard, /const DEFAULT_EVERY_DAYS = 7;/);
  assert.match(wizard, /await api\.putSchedule\(id, DEFAULT_EVERY_DAYS\);/);
  assert.match(wizard, /<ScheduleControl engagementId=\{engagementId\} canManage \/>/);
  // The old line promised a schedule that did not exist; it must say what is true now.
  assert.doesNotMatch(wizard, /The\s+schedule stops by itself/);
  assert.match(wizard, /Automatic runs stop by themselves when the authorization ends or its review date passes/);
});

test("REQ-MON-004 a monitoring engagement page shows the interval, the next run and why a due run waits", () => {
  assert.match(detail, /isMonitoring && !isDraft && engagement\.status !== "completed" && engagement\.status !== "revoked"/);
  assert.match(detail, /<ScheduleControl engagementId=\{engagement\.id\} canManage=\{canManage\} \/>/);
  assert.match(control, /Next run:/);
  assert.match(control, /schedule\.skip_message/);
  assert.match(control, /A run is due but did not start/);
  assert.match(control, /Off\. A run starts only when you press Run now\./);
});

test("REQ-MON-001 the interval is whole days from the limits the server reports, and null switches it off", () => {
  assert.match(control, /Number\.isInteger\(parsed\) && parsed >= min && parsed <= max/);
  assert.match(control, /type="number" min=\{min\} max=\{max\} step=\{1\}/);
  assert.match(control, /save\.mutate\(null\)/);
  assert.match(client, /putSchedule: \(id: string, everyDays: number \| null\)/);
  assert.match(client, /body: JSON\.stringify\(\{ every_days: everyDays \}\)/);
  assert.match(client, /min_days: number;\s*max_days: number;/);
});

test("REQ-MON-004 a non-owner sees the schedule read-only", () => {
  assert.match(control, /\{canManage \? \(/);
  assert.match(control, /Only the owner or an administrator can change this/);
});

test("REQ-MON-003 the console never offers a way to start a run on a schedule's behalf", () => {
  // The schedule control sets an interval only; starting runs stays Run now and the server's scheduler.
  assert.doesNotMatch(control, /startScan|api\.startScan|\/scan"/);
});

let failed = 0;
for (const { name, fn } of tests) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`not ok - ${name}`);
    console.error(error.stack || error.message || error);
  }
}
if (failed) {
  console.error(`${failed} requirement test(s) failed`);
  process.exit(1);
}
console.log(`${tests.length} requirement test(s) passed`);
