import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { readRecord, record } from "./_records.mjs";

// REQ-PORTSCAN-003 (GitHub issue #60): the console never shows a port scan with gaps as a clean success.
const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = readRecord("requirements", "port-scan-completeness.md");
const activity = read("frontend/src/lib/runActivity.ts");

for (const id of ["REQ-PORTSCAN-001", "REQ-PORTSCAN-002", "REQ-PORTSCAN-003", "REQ-PORTSCAN-004"]) {
  record.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}

// Both reasons have a plain-language text that says what it means and what to check.
assert.match(activity, /probes_dropped: "The scanner's own firewall refused to send some of nmap's probes/);
assert.match(activity, /ports_no_longer_open: "Ports that earlier runs found open were not found this time/);
assert.match(activity, /Check the target before relying on this list/);

// A successful result that carries partial reasons is an attention item, not a plain success.
assert.match(activity, /outcomeSummary\.partial_reasons/);
assert.match(activity, /title: `\$\{title\}, but the result is incomplete`/);
assert.match(activity, /outcome: "Partial",\s+tone: "attention"/);
assert.match(activity, /countsAsAttention: true/);

// The state counts are no longer called UDP-only, and the refused probes are shown as a lower bound.
assert.match(activity, /label: protocol === "UDP" \? "UDP states" : `\$\{protocol \|\| "Port"\} states`/);
assert.doesNotMatch(activity, /label: "UDP states"/);
assert.match(activity, /`\$\{dropped\} or more`/);
console.log("ok");
