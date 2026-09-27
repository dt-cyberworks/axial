import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirement = read("docs/requirements/audit-log-readability.md");
const client = read("frontend/src/api/client.ts");
const audit = read("frontend/src/pages/Audit.tsx");
const multiSelect = read("frontend/src/components/MultiSelectFilter.tsx");
const streamApi = read("control-plane/app/api/stream.py");

assert.match(requirement, /## REQ-AUDITUI-003:/);

// --- wire format: repeated params, matched with IN ---
assert.match(client, /actor\?: string\[\];/, "AuditQuery.actor must be a list");
assert.match(client, /action\?: string\[\];/, "AuditQuery.action must be a list");
assert.match(client, /for \(const value of query\.actor \?\? \[\]\) qs\.append\("actor", value\);/);
assert.match(client, /for \(const value of query\.action \?\? \[\]\) qs\.append\("action", value\);/);
assert.match(streamApi, /AuditLog\.actor\.in_\(actors\)/, "the backend must filter with IN");
assert.match(streamApi, /AuditLog\.action\.in_\(actions\)/);
assert.match(streamApi, /_MAX_FACET_FILTER_VALUES = \d+/, "the IN list must be bounded");

// --- the checkbox control itself ---
assert.match(multiSelect, /type="checkbox"/, "facet values must render as checkboxes");
assert.match(multiSelect, /checked=\{!excluded\.has\(value\)\}/, "unchecked means excluded");
assert.match(multiSelect, /Select all/);
assert.match(multiSelect, /Clear all/);
// Partial selection is visible at a glance without opening the popover.
assert.match(multiSelect, /\$\{selectedCount\}\/\$\{options\.length\}/, "the trigger must show a n/total summary");

// --- excluded-set model: a live log must not hide newly-seen values ---
assert.match(audit, /excludedActors, setExcludedActors\] = useState<Set<string>>/);
assert.match(audit, /excludedActions, setExcludedActions\] = useState<Set<string>>/);
assert.match(
  audit,
  /excludedActors\.size \? facets\.actors\.filter\(\(a\) => !excludedActors\.has\(a\)\) : \[\]/,
  "an unfiltered facet must send nothing rather than enumerating every value",
);

// --- clearing every value shows nothing, and issues no request ---
assert.match(audit, /const actorsAllExcluded = excludedActors\.size > 0 && actor\.length === 0;/);
assert.match(audit, /const nothingSelectable = actorsAllExcluded \|\| actionsAllExcluded;/);
assert.match(audit, /if \(nothingSelectable\) \{/, "loadHead must short-circuit instead of querying");
assert.match(audit, /if \(f\.nothingSelectable\) return;/, "auto-refresh must short-circuit too");

// --- the single-select dropdowns are gone ---
assert.doesNotMatch(audit, /All actors<\/option>/, "the single-select actor dropdown must be replaced");
assert.doesNotMatch(audit, /All actions<\/option>/, "the single-select action dropdown must be replaced");

console.log("ok - REQ-AUDITUI-003 audit actor/action filters support multi-select");
