import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/bounty-network-scan-profile.md");
const wizard = read("frontend/src/pages/EngagementWizard.tsx");
const edit = read("frontend/src/pages/EngagementEdit.tsx");
const client = read("frontend/src/api/client.ts");
const engagementSchema = read("control-plane/app/schemas/engagement.py");
const rawEgressLease = read("control-plane/app/gateway/raw_egress_lease.py");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}

function contains(source, pattern, message) {
  if (pattern instanceof RegExp) assert.match(source, pattern, message);
  else assert.equal(source.includes(pattern), true, message);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-BOUNTYSCAN-001 is documented with the three-tier model", () => {
  requirement("REQ-BOUNTYSCAN-001");
  contains(requirementDoc, "GitHub issue #37", "requirement doc must record the issue this closes");
  contains(requirementDoc, '"none", "common", "full"', "requirement doc must name the three tiers");
});

test("REQ-BOUNTYSCAN-002/003 document the rate-unit and evidence rules", () => {
  requirement("REQ-BOUNTYSCAN-002");
  requirement("REQ-BOUNTYSCAN-003");
  contains(requirementDoc, "raw_max_packets_per_second", "requirement doc must name the distinct raw-rate field");
});

test("REQ-BOUNTYSCAN-004 documents the kernel-level limiter", () => {
  requirement("REQ-BOUNTYSCAN-004");
  contains(requirementDoc, "limit rate", "requirement doc must name the nftables enforcement mechanism");
});

test("the requirement doc records the deliberate scope reduction from the issue's full proposal", () => {
  contains(requirementDoc, "Deliberate scope reduction", "requirement doc must explicitly record what was descoped, not silently under-deliver");
});

test("BountyProgramCreate schema carries the three new fields and enforces the evidence rule", () => {
  contains(engagementSchema, 'tcp_syn_scan_profile: Literal["none", "common", "full"]', "schema must declare the closed tier enum");
  contains(engagementSchema, "raw_max_packets_per_second", "schema must carry the distinct raw-rate field");
  contains(engagementSchema, "network_scan_authorization_evidence", "schema must carry the authorization-evidence field");
  contains(engagementSchema, "validate_full_profile_requires_evidence", "schema must validate the full-tier evidence requirement");
});

test("the gateway makes tcp_syn_scan_profile control configured_tcp/full_tcp exemption for bug_bounty", () => {
  contains(rawEgressLease, "allowed_profiles", "gateway must build an explicit allowed-profile set from the program's tier");
  contains(rawEgressLease, "full_tcp_requires_authorization_evidence", "gateway must independently re-check the evidence requirement, not trust the schema alone");
  contains(rawEgressLease, "_effective_raw_max_rate", "gateway must use the shared rate helper distinguishing raw_max_packets_per_second from max_rps");
});

test("the wizard and edit page both expose the network-scan tier fields", () => {
  for (const [name, source] of [["wizard", wizard], ["edit page", edit]]) {
    contains(source, "bountyTcpSynScanProfile", `${name} must manage the network-scan tier as state`);
    contains(source, "bountyRawMaxPps", `${name} must collect the optional raw packet-rate cap`);
    contains(source, "bountyNetworkScanEvidence", `${name} must collect the full-tier authorization evidence`);
    contains(source, "tcp_syn_scan_profile", `${name} must submit tcp_syn_scan_profile to the API`);
  }
});

test("the frontend BountyProgram type carries the three new fields", () => {
  contains(client, "tcp_syn_scan_profile", "client type must carry the scan-tier field");
  contains(client, "raw_max_packets_per_second", "client type must carry the raw-rate field");
  contains(client, "network_scan_authorization_evidence", "client type must carry the evidence field");
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
