import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/tool-grants.md");
const wizard = read("frontend/src/pages/EngagementWizard.tsx");
const registry = read("control-plane/app/tools/registry.py");
const gateway = read("control-plane/app/gateway/authorize.py");
const audit = read("frontend/src/pages/Audit.tsx");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}
function contains(source, pattern, message) {
  if (pattern instanceof RegExp) assert.match(source, pattern, message);
  else assert.equal(source.includes(pattern), true, message);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-TOOL-001 offers passive only when passive tools exist", () => {
  requirement("REQ-TOOL-001");
  contains(wizard, "passiveToolsByCategory", "Wizard must derive passive availability by category");
  contains(wizard, 'tool.execution_class === "passive"', "Wizard must use the registry execution class for passive availability");
  contains(wizard, "No passive tools", "Wizard must say when a category has no passive tools");
  contains(wizard, "Passive OSINT only", "Wizard summary must explain passive availability with concrete tools");
  contains(wizard, "public or third-party data sources", "Wizard help text must explain what passive means");
});

test("REQ-TOOL-002 saves passive grants only for executable passive categories", () => {
  requirement("REQ-TOOL-002");
  contains(wizard, "grant.passive && passiveToolsByCategory[category].length > 0", "Wizard must not save passive grants without passive tools");
  contains(registry, 'ToolSpec("subfinder", "recon", "passive"', "Registry must expose subfinder as a real passive recon tool");
  contains(registry, 'ToolSpec("amass", "recon", "passive"', "Registry must expose amass as a real passive recon tool");
  contains(registry, 'ToolSpec("nmap", "fingerprint", "raw_network"', "Registry must not model nmap as passive");
  contains(registry, 'ToolSpec("nuclei", "vuln", "http_proxy"', "Registry must not model nuclei as passive");
});

test("REQ-TOOL-003 gateway enforces passive mode as a real permission", () => {
  requirement("REQ-TOOL-003");
  contains(gateway, 'call.mode == "passive"', "Gateway must have a passive-mode branch");
  contains(gateway, '_tool_grant_for(db, eng.id, call.category, "passive")', "Gateway must require a passive grant");
  contains(gateway, 'tool_spec.execution_class != "passive"', "Gateway must verify passive execution class");
  contains(gateway, 'DENY("passive_not_supported")', "Gateway must deny non-passive tools in passive mode");
  contains(audit, "passive_not_supported", "Audit UI must explain passive_not_supported denials");
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
