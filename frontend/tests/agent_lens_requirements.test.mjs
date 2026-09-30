import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/agent-naming-and-lens.md");
const wizard = read("frontend/src/pages/EngagementWizard.tsx");
const edit = read("frontend/src/pages/EngagementEdit.tsx");
const runDetail = read("frontend/src/pages/RunDetail.tsx");
const runActivity = read("frontend/src/lib/runActivity.ts");
// The findings list and the finding detail panel it shares with the all-findings page.
const results = ["frontend/src/components/FindingsSection.tsx", "frontend/src/components/FindingDetail.tsx", "frontend/src/lib/findings.ts"]
  .map(read).join("\n");
const styles = read("frontend/src/styles.css");
const settings = read("frontend/src/pages/Settings.tsx");
const audit = read("frontend/src/pages/Audit.tsx");
const client = read("frontend/src/api/client.ts");
const findingsApi = read("control-plane/app/api/findings.py");
const findingSchema = read("control-plane/app/schemas/finding.py");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}
function contains(source, pattern, message) {
  if (pattern instanceof RegExp) assert.match(source, pattern, message);
  else assert.equal(source.includes(pattern), true, message);
}
function notContains(source, pattern, message) {
  if (pattern instanceof RegExp) assert.doesNotMatch(source, pattern, message);
  else assert.equal(source.includes(pattern), false, message);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-AGENT-001 uses Vector Agent in operator-facing frontend", () => {
  requirement("REQ-AGENT-001");
  for (const [name, source] of [["wizard", wizard], ["edit", edit], ["run detail", runDetail], ["run activity", runActivity], ["settings", settings], ["audit", audit]]) {
    contains(source, "Vector Agent", `${name} must use Vector Agent naming`);
  }
});

test("REQ-LENS-001 results page requests and displays Lens Agent explanations", () => {
  requirement("REQ-LENS-001");
  contains(results, "Lens Agent analysis", "Expanded finding detail must include Lens Agent analysis");
  contains(results, "Explain with Lens Agent", "Results page must expose a Lens Agent action");
  contains(results, "api.explainFindingWithLens", "Results page must call the Lens endpoint");
  contains(results, "lensTextByFinding", "Results page must render returned Lens text");
  contains(results, "cachedLensExplanation", "Results page must render cached Lens explanations from evidence");
  contains(client, "explainFindingWithLens", "Frontend client must expose Lens explanation API");
  contains(client, "/lens-explanation", "Frontend client must target the Lens endpoint");
});

test("REQ-LENS-002 backend uses finding evidence, LLM config, cache, and audit", () => {
  requirement("REQ-LENS-002");
  contains(findingSchema, "class FindingExplanationOut", "Backend must define a typed Lens response");
  contains(findingsApi, '@router.post("/{engagement_id}/findings/{finding_id}/lens-explanation"', "Backend must expose the Lens endpoint");
  contains(findingsApi, "get_llm_config", "Lens must use configured LLM provider settings");
  contains(findingsApi, "_lens_context", "Lens must build context from finding fields");
  for (const requiredField of ["title", "severity", "confidence", "risk_score", "target", "vulnerability", "evidence"]) {
    contains(findingsApi, `"${requiredField}"`, `Lens context must include ${requiredField}`);
  }
  contains(findingsApi, 'evidence["lens_agent"]', "Lens response must be cached in finding evidence");
  contains(findingsApi, 'actor="lens_agent"', "Lens actions must be audit logged with lens_agent actor");
  contains(findingsApi, 'source="cached"', "Cached Lens responses must be returned without another LLM call");
});

test("REQ-LENS-003 formats Lens output and hides raw cached JSON", () => {
  requirement("REQ-LENS-003");
  contains(results, "parseLensBlocks", "Results page must parse Lens Markdown into structured blocks");
  contains(results, "splitLensHeading", "Results page must recognize standard Lens headings");
  contains(results, "renderInlineMarkdown", "Results page must render inline Markdown emphasis/code");
  contains(results, "<ul key={index}>", "Results page must render unordered lists");
  contains(results, "<ol key={index}>", "Results page must render ordered lists");
  contains(results, 'key !== "lens_agent"', "Evidence cards must hide the raw cached Lens payload");
  contains(styles, ".lens-output h4", "Lens section headings must have explicit styles");
  contains(styles, ".lens-output code", "Lens inline code must have explicit styles");
  contains(styles, ".lens-output ul, .lens-output ol", "Lens lists must have explicit styles");
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
