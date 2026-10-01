import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/console-information-architecture.md");
const detail = read("frontend/src/pages/EngagementDetail.tsx");
const findingsSection = read("frontend/src/components/FindingsSection.tsx");
const findingDetail = read("frontend/src/components/FindingDetail.tsx");
const allFindings = read("frontend/src/pages/AllFindings.tsx");
const app = read("frontend/src/App.tsx");
const client = read("frontend/src/api/client.ts");
const styles = read("frontend/src/styles.css");
const login = read("frontend/src/pages/Login.tsx");
const account = read("frontend/src/pages/Account.tsx");
const viteConfig = read("frontend/vite.config.ts");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-CONSOLE-013 the engagement page has URL-driven tabs, findings first", () => {
  requirement("REQ-CONSOLE-013");
  const tabs = detail.match(/const ENGAGEMENT_TABS = \[([\s\S]*?)\] as const;/);
  assert.ok(tabs, "tab list defined");
  const ids = [...tabs[1].matchAll(/id: "(\w+)"/g)].map((m) => m[1]);
  assert.deepEqual(ids, ["findings", "assets", "runs"], "Findings is the first tab");
  assert.match(detail, /: "findings";\s*\}/, "no or an unknown ?tab= falls back to findings");
  assert.match(detail, /const activeTab = parseEngagementTab\(searchParams\.get\("tab"\)\)/);
  // A tab change pushes a history entry (no { replace: true }), so Back returns to the previous tab.
  assert.match(detail, /const selectTab = \(tab: EngagementTab\) => setSearchParams\(tab === "findings" \? \{\} : \{ tab \}\);/);
  assert.match(detail, /role="tablist" aria-label="Engagement sections"/);
  assert.match(detail, /role="tabpanel"/);
});

test("REQ-CONSOLE-013 only the shown tab is mounted, so only its data is requested", () => {
  assert.match(detail, /\{activeTab === "findings" && <FindingsSection engagementId=\{id\} canManage=\{canManage\} \/>\}/);
  assert.match(detail, /\{activeTab === "assets" && \(/);
  assert.match(detail, /\{activeTab === "runs" && \(/);
  // The reports list is the only runs-tab query that lives in the page component itself.
  assert.match(detail, /queryKey: \["reports", id\][^\n]*enabled: engagementLoaded && activeTab === "runs"/);
  // Findings and the graph are no longer rendered unconditionally below everything else.
  assert.doesNotMatch(detail, /\n\s*<FindingsSection engagementId=\{id\} \/>\n\s*<\/section>/);
});

test("REQ-CONSOLE-013 ?finding= opens that finding; expanding does not flood history", () => {
  assert.match(findingsSection, /const expandedFindingId = searchParams\.get\("finding"\)/);
  assert.match(findingsSection, /id=\{`finding-\$\{finding\.id\}`\}/, "rows are addressable for scrolling");
  assert.match(findingsSection, /scrollIntoView/);
  assert.match(findingsSection, /\{ replace: true \}/, "expanding and status changes replace the URL entry");
});

test("REQ-CONSOLE-013 negative: an unknown engagement shows no tabs", () => {
  const notFound = detail.indexOf('<NotFound title="Engagement not found"');
  const tabs = detail.indexOf('role="tablist" aria-label="Engagement sections"');
  assert.ok(notFound > 0 && tabs > notFound, "the not-found return comes before the tabs are rendered");
  assert.match(detail, /if \(engagementQuery\.isError && isNotFound\(engagementQuery\.error\)\) \{\s*return <NotFound/);
});

test("REQ-CONSOLE-013 existing deep links and redirects are still routed", () => {
  for (const route of ["/engagements/:id", "/engagements/:id/runs/:runId", "/engagements/:id/edit",
    "/engagements/:id/audit", "/engagements/:id/live", "/engagements/:id/results"]) {
    assert.ok(app.includes(`<Route path="${route}"`), `route ${route}`);
  }
});

test("REQ-CONSOLE-014 small screens get a top bar and an accessible drawer", () => {
  requirement("REQ-CONSOLE-014");
  assert.match(app, /className="menu-button" aria-expanded=\{nav\.open\} aria-controls="primary-navigation"/);
  assert.match(app, /aria-label=\{nav\.open \? "Close navigation" : "Open navigation"\}/);
  assert.match(app, /<aside className="sidebar" id="primary-navigation" ref=\{nav\.drawerRef\}>/);
  assert.match(app, /event\.key === "Escape"/, "Escape closes the drawer");
  assert.match(app, /if \(openRef\.current\) close\(\);\s*\}, \[location\.pathname, close\]\);/, "navigation closes the drawer");
  assert.match(app, /<div className="nav-backdrop" onClick=\{nav\.close\} \/>/, "a backdrop click closes the drawer");
  assert.match(app, /buttonRef\.current\?\.focus\(\)/, "focus returns to the menu button");
  assert.match(app, /event\.key !== "Tab"/, "Tab is kept inside the open drawer");
});

test("REQ-CONSOLE-014 the drawer only exists at the one-column breakpoint and is out of the tab order when closed", () => {
  assert.match(styles, /\.mobile-topbar, \.nav-backdrop \{ display: none; \}/, "hidden on wide screens");
  const mobile = styles.slice(styles.indexOf("/* REQ-CONSOLE-014"));
  assert.match(mobile, /@media \(max-width: 1040px\) \{[\s\S]*?\.sidebar \{[\s\S]*?transform: translateX\(-100%\); visibility: hidden;/);
  // Opening must not delay visibility (a transition on it left the first link hidden when focus moved in).
  assert.match(mobile, /\.app-shell\.nav-open \.sidebar \{ transform: none; visibility: visible; transition: transform 0\.2s ease; \}/);
  // The approval modal (z-index 110) must stay above the drawer, top bar, and backdrop.
  for (const z of [...mobile.matchAll(/z-index: (\d+)/g)].map((m) => Number(m[1]))) {
    assert.ok(z < 110, `z-index ${z} must stay below the approval modal`);
  }
  // The old stacked three-column sidebar is gone.
  assert.doesNotMatch(styles, /\.side-nav \{ grid-template-columns: repeat\(3, minmax\(0, 1fr\)\); \}/);
});

test("REQ-CONSOLE-015 the graph and the QR code library load on demand", () => {
  requirement("REQ-CONSOLE-015");
  assert.match(detail, /const SurfaceGraph = lazy\(\(\) => import\("\.\.\/components\/SurfaceGraph"\)\)/);
  assert.match(detail, /<ChunkErrorBoundary what="attack-surface graph">\s*<Suspense fallback=/);
  for (const [name, source] of [["Login", login], ["Account", account]]) {
    assert.doesNotMatch(source, /import QRCode from "qrcode"/, `${name} must not import qrcode statically`);
    assert.match(source, /qrCodeDataUrl\(/, `${name} loads the QR code on demand`);
    assert.match(source, /qrFailed \? QR_FAILED : QR_LOADING/, `${name} shows loading and failure states`);
  }
  assert.match(read("frontend/src/lib/qrCode.ts"), /await import\("qrcode"\)/);
  assert.match(read("frontend/src/components/ChunkErrorBoundary.tsx"), /Reload page/);
  assert.doesNotMatch(viteConfig, /chunkSizeWarningLimit/, "the warning limit is not raised");
});

test("REQ-CONSOLE-015 no statically imported module pulls in the graph library", () => {
  const sources = [];
  const walk = (dir) => {
    for (const entry of readdirSync(resolve(repo, dir), { withFileTypes: true })) {
      const path = `${dir}/${entry.name}`;
      if (entry.isDirectory()) walk(path);
      else if (/\.tsx?$/.test(entry.name)) sources.push([path, read(path)]);
    }
  };
  walk("frontend/src");
  for (const [path, source] of sources) {
    if (path.endsWith("components/SurfaceGraph.tsx")) continue;
    assert.doesNotMatch(source, /from "cytoscape/, `${path} imports cytoscape statically`);
    assert.doesNotMatch(source, /import SurfaceGraph from/, `${path} imports SurfaceGraph statically`);
  }
});

test("REQ-CONSOLE-016 an all-findings page is in the navigation and uses the cross-engagement API", () => {
  requirement("REQ-CONSOLE-016");
  assert.match(app, /<NavLink to="\/findings">Findings<\/NavLink>/);
  assert.match(app, /<Route path="\/findings" element=\{<AllFindings \/>\} \/>/);
  assert.match(client, /allFindings: \(query: FindingPageQuery\) =>[\s\S]*?request<FindingPage>\(`\/findings/);
  assert.match(allFindings, /api\.allFindings\(\{/);
  assert.match(allFindings, /const PAGE_SIZE = 50;/);
  assert.match(allFindings, /offset: \(page - 1\) \* PAGE_SIZE/);
});

test("REQ-CONSOLE-016 filters are in the URL; default is open findings", () => {
  assert.match(allFindings, /const status = parseFindingStatus\(searchParams\.get\("status"\)\)/);
  for (const param of ["severity", "engagement", "q", "page"]) {
    assert.match(allFindings, new RegExp(`searchParams\\.get\\("${param}"\\)`), `${param} is read from the URL`);
  }
  assert.match(allFindings, /role="tablist" aria-label="Finding status"/);
  assert.match(allFindings, /counts_by_status/);
  assert.match(allFindings, /counts_by_severity/);
});

test("REQ-CONSOLE-016 a row opens the shared detail with triage and a link into its engagement", () => {
  assert.match(allFindings, /<FindingDetail finding=\{finding\}/);
  assert.match(allFindings, /Open in engagement →/);
  assert.match(allFindings, /new URLSearchParams\(\{ finding: finding\.id \}\)/);
  // Triage goes through the engagement-scoped endpoint, where the router-wide ownership check applies.
  assert.match(findingDetail, /api\.triageFinding\(engagementId, finding\.id,/);
  assert.match(findingDetail, /const engagementId = finding\.engagement_id;/);
  assert.match(findingDetail, /queryKey: \["all-findings"\]/, "triage refreshes the all-findings list");
});

test("REQ-IAM-016 the login page explains a 429 instead of calling it a wrong password", () => {
  const login = read("frontend/src/pages/Login.tsx");
  assert.match(login, /error instanceof ApiError && error\.status === 429/);
  assert.match(login, /Too many sign-in attempts from your network/);
  assert.equal((login.match(/setError\(signInError\(err, /g) || []).length, 4, "every sign-in step uses it");
});

test("REQ-CONSOLE-016 empty states say why", () => {
  assert.match(allFindings, /You have no engagements yet\./);
  assert.match(allFindings, /No findings match these filters\./);
  // REQ-IAM-022: the list covers every engagement; "Only my engagements" narrows it.
  assert.match(allFindings, /No open findings in any engagement\./);
  assert.match(allFindings, /No open findings in your engagements\./);
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
