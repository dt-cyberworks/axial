import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/console-layout-and-navigation.md");
const app = read("frontend/src/App.tsx");
const styles = read("frontend/src/styles.css");
const adminHome = read("frontend/src/pages/AdminHome.tsx");
const wizard = read("frontend/src/pages/EngagementWizard.tsx");
const settings = read("frontend/src/pages/Settings.tsx");
const adminUsers = read("frontend/src/pages/AdminUsers.tsx");
const adminAudit = read("frontend/src/pages/AdminAudit.tsx");
const account = read("frontend/src/pages/Account.tsx");
const useLogout = read("frontend/src/lib/useLogout.ts");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}

function notContains(source, pattern, message) {
  if (pattern instanceof RegExp) assert.doesNotMatch(source, pattern, message);
  else assert.equal(source.includes(pattern), false, message);
}

function contains(source, pattern, message) {
  if (pattern instanceof RegExp) assert.match(source, pattern, message);
  else assert.equal(source.includes(pattern), true, message);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-CONSOLE-001 caps app-shell width and keeps existing breakpoints", () => {
  requirement("REQ-CONSOLE-001");
  contains(styles, /\.app-shell\s*\{[^}]*max-width:\s*1800px/, "app-shell must have a max-width cap for wide monitors");
  for (const breakpoint of [1040, 900, 760, 720, 620]) {
    contains(styles, new RegExp(`@media \\(max-width:\\s*${breakpoint}px\\)`), `existing ${breakpoint}px breakpoint must remain`);
  }
  contains(styles, /\.responsive-table\s*\{\s*overflow-x:\s*auto/, "tables must scroll horizontally within their own container");
});

test("REQ-CONSOLE-002 consolidates admin pages under one admin-gated nav entry", () => {
  requirement("REQ-CONSOLE-002");
  contains(app, '<NavLink to="/admin">Admin</NavLink>', "sidebar must expose a single Admin nav entry");
  notContains(app, "Agent settings</NavLink>", "sidebar must not expose a separate Agent settings nav entry");
  notContains(app, "Admin: Users", "sidebar must not expose a separate Admin: Users nav entry");
  notContains(app, "Admin: Account audit", "sidebar must not expose a separate Admin: Account audit nav entry");
  contains(app, '<Route path="/admin" element={<AdminHome />} />', "must route /admin to AdminHome");
  contains(app, '<Route path="/settings" element={<Navigate to="/admin" replace />} />', "/settings must redirect to /admin");
  contains(adminHome, 'me?.role !== "admin"', "AdminHome must enforce the admin role itself, not only hide the nav link");
  contains(adminHome, "You need an administrator role", "AdminHome must show a clear access-denied message for non-admins");
  contains(adminHome, "<Settings", "AdminHome must render the existing Settings component unchanged");
  contains(adminHome, "<AdminUsers", "AdminHome must render the existing AdminUsers component unchanged");
  contains(adminHome, "<AdminAudit", "AdminHome must render the existing AdminAudit component unchanged");
  // The three underlying pages keep their own behavior/exports unchanged.
  contains(settings, "export default function Settings", "Settings component must be unchanged");
  contains(adminUsers, "export default function AdminUsers", "AdminUsers component must be unchanged");
  contains(adminAudit, "export default function AdminAudit", "AdminAudit component must be unchanged");
});

test("REQ-CONSOLE-003 removes the static sidebar guardrail banner", () => {
  requirement("REQ-CONSOLE-003");
  notContains(app, "guardrail-panel", "sidebar must not render the guardrail-panel block");
  notContains(app, "Default guardrails", "sidebar must not render the 'Default guardrails' banner text");
  notContains(styles, /\.guardrail-panel/, "dead guardrail-panel CSS must be removed");
  // The unrelated wizard review row must be untouched.
  contains(wizard, "Scope enforcement", "wizard's per-engagement review row must remain");
  contains(wizard, "Scope Gateway authorizes every active tool call", "wizard's review row text must remain unchanged");
});

test("REQ-CONSOLE-004 legacy shared token is documented as answered, not built", () => {
  requirement("REQ-CONSOLE-004");
  contains(requirementDoc, /no shared\/legacy-token page or menu anywhere in the console\s+today/, "doc must state the answer plainly");
});

test("REQ-CONSOLE-005 account nav entry is labeled, not named", () => {
  requirement("REQ-CONSOLE-005");
  contains(app, '<NavLink to="/account" className="nav-account">', "the account entry must carry its own class");
  contains(app, "<span>Account</span>", "the nav entry must render a fixed 'Account' label");
  // The display name may still be shown, but never AS the label.
  notContains(app, '<NavLink to="/account">{me.display_name}</NavLink>', "the display name must not be the nav label");
  contains(app, 'className="nav-account-user"', "the signed-in identity must remain visible as a secondary line");
  contains(styles, /\.side-nav a\.nav-account/, "the account entry needs its two-line layout");
  contains(app, '<Route path="/account" element={<Account />} />', "the /account route must be unchanged");
});

test("REQ-CONSOLE-006 admin settings tab is labeled for its real scope", () => {
  requirement("REQ-CONSOLE-006");
  contains(adminHome, '"Operational settings"', "the settings tab must be labeled for its real scope");
  notContains(adminHome, '"Agent settings"', "the misleading agent-only label must be gone");
  // The other two tabs are untouched.
  contains(adminHome, '"Users"');
  contains(adminHome, '"Account audit"');
});

test("REQ-CONSOLE-007 logout is a one-click sidebar action shared with the Account page", () => {
  requirement("REQ-CONSOLE-007");
  contains(app, "useLogout", "the sidebar must use the shared logout hook");
  contains(app, ">Log out<", "the sidebar must render a Log out action");
  contains(account, "useLogout", "the Account page must use the same shared logout hook");
  notContains(account, "clearSession", "Account.tsx must not keep its own duplicate logout implementation");
  contains(useLogout, "api.logout()", "the shared hook must call the real logout endpoint");
  contains(useLogout, "clearSession()", "the shared hook must clear local session state");
  contains(useLogout, '"/login"', "the shared hook must redirect to /login");
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
