// REQ-TESTACCT-001..010 (GitHub #89): test accounts of an engagement. The pure rules of the panel live here so a test can run them
// without a browser: what may be submitted, what is said before the owner saves, how a refusal reads.

import type { LoginConsentView, TestAccountCreate, TestAccountKind, TestAccountView } from "../api/client";

export const KIND_LABEL: Record<TestAccountKind, string> = {
  login_form: "Login form (username and password)",
  login_json: "JSON login (username and password)",
  basic: "HTTP Basic (username and password)",
  header_token: "Bearer or API-key header (a token)",
};

export const LOGIN_KINDS: TestAccountKind[] = ["login_form", "login_json"];

/** Said above the form, before anything is saved (REQ-TESTACCT-010): the provider receives the credentials; use a dedicated account. */
export function disclosureText(provider: string | null): string {
  return (
    `A test account is sent to the language-model provider${provider ? ` (${provider})` : ""} with every request of a run, because the Vector Agent ` +
    "reads it to log in. Use a dedicated test account created for this test: not a person's account, without a second factor, with the least " +
    "rights that still reach what you want tested. It is erased when the engagement ends; disable it at the target too."
  );
}

export const ATTESTATION =
  "This is a dedicated test account that I am entitled to use on the hosts ticked above, without a second factor.";
export const ATTESTATION_BOUNTY =
  "This is a test account that I registered under the program's rules, without a second factor, and I am entitled to use it on the hosts ticked above.";

export const CONSENT_WORDING =
  "The scanner will sign in with these accounts on exactly these hosts, on each scheduled run, using the provider-hosted language model that " +
  "receives the credentials (never a host that is held, denied or flagged). It will not change data through the session.";

/** A refusal of the endpoints, in words. The code is what the server sends as `detail`. */
export const TESTACCOUNT_REFUSALS: Record<string, string> = {
  testaccount_label_invalid: "The label is 1 to 40 letters, digits, - or _.",
  testaccount_label_taken: "This engagement already has an account with that label.",
  testaccount_role_invalid: "Give the account a role (for example user or admin), at most 40 characters.",
  testaccount_kind_invalid: "Choose how the target logs in.",
  testaccount_login_path_invalid: "The login path starts with / and has no query (for example /login).",
  testaccount_username_required: "This kind of account needs a username.",
  testaccount_secret_invalid: "The password or token needs 8 to 512 characters.",
  testaccount_attestation_required: "Confirm that this is a dedicated test account you are entitled to use.",
  testaccount_limit: "An engagement can have at most 4 accounts, and an account at most 50 hosts.",
  testaccount_host_not_allowed: "A host must be a concrete host or address of this engagement's scope, and no deny rule may block it.",
  testaccount_cipher_unavailable: "The server has no encryption key for test accounts, so nothing was saved. An administrator sets TESTACCOUNT_ENCRYPTION_KEY (make env creates it).",
  testaccount_engagement_closed: "The engagement has ended; its accounts were erased and no new one can be added.",
  testaccount_erased: "An erased account cannot be revived. Enter a new one.",
  login_consent_required: "This monitor has a test account whose login no current consent covers. Give the login consent first.",
  login_consent_not_applicable: "Only a monitoring engagement needs a login consent.",
};

export function testAccountCode(message: string): string | null {
  const match = /\b((?:testaccount|login_consent)_[a-z_]+)\b/.exec(message);
  return match ? match[1] : null;
}

export function testAccountRefusal(message: string): string {
  const code = testAccountCode(message);
  return code && TESTACCOUNT_REFUSALS[code] ? TESTACCOUNT_REFUSALS[code] : message;
}

export interface AccountForm {
  label: string; role: string; kind: TestAccountKind | ""; username: string; secret: string; loginPath: string; headerName: string;
  /** host -> its own login path ("" = the account's), for the ticked hosts only. */
  hosts: Record<string, string>;
  attested: boolean;
}

export const EMPTY_FORM: AccountForm = {
  label: "", role: "", kind: "", username: "", secret: "", loginPath: "/login", headerName: "", hosts: {}, attested: false,
};

/** Why the form cannot be submitted yet, or null. The server checks again; this only says it early. */
export function problemWithForm(f: AccountForm): string | null {
  if (!/^[A-Za-z0-9_-]{1,40}$/.test(f.label)) return TESTACCOUNT_REFUSALS.testaccount_label_invalid;
  if (!f.role.trim()) return TESTACCOUNT_REFUSALS.testaccount_role_invalid;
  if (!f.kind) return TESTACCOUNT_REFUSALS.testaccount_kind_invalid;
  if (LOGIN_KINDS.includes(f.kind as TestAccountKind) && !/^\/[^?#\s]*$/.test(f.loginPath)) return TESTACCOUNT_REFUSALS.testaccount_login_path_invalid;
  if (f.kind !== "header_token" && !f.username.trim()) return TESTACCOUNT_REFUSALS.testaccount_username_required;
  if (f.secret.length < 8 || f.secret.length > 512) return TESTACCOUNT_REFUSALS.testaccount_secret_invalid;
  if (!f.attested) return TESTACCOUNT_REFUSALS.testaccount_attestation_required;
  return null;
}

/** The request body. The secret is in it and nowhere else. */
export function toRequest(f: AccountForm): TestAccountCreate {
  const login = LOGIN_KINDS.includes(f.kind as TestAccountKind);
  return {
    label: f.label.trim(), role: f.role.trim(), kind: f.kind as TestAccountKind,
    username: f.kind === "header_token" ? null : f.username.trim(), secret: f.secret,
    login_path: login ? f.loginPath : null, header_name: f.kind === "header_token" ? (f.headerName.trim() || null) : null,
    hosts: Object.entries(f.hosts).map(([host, path]) => ({ host, login_path: path.trim() || null })),
    attested: f.attested,
  };
}

export function stateLine(a: TestAccountView): string {
  if (a.state === "erased") return "erased";
  const suspendedHosts = a.hosts.filter((h) => h.suspended).length;
  if (a.state === "suspended") return "suspended on every host";
  if (suspendedHosts > 0) return `suspended on ${suspendedHosts} of ${a.hosts.length} host${a.hosts.length === 1 ? "" : "s"}`;
  return "active";
}

const OUTCOME_WORDS: Record<string, string> = {
  session_established: "logged in", rejected: "login rejected", not_attempted: "not attempted",
};
export function outcomeWords(outcome: string | null): string {
  return outcome ? OUTCOME_WORDS[outcome] ?? outcome : "not tried yet";
}

/** The consent block of a monitor: what is still to be consented to (REQ-TESTACCT-006). */
export function consentSummary(c: LoginConsentView): { needed: boolean; text: string } {
  if (!c.applicable) return { needed: false, text: "" };
  if (c.pairs.length === 0) return { needed: false, text: "No account of this monitor logs in, so no consent is needed." };
  if (c.uncovered.length === 0) return { needed: false, text: "Every login of this monitor is covered by your consent." };
  return {
    needed: true,
    text: `Not yet covered: ${c.uncovered.map((p) => `${p.label} on ${p.host}`).join(", ")}.`,
  };
}
