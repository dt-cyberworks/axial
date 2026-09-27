import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirement = read("docs/requirements/auth-check-network-resilience.md");
const app = read("frontend/src/App.tsx");

assert.match(requirement, /## REQ-IAM-012:/);

// Only a network-level failure (no response ever received) should retry -
// a confirmed HTTP response (including a real 401, already handled by the
// global redirect in api/client.ts) must not be retried here.
assert.match(
  app,
  /retry:\s*\(failureCount,\s*err\)\s*=>\s*failureCount\s*<\s*2\s*&&\s*err instanceof TypeError/,
  "the me query must only retry on network-level (TypeError) failures, capped at 2 attempts",
);
assert.match(app, /retryDelay:/, "retries must back off, not hammer the endpoint immediately");

// Found live 2026-08-10: exhausting retries with no error UI left the
// console permanently blank with no way to recover short of a manual reload.
assert.match(app, /isError/, "the query's error state must be read");
assert.match(
  app,
  /<AuthLayout title="Can't reach the server"/,
  "an exhausted retry must render a recoverable error screen, not fall through to a blank render",
);
assert.match(app, /onClick=\{\(\) => refetch\(\)\}/, "the error screen must offer a manual retry");
assert.match(app, /disabled=\{isFetching\}/, "the retry button must disable itself while a retry is already in flight");

// The isError branch must come before the pre-existing blank fallback, so
// an exhausted-retry failure never falls through to `return null`.
const errorBranchIndex = app.indexOf("if (isError)");
const blankFallbackIndex = app.indexOf("if (!me) return null;");
assert.ok(errorBranchIndex > -1 && blankFallbackIndex > -1 && errorBranchIndex < blankFallbackIndex,
  "the error branch must be checked before the blank '!me' fallback");

console.log("ok - REQ-IAM-012 auth check retries on network failure and shows a recoverable error otherwise");
