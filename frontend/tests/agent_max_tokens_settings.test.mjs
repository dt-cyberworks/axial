import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirement = read("docs/requirements/agent-max-tokens-configuration.md");
const client = read("frontend/src/api/client.ts");
const settings = read("frontend/src/pages/Settings.tsx");

assert.match(requirement, /## REQ-AGENT-026:/);

assert.match(client, /getAgentMaxTokens: \(\) => request<AgentMaxTokens>\("\/settings\/agent-max-tokens"\)/);
assert.match(client, /updateAgentMaxTokens: \(value: number\) =>/);

// The section mirrors the iteration-budget one: own query, own mutation, bounds.
assert.match(settings, /queryKey: \["agent-max-tokens"\]/);
assert.match(settings, /const maxTokensMutation = useMutation\(\{/);
assert.match(settings, /Vector Agent max tokens \(global default\)/);
assert.match(settings, /min=\{1024\}/, "the input must carry the documented lower bound");
assert.match(settings, /max=\{32768\}/, "the input must carry the documented upper bound");
assert.match(settings, /useState\(8192\)/, "the form default must match the built-in default");

// The help text must explain the real failure mode, not just "it's a limit".
assert.match(settings, /not the context window/i);
assert.match(settings, /truncates a turn mid-JSON/i);

console.log("ok - REQ-AGENT-026 max tokens is configurable from Settings");
