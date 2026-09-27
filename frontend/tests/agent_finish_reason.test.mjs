import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("../src/pages/RunDetail.tsx", import.meta.url),
  "utf8",
);

test("length-limited empty agent responses are labelled truthfully", () => {
  assert.match(source, /step\.stop_reason === "length"/);
  assert.match(source, /incomplete model response: output limit reached; no answer or tool calls/);
  assert.match(source, /the model returned no answer or tool calls/);
  assert.match(source, /structured tool calls are shown below/);
  assert.doesNotMatch(source, /the model returned no text, only tool calls/);
});
