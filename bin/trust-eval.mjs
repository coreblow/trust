#!/usr/bin/env node

import { evaluateAgenticPayload, loadThreatBundle } from "../src/evaluator.mjs";

const args = process.argv.slice(2);
if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
  console.log("Usage: coreblow-trust \"<input-text>\" [--json]");
  process.exit(0);
}

const isJson = args.includes("--json");
const textArgs = args.filter(a => a !== "--json");
const input = textArgs.join(" ");

const result = evaluateAgenticPayload(input);

if (isJson) {
  console.log(JSON.stringify(result, null, 2));
} else {
  console.log(`CoreBlow Trust Evaluation: ${result.pass ? "PASSED" : "FAILED"}`);
  if (!result.pass) {
    console.log(`Highest Severity: ${result.highestSeverity.toUpperCase()}`);
    console.log(`Violations Found (${result.violationCount}):`);
    for (const v of result.violations) {
      console.log(`  - [${v.severity.toUpperCase()}] ${v.category} (${v.threatId})`);
      console.log(`    Remediation: ${v.remediation}`);
    }
  }
}

process.exit(result.pass ? 0 : 1);
