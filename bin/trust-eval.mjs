#!/usr/bin/env node

import fs from "node:fs";
import { evaluateAgenticPayload, formatAuditResult, getBundleInfo, loadThreatBundle } from "../src/evaluator.mjs";

function printHelp() {
  console.log(`Usage: coreblow-trust "<input-text>" [--json]
       coreblow-trust --payload "<input-text>" [--json]
       coreblow-trust --bundle-info [--json]`);
}

function parseCliArgs(argv) {
  const isJson = argv.includes("--json");
  const isBundleInfo = argv.includes("--bundle-info");
  let payloadFlagValue = null;
  const positional = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--json" || arg === "--bundle-info" || arg === "--help" || arg === "-h") {
      continue;
    }
    if (arg === "--payload") {
      if (i + 1 >= argv.length) {
        return { error: "--payload requires a value", isJson, isBundleInfo };
      }
      payloadFlagValue = argv[++i];
      continue;
    }
    if (arg.startsWith("--payload=")) {
      payloadFlagValue = arg.slice("--payload=".length);
      continue;
    }
    positional.push(arg);
  }

  return { isJson, isBundleInfo, payloadFlagValue, positional };
}

const args = process.argv.slice(2);
if (args.includes("--help") || args.includes("-h")) {
  printHelp();
  process.exit(0);
}

const parsed = parseCliArgs(args);
if (parsed.error) {
  console.error(parsed.error);
  process.exit(2);
}

const bundle = loadThreatBundle();

if (parsed.isBundleInfo) {
  const info = getBundleInfo(bundle);
  if (parsed.isJson) {
    console.log(JSON.stringify(info, null, 2));
  } else {
    console.log(`${info.product} Trust Bundle v${info.version} (${info.framework}) - ${info.ruleCount} rules`);
  }
  process.exit(0);
}

let input = parsed.payloadFlagValue !== null ? parsed.payloadFlagValue : parsed.positional.join(" ");
if (!input && !process.stdin.isTTY) {
  try {
    input = fs.readFileSync(0, "utf8").trimEnd();
  } catch {
    input = "";
  }
}

if (!input) {
  if (parsed.isJson) {
    console.error(JSON.stringify({ error: "No payload provided. Pass positional text, --payload <text>, or stdin." }));
  } else {
    printHelp();
  }
  process.exit(2);
}

const result = evaluateAgenticPayload(input, bundle);

if (parsed.isJson) {
  console.log(JSON.stringify(formatAuditResult(result, bundle), null, 2));
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
