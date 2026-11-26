import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const threatsFile = path.resolve(__dirname, "../threats.json");

export function loadThreatBundle() {
  const content = fs.readFileSync(threatsFile, "utf8");
  const bundle = JSON.parse(content);
  validatePolicyBundle(bundle);
  return bundle;
}

export function validatePolicyBundle(bundle) {
  if (!bundle || typeof bundle !== "object") {
    throw new Error("Policy bundle must be an object");
  }
  if (bundle.product !== "CoreBlow") {
    throw new Error("Policy bundle product must be CoreBlow");
  }
  if (!Array.isArray(bundle.threats) || bundle.threats.length === 0) {
    throw new Error("Policy bundle must contain a non-empty threats array");
  }

  const requiredFields = ["id", "category", "owner", "severity", "summary", "patterns", "remediation"];
  for (const t of bundle.threats) {
    for (const f of requiredFields) {
      if (!t[f]) {
        throw new Error(`Threat '${t.id || "unknown"}' missing required field: ${f}`);
      }
    }
    if (!Array.isArray(t.patterns) || t.patterns.length === 0) {
      throw new Error(`Threat '${t.id}' must specify at least one detection pattern`);
    }
  }
  return true;
}

export function evaluateAgenticPayload(payload, customBundle) {
  const bundle = customBundle || loadThreatBundle();
  const text = typeof payload === "string" ? payload : (payload.input || payload.text || JSON.stringify(payload));
  const violations = [];

  for (const threat of bundle.threats) {
    for (const pattern of threat.patterns) {
      // Parse optional (?i) flag
      let flags = "";
      let rawPattern = pattern;
      if (rawPattern.startsWith("(?i)")) {
        flags = "i";
        rawPattern = rawPattern.slice(4);
      }
      try {
        const regex = new RegExp(rawPattern, flags);
        if (regex.test(text)) {
          violations.push({
            threatId: threat.id,
            category: threat.category,
            severity: threat.severity,
            owner: threat.owner,
            summary: threat.summary,
            remediation: threat.remediation,
            matchedPattern: pattern,
          });
          break; // Stop after first pattern match for this threat category
        }
      } catch (err) {
        // Skip unparseable regex in standard engine
      }
    }
  }

  return {
    pass: violations.length === 0,
    violationCount: violations.length,
    highestSeverity: getHighestSeverity(violations),
    violations,
  };
}

export function getBundleInfo(customBundle) {
  const bundle = customBundle || loadThreatBundle();
  const severities = {};
  for (const threat of bundle.threats) {
    const sev = String(threat.severity || "unknown").toLowerCase();
    severities[sev] = (severities[sev] || 0) + 1;
  }
  return {
    product: bundle.product,
    framework: bundle.framework || "OWASP Top 10 for Agentic AI",
    version: bundle.version || "0.0.0",
    ruleCount: bundle.threats.length,
    severities,
    ruleIds: bundle.threats.map((t) => t.id),
  };
}

export function formatAuditResult(result, customBundle) {
  const info = getBundleInfo(customBundle);
  return {
    pass: result.pass,
    framework: info.framework,
    bundleVersion: info.version,
    totalRules: info.ruleCount,
    highestSeverity: result.highestSeverity,
    violationCount: result.violationCount,
    findings: result.violations.map((v) => ({
      id: v.threatId,
      category: v.category,
      severity: v.severity,
      owner: v.owner,
      summary: v.summary,
      remediation: v.remediation,
    })),
  };
}

function getHighestSeverity(violations) {
  if (violations.length === 0) return "none";
  const levels = ["low", "medium", "high", "critical"];
  let maxIdx = -1;
  for (const v of violations) {
    const idx = levels.indexOf(v.severity.toLowerCase());
    if (idx > maxIdx) maxIdx = idx;
  }
  return maxIdx >= 0 ? levels[maxIdx] : "unknown";
}
