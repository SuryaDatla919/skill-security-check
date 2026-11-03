// Human-readable and JSON rendering of scan results.

const OUTCOME_LINE = {
  REJECT: "REJECT",
  CAUTION: "CAUTION",
  NO_FINDINGS: "NO AUTOMATED FINDINGS: manual review still required",
};

function pad(s, n) {
  s = String(s);
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

export function renderText(result) {
  const lines = [];
  lines.push(`skill-security-check  —  ${result.target}`);
  lines.push(
    result.privateRulesLoaded
      ? `private rules: loaded from ${result.privateRulesSource}`
      : "private rules: none loaded (no overlay file found)",
  );
  lines.push(`files scanned: ${result.filesScanned}`);
  lines.push("");

  if (result.findings.length === 0) {
    lines.push("No automated findings.");
  } else {
    const rows = result.findings.map((f) => ({
      sev: f.severity,
      rule: f.ruleId,
      loc: `${f.file}:${f.line}`,
      src: f.source,
      excerpt: f.excerpt,
    }));
    const wSev = Math.max(8, ...rows.map((r) => r.sev.length));
    const wRule = Math.max(4, ...rows.map((r) => r.rule.length));
    const wLoc = Math.max(8, ...rows.map((r) => r.loc.length));
    const wSrc = Math.max(6, ...rows.map((r) => r.src.length));

    lines.push(
      `${pad("SEVERITY", wSev)}  ${pad("RULE", wRule)}  ${pad("LOCATION", wLoc)}  ${pad("SRC", wSrc)}  EXCERPT`,
    );
    lines.push(
      `${"-".repeat(wSev)}  ${"-".repeat(wRule)}  ${"-".repeat(wLoc)}  ${"-".repeat(wSrc)}  ${"-".repeat(7)}`,
    );
    for (const r of rows) {
      lines.push(
        `${pad(r.sev, wSev)}  ${pad(r.rule, wRule)}  ${pad(r.loc, wLoc)}  ${pad(r.src, wSrc)}  ${r.excerpt}`,
      );
    }

    // Count summary.
    const rej = result.findings.filter((f) => f.severity === "REJECT").length;
    const cau = result.findings.filter((f) => f.severity === "CAUTION").length;
    lines.push("");
    lines.push(`findings: ${rej} REJECT, ${cau} CAUTION`);
  }

  lines.push("");
  lines.push(`OUTCOME: ${OUTCOME_LINE[result.outcome]}`);
  if (result.outcome !== "NO_FINDINGS") {
    lines.push(
      "This is one layer. A pass is not proof of safety; complete the manual review in SKILL.md before trusting any skill.",
    );
  } else {
    lines.push(
      "The scanner issues no pass verdict. Manual review (provenance, permissions, reading every file) is still required; only a human or Claude, via the SKILL.md procedure, decides to trust a skill.",
    );
  }
  return lines.join("\n");
}

export function renderJson(result) {
  return JSON.stringify(
    {
      tool: result.tool,
      version: "1.0.0",
      target: result.target,
      scannedAt: result.scannedAt,
      privateRulesLoaded: result.privateRulesLoaded,
      privateRulesSource: result.privateRulesSource,
      filesScanned: result.filesScanned,
      outcome: result.outcome,
      outcomeLabel: OUTCOME_LINE[result.outcome],
      exitCode: result.exitCode,
      findings: result.findings.map((f) => ({
        severity: f.severity,
        ruleId: f.ruleId,
        category: f.category,
        source: f.source,
        file: f.file,
        line: f.line,
        excerpt: f.excerpt,
        description: f.description,
        escalated: !!f.escalated,
      })),
    },
    null,
    2,
  );
}
