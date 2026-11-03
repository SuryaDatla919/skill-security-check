// Scanner orchestration.
//
// Outcomes (the scanner NEVER prints APPROVE):
//   - REJECT   (exit 2): at least one REJECT finding.
//   - CAUTION  (exit 1): at least one CAUTION finding, no REJECT.
//   - NO_FINDINGS (exit 0): "NO AUTOMATED FINDINGS: manual review still required".
// Private-rules failure => PrivateRulesError (the CLI maps it to exit 3).
//
// A pass is NOT proof of safety. APPROVE is only ever a human or Claude decision
// made through the SKILL.md review procedure.

import fs from "node:fs";
import path from "node:path";

import { GENERIC_RULES, CATEGORY } from "./rules.mjs";
import {
  analyzeFile,
  buildLineIndex,
  lineAt,
  lineTextAt,
  excerpt,
} from "./deny.mjs";
import { loadPrivateRules } from "./private-rules.mjs";

export const OUTCOME = {
  REJECT: "REJECT",
  CAUTION: "CAUTION",
  NO_FINDINGS: "NO_FINDINGS",
};

export const EXIT = {
  NO_FINDINGS: 0,
  CAUTION: 1,
  REJECT: 2,
  PRIVATE_RULES_INVALID: 3,
  USAGE: 64,
};

// Nothing is skipped silently. A `.git` folder is not scanned (its object store
// is binary), but it becomes an entry so deny.mjs reports it; a folder that
// cannot be listed becomes an entry so deny.mjs rejects it.

// -- directory walking --------------------------------------------------------

function walk(target, fsmod) {
  const entries = [];
  const rootStat = fsmod.lstatSync(target); // throws if missing

  if (rootStat.isFile()) {
    entries.push({
      abs: target,
      rel: path.basename(target),
      isSymlink: rootStat.isSymbolicLink(),
      size: rootStat.size,
    });
    return entries;
  }

  if (!rootStat.isDirectory()) {
    // e.g. a symlink passed directly as the target; resolve via stat.
    const realStat = fsmod.statSync(target);
    if (realStat.isFile()) {
      entries.push({ abs: target, rel: path.basename(target), isSymlink: false, size: realStat.size });
      return entries;
    }
  }

  const rootName = path.basename(target);
  const stack = [{ dir: target, relBase: "" }];
  while (stack.length) {
    const { dir, relBase } = stack.pop();
    let dirents;
    try {
      dirents = fsmod.readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      // Deny by default: a folder that cannot be listed is reported, not skipped.
      entries.push({ abs: dir, rel: relBase || ".", kind: "unreadable-dir", error: err.code || err.message });
      continue;
    }
    for (const d of dirents) {
      const abs = path.join(dir, d.name);
      const rel = relBase ? `${relBase}/${d.name}` : d.name;
      if (d.isSymbolicLink()) {
        entries.push({ abs, rel, isSymlink: true, size: 0 });
        continue;
      }
      if (d.isDirectory()) {
        if (d.name === ".git") {
          entries.push({ abs, rel, kind: "git-dir" });
          continue;
        }
        stack.push({ dir: abs, relBase: rel });
        continue;
      }
      if (d.isFile()) {
        let size = 0;
        try {
          size = fsmod.statSync(abs).size;
        } catch {
          size = 0;
        }
        entries.push({ abs, rel, isSymlink: false, size });
      }
      // sockets/fifos/etc. are ignored
    }
  }
  // Keep output stable/deterministic.
  entries.sort((a, b) => a.rel.localeCompare(b.rel));
  // Prefix a readable root label for single-file targets handled above only.
  void rootName;
  return entries;
}

// -- rule applicability -------------------------------------------------------

function fileMatchesAppliesTo(rel, appliesTo) {
  if (!appliesTo || appliesTo.length === 0) return true;
  const relLower = rel.toLowerCase().replace(/\\/g, "/");
  const base = relLower.includes("/") ? relLower.slice(relLower.lastIndexOf("/") + 1) : relLower;
  const dot = base.lastIndexOf(".");
  const ext = dot > 0 ? base.slice(dot) : "";
  for (const sel of appliesTo) {
    const s = sel.toLowerCase();
    if (s === "*" || s === "**" || s === "**/*") return true;
    if (s.startsWith(".")) {
      if (ext === s) return true;
    } else if (s.includes("*")) {
      const reStr =
        "^" +
        s.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\\\*/g, ".*") +
        "$";
      const re = new RegExp(reStr);
      if (re.test(base) || re.test(relLower)) return true;
    } else if (base === s) {
      return true;
    }
  }
  return false;
}

// -- content matching ---------------------------------------------------------

function applyRules(rules, rel, text, cap = 50) {
  const findings = [];
  const lineStarts = buildLineIndex(text);
  for (const rule of rules) {
    if (!fileMatchesAppliesTo(rel, rule.appliesTo)) continue;
    rule.re.lastIndex = 0;
    let count = 0;
    for (const m of text.matchAll(rule.re)) {
      const ln = lineAt(lineStarts, m.index);
      findings.push({
        source: rule.source || "generic",
        category: rule.category,
        ruleId: rule.id,
        severity: rule.severity,
        file: rel,
        line: ln,
        excerpt: excerpt(lineTextAt(text, lineStarts, ln), 120),
        description: rule.description,
        escalateIfNetwork: !!rule.escalateIfNetwork,
      });
      if (++count >= cap) break;
    }
  }
  return findings;
}

// -- escalation ---------------------------------------------------------------

function isNetworkFinding(f) {
  return f.category === CATEGORY.NETWORK || f.category === CATEGORY.EXFIL;
}

function escalateCredentialsWithNetwork(findings) {
  const byFile = new Map();
  for (const f of findings) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  }
  for (const [, fileFindings] of byFile) {
    const hasNetwork = fileFindings.some(isNetworkFinding);
    if (!hasNetwork) continue;
    for (const f of fileFindings) {
      if (f.escalateIfNetwork && f.severity === "CAUTION") {
        f.severity = "REJECT";
        f.escalated = true;
        f.description += " [escalated to REJECT: same file also makes network calls]";
      }
    }
  }
}

// -- public API ---------------------------------------------------------------

/**
 * Scan a folder (or a single file) for findings.
 *
 * @param {string} target  path to a skill folder or file
 * @param {object} [opts]
 * @param {string|null} [opts.privateRulesPath]  value of --private-rules
 * @param {object} [opts.fsmod]  fs module (injectable for tests)
 * @param {object} [opts.env]    environment (injectable for tests)
 * @returns {{ outcome, exitCode, findings, filesScanned, privateRulesLoaded, privateRulesSource, target, scannedAt }}
 * @throws {PrivateRulesError}
 */
export function scan(target, opts = {}) {
  const fsmod = opts.fsmod || fs;
  const env = opts.env || process.env;

  const priv = loadPrivateRules(opts.privateRulesPath, { fsmod, env });
  const allRules = GENERIC_RULES.concat(priv.rules);

  const entries = walk(target, fsmod);

  let findings = [];
  let filesScanned = 0;
  for (const entry of entries) {
    const { findings: denyFindings, readable, text } = analyzeFile(entry, fsmod);
    findings.push(...denyFindings);
    filesScanned++;
    if (readable && text !== null) {
      findings.push(...applyRules(allRules, entry.rel, text));
    }
  }

  escalateCredentialsWithNetwork(findings);

  // Order: REJECT first, then CAUTION; then by file, then line.
  const sevRank = { REJECT: 0, CAUTION: 1 };
  findings.sort(
    (a, b) =>
      (sevRank[a.severity] - sevRank[b.severity]) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line ||
      a.ruleId.localeCompare(b.ruleId),
  );

  const hasReject = findings.some((f) => f.severity === "REJECT");
  const hasCaution = findings.some((f) => f.severity === "CAUTION");

  let outcome, exitCode;
  if (hasReject) {
    outcome = OUTCOME.REJECT;
    exitCode = EXIT.REJECT;
  } else if (hasCaution) {
    outcome = OUTCOME.CAUTION;
    exitCode = EXIT.CAUTION;
  } else {
    outcome = OUTCOME.NO_FINDINGS;
    exitCode = EXIT.NO_FINDINGS;
  }

  return {
    tool: "skill-security-check",
    target,
    scannedAt: new Date().toISOString(),
    privateRulesLoaded: priv.loaded,
    privateRulesSource: priv.source,
    filesScanned,
    findings,
    outcome,
    exitCode,
  };
}
