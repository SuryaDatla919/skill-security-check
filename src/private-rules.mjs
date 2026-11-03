// Private rules overlay loader.
//
// "Public method, private rules": the generic checks are published; the
// organization- or incident-specific indicators live in a JSON file OUTSIDE
// any repo. This module resolves and validates that file.
//
// Resolution order:
//   1) --private-rules <file>            (explicit; missing => error)
//   2) env SKILL_CHECK_PRIVATE_RULES     (explicit; missing => error)
//   3) ~/.skill-security-check/private-rules.json  (default; missing => fine)
//
// FAIL CLOSED: a file that exists but is invalid stops the scan (exit 3). It is
// never silently skipped — that is the whole point of a private overlay.

import path from "node:path";
import os from "node:os";

export class PrivateRulesError extends Error {
  constructor(message) {
    super(message);
    this.name = "PrivateRulesError";
  }
}

const VALID_SEVERITY = new Set(["REJECT", "CAUTION"]);
const VALID_FLAGS = /^[gimsuy]*$/;

function homeDir(env = process.env) {
  // Honor %USERPROFILE% on Windows, else HOME. Uses the passed env so callers
  // (and tests) can isolate the home directory consistently.
  return env.USERPROFILE || env.HOME || os.homedir();
}

export function defaultPrivateRulesPath(env = process.env) {
  return path.join(homeDir(env), ".skill-security-check", "private-rules.json");
}

/**
 * Resolve which private-rules path to use and whether it was explicitly set.
 * @returns {{ file: string|null, explicit: boolean }}
 */
export function resolvePrivateRulesPath(cliPath, env = process.env) {
  if (cliPath) return { file: path.resolve(cliPath), explicit: true };
  if (env.SKILL_CHECK_PRIVATE_RULES) {
    return { file: path.resolve(env.SKILL_CHECK_PRIVATE_RULES), explicit: true };
  }
  return { file: defaultPrivateRulesPath(env), explicit: false };
}

function ensureGlobal(flags) {
  const f = flags || "";
  return f.includes("g") ? f : f + "g";
}

/**
 * Load and validate private rules.
 *
 * @returns {{ loaded: boolean, source: string|null, rules: object[] }}
 * @throws {PrivateRulesError} on fail-closed conditions (exit 3) and on an
 *         explicitly requested file that is missing (treated as user error upstream).
 */
export function loadPrivateRules(cliPath, { fsmod, env = process.env } = {}) {
  const fs = fsmod;
  const { file, explicit } = resolvePrivateRulesPath(cliPath, env);

  let exists = false;
  try {
    exists = fs.existsSync(file);
  } catch {
    exists = false;
  }

  if (!exists) {
    if (explicit) {
      // The user pointed us at a file that is not there. Do not pretend to scan
      // with protections the user believes are active.
      const err = new PrivateRulesError(
        `Private rules file not found: ${file}\n` +
          `(It was requested explicitly via --private-rules or SKILL_CHECK_PRIVATE_RULES.)`,
      );
      err.kind = "missing-explicit";
      throw err;
    }
    // Default location absent => private overlay is simply not in use.
    return { loaded: false, source: null, rules: [] };
  }

  let raw;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch (e) {
    const err = new PrivateRulesError(`Cannot read private rules file ${file}: ${e.message}`);
    err.kind = "unreadable";
    throw err;
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    const err = new PrivateRulesError(
      `Private rules file ${file} is not valid JSON: ${e.message}`,
    );
    err.kind = "invalid-json";
    throw err;
  }

  if (!Array.isArray(data)) {
    const err = new PrivateRulesError(
      `Private rules file ${file} must contain a JSON array of rule objects.`,
    );
    err.kind = "invalid-schema";
    throw err;
  }

  const rules = [];
  data.forEach((item, i) => {
    const where = `rule #${i + 1}`;
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      fail(file, `${where} must be an object.`);
    }
    const { id, severity, pattern, flags, description, appliesTo } = item;
    if (typeof id !== "string" || id.trim() === "") {
      fail(file, `${where} is missing a non-empty string "id".`);
    }
    if (typeof severity !== "string" || !VALID_SEVERITY.has(severity)) {
      fail(file, `${where} ("${id}") has invalid "severity"; use "REJECT" or "CAUTION".`);
    }
    if (typeof pattern !== "string" || pattern === "") {
      fail(file, `${where} ("${id}") is missing a non-empty string "pattern" (regex source).`);
    }
    if (flags !== undefined && (typeof flags !== "string" || !VALID_FLAGS.test(flags))) {
      fail(file, `${where} ("${id}") has invalid "flags"; only g,i,m,s,u,y are allowed.`);
    }
    if (typeof description !== "string" || description.trim() === "") {
      fail(file, `${where} ("${id}") is missing a non-empty string "description".`);
    }
    if (appliesTo !== undefined) {
      if (!Array.isArray(appliesTo) || appliesTo.some((s) => typeof s !== "string")) {
        fail(file, `${where} ("${id}") has invalid "appliesTo"; use an array of strings.`);
      }
    }
    let re;
    try {
      re = new RegExp(pattern, ensureGlobal(flags));
    } catch (e) {
      fail(file, `${where} ("${id}") has an invalid regex: ${e.message}`);
    }
    rules.push({
      id,
      category: "private",
      severity,
      description,
      re,
      appliesTo,
      source: "private",
    });
  });

  return { loaded: true, source: file, rules };
}

function fail(file, msg) {
  const err = new PrivateRulesError(`Private rules file ${file} is invalid: ${msg}`);
  err.kind = "invalid-schema";
  throw err;
}
