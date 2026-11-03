#!/usr/bin/env node
// skill-security-check CLI
//
// Usage:
//   node bin/skill-check.mjs <folder> [--json] [--private-rules <file>]
//
// Exit codes:
//   0  NO AUTOMATED FINDINGS (manual review still required)
//   1  CAUTION
//   2  REJECT
//   3  private rules file exists but is invalid (fail closed)
//   64 usage error (bad arguments, target missing, explicit overlay missing)

import { scan, EXIT } from "../src/scanner.mjs";
import { renderText, renderJson } from "../src/report.mjs";
import { PrivateRulesError } from "../src/private-rules.mjs";

const HELP = `skill-security-check — vet a third-party AI agent skill before installing it.

Usage:
  skill-check <folder> [--json] [--private-rules <file>]

Arguments:
  <folder>                 Path to the skill folder (or a single file) to scan.

Options:
  --json                   Emit machine-readable JSON instead of a table.
  --private-rules <file>   Load a private rules overlay from <file>.
                           Otherwise: env SKILL_CHECK_PRIVATE_RULES, else
                           ~/.skill-security-check/private-rules.json (optional).
  -h, --help               Show this help.

Outcomes (this tool never prints APPROVE):
  REJECT (exit 2) · CAUTION (exit 1) · NO AUTOMATED FINDINGS (exit 0)

A pass is not proof of safety. This is one layer; finish the manual review
procedure in SKILL.md before trusting any skill.`;

function parseArgs(argv) {
  const out = { target: null, json: false, privateRules: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") out.json = true;
    else if (a === "-h" || a === "--help") out.help = true;
    else if (a === "--private-rules") {
      i++;
      if (i >= argv.length) {
        return { error: "--private-rules requires a file path." };
      }
      out.privateRules = argv[i];
    } else if (a.startsWith("--private-rules=")) {
      out.privateRules = a.slice("--private-rules=".length);
    } else if (a.startsWith("-")) {
      return { error: `Unknown option: ${a}` };
    } else if (out.target === null) {
      out.target = a;
    } else {
      return { error: `Unexpected extra argument: ${a}` };
    }
  }
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    process.stdout.write(HELP + "\n");
    process.exit(EXIT.NO_FINDINGS);
  }
  if (args.error) {
    process.stderr.write(`Error: ${args.error}\n\n${HELP}\n`);
    process.exit(EXIT.USAGE);
  }
  if (!args.target) {
    process.stderr.write(`Error: a target folder is required.\n\n${HELP}\n`);
    process.exit(EXIT.USAGE);
  }

  let result;
  try {
    result = scan(args.target, { privateRulesPath: args.privateRules });
  } catch (err) {
    if (err instanceof PrivateRulesError) {
      if (err.kind === "missing-explicit") {
        // User explicitly named a file that is not there: a usage error.
        process.stderr.write(`Error: ${err.message}\n`);
        process.exit(EXIT.USAGE);
      }
      // Exists but invalid => FAIL CLOSED.
      process.stderr.write(
        `Error: ${err.message}\n` +
          `Refusing to scan without the private overlay the file was meant to provide.\n`,
      );
      process.exit(EXIT.PRIVATE_RULES_INVALID);
    }
    if (err && (err.code === "ENOENT" || /ENOENT|no such file/i.test(err.message || ""))) {
      process.stderr.write(`Error: target not found: ${args.target}\n`);
      process.exit(EXIT.USAGE);
    }
    process.stderr.write(`Error: ${err && err.message ? err.message : err}\n`);
    process.exit(EXIT.USAGE);
  }

  if (args.json) {
    process.stdout.write(renderJson(result) + "\n");
  } else {
    process.stdout.write(renderText(result) + "\n");
  }
  process.exit(result.exitCode);
}

main();
