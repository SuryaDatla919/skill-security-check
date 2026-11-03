# skill-security-check

A scanner **and** a review procedure for vetting third-party AI agent "skills" —
Claude Code skills, plugins, and similar folders of instructions plus code —
*before* anyone installs them. A skill runs with your agent's privileges, so an
unreviewed one is a supply-chain risk.

The tool has two halves:

- a **scanner** (`bin/skill-check.mjs`) that mechanically flags known-dangerous
  patterns and refuses to pass anything it cannot clearly read, and
- a **review procedure** (`SKILL.md`) — the human/agent steps for provenance,
  reading files as untrusted data, and recording a decision.

> **Authorship.** Surya Datla set the requirements, including the rule that
> publishing it must not make it easier to bypass. Claude Code (Anthropic's
> coding agent) wrote the code and tests.

## Why this exists

The reason this tool exists is a real near-miss: a forwarded list of
recommended AI tools mixed real projects with a look-alike repo impersonating a
real AI model's publisher and offering a Windows installer. Real open-weight
models ship as weight files, not `.exe` installers — and manual review caught it
before anything was downloaded. The lesson: a credible-looking list is not
evidence of safety, and a single mechanical check is not enough. This tool makes
that review repeatable.

## Install

No install step and **no dependencies** (see below). You need Node.js 24+.

```
git clone https://github.com/SuryaDatla919/skill-security-check.git
cd skill-security-check
node bin/skill-check.mjs --help
```

Optionally link the `skill-check` command:

```
npm link        # exposes `skill-check` on your PATH
```

## Usage

```
node bin/skill-check.mjs <folder> [--json] [--private-rules <file>]
```

- `<folder>` — the skill folder (or a single file) to scan.
- `--json` — machine-readable output instead of the table.
- `--private-rules <file>` — load a private rules overlay (see below).

### Outcomes and exit codes

The scanner **never prints APPROVE.** Approval is a human (or Claude) decision
made through the `SKILL.md` procedure. The scanner only reports:

| Exit | Outcome | Meaning |
| ---- | ------- | ------- |
| `0` | NO AUTOMATED FINDINGS: manual review still required | Nothing mechanical fired. **Not** a pass. |
| `1` | CAUTION | At least one CAUTION finding. |
| `2` | REJECT | At least one REJECT finding. Stop and investigate. |
| `3` | (error) | A private rules file exists but is invalid — **fails closed**, scan refused. |
| `64` | (error) | Usage error (bad arguments, target missing). |

## What it checks (public, generic rules)

These are the generic checks every mainstream scanner already performs.
Publishing them changes nothing for an attacker (see
["Why publishing this doesn't make it easy to bypass"](#why-publishing-this-doesnt-make-it-easy-to-bypass)).

**Deny by default — unreadable means REJECT.** Anything the scanner cannot
clearly read as text is rejected, so hiding code to dodge a content rule is
blocked by the hiding itself:

- symbolic links (`deny-symlink`)
- files over ~1 MB (`deny-oversize`)
- binaries / archives / executables, by type or by NUL bytes (`deny-binary-filetype`, `deny-binary-content`)
- non-UTF-8 text (`deny-non-utf8`)
- minified / packed lines over 1,000 characters (`deny-long-line`)
- long base64 / hex blobs (`deny-long-blob`)
- invisible Unicode (`deny-invisible-unicode`): zero-width characters, soft hyphens and other invisible format characters, bidi controls (U+202A–U+202E, U+2066–U+2069), Unicode tag characters (U+E0000–U+E007F, "ASCII smuggling"), and variation selectors used to hide data after a visible character (U+E0100–U+E01EF, or two or more of U+FE00–U+FE0F in a row; a single emoji selector is ordinary text). An invisible character inside a keyword is also how a content rule would be dodged, so it is rejected rather than ignored.
- folders that cannot be listed (`deny-unreadable`)

Nothing is skipped silently. A `.git` folder is not scanned, because its object
store is binary, but it is reported as **CAUTION** (`deny-unscanned-git`):
scan and install from a clean export (for example `git archive`, or a copy
without `.git`), so nothing can hide there.

**Content rules:**

| Category | Severity | What it catches |
| -------- | -------- | --------------- |
| Download-and-execute | **REJECT** | `curl`/`wget` piped to a shell; `Invoke-Expression`/`iex` on fetched content; PowerShell `-EncodedCommand`; `FromBase64String`; `eval`/`new Function` on decoded data |
| Credential & secret access | **CAUTION** → REJECT with network | `.ssh`/`id_rsa`, `.aws/credentials`, `.env` secrets, browser credential/cookie stores, OS keychain / credential-manager commands, full-environment dumps. Escalates to REJECT when the same file also makes a network call. |
| Hard-coded secrets | **REJECT** | AWS `AKIA…`, GitHub `ghp_`/`gho_`/`github_pat_`, `sk-ant-`, OpenAI-style `sk-`, `gsk_`, `sk-or-`, Slack `xox…`, Stripe `sk_live_`, Google `AIza…`, JWTs, PEM private keys |
| Exfiltration channels | **REJECT** | Discord / Slack webhooks, paste & file-drop & request-capture hosts |
| Outbound network | **CAUTION** | Generic outbound HTTP / socket calls |
| Install hooks | **CAUTION** | `package.json` pre/post/install/prepare scripts; `setup.py` `cmdclass` |
| Persistence | **REJECT** | Shell profiles, crontab, scheduled tasks, registry Run keys, writing agent settings / hooks / `CLAUDE.md` |
| Destructive commands | **CAUTION** | Recursive deletes of home/system paths, force-push, disk format, `DROP TABLE` |
| Prompt injection / authority spoofing | **REJECT** / CAUTION | Hide-from-user and permission-bypass directives (REJECT); "ignore previous instructions", fake system/Anthropic authority, instructions hidden in HTML comments (CAUTION) |
| Overly broad activation | **CAUTION** | A description that says to use the skill for everything/always; wildcard `allowed-tools` such as `Bash(*)` |

## Private rules overlay

The published rules are generic. Your organization- or incident-specific
indicators live in a **private overlay** that is never committed to any repo.
The scanner loads it from, in order:

1. `--private-rules <file>`
2. the `SKILL_CHECK_PRIVATE_RULES` environment variable
3. `~/.skill-security-check/private-rules.json` (on Windows, under `%USERPROFILE%`)

If no overlay is found at the default location, that is fine — the scan runs and
the output says no private rules were loaded. If an overlay file **exists but is
invalid**, the scan **fails closed** (exit `3`) rather than silently continuing
without the protection you expected.

The overlay is a JSON array of rule objects:

```json
[
  {
    "id": "example-private-rule",
    "severity": "CAUTION",
    "pattern": "example-internal-marker",
    "flags": "i",
    "description": "What this indicator means and why it matters.",
    "appliesTo": ["*"]
  }
]
```

- `id` — a short identifier.
- `severity` — `"REJECT"` or `"CAUTION"`.
- `pattern` — a regular-expression source string.
- `flags` — optional regex flags (`g`, `i`, `m`, `s`, `u`, `y`).
- `description` — plain-English explanation shown with the finding.
- `appliesTo` — optional array of selectors: an extension (`".md"`), an exact
  filename (`"package.json"`), or a simple `"*"` glob.

A harmless starter lives at [`rules/private-rules.example.json`](rules/private-rules.example.json).
Copy it to your private location and replace its contents with your own
indicators. **This README does not describe what any particular user's private
rules contain — that is the point of keeping them private.**

## Why publishing this doesn't make it easy to bypass

A fair question for any open-source security tool: if the rules are public, can't
an attacker just read them and route around them? In practice, no — for four
reasons, which together are the design.

1. **Kerckhoffs's principle.** A scanner's strength must not depend on its rules
   being secret. The established tools work this way: Semgrep, YARA, and CodeQL
   all publish their rules and rule-writing languages, and they remain useful.
   Secret detection logic is security by obscurity; it fails the moment the
   binary leaks. Public rules can be reviewed, improved, and trusted.
2. **Deny by default.** The scanner rejects anything it cannot clearly read —
   binaries, archives, oversized files, packed lines, encoded blobs, invisible
   characters, symlinks. The usual way to dodge a content rule is to hide the
   code (pack it, encode it, smuggle it). Here, the hiding technique is itself
   what triggers REJECT, so evasion does not buy the attacker a pass.
3. **A private rules overlay.** The checks that *would* help a specific attacker
   — an organization's internal indicators, the fingerprints of a specific
   known campaign — are loaded at runtime from a file that lives outside this
   repository and is never published. Public method, private rules.
4. **A pass is not proof of safety.** The scanner is one layer. It never
   approves; it only narrows what a human (or Claude, via `SKILL.md`) must look
   at. Provenance, reading files as untrusted data, and checking permissions are
   where the trust decision actually happens.

**Known limits.** Like any static scanner, it reads files; it does not run them.
Code that is assembled at runtime, or logic split across several files, can get
past a content rule. That is why the scanner never approves anything, and why
the review procedure in `SKILL.md` (provenance, reading every file, checking
permissions) is required before trusting a skill.

Found a real bypass? Please report it **privately** — see
[`SECURITY.md`](SECURITY.md) — through GitHub's private vulnerability reporting,
not a public issue.

## Zero dependencies, on purpose

A tool whose job is to reduce supply-chain risk must not add any. This project
has **zero runtime and zero development dependencies**: the scanner uses only the
Node.js standard library, and the tests use the built-in `node:test` runner and
`node:assert`. There is nothing in `node_modules` to audit, pin, or get
compromised — `package.json` lists no `dependencies` or `devDependencies` at
all.

## Tests

```
npm test        # node --test
```

The suite covers a benign skill (no findings), at least one positive per rule
category with near-miss negatives so ordinary skills are not flagged, every
deny-by-default case, the private overlay (loads / applies / missing / invalid),
and the CLI's JSON output and exit codes. All fixtures are inert: reserved
domains, format-only fake tokens built by concatenation at runtime, and no
antivirus-flagged strings written to disk.

## Layout

```
bin/skill-check.mjs            # CLI
src/scanner.mjs                # walk + orchestrate + outcome
src/rules.mjs                  # generic (public) rule set
src/deny.mjs                   # deny-by-default checks
src/private-rules.mjs          # overlay loader (fails closed)
src/report.mjs                 # table + JSON rendering
rules/private-rules.example.json
test/scanner.test.js
SKILL.md                       # the review procedure (a Claude Code skill)
SECURITY.md                    # private vulnerability reporting
```

## License

MIT — see [`LICENSE`](LICENSE) for the copyright notice.
