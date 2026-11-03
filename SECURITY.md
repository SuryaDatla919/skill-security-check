# Security policy

## Reporting a vulnerability or a bypass — privately

If you find a way to get a malicious skill past this scanner, **please report it
privately**, not in a public issue. A public bypass report is a working evasion
recipe for everyone until it is fixed.

Use GitHub's **private vulnerability reporting**:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability** (GitHub Private Vulnerability Reporting).
3. Describe the bypass and, ideally, a minimal **inert, defanged** reproduction
   (reserved domains such as `example.invalid`, fake tokens that match only the
   format — never a live payload or real secret).

Please do **not** open a public issue or pull request that contains a working
evasion technique.

## Scope

In scope:

- A technique that makes the scanner return a weaker outcome than the content
  warrants (for example, hiding download-and-execute, a hard-coded secret, or an
  exfiltration channel so that no finding is raised).
- A way to make the scanner crash, hang, or skip files such that unreviewed
  content slips through.
- A failure of a deny-by-default guard (binary, archive, oversize, symlink,
  packed line, encoded blob, invisible Unicode) to trigger.
- A private-rules loading flaw that silently disables the overlay instead of
  failing closed.

Out of scope:

- The scanner reporting REJECT or CAUTION on content that is ultimately benign.
  This tool is deliberately strict and **fails closed**; a conservative flag is
  working as intended, and the human review in `SKILL.md` resolves it.

## Remember what a pass means

A clean scan is **not** proof of safety. This scanner is one layer. The complete
review procedure in `SKILL.md` — provenance, reading every file as untrusted
data, checking tools and permissions — is what a trust decision rests on.
