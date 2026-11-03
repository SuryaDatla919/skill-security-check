// Deny-by-default checks.
//
// Philosophy: anything the scanner cannot *clearly read* is rejected. Hiding
// code to dodge a content rule therefore gets blocked anyway, because the
// hiding technique itself (a binary blob, a packed line, invisible characters)
// is what trips the deny check. These findings are REJECT, with one exception:
// a `.git` folder is reported as CAUTION (it is normal in a clone, but it is
// never scanned, so the reviewer is told to scan a clean export instead).

export const DENY_CATEGORY = "deny-by-default";

export const MAX_FILE_BYTES = 1024 * 1024; // ~1 MB
export const MAX_LINE_LENGTH = 1000; // minified / packed line threshold
const BASE64_RUN = 200; // suspicious inline base64 run (chars)
const HEX_RUN = 200; // suspicious inline hex run (chars)
const MAX_FINDINGS_PER_RULE_PER_FILE = 5;

// File types we treat as opaque (binary / archive / executable) by extension,
// even before reading a byte.
const OPAQUE_EXTENSIONS = new Set([
  // executables / libraries / bytecode
  "exe", "dll", "so", "dylib", "bin", "o", "obj", "a", "lib", "node", "wasm",
  "msi", "scr", "com", "cpl", "sys", "drv", "pyc", "pyo", "pyd", "class",
  "jar", "war", "ear", "apk", "aab", "ipa", "dex",
  // disk images / installers
  "dmg", "pkg", "deb", "rpm", "cab", "iso", "img", "vhd", "vhdx", "vmdk",
  // archives
  "7z", "zip", "rar", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "zst", "lz",
  "lzma", "z", "tar", "arj", "lzh",
  // media / documents that are binary containers
  "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "tiff", "tif", "psd",
  "heic", "avif", "mp3", "mp4", "m4a", "m4v", "mov", "avi", "mkv", "webm",
  "wav", "flac", "ogg", "opus", "aac", "pdf", "woff", "woff2", "ttf", "otf",
  "eot", "sqlite", "sqlite3", "db",
]);

function extOf(relPath) {
  const base = relPath.toLowerCase();
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return "";
  return base.slice(dot + 1);
}

// Build an index of line-start byte offsets so a match index can be turned
// into a 1-based line number.
export function buildLineIndex(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10 /* \n */) starts.push(i + 1);
  }
  return starts;
}

export function lineAt(lineStarts, index) {
  // binary search for greatest start <= index
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid] <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1; // 1-based
}

export function lineTextAt(text, lineStarts, lineNo) {
  const start = lineStarts[lineNo - 1];
  let end = lineStarts[lineNo] !== undefined ? lineStarts[lineNo] - 1 : text.length;
  if (end > start && text.charCodeAt(end - 1) === 13 /* \r */) end--;
  return text.slice(start, end);
}

export function excerpt(line, max = 120) {
  const collapsed = line.replace(/\s+/g, " ").trim();
  return collapsed.length > max ? collapsed.slice(0, max - 1) + "…" : collapsed;
}

// Characters that render as nothing (or reorder text) and have no business in
// skill instructions or code. Inserting one inside a keyword is also a way to
// dodge a content rule, which is why they are REJECT rather than ignored.
const INVISIBLE_SINGLES = new Set([
  0x00ad, // soft hyphen
  0x034f, // combining grapheme joiner
  0x061c, // Arabic letter mark (bidi)
  0x115f, 0x1160, 0x3164, 0xffa0, // Hangul fillers (blank "letters")
  0x180e, // Mongolian vowel separator
  0x200b, 0x200c, 0x200d, // zero-width space / non-joiner / joiner
  0x200e, 0x200f, // left-to-right / right-to-left marks
  0x2060, 0x2061, 0x2062, 0x2063, 0x2064, // word joiner, invisible operators
  0xfeff, // zero-width no-break space (a single leading BOM is allowed)
]);

function isInvisibleCodePoint(cp) {
  if (INVISIBLE_SINGLES.has(cp)) return true;
  // bidi overrides/embeddings
  if (cp >= 0x202a && cp <= 0x202e) return true;
  // bidi isolates
  if (cp >= 0x2066 && cp <= 0x2069) return true;
  // Unicode tag characters ("ASCII smuggling")
  if (cp >= 0xe0000 && cp <= 0xe007f) return true;
  // Variation Selectors Supplement: used to hide bytes after a visible character
  if (cp >= 0xe0100 && cp <= 0xe01ef) return true;
  return false;
}

function isBasicVariationSelector(cp) {
  return cp >= 0xfe00 && cp <= 0xfe0f;
}

function labelForCodePoint(cp) {
  if (cp >= 0x202a && cp <= 0x202e) return "bidi control";
  if (cp >= 0x2066 && cp <= 0x2069) return "bidi isolate";
  if (cp >= 0xe0000 && cp <= 0xe007f) return "Unicode tag char (ASCII smuggling)";
  if (cp >= 0xe0100 && cp <= 0xe01ef) return "variation selector (hidden data)";
  if (isBasicVariationSelector(cp)) return "run of variation selectors (hidden data)";
  if (cp === 0x00ad) return "soft hyphen";
  if (cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0xfeff) return "zero-width char";
  return "invisible format char";
}

function toHex(cp) {
  return "U+" + cp.toString(16).toUpperCase().padStart(4, "0");
}

/**
 * Analyze one file for deny-by-default conditions.
 *
 * @returns {{ findings: object[], readable: boolean, text: string|null }}
 *   - readable=false means the file is opaque (binary/oversize/etc.); content
 *     rules must NOT run on it. A REJECT finding is always present in that case.
 *   - text is the decoded UTF-8 content when readable, else null.
 */
export function analyzeFile(entry, fsmod) {
  const findings = [];
  const rel = entry.rel;

  const mk = (id, severity, description, line, excerptText) => ({
    source: "deny",
    category: DENY_CATEGORY,
    ruleId: id,
    severity,
    file: rel,
    line: line ?? 0,
    excerpt: excerptText ?? "",
    description,
  });

  // 0) Folders the walker could not scan. Never skipped silently.
  if (entry.kind === "git-dir") {
    findings.push(mk(
      "deny-unscanned-git",
      "CAUTION",
      "Git metadata folder (.git) is not scanned: its object store is binary, so anything hidden inside it is not checked. Scan and install from a clean export instead (for example `git archive`, or a copy without .git).",
      0,
      "(.git folder) " + rel,
    ));
    return { findings, readable: false, text: null };
  }
  if (entry.kind === "unreadable-dir") {
    findings.push(mk(
      "deny-unreadable",
      "REJECT",
      `Folder could not be listed (${entry.error}); its contents were not scanned.`,
      0,
      "(unreadable folder) " + rel,
    ));
    return { findings, readable: false, text: null };
  }

  // 1) Symlink — never followed, always rejected.
  if (entry.isSymlink) {
    findings.push(mk(
      "deny-symlink",
      "REJECT",
      "Symbolic link: target is outside the scanned tree and not verifiable.",
      0,
      "(symlink) " + rel,
    ));
    return { findings, readable: false, text: null };
  }

  // 2) Oversize — reject before reading into memory.
  const size = entry.size;
  if (size > MAX_FILE_BYTES) {
    findings.push(mk(
      "deny-oversize",
      "REJECT",
      `File exceeds the ${Math.round(MAX_FILE_BYTES / 1024)} KB readable limit (${size} bytes); not scanned.`,
      0,
      "(oversize) " + rel,
    ));
    return { findings, readable: false, text: null };
  }

  // 3) Opaque by extension (binary / archive / executable).
  const ext = extOf(rel);
  if (OPAQUE_EXTENSIONS.has(ext)) {
    findings.push(mk(
      "deny-binary-filetype",
      "REJECT",
      `Opaque file type ".${ext}" (binary / archive / executable); contents cannot be reviewed as text.`,
      0,
      "(binary) " + rel,
    ));
    return { findings, readable: false, text: null };
  }

  // Read bytes.
  let buf;
  try {
    buf = fsmod.readFileSync(entry.abs);
  } catch (err) {
    findings.push(mk(
      "deny-unreadable",
      "REJECT",
      `File could not be read (${err.code || err.message}); treated as opaque.`,
      0,
      "(unreadable) " + rel,
    ));
    return { findings, readable: false, text: null };
  }

  // 4) Binary content (NUL byte) or non-UTF-8.
  if (buf.includes(0)) {
    findings.push(mk(
      "deny-binary-content",
      "REJECT",
      "Binary content (contains NUL bytes); cannot be reviewed as text.",
      0,
      "(binary) " + rel,
    ));
    return { findings, readable: false, text: null };
  }

  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(buf);
  } catch {
    findings.push(mk(
      "deny-non-utf8",
      "REJECT",
      "Not valid UTF-8 text; cannot be reviewed reliably.",
      0,
      "(non-utf8) " + rel,
    ));
    return { findings, readable: false, text: null };
  }

  // From here the file is readable text. The following are REJECT findings but
  // do NOT stop content-rule scanning (the readable portion is still checked).
  const lineStarts = buildLineIndex(text);
  const perRuleCount = Object.create(null);
  const bump = (id) => {
    perRuleCount[id] = (perRuleCount[id] || 0) + 1;
    return perRuleCount[id] <= MAX_FINDINGS_PER_RULE_PER_FILE;
  };

  // 5) Invisible / smuggling Unicode.
  // One basic variation selector (U+FE0E/U+FE0F after an emoji) is normal text;
  // two or more in a row only happen when data is being hidden.
  let vsRun = 0;
  for (let i = 0; i < text.length; ) {
    const cp = text.codePointAt(i);
    vsRun = isBasicVariationSelector(cp) ? vsRun + 1 : 0;
    // Ignore a single leading BOM at offset 0.
    if ((!(i === 0 && cp === 0xfeff) && isInvisibleCodePoint(cp)) || vsRun === 2) {
      if (bump("deny-invisible-unicode")) {
        const ln = lineAt(lineStarts, i);
        findings.push(mk(
          "deny-invisible-unicode",
          "REJECT",
          `Invisible / control character ${toHex(cp)} (${labelForCodePoint(cp)}); used to smuggle hidden text.`,
          ln,
          excerpt(lineTextAt(text, lineStarts, ln)) || `${toHex(cp)} at offset ${i}`,
        ));
      }
    }
    i += cp > 0xffff ? 2 : 1;
  }

  // 6) Minified / packed long lines.
  // A long line is only unreviewable when it is *packed* — very little
  // whitespace, or one enormous unbroken token. Long wrapped prose, markdown
  // tables, and SVG path data have normal spacing and stay readable, so they
  // are not flagged (that would be noise, not security).
  for (let ln = 1; ln <= lineStarts.length; ln++) {
    const lt = lineTextAt(text, lineStarts, ln);
    if (lt.length <= MAX_LINE_LENGTH) continue;
    let wsCount = 0;
    let longestRun = 0;
    let cur = 0;
    for (let i = 0; i < lt.length; i++) {
      const c = lt.charCodeAt(i);
      const isWs = c === 32 || c === 9 || c === 10 || c === 13 || c === 12 || c === 11;
      if (isWs) {
        wsCount++;
        if (cur > longestRun) longestRun = cur;
        cur = 0;
      } else {
        cur++;
      }
    }
    if (cur > longestRun) longestRun = cur;
    const wsRatio = wsCount / lt.length;
    const packed = wsRatio < 0.08 || longestRun >= 200;
    if (!packed) continue;
    if (bump("deny-long-line")) {
      findings.push(mk(
        "deny-long-line",
        "REJECT",
        `Line is ${lt.length} chars, ${Math.round(wsRatio * 100)}% whitespace, longest token ${longestRun} (> ${MAX_LINE_LENGTH} and packed); minified or packed content is not reviewable.`,
        ln,
        excerpt(lt, 80),
      ));
    }
  }

  // 7) Long base64 / hex blobs (inline).
  const blobRe = new RegExp(
    `(?:[A-Za-z0-9+/]{${BASE64_RUN},}={0,2})|(?:(?:0x)?[0-9a-fA-F]{${HEX_RUN},})`,
    "g",
  );
  for (const m of text.matchAll(blobRe)) {
    if (bump("deny-long-blob")) {
      const ln = lineAt(lineStarts, m.index);
      findings.push(mk(
        "deny-long-blob",
        "REJECT",
        `Long encoded blob (${m[0].length} chars of base64/hex); may conceal a payload.`,
        ln,
        excerpt(lineTextAt(text, lineStarts, ln), 80),
      ));
    }
  }

  // 7b) Chunked base64 block (several consecutive wide base64 lines).
  const chunkRe = /(?:[A-Za-z0-9+/]{60,}={0,2}\r?\n){4,}/g;
  for (const m of text.matchAll(chunkRe)) {
    if (bump("deny-long-blob")) {
      const ln = lineAt(lineStarts, m.index);
      findings.push(mk(
        "deny-long-blob",
        "REJECT",
        "Multi-line base64 block; may conceal a payload.",
        ln,
        excerpt(lineTextAt(text, lineStarts, ln), 80),
      ));
    }
  }

  return { findings, readable: true, text };
}
