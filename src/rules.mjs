// Generic, public rule set for skill-security-check.
//
// DESIGN NOTE (read before editing): these are intentionally the *generic*
// checks that every mainstream scanner already performs. Publishing them does
// not make the tool easier to bypass (see README, "Why publishing this doesn't
// make it easy to bypass"). Anything organization- or incident-specific belongs
// in a PRIVATE rules overlay loaded at runtime from outside any repo, never here.
//
// Each rule: { id, category, severity, description, re, appliesTo?, escalateIfNetwork? }
//   - severity: "REJECT" | "CAUTION"
//   - re: a RegExp with the global flag (matching runs over the whole file text;
//         patterns use [^\n] where a match must stay on one line)
//   - appliesTo: optional array of selectors (extension like ".md", exact
//         filename like "package.json", or a simple "*" glob). Omitted = all files.
//   - escalateIfNetwork: if true, a CAUTION finding is raised to REJECT when the
//         same file also contains an outbound network call.

export const SEVERITY = { REJECT: "REJECT", CAUTION: "CAUTION" };

export const CATEGORY = {
  EXEC: "download-and-execute",
  CREDENTIAL: "credential-access",
  SECRET: "hard-coded-secret",
  EXFIL: "exfiltration",
  NETWORK: "network",
  INSTALL: "install-hook",
  PERSISTENCE: "persistence",
  DESTRUCTIVE: "destructive",
  INJECTION: "prompt-injection",
  ACTIVATION: "overly-broad-activation",
};

const MD = [".md", ".markdown", ".mdx", ".mdc", ".txt"];
const CONFIGISH = [".md", ".markdown", ".mdx", ".mdc", ".json", ".yaml", ".yml", ".toml"];

export const GENERIC_RULES = [
  // ---------------------------------------------------------------------------
  // Download-and-execute  (REJECT)
  // ---------------------------------------------------------------------------
  {
    id: "exec-curl-pipe-shell",
    category: CATEGORY.EXEC,
    severity: SEVERITY.REJECT,
    description: "Pipes a downloaded script straight into a shell (curl/wget | sh).",
    re: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da|k|c)?sh\b/gi,
  },
  {
    id: "exec-iex-download",
    category: CATEGORY.EXEC,
    severity: SEVERITY.REJECT,
    description: "Runs downloaded content as code via Invoke-Expression / iex.",
    re: /\b(?:iex|Invoke-Expression)\b[^\n]*\b(?:DownloadString|DownloadData|DownloadFile|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|Net\.WebClient|System\.Net|curl|wget)\b/gi,
  },
  {
    id: "exec-download-pipe-iex",
    category: CATEGORY.EXEC,
    severity: SEVERITY.REJECT,
    description: "Pipes a web download into Invoke-Expression / iex.",
    re: /\b(?:DownloadString|DownloadData|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|curl|wget)\b[^\n]*\|\s*(?:iex|Invoke-Expression)\b/gi,
  },
  {
    id: "exec-powershell-encoded",
    category: CATEGORY.EXEC,
    severity: SEVERITY.REJECT,
    description: "PowerShell -EncodedCommand (base64 command payload run as code).",
    re: /(?:\b(?:powershell|pwsh)\b[^\n]*\s-[Ee]nc\b|\s-[Ee]ncodedCommand\b)/g,
  },
  {
    id: "exec-frombase64-code",
    category: CATEGORY.EXEC,
    severity: SEVERITY.REJECT,
    description: "Decodes base64 to bytes for execution (FromBase64String).",
    re: /\bFromBase64String\b/g,
  },
  {
    id: "exec-eval-decoded",
    category: CATEGORY.EXEC,
    severity: SEVERITY.REJECT,
    description: "eval / new Function on decoded data (atob, Buffer.from, unescape).",
    re: /\b(?:eval|new\s+Function)\s*\(\s*(?:atob|window\.atob|Buffer\.from|decodeURIComponent|unescape|String\.fromCharCode)\b/g,
  },

  // ---------------------------------------------------------------------------
  // Credential & secret access  (CAUTION; escalates to REJECT with network)
  // ---------------------------------------------------------------------------
  {
    id: "cred-ssh-keys",
    category: CATEGORY.CREDENTIAL,
    severity: SEVERITY.CAUTION,
    escalateIfNetwork: true,
    description: "References SSH private keys or the ~/.ssh directory.",
    re: /(?:[/\\~]\.ssh[/\\]|\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b|\bid_dsa\b)/g,
  },
  {
    id: "cred-aws",
    category: CATEGORY.CREDENTIAL,
    severity: SEVERITY.CAUTION,
    escalateIfNetwork: true,
    description: "References the AWS credentials file (~/.aws/credentials).",
    re: /\.aws[/\\]credentials\b/gi,
  },
  {
    id: "cred-dotenv",
    category: CATEGORY.CREDENTIAL,
    severity: SEVERITY.CAUTION,
    escalateIfNetwork: true,
    description: "Reads a .env secrets file (optionally a named variant).",
    re: /(?:\.env\.(?:local|production|development|prod|dev|secret|secrets|vars)\b|(?:cat|type|Get-Content|readFileSync|readFile|require|load_dotenv|dotenv|source)\b[^\n]{0,40}\.env\b|(?<![\w.])\.env(?![\w.])(?=[^\n]{0,20}(?:secret|token|key|password|cred))?)/gi,
  },
  {
    id: "cred-browser-store",
    category: CATEGORY.CREDENTIAL,
    severity: SEVERITY.CAUTION,
    escalateIfNetwork: true,
    description: "Reads a browser profile credential/cookie store.",
    // Standalone matches are limited to unambiguous credential-store filenames.
    // Generic English terms (Login Data, Cookies, Local State) only match when a
    // browser name is adjacent, so prose like "drops the local state file" is safe.
    re: /(?:(?:Chrome|Chromium|Edge|Brave|Opera|Vivaldi|Firefox)[^\n]{0,80}(?:Login Data|Web Data|Cookies|User Data|Local State|logins\.json|key4\.db|cookies\.sqlite)|\b(?:logins\.json|key4\.db|cookies\.sqlite)\b|User Data[/\\](?:Default|Profile\s*\d*))/gi,
  },
  {
    id: "cred-keychain",
    category: CATEGORY.CREDENTIAL,
    severity: SEVERITY.CAUTION,
    escalateIfNetwork: true,
    description: "Invokes an OS keychain / credential-manager command.",
    re: /\b(?:security\s+find-(?:generic|internet)-password|cmdkey(?:\s+\/list)?|vaultcmd|secret-tool\s+(?:lookup|search)|keyring\.get_password|SecItemCopyMatching|Get-Credential|Export-Clixml\b[^\n]*credential)\b/gi,
  },
  {
    id: "cred-env-dump",
    category: CATEGORY.CREDENTIAL,
    severity: SEVERITY.CAUTION,
    escalateIfNetwork: true,
    description: "Dumps the full process environment (prints/pipes every variable at once).",
    // Intentionally narrow: reading os.environ / process.env for normal use is
    // not flagged. Only printing/piping the whole environment counts as a dump.
    re: /(?:\bprintenv\b|\benv\s*\|\s*(?:grep|curl|wget|nc|base64|mail|xargs|tee|python|node|perl|ruby|sh\b|bash\b|while)|\bGet-ChildItem\s+(?:-\w+\s+)*[Ee]nv:|\bdir\s+[Ee]nv:|(?:print|console\.log|echo|json\.dumps|JSON\.stringify)\s*\(\s*(?:os\.environ|process\.env)\s*\))/gi,
  },

  // ---------------------------------------------------------------------------
  // Hard-coded secrets  (REJECT)
  // ---------------------------------------------------------------------------
  {
    id: "secret-aws-access-key",
    category: CATEGORY.SECRET,
    severity: SEVERITY.REJECT,
    description: "Hard-coded AWS access key id (AKIA...).",
    re: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    id: "secret-github-token",
    category: CATEGORY.SECRET,
    severity: SEVERITY.REJECT,
    description: "Hard-coded GitHub token (ghp_/gho_/ghu_/ghs_/ghr_).",
    re: /\bgh[pousr]_[A-Za-z0-9]{36}\b/g,
  },
  {
    id: "secret-github-pat-finegrained",
    category: CATEGORY.SECRET,
    severity: SEVERITY.REJECT,
    description: "Hard-coded GitHub fine-grained PAT (github_pat_...).",
    re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
  },
  {
    id: "secret-anthropic",
    category: CATEGORY.SECRET,
    severity: SEVERITY.REJECT,
    description: "Hard-coded Anthropic API key (sk-ant-...).",
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: "secret-openrouter",
    category: CATEGORY.SECRET,
    severity: SEVERITY.REJECT,
    description: "Hard-coded OpenRouter API key (sk-or-...).",
    re: /\bsk-or-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: "secret-groq",
    category: CATEGORY.SECRET,
    severity: SEVERITY.REJECT,
    description: "Hard-coded Groq API key (gsk_...).",
    re: /\bgsk_[A-Za-z0-9]{20,}\b/g,
  },
  {
    id: "secret-openai",
    category: CATEGORY.SECRET,
    severity: SEVERITY.REJECT,
    description: "Hard-coded OpenAI-style API key (sk-...).",
    re: /\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b/g,
  },
  {
    id: "secret-slack-token",
    category: CATEGORY.SECRET,
    severity: SEVERITY.REJECT,
    description: "Hard-coded Slack token (xox...).",
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    id: "secret-stripe-live",
    category: CATEGORY.SECRET,
    severity: SEVERITY.REJECT,
    description: "Hard-coded Stripe live secret key (sk_live_...).",
    re: /\bsk_live_[A-Za-z0-9]{20,}\b/g,
  },
  {
    id: "secret-google-api-key",
    category: CATEGORY.SECRET,
    severity: SEVERITY.REJECT,
    description: "Hard-coded Google API key (AIza...).",
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    id: "secret-jwt",
    category: CATEGORY.SECRET,
    severity: SEVERITY.REJECT,
    description: "Hard-coded JSON Web Token (three base64url segments).",
    re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
  {
    id: "secret-pem-private-key",
    category: CATEGORY.SECRET,
    severity: SEVERITY.REJECT,
    description: "Embedded PEM private key block.",
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
  },

  // ---------------------------------------------------------------------------
  // Exfiltration channels
  // ---------------------------------------------------------------------------
  {
    id: "exfil-discord-webhook",
    category: CATEGORY.EXFIL,
    severity: SEVERITY.REJECT,
    description: "Posts to a Discord webhook (common exfiltration channel).",
    re: /https?:\/\/(?:[\w.-]*\.)?discord(?:app)?\.com\/api\/(?:v\d+\/)?webhooks\//gi,
  },
  {
    id: "exfil-slack-webhook",
    category: CATEGORY.EXFIL,
    severity: SEVERITY.REJECT,
    description: "Posts to a Slack incoming webhook (common exfiltration channel).",
    re: /https?:\/\/hooks\.slack\.com\//gi,
  },
  {
    id: "exfil-paste-host",
    category: CATEGORY.EXFIL,
    severity: SEVERITY.REJECT,
    description: "Contacts a paste / file-drop / request-capture host used for exfiltration.",
    re: /\b(?:pastebin\.com|paste\.ee|dpaste\.(?:com|org)|hastebin\.com|controlc\.com|termbin\.com|transfer\.sh|file\.io|0x0\.st|anonfiles\.com|gofile\.io|bashupload\.com|webhook\.site|requestbin\.\w+|pipedream\.net|ngrok\.io|ngrok-free\.app|trycloudflare\.com|interact\.sh|oast\.(?:fun|live|pro|site|me)|burpcollaborator\.net)\b/gi,
  },
  {
    id: "net-outbound",
    category: CATEGORY.NETWORK,
    severity: SEVERITY.CAUTION,
    description: "Makes an outbound network call.",
    re: /(?:\bfetch\s*\(|\baxios\s*(?:\.\s*(?:get|post|put|delete|patch|request)|\()|\brequests\.(?:get|post|put|delete|patch|request|Session)\b|\burllib\.(?:request|urlopen)|\bhttp\.client\b|\bhttps?\.request\b|\bXMLHttpRequest\b|\bInvoke-WebRequest\b|\bInvoke-RestMethod\b|\bNet\.WebClient\b|\bHttpClient\b|\bnet\/http\b|\bsocket\.(?:connect|create_connection)\b)/gi,
  },

  // ---------------------------------------------------------------------------
  // Install hooks  (CAUTION) — scoped to manifest files
  // ---------------------------------------------------------------------------
  {
    id: "install-npm-lifecycle",
    category: CATEGORY.INSTALL,
    severity: SEVERITY.CAUTION,
    appliesTo: ["package.json"],
    description: "npm lifecycle script that runs automatically on install.",
    re: /"(?:preinstall|postinstall|install|prepare|prepublish|prepublishOnly|preuninstall|postuninstall)"\s*:/g,
  },
  {
    id: "install-setuppy-cmdclass",
    category: CATEGORY.INSTALL,
    severity: SEVERITY.CAUTION,
    appliesTo: ["setup.py"],
    description: "setup.py overrides install commands via cmdclass.",
    re: /\bcmdclass\b|class\s+\w+\(\s*(?:install|develop|build_py|egg_info)\s*\)/g,
  },

  // ---------------------------------------------------------------------------
  // Persistence  (REJECT)
  // ---------------------------------------------------------------------------
  {
    id: "persist-shell-profile",
    category: CATEGORY.PERSISTENCE,
    severity: SEVERITY.REJECT,
    description: "Writes to a shell startup profile for persistence.",
    re: /(?:>>|>|\btee\b|Add-Content|Set-Content|Out-File)[^\n]{0,50}(?:\.bashrc|\.bash_profile|\.zshrc|\.zprofile|\.profile|\.config[/\\]fish)/gi,
  },
  {
    id: "persist-cron",
    category: CATEGORY.PERSISTENCE,
    severity: SEVERITY.REJECT,
    description: "Installs a cron job for persistence.",
    re: /\bcrontab\b|\/etc\/cron|\/var\/spool\/cron/gi,
  },
  {
    id: "persist-schtasks",
    category: CATEGORY.PERSISTENCE,
    severity: SEVERITY.REJECT,
    description: "Registers a scheduled task for persistence.",
    re: /\bschtasks\b|\bRegister-ScheduledTask\b/gi,
  },
  {
    id: "persist-registry-run",
    category: CATEGORY.PERSISTENCE,
    severity: SEVERITY.REJECT,
    description: "Adds a Windows registry Run key for persistence.",
    re: /(?:HK(?:LM|CU|EY_[A-Z_]+)|reg(?:\.exe)?\s+add)[^\n]*\\(?:CurrentVersion\\Run|Run)\b/gi,
  },
  {
    id: "persist-agent-config",
    category: CATEGORY.PERSISTENCE,
    severity: SEVERITY.REJECT,
    description: "Writes to agent settings, hooks, or a CLAUDE.md instruction file.",
    re: /(?:>>|>|\bAdd-Content\b|\bSet-Content\b|\bOut-File\b|writeFile(?:Sync)?|fs\.append|appendFile(?:Sync)?|\becho\b[^\n]*>)[^\n]{0,60}(?:CLAUDE\.md|\.claude[/\\](?:settings(?:\.local)?\.json|hooks)|settings\.local\.json)/gi,
  },

  // ---------------------------------------------------------------------------
  // Destructive commands  (CAUTION)
  // ---------------------------------------------------------------------------
  {
    id: "destruct-recursive-delete",
    category: CATEGORY.DESTRUCTIVE,
    severity: SEVERITY.CAUTION,
    description: "Recursive force delete of a home, root, or wildcard path.",
    re: /(?:\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+[^\n]*(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\s\/(?:\s|$|\*)|\s\*|[A-Za-z]:\\)|Remove-Item\b[^\n]*(?:-[Rr]ecurse[^\n]*-[Ff]orce|-[Ff]orce[^\n]*-[Rr]ecurse)|\brmdir\s+\/s\b)/g,
  },
  {
    id: "destruct-force-push",
    category: CATEGORY.DESTRUCTIVE,
    severity: SEVERITY.CAUTION,
    description: "Force-pushes to git, which can overwrite shared history.",
    re: /\bgit\s+push\b[^\n]*(?:--force\b|--force-with-lease\b|\s-f\b)/g,
  },
  {
    id: "destruct-disk",
    category: CATEGORY.DESTRUCTIVE,
    severity: SEVERITY.CAUTION,
    description: "Formats a disk or overwrites a raw device.",
    re: /\b(?:mkfs(?:\.\w+)?|diskpart|format\s+[A-Za-z]:|dd\s+if=[^\n]*of=\/dev\/(?:sd|nvme|disk|hd))\b/gi,
  },
  {
    id: "destruct-drop-table",
    category: CATEGORY.DESTRUCTIVE,
    severity: SEVERITY.CAUTION,
    description: "Drops a database table.",
    re: /\bDROP\s+TABLE\b/gi,
  },

  // ---------------------------------------------------------------------------
  // Prompt injection / authority spoofing  (markdown & text)
  // ---------------------------------------------------------------------------
  {
    id: "inj-ignore-previous",
    category: CATEGORY.INJECTION,
    severity: SEVERITY.CAUTION,
    appliesTo: MD,
    description: "Classic prompt-injection phrase ('ignore previous instructions').",
    re: /\bignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|preceding|earlier|foregoing)\s+(?:instructions?|prompts?|messages?|directions?|context|rules?)\b/gi,
  },
  {
    id: "inj-fake-authority",
    category: CATEGORY.INJECTION,
    severity: SEVERITY.CAUTION,
    appliesTo: MD,
    description: "Spoofs system / admin / Anthropic authority to steer the agent.",
    // A bracketed role tag ([SYSTEM]) or an explicit authority-claim sentence.
    // A bare "root:" / "system:" line prefix is NOT matched (common in CSS/YAML).
    re: /(?:\[(?:SYSTEM|ADMIN|ADMINISTRATOR|ANTHROPIC)\]|this\s+is\s+(?:an?\s+)?(?:official\s+)?(?:system|anthropic|administrator|admin)\s+(?:message|instruction|directive|override|command)|i\s+am\s+(?:the\s+)?(?:system|anthropic|administrator|an\s+anthropic\b)|on\s+behalf\s+of\s+anthropic|authorized\s+by\s+anthropic)/gi,
  },
  {
    id: "inj-hide-from-user",
    category: CATEGORY.INJECTION,
    severity: SEVERITY.REJECT,
    appliesTo: MD,
    description: "Instructs the agent to hide actions from the user ('do not tell the user', 'silently exfiltrate').",
    // "silently" alone is far too common in ordinary prose ("don't silently
    // skip", "silently filtered"), so it only counts when paired with a hidden
    // network/install/theft action — not with benign control-flow words.
    re: /(?:(?:do\s*n'?t|do\s+not|never)\s+(?:ever\s+)?(?:tell|telling|inform|informing|notify|notifying|reveal|revealing|mention|mentioning|show|showing|disclos\w*|alert\w*|warn)\s+(?:this\s+)?(?:to\s+)?(?:the\s+)?(?:user|human|operator|person)\b|without\s+the\s+user'?s?\s+(?:knowledge|awareness|consent|permission)|silently\s+(?:exfiltrat\w*|upload\w*|send\w*|transmit\w*|post\w*|email\w*|install\w*|download\w*|collect\w*|harvest\w*|steal\w*|copy|copies|copied|forward\w*|run|execut\w*))/gi,
  },
  {
    id: "inj-bypass-permissions",
    category: CATEGORY.INJECTION,
    severity: SEVERITY.REJECT,
    appliesTo: MD,
    description: "Instructs the agent to bypass the permission system.",
    re: /(?:--dangerously-skip-permissions\b|\bbypassPermissions\b|\bskip\s+permissions?\s+(?:check|prompt|dialog)|\bdisable\s+(?:the\s+)?permissions?\b)/gi,
  },
  {
    id: "inj-html-comment-instruction",
    category: CATEGORY.INJECTION,
    severity: SEVERITY.CAUTION,
    appliesTo: MD,
    description: "Hides agent instructions inside an HTML comment.",
    re: /<!--(?:[^-]|-(?!->))*?\b(?:ignore|instructions?|system\s+prompt|do\s+not\s+tell|silently|execute|run\s+this|install|you\s+must|you\s+should|assistant|claude|override|bypass)\b(?:[^-]|-(?!->))*?-->/gis,
  },

  // ---------------------------------------------------------------------------
  // Overly broad activation  (CAUTION)
  // ---------------------------------------------------------------------------
  {
    id: "activation-broad-description",
    category: CATEGORY.ACTIVATION,
    severity: SEVERITY.CAUTION,
    appliesTo: CONFIGISH,
    description: "Description claims the skill should be used for everything / always.",
    re: /description\s*[:=]\s*["']?[^\n"']*\b(?:use\s+(?:this\s+)?(?:skill\s+)?for\s+(?:everything|all\s+tasks|every\s+(?:task|request|time|message|prompt)|anything|any\s+task)|always\s+use\s+this|for\s+all\s+(?:tasks|requests|prompts|messages)|on\s+every\s+(?:message|request|prompt)|use\s+(?:this\s+)?(?:always|constantly))/gi,
  },
  {
    id: "activation-wildcard-tools",
    category: CATEGORY.ACTIVATION,
    severity: SEVERITY.CAUTION,
    appliesTo: CONFIGISH,
    description: "allowed-tools grants a wildcard such as Bash(*) or '*'.",
    re: /(?:\bBash\s*\(\s*\*\s*\)|allowed[_-]?tools\s*[:=]\s*(?:\[\s*)?["']?\s*\*|allowed[_-]?tools\s*[:=][^\n]*\bBash\s*\(\s*\*)/gi,
  },
];
