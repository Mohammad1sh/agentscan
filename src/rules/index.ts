// Detection rules for agentscan.
// Each rule inspects a ScanTarget and returns zero or more Findings.
// agentscan-ignore-file — a rules file necessarily contains the signatures it detects.

import type { Rule, Finding, ScanTarget, FileKind, Severity } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface RawMatch {
  line: number; // 1-indexed
  column: number; // 1-indexed
  text: string;
}

/** Scan a target line-by-line for a regex, returning located matches. */
function findMatches(target: ScanTarget, pattern: RegExp, maxPerFile = 15): RawMatch[] {
  const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
  const out: RawMatch[] = [];
  for (let i = 0; i < target.lines.length; i++) {
    const line = target.lines[i] ?? '';
    const re = new RegExp(pattern.source, flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(line)) !== null) {
      out.push({ line: i + 1, column: m.index + 1, text: m[0] });
      if (m.index === re.lastIndex) re.lastIndex++;
      if (out.length >= maxPerFile) return out;
    }
  }
  return out;
}

function excerpt(text: string, max = 140): string {
  const t = text.replace(/\s+/g, ' ').trim();
  return t.length > max ? t.slice(0, max) + '…' : t;
}

/** Mask the middle of a sensitive string so it is safe to print. */
export function redact(secret: string): string {
  const t = secret.trim();
  if (t.length <= 10) return t.slice(0, 2) + '***';
  return `${t.slice(0, 4)}…${t.slice(-4)} [redacted ${t.length} chars]`;
}

function applies(target: ScanTarget, appliesTo: FileKind[] | 'all'): boolean {
  return appliesTo === 'all' || appliesTo.includes(target.kind);
}

// Documentation (README/CHANGELOG/reference .md, translations, bundled web
// content) is not executed by the agent — a dangerous command shown there is an
// example, not an instruction. For these categories, findings in a 'markdown'
// doc are demoted to 'info' so they inform without failing an otherwise
// legitimate plugin. SKILL.md, scripts, and configs keep full severity.
const PROSE_DEMOTED_CATEGORIES = new Set([
  'dangerous-command',
  'obfuscation',
  'supply-chain',
  'data-exfiltration',
  'permissions',
]);

/** Return the less-severe of two severities (SEVERITY_ORDER is critical→info). */
function minSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b;
}

function severityForProse(
  base: Severity,
  category: string,
  kind: FileKind,
  proseMax?: Severity,
): Severity {
  if (kind !== 'markdown') return base;
  if (proseMax) return minSeverity(base, proseMax);
  if (PROSE_DEMOTED_CATEGORIES.has(category)) return 'info';
  return base;
}

function basename(relPath: string): string {
  const parts = relPath.split(/[\\/]/);
  return parts[parts.length - 1] ?? relPath;
}

// ---------------------------------------------------------------------------
// Pattern rules — the common case: one regex → findings.
// ---------------------------------------------------------------------------

interface PatternRuleDef {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  appliesTo: FileKind[] | 'all';
  pattern: RegExp;
  message: string;
  recommendation: string;
  /** Skip a match if its line also matches this (placeholder allowlist etc.). */
  ignoreIf?: RegExp;
  /** Redact the matched text in the excerpt (secrets). */
  redact?: boolean;
  /** When the match is in a prose/markdown doc, cap severity here (not below). */
  proseMaxSeverity?: Severity;
}

function patternRule(def: PatternRuleDef): Rule {
  return {
    id: def.id,
    title: def.title,
    severity: def.severity,
    category: def.category,
    appliesTo: def.appliesTo,
    check(target: ScanTarget): Finding[] {
      if (!applies(target, def.appliesTo)) return [];
      const matches = findMatches(target, def.pattern);
      const findings: Finding[] = [];
      for (const m of matches) {
        const lineText = target.lines[m.line - 1] ?? '';
        if (def.ignoreIf && def.ignoreIf.test(lineText)) continue;
        findings.push({
          ruleId: def.id,
          title: def.title,
          severity: severityForProse(def.severity, def.category, target.kind, def.proseMaxSeverity),
          category: def.category,
          file: target.relPath,
          line: m.line,
          column: m.column,
          excerpt: def.redact ? redact(m.text) : excerpt(m.text),
          message: def.message,
          recommendation: def.recommendation,
        });
      }
      return findings;
    },
  };
}

const TEXT_KINDS: FileKind[] = ['skill', 'agent-rules', 'markdown', 'mcp-config'];
const CODE_KINDS: FileKind[] = ['script', 'skill', 'markdown'];
const PLACEHOLDER =
  /(example|sample|dummy|placeholder|your[-_ ]?(api|key|token|secret)|changeme|xxxx|<[^>]+>|\{\{|redacted|\bfoo\b|\bbar\b|test[-_ ]?(key|token|secret))/i;

const PATTERN_RULES: PatternRuleDef[] = [
  // --- Prompt injection ---------------------------------------------------
  {
    id: 'PI001',
    title: 'Instruction-override phrasing',
    severity: 'high',
    category: 'prompt-injection',
    appliesTo: TEXT_KINDS,
    pattern:
      /\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any)\b[^.\n]{0,25}\b(instruction|prompt|rule|context|message|guardrail)/i,
    message:
      'Text attempts to override the agent’s prior instructions — a classic prompt-injection pattern.',
    recommendation:
      'Remove instructions that tell the agent to ignore or override its system prompt. Legitimate skills describe a task, they do not reprogram the agent.',
  },
  {
    id: 'PI002',
    title: 'Authority impersonation',
    severity: 'medium',
    category: 'prompt-injection',
    appliesTo: TEXT_KINDS,
    pattern:
      /\b(as|i am|this is|acting as)\s+(the\s+)?(system|developer|administrator|admin|anthropic|openai|root|superuser)\b/i,
    message:
      'Content claims elevated authority (system/developer/admin) to pressure the agent into compliance.',
    recommendation:
      'Skills should not impersonate the system or platform. Rewrite as a plain task description.',
    proseMaxSeverity: 'low',
  },
  {
    id: 'PI003',
    title: 'Covert-action instruction',
    severity: 'high',
    category: 'prompt-injection',
    appliesTo: TEXT_KINDS,
    pattern:
      /\b(do not|don't|never)\b[^.\n]{0,25}\b(tell|inform|mention|notify|show|reveal|warn)\b[^.\n]{0,25}\b(the\s+)?(user|human|owner|operator)\b/i,
    message:
      'Instructs the agent to hide an action from the user — a hallmark of malicious skills.',
    recommendation:
      'Any skill that asks the agent to conceal what it is doing should be treated as hostile. Remove it.',
  },
  {
    id: 'PI004',
    title: 'Forced tool execution',
    severity: 'medium',
    category: 'prompt-injection',
    appliesTo: TEXT_KINDS,
    pattern:
      /\b(you must|always|be sure to|make sure to|immediately)\b[^.\n]{0,30}\b(run|execute|invoke|call|curl|download|install|delete|send)\b/i,
    message:
      'Uses coercive phrasing to force the agent to run a command or tool without judgement.',
    recommendation:
      'Describe when a step is appropriate rather than commanding unconditional execution.',
    proseMaxSeverity: 'low',
  },

  // --- Dangerous commands -------------------------------------------------
  {
    id: 'DC001',
    title: 'Destructive recursive delete',
    severity: 'critical',
    category: 'dangerous-command',
    appliesTo: CODE_KINDS,
    pattern: /\brm\s+-[a-z]*[rf][a-z]*\s+(--no-preserve-root\s+)?(\/(?!\w)|~|\$HOME|\*|\.)/i,
    message: 'Recursive force-delete targeting a root, home, or wildcard path can wipe a machine.',
    recommendation:
      'Never ship an unscoped rm -rf. Scope deletes to a specific, non-critical directory.',
  },
  {
    id: 'DC002',
    title: 'Pipe-to-shell remote execution',
    severity: 'critical',
    category: 'dangerous-command',
    appliesTo: CODE_KINDS,
    pattern:
      /\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*(sudo\s+)?(sh|bash|zsh|dash|python3?|node|pwsh|powershell)\b/i,
    message:
      'Downloads and executes remote code in one step; the fetched payload can change at any time.',
    recommendation:
      'Download to a file, review it, pin it by checksum, then run. Do not pipe network output straight into a shell.',
  },
  {
    id: 'DC003',
    title: 'Privileged execution (sudo)',
    severity: 'medium',
    category: 'dangerous-command',
    appliesTo: CODE_KINDS,
    pattern: /(^|[\s;&|])sudo\s+\S/i,
    message: 'Runs commands with elevated privileges from inside an agent skill.',
    recommendation:
      'A skill should not silently escalate privileges. If root is truly required, make it explicit and ask the user.',
  },
  {
    id: 'DC004',
    title: 'Loosened permissions (chmod 777)',
    severity: 'medium',
    category: 'dangerous-command',
    appliesTo: CODE_KINDS,
    pattern: /\bchmod\s+(-[a-z]+\s+)?(777|a\+rwx|o\+w)\b/i,
    message: 'Makes files world-writable/executable, a common foothold for privilege escalation.',
    recommendation: 'Grant the narrowest permissions that work (e.g. 750 / 640).',
  },
  {
    id: 'DC005',
    title: 'Shell-startup persistence',
    severity: 'high',
    category: 'dangerous-command',
    appliesTo: CODE_KINDS,
    pattern:
      /(>>?\s*~?\/?\.(bashrc|zshrc|profile|bash_profile|zprofile)\b|crontab\s+-|launchctl\s+load|New-ItemProperty[^\n]*CurrentVersion\\\\Run)/i,
    message:
      'Writes to a shell-startup file, cron, or autorun key — establishes persistence that outlives the skill.',
    recommendation:
      'Skills should not install background persistence. Remove edits to startup files, cron, or run keys.',
  },
  {
    id: 'DC006',
    title: 'Reverse shell / raw socket',
    severity: 'critical',
    category: 'dangerous-command',
    appliesTo: CODE_KINDS,
    pattern:
      /(\/dev\/tcp\/\d|\bnc(at)?\b[^\n]{0,40}\s-[a-z]*e|bash\s+-i\b|socket\.socket\([^\n]*SOCK_STREAM[^\n]*connect)/i,
    message: 'Opens an interactive connection to a remote host — consistent with a reverse shell.',
    recommendation: 'There is no legitimate reason for a skill to open a reverse shell. Remove it.',
  },
  {
    id: 'DC007',
    title: 'History tampering / trace hiding',
    severity: 'high',
    category: 'dangerous-command',
    appliesTo: CODE_KINDS,
    pattern: /\b(history\s+-c|unset\s+HISTFILE|set\s+\+o\s+history|export\s+HISTSIZE=0)\b/i,
    message: 'Clears or disables shell history to hide what the skill did.',
    recommendation: 'Remove anti-forensic commands; a trustworthy skill has nothing to hide.',
  },

  // --- Data exfiltration --------------------------------------------------
  {
    id: 'EX002',
    title: 'SSH key access',
    severity: 'high',
    category: 'data-exfiltration',
    appliesTo: CODE_KINDS,
    pattern: /(~\/\.ssh\/|id_rsa\b|id_ed25519\b|authorized_keys\b)/,
    message: 'Reads SSH private keys or authorized_keys.',
    recommendation:
      'Skills should never touch SSH keys. If key access is essential, require explicit user consent and document it.',
  },
  {
    id: 'EX003',
    title: 'Cloud / credential file access',
    severity: 'high',
    category: 'data-exfiltration',
    appliesTo: CODE_KINDS,
    pattern:
      /(\.aws\/credentials|\.config\/gcloud|\.kube\/config|\.docker\/config\.json|\.npmrc|\.netrc|\.git-credentials|security\s+find-generic-password)/i,
    message: 'Reads cloud or package-manager credential stores.',
    recommendation:
      'Do not harvest credential files. Use the platform’s official auth flow scoped to what the task needs.',
  },
  {
    id: 'EX005',
    title: 'Suspicious exfiltration endpoint',
    severity: 'high',
    category: 'data-exfiltration',
    appliesTo: 'all',
    pattern:
      /(webhook\.site|requestbin|\.ngrok\.(io|app)|pastebin\.com|hastebin|discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|oast\.(pro|live|site))/i,
    message: 'References an endpoint commonly used to receive exfiltrated data.',
    recommendation:
      'Verify why data is being sent here. These hosts are frequently used to smuggle secrets out.',
  },

  // --- Hardcoded secrets --------------------------------------------------
  {
    id: 'SE001',
    title: 'AWS access key id',
    severity: 'critical',
    category: 'secret',
    appliesTo: 'all',
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    message: 'A live-looking AWS access key id is hardcoded in the file.',
    recommendation: 'Revoke the key immediately and load credentials from the environment instead.',
    redact: true,
  },
  {
    id: 'SE002',
    title: 'Private key block',
    severity: 'critical',
    category: 'secret',
    appliesTo: 'all',
    pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
    message: 'An embedded private key was found.',
    recommendation: 'Remove the key, rotate it, and never commit private keys to a distributed skill.',
    redact: false,
  },
  {
    id: 'SE003',
    title: 'OpenAI-style API key',
    severity: 'high',
    category: 'secret',
    appliesTo: 'all',
    pattern: /\bsk-(proj-)?[A-Za-z0-9]{24,}\b/,
    message: 'A hardcoded OpenAI-style secret key was found.',
    recommendation: 'Rotate the key and read it from an environment variable at runtime.',
    ignoreIf: PLACEHOLDER,
    redact: true,
  },
  {
    id: 'SE004',
    title: 'Anthropic API key',
    severity: 'high',
    category: 'secret',
    appliesTo: 'all',
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
    message: 'A hardcoded Anthropic API key was found.',
    recommendation: 'Rotate the key and read it from an environment variable at runtime.',
    ignoreIf: PLACEHOLDER,
    redact: true,
  },
  {
    id: 'SE005',
    title: 'GitHub token',
    severity: 'high',
    category: 'secret',
    appliesTo: 'all',
    pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/,
    message: 'A hardcoded GitHub token was found.',
    recommendation: 'Revoke the token and use a scoped, environment-provided credential.',
    redact: true,
  },
  {
    id: 'SE006',
    title: 'Google API key',
    severity: 'high',
    category: 'secret',
    appliesTo: 'all',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
    message: 'A hardcoded Google API key was found.',
    recommendation: 'Rotate the key and restrict it; never ship it inside a skill.',
    ignoreIf: PLACEHOLDER,
    redact: true,
  },
  {
    id: 'SE007',
    title: 'Slack token',
    severity: 'high',
    category: 'secret',
    appliesTo: 'all',
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
    message: 'A hardcoded Slack token was found.',
    recommendation: 'Revoke the token and load it from the environment.',
    redact: true,
  },
  {
    id: 'SE008',
    title: 'Stripe secret key',
    severity: 'high',
    category: 'secret',
    appliesTo: 'all',
    pattern: /\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}\b/,
    message: 'A hardcoded Stripe secret key was found.',
    recommendation: 'Roll the key in the Stripe dashboard and read it from the environment.',
    ignoreIf: PLACEHOLDER,
    redact: true,
  },
  {
    id: 'SE009',
    title: 'Generic hardcoded credential',
    severity: 'medium',
    category: 'secret',
    appliesTo: 'all',
    pattern:
      /\b(api[_-]?key|secret|token|password|passwd|access[_-]?key)\b\s*[:=]\s*["'][^"'\s]{8,}["']/i,
    message: 'A credential appears to be assigned a hardcoded literal value.',
    recommendation:
      'Move the value to an environment variable or secret store. Keep only a placeholder in the skill.',
    ignoreIf: PLACEHOLDER,
    redact: true,
    proseMaxSeverity: 'low',
  },

  // --- Supply chain -------------------------------------------------------
  {
    id: 'SC001',
    title: 'Auto-confirmed remote install',
    severity: 'medium',
    category: 'supply-chain',
    appliesTo: ['mcp-config', 'script', 'skill'],
    pattern: /\bnpx\s+(-y|--yes)\b/i,
    message: 'Runs npx with auto-confirm, installing and executing a remote package unattended.',
    recommendation:
      'Pin the package version and drop -y so the install is reviewed. Prefer vendored or audited dependencies.',
  },
  {
    id: 'SC002',
    title: 'Runtime package install',
    severity: 'low',
    category: 'supply-chain',
    appliesTo: CODE_KINDS,
    pattern: /\b(pip3?|uv\s+pip|pipx|gem)\s+install\b|\bnpm\s+i(nstall)?\b\s+\S/i,
    message: 'Installs packages at skill runtime, pulling unaudited code onto the machine.',
    recommendation: 'Declare dependencies up front and pin versions rather than installing on the fly.',
  },
  {
    id: 'SC003',
    title: 'Unpinned remote script fetch',
    severity: 'low',
    category: 'supply-chain',
    appliesTo: CODE_KINDS,
    pattern: /raw\.githubusercontent\.com\/[^\s"'`]+/i,
    message: 'Fetches a script from a mutable raw URL that can change without notice.',
    recommendation: 'Pin to a specific commit SHA and verify a checksum before executing.',
    ignoreIf: /[0-9a-f]{40}/i,
  },
];

// ---------------------------------------------------------------------------
// Custom rules — logic that a single regex cannot express.
// ---------------------------------------------------------------------------

// Invisible/bidi Unicode that can smuggle instructions past a human reviewer.
// Tuned to avoid false positives on legitimate content: emoji zero-width
// joiners, right-to-left scripts (Arabic/Hebrew/…), and a leading BOM.
const RTL_LETTER =
  /[֐-׿؀-ۿ܀-ݏݐ-ݿࢠ-ࣿיִ-﷿ﹰ-﻿]/;
const TAG_CHAR = (cp: number): boolean => cp >= 0xe0000 && cp <= 0xe007f;
const BIDI_CONTROL = (cp: number): boolean =>
  cp === 0x200e || cp === 0x200f || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x206f);
const ZERO_WIDTH = (cp: number): boolean =>
  cp === 0x200b || (cp >= 0x2060 && cp <= 0x2064) || cp === 0xfeff;
// 0x200c / 0x200d (ZWNJ / ZWJ) are intentionally excluded — they are used in
// emoji sequences and in Persian, Indic, and other scripts.

function isAsciiWord(ch: string | undefined): boolean {
  return ch !== undefined && /[A-Za-z0-9]/.test(ch);
}

const hiddenUnicodeRule: Rule = {
  id: 'PI005',
  title: 'Hidden Unicode characters',
  severity: 'high',
  category: 'prompt-injection',
  appliesTo: 'all',
  check(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    for (let i = 0; i < target.lines.length; i++) {
      const line = target.lines[i] ?? '';
      const lineIsRtl = RTL_LETTER.test(line);
      for (let j = 0; j < line.length; j++) {
        const cp = line.codePointAt(j);
        if (cp === undefined) continue;
        let flagged = false;
        if (TAG_CHAR(cp)) {
          flagged = true; // Unicode tag chars have no legitimate textual use.
        } else if (BIDI_CONTROL(cp)) {
          // Bidi controls are expected inside RTL text; only suspicious when the
          // line is otherwise left-to-right / ASCII.
          flagged = !lineIsRtl;
        } else if (ZERO_WIDTH(cp)) {
          if (cp === 0xfeff && i === 0 && j === 0) continue; // leading BOM is fine
          // Only flag a zero-width char wedged between ASCII word characters —
          // the invisible-splitter smuggling pattern. Decorative/spacing uses
          // (e.g. inside emoji or non-ASCII text) are left alone.
          flagged = isAsciiWord(line[j - 1]) && isAsciiWord(line[j + 1]);
        }
        if (flagged) {
          findings.push({
            ruleId: 'PI005',
            title: 'Hidden Unicode characters',
            severity: 'high',
            category: 'prompt-injection',
            file: target.relPath,
            line: i + 1,
            column: j + 1,
            excerpt: `U+${cp.toString(16).toUpperCase().padStart(4, '0')} (invisible character)`,
            message:
              'Invisible/bidirectional Unicode can hide instructions from a human reviewer while the model still reads them.',
            recommendation:
              'Strip zero-width, bidi, and tag characters. If they are not intentional, the file may be a smuggling attempt.',
          });
          break; // one finding per line is enough
        }
      }
      if (findings.length >= 15) break;
    }
    return findings;
  },
};

// A genuine exfiltration payload reads a *sensitive* secret and sends it over
// the network *near* the read. Requiring a specific secret (not bare .env /
// process.env, which every app touches) plus line proximity avoids flagging a
// README that mentions `.env` in one place and `curl` far away in another.
const SECRET_READ =
  /(id_rsa\b|id_ed25519\b|~?\/?\.ssh\/|\.aws\/credentials|\.config\/gcloud|\.git-credentials|\.netrc\b|\.npmrc\b|find-generic-password|\b[A-Z][A-Z0-9_]*(_KEY|_TOKEN|_SECRET|_PASSWORD|_PASSWD)\b|process\.env\.[A-Za-z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)|os\.environ(\.get\(|\[)['"][^'"]*(KEY|TOKEN|SECRET|PASSWORD))/;
const NETWORK_SEND =
  /\b(curl|wget|fetch\s*\(|axios|requests\.(get|post|put)|urllib|http\.request|Invoke-WebRequest|Invoke-RestMethod|nc\s|ncat\s|\/dev\/tcp\/)/i;
const EXFIL_WINDOW = 4; // secret read and network send must be within N lines

const exfilComboRule: Rule = {
  id: 'EX001',
  title: 'Credential read combined with network send',
  severity: 'critical',
  category: 'data-exfiltration',
  appliesTo: ['script', 'skill', 'markdown'],
  check(target: ScanTarget): Finding[] {
    const secretLines: number[] = [];
    const netLines: number[] = [];
    for (let i = 0; i < target.lines.length; i++) {
      const line = target.lines[i] ?? '';
      if (SECRET_READ.test(line)) secretLines.push(i);
      if (NETWORK_SEND.test(line)) netLines.push(i);
    }
    if (!secretLines.length || !netLines.length) return [];
    let secretLine = -1;
    let netLine = -1;
    for (const s of secretLines) {
      for (const n of netLines) {
        if (Math.abs(s - n) <= EXFIL_WINDOW) {
          secretLine = s;
          netLine = n;
          break;
        }
      }
      if (secretLine !== -1) break;
    }
    if (secretLine === -1) return []; // secret and network never close together
    const severity: Severity = target.kind === 'markdown' ? 'info' : 'critical';
    return [
      {
        ruleId: 'EX001',
        title: 'Credential read combined with network send',
        severity,
        category: 'data-exfiltration',
        file: target.relPath,
        line: netLine + 1,
        column: 1,
        excerpt: excerpt(target.lines[netLine] ?? ''),
        message: `This file reads a secret (line ${secretLine + 1}) and sends data over the network (line ${netLine + 1}) within ${EXFIL_WINDOW} lines — the shape of a data-exfiltration payload.`,
        recommendation:
          'Confirm the destination and payload. A skill that reads credentials and phones home should be treated as hostile until proven otherwise.',
      },
    ];
  },
};

// --- Over-broad permissions (config / frontmatter) ------------------------

const PERMISSION_PATTERNS: PatternRuleDef[] = [
  {
    id: 'PM001',
    title: 'Wildcard tool grant',
    severity: 'high',
    category: 'permissions',
    appliesTo: ['mcp-config', 'skill', 'agent-rules'],
    pattern: /["']?(allowed[-_]?tools|allowedTools|tools|permissions)["']?\s*[:=]\s*["']?\*["']?/i,
    message: 'Grants the skill access to every tool via a wildcard.',
    recommendation: 'List only the specific tools the skill needs.',
  },
  {
    id: 'PM002',
    title: 'Permission bypass flag',
    severity: 'high',
    category: 'permissions',
    appliesTo: 'all',
    pattern:
      /(--dangerously-skip-permissions|"?permission[_-]?mode"?\s*[:=]\s*["']?bypasspermissions|"?(bypasspermissions|autoapprove|yolo)"?\s*[:=]\s*true)/i,
    message: 'Disables the human-in-the-loop confirmation step.',
    recommendation:
      'Never ship auto-approve/permission-bypass in a distributed skill. Let the user approve sensitive actions.',
  },
  {
    id: 'PM003',
    title: 'Unrestricted Bash grant',
    severity: 'medium',
    category: 'permissions',
    appliesTo: ['mcp-config', 'skill', 'agent-rules'],
    pattern: /Bash\(\s*\*\s*\)|Bash\(:\*\)/,
    message: 'Allows arbitrary shell execution with a wildcard Bash grant.',
    recommendation: 'Scope Bash permissions to specific commands (e.g. Bash(npm run test:*)).',
  },
];

// --- Hygiene / quality ----------------------------------------------------

const hygieneRule: Rule = {
  id: 'HY001',
  title: 'Skill hygiene',
  severity: 'low',
  category: 'hygiene',
  appliesTo: ['skill'],
  check(target: ScanTarget): Finding[] {
    if (target.kind !== 'skill') return [];
    const findings: Finding[] = [];
    const name = basename(target.relPath).toLowerCase();
    const isSkillManifest = name === 'skill.md';
    if (isSkillManifest) {
      const hasFrontmatter = /^\s*---\s*\n/.test(target.content);
      if (!hasFrontmatter) {
        findings.push(mkHygiene(target, 1, 'low', 'HY001', 'Missing YAML frontmatter',
          'SKILL.md has no frontmatter block, so the agent cannot read its name/description.',
          'Add a --- frontmatter block with at least name and description fields.'));
      } else if (!/\n\s*description\s*:/i.test(target.content)) {
        findings.push(mkHygiene(target, 1, 'low', 'HY002', 'Missing description',
          'Frontmatter has no description; discovery and routing will be poor.',
          'Add a one-line description of when to use this skill.'));
      }
    }
    if (target.sizeBytes > 51200) {
      findings.push(mkHygiene(target, 1, 'info', 'HY003', 'Oversized skill file',
        `This file is ${Math.round(target.sizeBytes / 1024)}KB; large skills waste context on every load.`,
        'Split reference material into separate files the skill links to on demand.'));
    }
    return findings;
  },
};

function mkHygiene(
  target: ScanTarget,
  line: number,
  severity: Severity,
  ruleId: string,
  title: string,
  message: string,
  recommendation: string,
): Finding {
  return {
    ruleId,
    title,
    severity,
    category: 'hygiene',
    file: target.relPath,
    line,
    column: 1,
    excerpt: basename(target.relPath),
    message,
    recommendation,
  };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

// Second-wave rules: MCP-specific threats, obfuscation, Windows commands,
// deeper supply chain. Derived from a structured threat-research pass.
const PATTERN_RULES_V2: PatternRuleDef[] = [
  // --- MCP-server-specific ---------------------------------------------
  {
    id: 'MCP001',
    title: 'Hidden directive tag in tool description',
    severity: 'critical',
    category: 'mcp-tool-poisoning',
    appliesTo: TEXT_KINDS,
    pattern: /"(description|instructions)"\s*:\s*".*<\s*(important|system|instructions?|admin|hidden)\s*>/i,
    message:
      'A tool/parameter description hides an agent-directed directive tag (e.g. <IMPORTANT>). This is the MCP "tool poisoning" technique — the model reads it as trusted docs the moment tools are listed, before any call is approved.',
    recommendation:
      'Reject tool descriptions that contain directive tags, and show descriptions to the user before approval.',
  },
  {
    id: 'MCP002',
    title: 'Cross-server forwarding instruction',
    severity: 'critical',
    category: 'mcp-tool-poisoning',
    appliesTo: TEXT_KINDS,
    pattern:
      /\b(whenever|every time|any time)\b[^.\n]{0,40}\byou (use|call|invoke)\b[^.\n]{0,60}\b(also|additionally)\b[^.\n]{0,40}\b(bcc|cc|forward|send (a copy|it) to)\b/i,
    message:
      'Instructs the agent that whenever it uses another (trusted) tool it should also silently copy or forward data elsewhere — the cross-server tool-shadowing exfiltration pattern.',
    recommendation:
      'A tool description must not change how other tools are used. Treat this as a compromise indicator.',
  },
  {
    id: 'MCP003',
    title: 'Credential contents routed into a tool parameter',
    severity: 'high',
    category: 'mcp-tool-poisoning',
    appliesTo: TEXT_KINDS,
    pattern:
      /\b(include|insert|append|attach|embed|put)\b[^.\n]{0,50}\bcontents?\s+of\b[^.\n]{0,60}(id_rsa|\.ssh|\.aws\/credentials|\.env|password|api[_-]?key)/i,
    message:
      'Instructs the agent to embed the contents of a credential file or secret into a call parameter — side-channel exfiltration through a legitimate-looking tool call.',
    recommendation:
      'Legitimate tool docs do not reference ~/.ssh, .aws/credentials or .env. Reject and review.',
  },
  {
    id: 'MCP008',
    title: 'Privileged container or host-root mount',
    severity: 'critical',
    category: 'permissions',
    appliesTo: ['mcp-config'],
    pattern: /--privileged|--cap-add[=\s]*all|"-v"\s*,\s*"\/:/i,
    message:
      'An MCP server container is launched privileged or with the host filesystem root mounted — container isolation then provides no protection.',
    recommendation:
      'Never use --privileged, --cap-add=ALL, or a -v /:/… root mount. Mount only the directory the server needs, read-only where possible.',
  },
  {
    id: 'MCP009',
    title: 'Command substitution in MCP env value',
    severity: 'high',
    category: 'data-exfiltration',
    appliesTo: ['mcp-config'],
    pattern: /"[A-Z_][A-Z0-9_]*"\s*:\s*"[^"]*\$\([^)]*\)[^"]*"/,
    message:
      'An MCP env value uses shell command substitution $(…) instead of a literal or ${VAR} — a structure used to harvest credentials into the server process at launch.',
    recommendation:
      'MCP env blocks should contain only literal values or ${VAR} references. Reject command substitution.',
  },
  {
    id: 'MCP011',
    title: 'Dangerous tool on MCP auto-approve list',
    severity: 'high',
    category: 'permissions',
    appliesTo: ['mcp-config'],
    pattern:
      /"(alwaysallow|autoapprove|auto_approve)"\s*:\s*\[[^\]]*"(execute_command|run_command|shell|bash|write_file|delete_file|eval|exec)"[^\]]*\]/i,
    message:
      'A code-execution or file-mutating tool is on the MCP auto-approve list, so it runs with no per-call confirmation — any later compromise of that server gets unattended execution rights.',
    recommendation:
      'Keep destructive/exec tools out of autoApprove/alwaysAllow; require explicit confirmation for anything that mutates files or runs code.',
  },
  // --- Obfuscation: decode-and-execute ---------------------------------
  {
    id: 'OBF001',
    title: 'eval(atob(...)) decode-and-execute',
    severity: 'critical',
    category: 'obfuscation',
    appliesTo: CODE_KINDS,
    pattern: /\b(eval|Function)\s*\(\s*atob\s*\(/,
    message:
      'A base64-decoded string is fed straight into eval()/Function() — the real behavior is hidden from static reading and only appears at runtime.',
    recommendation: 'Decode the payload offline and review it. A skill should not execute code from a decoded blob.',
  },
  {
    id: 'OBF002',
    title: 'Buffer.from(base64) piped into exec/eval',
    severity: 'critical',
    category: 'obfuscation',
    appliesTo: CODE_KINDS,
    pattern: /\b(eval|Function|exec|execSync|spawn|spawnSync)\s*\(\s*Buffer\.from\([^,]+,\s*['"]base64['"]/,
    message:
      'A base64-decoded Buffer is passed directly into eval/Function or a child_process call — a Node.js stage-2 loader pattern.',
    recommendation: 'Never decode and execute in one step. Write the decoded content to a reviewable file first.',
  },
  {
    id: 'OBF003',
    title: 'exec/eval of base64.b64decode (Python)',
    severity: 'critical',
    category: 'obfuscation',
    appliesTo: CODE_KINDS,
    pattern: /\b(exec|eval)\s*\([^\n]{0,80}\bb64decode\s*\(/,
    message:
      'A base64-decoded value is executed with exec()/eval(), hiding the real command from anyone reading the source.',
    recommendation: 'Decode and review the blob. Legitimate b64decode is followed by parsing, not exec/eval.',
  },
  {
    id: 'OBF005',
    title: 'exec(marshal.loads(...)) bytecode loader',
    severity: 'critical',
    category: 'obfuscation',
    appliesTo: CODE_KINDS,
    pattern: /\bexec\s*\(\s*marshal\.loads\s*\(/,
    message:
      'Raw marshalled Python bytecode is deserialized and executed — a hallmark of Python malware loaders with no benign use in a skill.',
    recommendation: 'Quarantine the file. There is no legitimate reason to exec marshalled bytecode in a skill.',
  },
  {
    id: 'OBF006',
    title: 'PowerShell -EncodedCommand base64 blob',
    severity: 'critical',
    category: 'obfuscation',
    appliesTo: CODE_KINDS,
    pattern: /-(e|enc|encodedcommand)\b\s+[A-Za-z0-9+\/=]{60,}/i,
    message:
      'PowerShell -EncodedCommand runs a base64/UTF-16LE script with no plaintext on the command line — a common evasion technique.',
    recommendation: 'Decode the blob and review it. Ship plaintext .ps1 files, not pre-encoded one-liners.',
  },
  {
    id: 'OBF011',
    title: 'base64 -d piped into a shell',
    severity: 'critical',
    category: 'obfuscation',
    appliesTo: CODE_KINDS,
    pattern:
      /base64\s+(-d|--decode)\b[^\n]*\|\s*(bash|sh|zsh)\b|(eval|bash|sh|zsh)\s*(<\(|"?\$\()[^\n]*base64\s+(-d|--decode)\b/i,
    message:
      'A base64 blob is decoded and streamed straight into a shell, so the real command never appears in plaintext.',
    recommendation: 'Decode the blob and review the command before running the skill.',
  },
  // --- Windows / PowerShell dangerous commands -------------------------
  {
    id: 'WIN001',
    title: 'PowerShell download-and-execute cradle',
    severity: 'critical',
    category: 'dangerous-command',
    appliesTo: CODE_KINDS,
    pattern:
      /(\biwr\b|\birm\b|invoke-webrequest|invoke-restmethod)[^\n|]{0,200}\|\s*(iex|invoke-expression)\b|iex\s*\(\s*(new-object\s+)?(system\.)?net\.webclient/i,
    message:
      'Downloads a remote script and runs it in memory via Invoke-Expression — the Windows analog of curl|bash, leaving nothing on disk to scan.',
    recommendation: 'Download to a file, review it, then run a pinned, hash-verified copy. Never pipe web output into iex.',
  },
  {
    id: 'WIN002',
    title: 'Disables Windows Defender protection',
    severity: 'critical',
    category: 'dangerous-command',
    appliesTo: CODE_KINDS,
    pattern:
      /set-mppreference\b[^\n]*-disable(realtimemonitoring|ioavprotection|behaviormonitoring|scriptscanning)\b[^\n]*\$?true\b/i,
    message: 'Turns off a Windows Defender protection feature — the standard first step before dropping further malware.',
    recommendation: 'A skill should never alter endpoint AV settings. Remove it.',
  },
  {
    id: 'WIN004',
    title: 'Registry Run-key persistence',
    severity: 'high',
    category: 'dangerous-command',
    appliesTo: CODE_KINDS,
    pattern:
      /reg(\.exe)?\s+add\s+[^\n]*currentversion.run(once)?\b[^\n]*\/v\s|new-itemproperty\s+[^\n]*currentversion.run(once)?\b/i,
    message:
      'Writes to the CurrentVersion\\Run / RunOnce registry key — the most common Windows auto-start persistence mechanism.',
    recommendation: 'Skills should not install logon persistence. Remove the Run-key write.',
  },
  {
    id: 'WIN011',
    title: 'Shadow copy / backup deletion',
    severity: 'critical',
    category: 'dangerous-command',
    appliesTo: CODE_KINDS,
    pattern:
      /vssadmin(\.exe)?\s+delete\s+shadows\b|wmic\s+shadowcopy\s+delete\b|wbadmin\s+delete\s+(catalog|backup|systemstatebackup)\b|bcdedit(\.exe)?\s+[^\n]*recoveryenabled\s+no\b/i,
    message:
      'Deletes Volume Shadow Copies / backups or disables Windows recovery — the standard ransomware pre-encryption step.',
    recommendation: 'There is no legitimate skill use for deleting all shadow copies. Treat as hostile.',
  },
  // --- Deeper supply chain ---------------------------------------------
  {
    id: 'SC004',
    title: 'Install lifecycle script runs network/shell',
    severity: 'high',
    category: 'supply-chain',
    appliesTo: ['json', 'mcp-config'],
    pattern:
      /"(preinstall|postinstall|install)"\s*:\s*"[^"]*(curl|wget|node\s+-e|npx\s|bash\s+-c|powershell|iwr|invoke-webrequest)/i,
    message:
      'A package install lifecycle script runs network or shell commands — this code executes automatically on npm install.',
    recommendation: 'Remove network/shell from install hooks; run setup explicitly and reviewably.',
  },
  {
    id: 'SC005',
    title: 'TLS certificate verification disabled',
    severity: 'medium',
    category: 'supply-chain',
    appliesTo: CODE_KINDS,
    pattern: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|curl\s+[^\n]*(-k|--insecure)\b|verify\s*=\s*False\b/i,
    message:
      'Disables TLS certificate verification, opening downloaded code to on-path tampering.',
    recommendation: 'Keep certificate verification on; fix the root cause instead of disabling TLS checks.',
  },
];

export const ALL_RULES: Rule[] = [
  ...PATTERN_RULES.map(patternRule),
  ...PATTERN_RULES_V2.map(patternRule),
  ...PERMISSION_PATTERNS.map(patternRule),
  hiddenUnicodeRule,
  exfilComboRule,
  hygieneRule,
];

export function ruleCount(): number {
  return ALL_RULES.length;
}
