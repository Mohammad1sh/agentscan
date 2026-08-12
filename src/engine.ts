// Discovery + scan orchestration + scoring.

import { readFileSync, statSync, readdirSync, type Stats } from 'node:fs';
import { join, relative, extname, basename } from 'node:path';
import type { ScanTarget, Finding, ScanSummary, Severity, FileKind } from './types.js';
import { SEVERITY_ORDER, SEVERITY_WEIGHT } from './types.js';
import { ALL_RULES } from './rules/index.js';

const IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  '.next',
  '.turbo',
  'coverage',
  'vendor',
  '.venv',
  'venv',
  '__pycache__',
  '.cache',
  '.idea',
  '.vscode',
]);

const SCRIPT_EXT = new Set([
  '.sh',
  '.bash',
  '.zsh',
  '.ps1',
  '.py',
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.rb',
  '.pl',
]);

const AGENT_RULE_FILES = new Set([
  'claude.md',
  'agents.md',
  'gemini.md',
  '.clauderc',
  '.cursorrules',
  '.windsurfrules',
  '.aider.conf.yml',
]);

const MCP_CONFIG_FILES = new Set(['.mcp.json', 'mcp.json', 'claude_desktop_config.json']);

const MAX_FILE_BYTES = 2 * 1024 * 1024; // skip files larger than 2MB
const NULL_BYTE = String.fromCharCode(0);

export function classify(relPath: string): FileKind | null {
  const name = basename(relPath).toLowerCase();
  const ext = extname(name);
  const normalized = relPath.replace(/\\/g, '/').toLowerCase();

  if (name === 'skill.md') return 'skill';
  if (normalized.includes('/skills/') && ext === '.md') return 'skill';
  if (MCP_CONFIG_FILES.has(name)) return 'mcp-config';
  if (AGENT_RULE_FILES.has(name)) return 'agent-rules';
  if (normalized.includes('/.cursor/rules/') && (ext === '.mdc' || ext === '.md')) return 'agent-rules';
  if (ext === '.mdc') return 'agent-rules';
  if (SCRIPT_EXT.has(ext)) return 'script';
  if (ext === '.md') return 'markdown';
  if (ext === '.json') return 'json';
  return null; // not a file we care about
}

export function discover(root: string): ScanTarget[] {
  const targets: ScanTarget[] = [];
  const rootStat = safeStat(root);
  if (!rootStat) return targets;

  if (rootStat.isFile()) {
    const t = toTarget(root, root);
    if (t) targets.push(t);
    return targets;
  }

  const walk = (dir: string): void => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry);
      const st = safeStat(full);
      if (!st) continue;
      if (st.isDirectory()) {
        if (IGNORED_DIRS.has(entry)) continue;
        walk(full);
      } else if (st.isFile()) {
        const t = toTarget(full, root, st.size);
        if (t) targets.push(t);
      }
    }
  };
  walk(root);
  return targets;
}

function toTarget(absPath: string, root: string, knownSize?: number): ScanTarget | null {
  const relPath = root === absPath ? basename(absPath) : relative(root, absPath);
  const kind = classify(relPath);
  if (kind === null) return null;

  const size = knownSize ?? safeStat(absPath)?.size ?? 0;
  if (size > MAX_FILE_BYTES) return null;

  let content: string;
  try {
    content = readFileSync(absPath, 'utf8');
  } catch {
    return null;
  }
  if (content.indexOf(NULL_BYTE) !== -1) return null; // skip binary files

  return {
    absPath,
    relPath: relPath.replace(/\\/g, '/'),
    kind,
    content,
    lines: content.split('\n'),
    sizeBytes: size,
  };
}

function safeStat(p: string): Stats | null {
  try {
    return statSync(p);
  } catch {
    return null;
  }
}

export interface ScanOptions {
  now?: () => number;
}

export function scan(root: string, options: ScanOptions = {}): ScanSummary {
  const now = options.now ?? Date.now;
  const start = now();
  const targets = discover(root);
  const findings: Finding[] = [];

  for (const target of targets) {
    if (fileSuppressed(target)) continue;
    const perFile: Finding[] = [];
    for (const rule of ALL_RULES) {
      try {
        perFile.push(...rule.check(target));
      } catch {
        // A misbehaving rule must never crash the whole scan.
      }
    }
    for (const f of perFile) {
      if (!isSuppressed(f, target)) findings.push(f);
    }
  }

  findings.sort(sortFindings);

  const counts = emptyCounts();
  for (const f of findings) counts[f.severity]++;

  const score = computeScore(counts);
  return {
    root,
    filesScanned: targets.length,
    findings,
    counts,
    score,
    grade: gradeFor(score),
    durationMs: Math.max(0, now() - start),
  };
}

function sortFindings(a: Finding, b: Finding): number {
  const bySeverity = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
  if (bySeverity !== 0) return bySeverity;
  const byFile = a.file.localeCompare(b.file);
  if (byFile !== 0) return byFile;
  return a.line - b.line;
}

export function emptyCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function computeScore(counts: Record<Severity, number>): number {
  let deduction = 0;
  for (const sev of SEVERITY_ORDER) {
    deduction += counts[sev] * SEVERITY_WEIGHT[sev];
  }
  return Math.max(0, Math.min(100, 100 - deduction));
}

export function gradeFor(score: number): string {
  if (score >= 100) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

// ---------------------------------------------------------------------------
// Suppression directives
//   // agentscan-ignore-file            (in first 5 lines) skip the whole file
//   <code> // agentscan-ignore RULEID   skip listed rules on this line
//   // agentscan-ignore-next-line SE001 skip listed rules on the next line
// Omitting rule ids suppresses every finding on that line.
// ---------------------------------------------------------------------------

const IGNORE_FILE = /agentscan-ignore-file/i;
const IGNORE_INLINE = /agentscan-ignore(?:-next-line)?\b[:\s]*([A-Za-z0-9,\s]*)/i;

function fileSuppressed(target: ScanTarget): boolean {
  const head = target.lines.slice(0, 5).join('\n');
  return IGNORE_FILE.test(head);
}

function parseIgnore(text: string): { ids: string[] } | null {
  const m = IGNORE_INLINE.exec(text);
  if (!m) return null;
  const ids = (m[1] ?? '')
    .split(/[^A-Za-z0-9]+/)
    .map((x) => x.trim())
    .filter(Boolean);
  return { ids };
}

function isSuppressed(f: Finding, target: ScanTarget): boolean {
  const sameLine = parseIgnore(target.lines[f.line - 1] ?? '');
  const prevLine = parseIgnore(target.lines[f.line - 2] ?? '');
  for (const ig of [sameLine, prevLine]) {
    if (ig && (ig.ids.length === 0 || ig.ids.includes(f.ruleId))) return true;
  }
  return false;
}
