// Discovery + scan orchestration + scoring.

import { readFileSync, statSync, readdirSync, type Stats } from 'node:fs';
import { join, relative, extname, basename, dirname, resolve } from 'node:path';
import type { ScanTarget, Finding, ScanSummary, Severity, FileKind, PackageKind, PackageScore } from './types.js';
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
  'site-packages',
  'PackageCache',
  '.gradle',
  '.nuget',
  '.cargo',
  '.tox',
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

// File kinds that are always in scope: these files ARE agent extensions.
const AGENT_EXTENSION_KINDS: FileKind[] = ['skill', 'mcp-config', 'agent-rules'];

const MAX_FILE_BYTES = 2 * 1024 * 1024; // skip files larger than 2MB
const NULL_BYTE = String.fromCharCode(0);

export function classify(relPath: string): FileKind | null {
  const name = basename(relPath).toLowerCase();
  const ext = extname(name);
  const normalized = relPath.replace(/\\/g, '/').toLowerCase();

  // The live SKILL.md manifest is a "skill". A SKILL.md that lives under a
  // /docs/ tree is a translated or example mirror of the real skill (which sits
  // at the package root) — treat it as documentation, not a second live skill,
  // so localized copies don't multiply the same finding across every language.
  if (name === 'skill.md' && !/(^|\/)docs\//.test(normalized)) return 'skill';
  // Other .md files under a skills/ tree (README, CHANGELOG, references,
  // translations, bundled web content) are documentation — classified as
  // 'markdown' so danger rules there inform rather than fail a legit plugin.
  if (MCP_CONFIG_FILES.has(name)) return 'mcp-config';
  if (AGENT_RULE_FILES.has(name)) return 'agent-rules';
  if (normalized.includes('/.cursor/rules/') && (ext === '.mdc' || ext === '.md')) return 'agent-rules';
  if (ext === '.mdc') return 'agent-rules';
  if (SCRIPT_EXT.has(ext)) return 'script';
  if (ext === '.md') return 'markdown';
  if (ext === '.json') return 'json';
  return null; // not a file we care about
}

interface Candidate {
  absPath: string;
  relPath: string;
  kind: FileKind;
  size: number;
}

export interface DiscoverOptions {
  /** Scan every candidate file, not just those in an agent-extension context. */
  all?: boolean;
}

const norm = (p: string): string => p.replace(/\\/g, '/');

export function discover(root: string, options: DiscoverOptions = {}): ScanTarget[] {
  const rootStat = safeStat(root);
  if (!rootStat) return [];

  // A single explicit file target is always scanned.
  if (rootStat.isFile()) {
    const t = toTarget(root, root, rootStat.size);
    return t ? [t] : [];
  }

  const candidates: Candidate[] = [];
  const skillDirs = new Set<string>(); // normalized dirs that directly contain a SKILL.md

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
        if (entry.toLowerCase() === 'skill.md') skillDirs.add(norm(dir));
        if (st.size > MAX_FILE_BYTES) continue;
        const rel = relative(root, full);
        const kind = classify(rel);
        if (kind === null) continue;
        candidates.push({ absPath: full, relPath: norm(rel), kind, size: st.size });
      }
    }
  };
  walk(root);

  const all = options.all === true;
  const targets: ScanTarget[] = [];
  for (const c of candidates) {
    if (all || inScope(c, skillDirs)) {
      const t = readTarget(c);
      if (t) targets.push(t);
    }
  }
  return targets;
}

/**
 * A candidate is "in scope" for the default scan when it is itself an agent
 * extension, or it lives inside an agent-extension context (a skills/.claude/
 * .cursor tree, or a directory that ships a SKILL.md). Arbitrary source files
 * elsewhere on disk are ignored unless --all is passed.
 */
function inScope(c: Candidate, skillDirs: Set<string>): boolean {
  if (AGENT_EXTENSION_KINDS.includes(c.kind)) return true;
  if (/(^|\/)(skills|\.claude|\.cursor)\//.test(c.relPath.toLowerCase())) return true;
  const dir = norm(dirname(c.absPath));
  for (const sd of skillDirs) {
    if (dir === sd || dir.startsWith(sd + '/')) return true;
  }
  return false;
}

function readTarget(c: Candidate): ScanTarget | null {
  let content: string;
  try {
    content = readFileSync(c.absPath, 'utf8');
  } catch {
    return null;
  }
  if (content.indexOf(NULL_BYTE) !== -1) return null; // skip binary files
  return {
    absPath: c.absPath,
    relPath: c.relPath,
    kind: c.kind,
    content,
    lines: content.split('\n'),
    sizeBytes: c.size,
  };
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
  if (content.indexOf(NULL_BYTE) !== -1) return null;
  return {
    absPath,
    relPath: norm(relPath),
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
  all?: boolean;
}

export function scan(root: string, options: ScanOptions = {}): ScanSummary {
  const now = options.now ?? Date.now;
  const start = now();
  const targets = discover(root, { all: options.all });
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
    packages: computePackages(targets, findings, root),
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
// Per-package grouping. Grade each detected package (a skill, a plugin, a
// marketplace, an installed plugin) on its own, so one aggregate F over
// thousands of third-party extensions is no longer the only signal. Pure
// string work over the already-discovered targets and findings — no extra I/O.
// ---------------------------------------------------------------------------

function parentDir(rel: string): string {
  const p = rel.replace(/\\/g, '/');
  const i = p.lastIndexOf('/');
  return i < 0 ? '' : p.slice(0, i);
}

/**
 * Map a scan-root-relative file path to the root of the package that owns it.
 * Deepest boundary wins, with a live SKILL.md dir taking priority (it is the
 * unit a user vets), then a skills/<name> collection, then the enclosing
 * plugin / marketplace / installed-plugin dir, then a coarse top-level bucket.
 * `root === ''` means the scan root itself (loose files, single-file scans).
 */
export function packageRootOf(
  fileRel: string,
  skillRoots: ReadonlySet<string>,
): { root: string; kind: PackageKind } {
  const dir = fileRel.replace(/\\/g, '/').split('/').slice(0, -1);
  const n = dir.length;
  const lc = (str: string): string => str.toLowerCase();

  // R0 — the scan root itself ships a SKILL.md: the whole tree is one package.
  if (skillRoots.has('')) return { root: '', kind: 'skill' };

  let k = 0;
  let kind: PackageKind = 'root';
  const bump = (depth: number, kd: PackageKind): void => {
    if (depth > k && depth <= n) {
      k = depth;
      kind = kd;
    }
  };

  // R1 — deepest live SKILL.md dir that is an ancestor-or-equal of the file.
  // AUTHORITATIVE: a file inside a skill belongs to that skill, so return
  // immediately. A nested skills/<name>, plugins/*, or plugin_<id> subfolder
  // that lacks its own SKILL.md must NOT carve files out of the enclosing
  // skill (that would hide the skill's own risk from the unit a user vets).
  for (let len = n; len >= 1; len--) {
    if (skillRoots.has(dir.slice(0, len).join('/'))) {
      return { root: dir.slice(0, len).join('/'), kind: 'skill' };
    }
  }
  // R2 — deepest 'skills/<name>' collection.
  for (let i = n - 1; i >= 0; i--) {
    if (lc(dir[i] ?? '') === 'skills' && i + 1 <= n - 1) {
      bump(i + 2, 'collection');
      break;
    }
  }
  // R3 — plugins/cache/<owner>/<repo>/<version>.
  for (let i = 0; i + 1 <= n - 1; i++) {
    if (lc(dir[i] ?? '') === 'plugins' && lc(dir[i + 1] ?? '') === 'cache') {
      bump(Math.min(i + 5, n), 'plugin');
      break;
    }
  }
  // R4 — plugins/marketplaces/<market> (+ a nested plugins/<plugin> if present).
  for (let i = 0; i + 1 <= n - 1; i++) {
    if (lc(dir[i] ?? '') === 'plugins' && lc(dir[i + 1] ?? '') === 'marketplaces') {
      bump(Math.min(i + 3, n), 'marketplace');
      for (let j = i + 3; j + 1 <= n - 1; j++) {
        if (lc(dir[j] ?? '') === 'plugins') {
          bump(j + 2, 'plugin');
          break;
        }
      }
      break;
    }
  }
  // R5 — installed-plugin dir (rpm/session layout): deepest plugin_<id> segment.
  for (let i = n - 1; i >= 0; i--) {
    if (/^plugin_/i.test(dir[i] ?? '')) {
      bump(i + 1, 'installed-plugin');
      break;
    }
  }
  // R6 — coarse fallback: the top-level dir (root stays '' only for a loose
  // file directly at the scan root, including a single-file scan).
  if (k === 0 && n >= 1) {
    k = 1;
    kind = 'root';
  }

  return { root: dir.slice(0, k).join('/'), kind };
}

function labelFor(root: string, scanRootBase: string): string {
  if (root === '') return scanRootBase;
  const segs = root.split('/');
  const last = segs[segs.length - 1] ?? root;
  if (segs.length >= 2 && /^v?\d+([._]\d+)+/.test(last)) {
    return `${segs[segs.length - 2] ?? ''}@${last}`;
  }
  return last;
}

/**
 * Name for the scan-root bucket. When the scan target is a single file, use
 * its parent directory's name (the skill's dir), not the file name, so
 * `agentscan path/to/SKILL.md` labels the package by the skill it belongs to.
 */
function scanRootBaseFor(root: string): string {
  const st = safeStat(root);
  const base = st?.isFile() ? dirname(resolve(root)) : resolve(root);
  return basename(base) || 'root';
}

function cmpPackages(a: PackageScore, b: PackageScore): number {
  if (a.score !== b.score) return a.score - b.score; // worst (lowest) first
  for (const sev of SEVERITY_ORDER) {
    if (a.counts[sev] !== b.counts[sev]) return b.counts[sev] - a.counts[sev];
  }
  if (a.filesScanned !== b.filesScanned) return b.filesScanned - a.filesScanned;
  return a.id.localeCompare(b.id);
}

export function computePackages(
  targets: ScanTarget[],
  findings: Finding[],
  root: string,
): PackageScore[] {
  const skillRoots = new Set<string>(
    targets.filter((t) => t.kind === 'skill').map((t) => parentDir(t.relPath)),
  );
  const scanRootBase = scanRootBaseFor(root);

  interface Acc {
    id: string;
    label: string;
    root: string;
    kind: PackageKind;
    files: number;
    findings: Finding[];
  }
  const map = new Map<string, Acc>();
  const ensure = (rel: string): Acc => {
    const { root: r, kind } = packageRootOf(rel, skillRoots);
    const id = r === '' ? '.' : r;
    let acc = map.get(id);
    if (!acc) {
      acc = { id, label: labelFor(r, scanRootBase), root: r, kind, files: 0, findings: [] };
      map.set(id, acc);
    }
    return acc;
  };

  for (const t of targets) ensure(t.relPath).files++;
  for (const f of findings) ensure(f.file).findings.push(f);

  const pkgs: PackageScore[] = [];
  for (const acc of map.values()) {
    const counts = emptyCounts();
    for (const f of acc.findings) counts[f.severity]++;
    const score = computeScore(counts);
    pkgs.push({
      id: acc.id,
      label: acc.label,
      root: acc.root,
      kind: acc.kind,
      filesScanned: acc.files,
      findings: acc.findings,
      counts,
      score,
      grade: gradeFor(score),
    });
  }
  pkgs.sort(cmpPackages);
  return pkgs;
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
