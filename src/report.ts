// Human-readable "security scorecard" and machine-readable JSON reporters.

import type { Finding, ScanSummary, Severity, PackageScore } from './types.js';
import { SEVERITY_ORDER, severityAtLeast } from './types.js';

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  brightRed: '\x1b[91m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  gray: '\x1b[90m',
  magenta: '\x1b[35m',
};

interface Style {
  (code: string, text: string): string;
}

function makeStyle(color: boolean): Style {
  return (code, text) => (color ? code + text + ANSI.reset : text);
}

const SEVERITY_META: Record<Severity, { label: string; color: string }> = {
  critical: { label: 'CRIT', color: ANSI.red },
  high: { label: 'HIGH', color: ANSI.brightRed },
  medium: { label: 'MED ', color: ANSI.yellow },
  low: { label: 'LOW ', color: ANSI.cyan },
  info: { label: 'INFO', color: ANSI.gray },
};

export interface ReportOptions {
  color: boolean;
  minSeverity: Severity;
  version: string;
  failOn: Severity | 'none';
  byPackage: boolean;
}

export function renderHuman(summary: ScanSummary, opts: ReportOptions): string {
  const s = makeStyle(opts.color);
  const out: string[] = [];
  const visible = summary.findings.filter((f) => severityAtLeast(f.severity, opts.minSeverity));

  out.push('');
  out.push(
    s(ANSI.bold, 'agentscan') +
      s(ANSI.gray, ` v${opts.version}`) +
      s(ANSI.gray, `  ·  ${summary.filesScanned} file(s) scanned in ${summary.durationMs}ms`),
  );
  out.push('');

  if (summary.findings.length === 0) {
    out.push(s(ANSI.green, '  ✓ No issues found. Nothing suspicious in the scanned extensions.'));
    out.push('');
    if (opts.byPackage) {
      out.push(packagesSection(summary, s));
      out.push('');
    }
    out.push(scorecard(summary, opts, s));
    return out.join('\n');
  }

  for (const f of visible) {
    out.push(renderFinding(f, s));
  }

  const hiddenCount = summary.findings.length - visible.length;
  if (hiddenCount > 0) {
    out.push(
      s(ANSI.gray, `  … ${hiddenCount} lower-severity finding(s) hidden (below --min-severity ${opts.minSeverity}).`),
    );
    out.push('');
  }

  if (opts.byPackage) {
    out.push(packagesSection(summary, s));
    out.push('');
  }
  out.push(scorecard(summary, opts, s));
  return out.join('\n');
}

function renderFinding(f: Finding, s: Style): string {
  const meta = SEVERITY_META[f.severity];
  const badge = s(ANSI.bold, s(meta.color, `  ${meta.label}`));
  const head = `${badge}  ${s(ANSI.gray, f.ruleId)}  ${s(ANSI.bold, f.title)}`;
  const loc = s(ANSI.cyan, `    ${f.file}:${f.line}:${f.column}`);
  const msg = `    ${f.message}`;
  const rec = s(ANSI.gray, `    ↳ ${f.recommendation}`);
  const excerpt = f.excerpt ? s(ANSI.dim, `    | ${f.excerpt}`) : '';
  return [head, loc, msg, rec, excerpt, ''].filter(Boolean).join('\n');
}

function scorecard(summary: ScanSummary, opts: ReportOptions, s: Style): string {
  const line = '─'.repeat(52);
  const gradeColor = gradeColorOf(summary.grade);
  const rows: string[] = [];
  rows.push(s(ANSI.gray, line));
  rows.push(
    `  Security score  ${s(ANSI.bold, String(summary.score) + '/100')}   ` +
      `grade ${s(ANSI.bold, s(gradeColor, summary.grade))}`,
  );
  rows.push('  ' + severityBreakdown(summary, s));

  const failOn: Severity | 'none' = opts.failOn;
  if (failOn !== 'none') {
    const blocking = summary.findings.filter((f) => severityAtLeast(f.severity, failOn)).length;
    const verdict =
      blocking > 0
        ? s(ANSI.red, `  ✗ ${blocking} finding(s) at or above "${opts.failOn}" — CI would fail.`)
        : s(ANSI.green, `  ✓ No findings at or above "${opts.failOn}" — CI would pass.`);
    rows.push(verdict);
  }
  rows.push(s(ANSI.gray, line));
  return rows.join('\n');
}

function severityBreakdown(summary: ScanSummary, s: Style): string {
  return SEVERITY_ORDER.map((sev) => {
    const n = summary.counts[sev];
    const meta = SEVERITY_META[sev];
    const label = `${meta.label.trim().toLowerCase()} ${n}`;
    return n > 0 ? s(ANSI.bold, s(meta.color, label)) : s(ANSI.gray, label);
  }).join('   ');
}

function gradeColorOf(grade: string): string {
  if (grade === 'A+' || grade === 'A') return ANSI.green;
  if (grade === 'B' || grade === 'C') return ANSI.yellow;
  return ANSI.red;
}

// ---------------------------------------------------------------------------
// Per-package breakdown (shown with --by-package). Purely additive: without
// the flag the output is byte-identical to before. Worst packages first; a
// home-dir scan of thousands of clean third-party packages is capped here
// (use --json for the complete list).
// ---------------------------------------------------------------------------

const PACKAGE_CAP = 12;

function fit(str: string, w: number): string {
  if (str.length === w) return str;
  if (str.length > w) return w <= 1 ? str.slice(0, w) : str.slice(0, w - 1) + '…';
  return str.padEnd(w);
}

function plainTallies(p: PackageScore): string {
  const short: Record<Severity, string> = {
    critical: 'crit',
    high: 'high',
    medium: 'med',
    low: 'low',
    info: 'info',
  };
  const parts: string[] = [];
  for (const sev of SEVERITY_ORDER) {
    if (sev === 'info') continue;
    const n = p.counts[sev];
    if (n > 0) parts.push(`${short[sev]} ${n}`);
  }
  if (parts.length > 0) return parts.join(' ');
  // Only info-severity findings (or none): surface info explicitly rather than
  // rendering identically to a truly clean package.
  return p.counts.info > 0 ? `info ${p.counts.info}` : '—';
}

function worstColor(p: PackageScore): string {
  if (p.counts.critical > 0 || p.counts.high > 0) return ANSI.red;
  if (p.counts.medium > 0) return ANSI.yellow;
  if (p.counts.low > 0) return ANSI.cyan;
  return ANSI.gray;
}

function packageRow(p: PackageScore, s: Style): string {
  const grade = s(ANSI.bold, s(gradeColorOf(p.grade), fit(p.grade, 2)));
  const score = s(ANSI.gray, `${String(p.score).padStart(3)}/100`);
  const label = s(ANSI.bold, fit(p.label, 18));
  const kind = s(ANSI.gray, fit(`(${p.kind})`, 18));
  const tallies = s(worstColor(p), plainTallies(p).padEnd(20));
  const files = s(ANSI.gray, `${String(p.filesScanned).padStart(4)} file(s)`);
  const id = s(ANSI.cyan, p.id);
  return `${grade} ${score}  ${label} ${kind} ${tallies} ${files}  ${id}`;
}

function packagesSection(summary: ScanSummary, s: Style): string {
  const line = '─'.repeat(52);
  const pkgs = summary.packages;
  const rows: string[] = [];
  rows.push(s(ANSI.gray, line));
  rows.push(
    `  ${s(ANSI.bold, 'Packages')} ${s(ANSI.gray, '(worst first)')}   ` +
      s(ANSI.gray, `${pkgs.length} total`),
  );
  rows.push(s(ANSI.gray, line));

  if (pkgs.length === 0) {
    rows.push(s(ANSI.gray, '  (no packages detected)'));
    rows.push(s(ANSI.gray, line));
    return rows.join('\n');
  }

  for (const p of pkgs.slice(0, PACKAGE_CAP)) {
    rows.push('  ' + packageRow(p, s));
  }
  const hidden = pkgs.length - Math.min(pkgs.length, PACKAGE_CAP);
  if (hidden > 0) {
    rows.push(s(ANSI.gray, `  … ${hidden} more package(s) — use --json for the full list`));
  }
  rows.push(s(ANSI.gray, line));
  return rows.join('\n');
}

export function renderJson(summary: ScanSummary, version: string): string {
  return JSON.stringify(
    {
      tool: 'agentscan',
      version,
      root: summary.root,
      filesScanned: summary.filesScanned,
      score: summary.score,
      grade: summary.grade,
      counts: summary.counts,
      durationMs: summary.durationMs,
      packages: summary.packages.map((p) => ({
        id: p.id,
        label: p.label,
        root: p.root,
        kind: p.kind,
        filesScanned: p.filesScanned,
        counts: p.counts,
        score: p.score,
        grade: p.grade,
      })),
      findings: summary.findings,
    },
    null,
    2,
  );
}
