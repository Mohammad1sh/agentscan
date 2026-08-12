// Core type definitions for agentscan.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Highest-to-lowest ordering. Index 0 is the most severe. */
export const SEVERITY_ORDER: readonly Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
] as const;

/** Points each finding of a given severity deducts from a perfect score. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 0,
};

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/** True when `a` is at least as severe as `b`. */
export function severityAtLeast(a: Severity, b: Severity): boolean {
  return severityRank(a) <= severityRank(b);
}

export type FileKind =
  | 'skill' // SKILL.md and files under a skills/ directory
  | 'mcp-config' // .mcp.json, claude_desktop_config.json, mcp server manifests
  | 'agent-rules' // CLAUDE.md, AGENTS.md, .cursorrules, .cursor/rules/*.mdc
  | 'script' // executable script bodies (.sh, .ps1, .py, .js, .ts, ...)
  | 'markdown' // generic markdown
  | 'json' // generic json
  | 'other';

export interface ScanTarget {
  absPath: string;
  relPath: string;
  kind: FileKind;
  content: string;
  lines: string[];
  sizeBytes: number;
}

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  category: string;
  file: string; // relative path
  line: number; // 1-indexed
  column: number; // 1-indexed
  excerpt: string; // matched snippet, already redacted where needed
  message: string;
  recommendation: string;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  /** Which file kinds this rule inspects. 'all' means every scanned file. */
  appliesTo: FileKind[] | 'all';
  check(target: ScanTarget): Finding[];
}

export type PackageKind =
  | 'skill'
  | 'collection'
  | 'plugin'
  | 'marketplace'
  | 'installed-plugin'
  | 'root';

/** One detected package (a skill, plugin, marketplace, …) graded on its own. */
export interface PackageScore {
  id: string; // stable unique key: the package root path, or '.' for the scan root
  label: string; // short display name (may repeat across different roots)
  root: string; // package-root dir relative to the scan root ('' = the scan root)
  kind: PackageKind;
  filesScanned: number;
  findings: Finding[]; // this package's slice of ScanSummary.findings (same refs)
  counts: Record<Severity, number>;
  score: number; // 0-100
  grade: string; // A+ .. F
}

export interface ScanSummary {
  root: string;
  filesScanned: number;
  findings: Finding[];
  counts: Record<Severity, number>;
  score: number; // 0-100
  grade: string; // A+ .. F
  durationMs: number;
  /** Per-package breakdown; always present (possibly empty). */
  packages: PackageScore[];
}
