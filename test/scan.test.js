import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  scan,
  classify,
  computeScore,
  gradeFor,
  emptyCounts,
  packageRootOf,
  computePackages,
} from '../dist/engine.js';
import { ALL_RULES, ruleCount, redact } from '../dist/rules/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, 'fixtures');

test('flags a malicious skill with critical findings', () => {
  const result = scan(join(fixtures, 'malicious-skill'));
  const ids = new Set(result.findings.map((f) => f.ruleId));
  for (const id of ['PI001', 'PI003', 'DC001', 'DC002', 'EX001', 'EX005', 'SE001']) {
    assert.ok(ids.has(id), `expected rule ${id} to fire; got: ${[...ids].join(', ')}`);
  }
  assert.ok(result.counts.critical >= 3, `expected >=3 critical, got ${result.counts.critical}`);
  assert.equal(result.grade, 'F');
  assert.equal(result.score, 0);
});

test('passes a clean skill with no findings', () => {
  const result = scan(join(fixtures, 'clean-skill'));
  assert.deepEqual(
    result.findings,
    [],
    `clean skill should be empty, got: ${JSON.stringify(result.findings, null, 2)}`,
  );
  assert.equal(result.score, 100);
  assert.equal(result.grade, 'A+');
});

test('scoring and grading behave', () => {
  assert.equal(computeScore(emptyCounts()), 100);
  assert.equal(gradeFor(100), 'A+');
  assert.equal(gradeFor(85), 'B');
  assert.equal(gradeFor(50), 'F');
  const counts = emptyCounts();
  counts.high = 1;
  assert.equal(computeScore(counts), 80);
});

test('file classification', () => {
  assert.equal(classify('skills/foo/SKILL.md'), 'skill');
  assert.equal(classify('.mcp.json'), 'mcp-config');
  assert.equal(classify('CLAUDE.md'), 'agent-rules');
  assert.equal(classify('setup.sh'), 'script');
  assert.equal(classify('notes.md'), 'markdown');
  assert.equal(classify('image.png'), null);
});

test('rule registry is populated with unique ids', () => {
  assert.ok(ruleCount() >= 20, `expected a healthy rule set, got ${ruleCount()}`);
  const ids = ALL_RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, 'rule ids must be unique');
});

test('redaction masks the middle of a secret', () => {
  const masked = redact('AKIAIOSFODNN7EXAMPLE');
  assert.ok(!masked.includes('IOSFODNN7'), 'the middle of the secret should be hidden');
});

test('flags MCP tool-poisoning and misconfiguration', () => {
  const result = scan(join(fixtures, 'malicious-mcp'));
  const ids = new Set(result.findings.map((f) => f.ruleId));
  for (const id of ['MCP001', 'MCP008', 'MCP009', 'MCP011']) {
    assert.ok(ids.has(id), `expected rule ${id} to fire; got: ${[...ids].join(', ')}`);
  }
});

test('flags Windows/PowerShell obfuscation and defense-evasion', () => {
  const result = scan(join(fixtures, 'malicious-ps'));
  const ids = new Set(result.findings.map((f) => f.ruleId));
  for (const id of ['OBF006', 'WIN001', 'WIN002']) {
    assert.ok(ids.has(id), `expected rule ${id} to fire; got: ${[...ids].join(', ')}`);
  }
});

test('inline agentscan-ignore suppresses only the named rule', () => {
  const result = scan(join(fixtures, 'suppression'));
  const ids = new Set(result.findings.map((f) => f.ruleId));
  assert.ok(!ids.has('DC001'), 'DC001 should be suppressed by the inline directive');
  assert.ok(ids.has('DC004'), 'DC004 (chmod 777) should still fire');
});

test('packageRootOf maps files to the owning package (deepest boundary wins)', () => {
  const skillRoots = new Set([
    'plugins/cache/ecc/ecc/2.0.0/skills/perl-security',
    'skills/gstack/spec',
  ]);
  const cases = [
    ['plugins/cache/ecc/ecc/2.0.0/skills/perl-security/SKILL.md', 'plugins/cache/ecc/ecc/2.0.0/skills/perl-security', 'skill'],
    ['plugins/cache/ecc/ecc/2.0.0/README.md', 'plugins/cache/ecc/ecc/2.0.0', 'plugin'],
    ['plugins/cache/ecc/ecc/2.0.0/docs/tr/the-security-guide.md', 'plugins/cache/ecc/ecc/2.0.0', 'plugin'],
    ['plugins/marketplaces/thedotmack/CHANGELOG.md', 'plugins/marketplaces/thedotmack', 'marketplace'],
    ['skills/gstack/lib/redact-patterns.ts', 'skills/gstack', 'collection'],
    ['skills/cloudflare/references/pages-functions/patterns.md', 'skills/cloudflare', 'collection'],
    ['.copilot/skills/cloudflare/references/bindings/api.md', '.copilot/skills/cloudflare', 'collection'],
    ['setup.sh', '', 'root'],
  ];
  for (const [file, root, kind] of cases) {
    const r = packageRootOf(file, skillRoots);
    assert.equal(r.root, root, `root for ${file}`);
    assert.equal(r.kind, kind, `kind for ${file}`);
  }
  // Windows backslashes normalize before splitting.
  assert.equal(packageRootOf('skills\\cloudflare\\x.md', skillRoots).root, 'skills/cloudflare');
});

test('packageRootOf: a scan-root skill collapses the whole tree to one package', () => {
  const skillRoots = new Set(['']);
  for (const f of ['SKILL.md', 'setup.sh', 'scripts/deep/nested.sh']) {
    const r = packageRootOf(f, skillRoots);
    assert.equal(r.root, '');
    assert.equal(r.kind, 'skill');
  }
});

test('packageRootOf: installed-plugin (plugin_<id>) dir', () => {
  const r = packageRootOf('AppData/x/rpm/plugin_016c/config.json', new Set());
  assert.equal(r.root, 'AppData/x/rpm/plugin_016c');
  assert.equal(r.kind, 'installed-plugin');
});

test('per-package grading: single skill is one package that mirrors the aggregate', () => {
  const result = scan(join(fixtures, 'malicious-skill'));
  assert.equal(result.packages.length, 1);
  const p = result.packages[0];
  assert.equal(p.label, 'malicious-skill');
  assert.equal(p.grade, 'F');
  assert.equal(p.score, 0);
  // partition completeness: packages reconcile with the aggregate
  const pkgFindings = result.packages.reduce((n, x) => n + x.findings.length, 0);
  assert.equal(pkgFindings, result.findings.length);
  const pkgFiles = result.packages.reduce((n, x) => n + x.filesScanned, 0);
  assert.equal(pkgFiles, result.filesScanned);
});

test('per-package grading: a clean skill is one A+ package', () => {
  const result = scan(join(fixtures, 'clean-skill'));
  assert.equal(result.packages.length, 1);
  assert.equal(result.packages[0].grade, 'A+');
  assert.equal(result.packages[0].score, 100);
});

test('computePackages: multi-package partition, labels, and worst-first order', () => {
  const targets = [
    { kind: 'skill', relPath: 'skills/alpha/SKILL.md' },
    { kind: 'script', relPath: 'skills/alpha/setup.sh' },
    { kind: 'markdown', relPath: 'plugins/cache/o/ecc/2.0.0/README.md' },
    { kind: 'markdown', relPath: 'skills/beta/notes.md' },
  ];
  const findings = [
    { file: 'skills/alpha/setup.sh', severity: 'critical' },
    { file: 'plugins/cache/o/ecc/2.0.0/README.md', severity: 'high' },
  ];
  const pkgs = computePackages(targets, findings, '.');
  const byId = Object.fromEntries(pkgs.map((p) => [p.id, p]));

  assert.equal(pkgs.length, 3);
  assert.equal(byId['skills/alpha'].kind, 'skill');
  assert.equal(byId['skills/alpha'].score, 60); // one critical => -40
  assert.equal(byId['skills/alpha'].grade, 'D');
  assert.equal(byId['plugins/cache/o/ecc/2.0.0'].label, 'ecc@2.0.0');
  assert.equal(byId['skills/beta'].grade, 'A+');
  assert.equal(byId['skills/beta'].score, 100);
  // worst-first
  assert.ok(pkgs[0].score <= pkgs[pkgs.length - 1].score);
  // per-package score matches the shared scoring formula
  for (const p of pkgs) assert.equal(p.score, computeScore(p.counts));
});

test('packageRootOf: a nested collection/plugin inside a skill stays in the skill', () => {
  const skillRoots = new Set(['bundle']);
  // a skills/<name> subfolder inside the skill, with no inner SKILL.md, must
  // NOT carve its files out of the enclosing skill.
  assert.deepEqual(packageRootOf('bundle/skills/examples/run.sh', skillRoots), {
    root: 'bundle',
    kind: 'skill',
  });
  // a plugin_<id> subfolder inside the skill likewise stays put.
  assert.deepEqual(packageRootOf('bundle/plugin_x/y.md', skillRoots), {
    root: 'bundle',
    kind: 'skill',
  });
  // deepest-skill-wins still holds when a real inner SKILL.md exists.
  const nested = new Set(['bundle', 'bundle/inner']);
  assert.equal(packageRootOf('bundle/inner/z.md', nested).root, 'bundle/inner');
});

test('per-package grading: a single-file scan labels by the skill directory', () => {
  const result = scan(join(fixtures, 'malicious-skill', 'SKILL.md'));
  assert.equal(result.packages.length, 1);
  assert.equal(result.packages[0].label, 'malicious-skill');
});
