import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { scan, classify, computeScore, gradeFor, emptyCounts } from '../dist/engine.js';
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

test('inline agentscan-ignore suppresses only the named rule', () => {
  const result = scan(join(fixtures, 'suppression'));
  const ids = new Set(result.findings.map((f) => f.ruleId));
  assert.ok(!ids.has('DC001'), 'DC001 should be suppressed by the inline directive');
  assert.ok(ids.has('DC004'), 'DC004 (chmod 777) should still fire');
});
