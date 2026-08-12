# Contributing to agentscan

Thanks for helping make AI agent extensions safer to install. Rule contributions
are especially welcome — the value of agentscan is its rule set.

## Development setup

```bash
git clone https://github.com/OWNER/agentscan.git
cd agentscan
npm install
npm run build
node --test
```

- `npm run build` — compile `src/` (TypeScript) to `dist/`
- `node --test` — run the test suite (Node's built-in runner)
- `npm run scan -- <path>` — run the CLI locally against a path

Keep the tool **dependency-free at runtime**. Anything under `dependencies`
in `package.json` will be rejected — a security scanner should not add supply-chain
surface of its own. Dev dependencies (TypeScript, types) are fine.

## Adding a detection rule

Most rules live in [`src/rules/index.ts`](src/rules/index.ts) as declarative
`PatternRuleDef` entries:

```ts
{
  id: 'DC010',                       // unique, category-prefixed
  title: 'Short human title',
  severity: 'high',                  // critical | high | medium | low | info
  category: 'dangerous-command',
  appliesTo: CODE_KINDS,             // or 'all', or a FileKind[]
  pattern: /your-regex/i,
  message: 'What is wrong and why it matters.',
  recommendation: 'What the author should do instead.',
  ignoreIf: PLACEHOLDER,             // optional: skip obvious placeholders
  redact: true,                      // optional: mask the match (secrets)
}
```

Rules that need whole-file logic (like the credential-read + network-send combo)
are written as custom `Rule` objects in the same file.

### Rule quality bar

- **Low false positives.** A rule that fires on legitimate skills is worse than
  no rule. Prefer specific patterns over broad ones.
- **Actionable.** Every finding must tell the user what to do next.
- **Tested.** Add a fixture under `test/fixtures/` and assert the rule fires on
  malicious input and stays quiet on clean input (see `test/scan.test.js`).
- **Right severity.** `critical` = machine compromise / exfiltration; `high` =
  strong attack signal; `medium` = risky pattern; `low`/`info` = hygiene.

## Reporting a vulnerability or false positive

Open an issue with a minimal example file and the actual vs. expected output.
For a suspected security issue in agentscan itself, please mark the issue clearly.

## Commit / PR conventions

- One logical change per PR.
- Run `npm run build && node --test` before pushing.
- Describe the threat a new rule addresses and cite a source if it is based on a
  known attack technique.
