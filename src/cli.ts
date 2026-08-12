#!/usr/bin/env node
// agentscan CLI entry point.

import { scan } from './engine.js';
import { renderHuman, renderJson } from './report.js';
import type { Severity } from './types.js';
import { SEVERITY_ORDER, severityAtLeast } from './types.js';

const VERSION = '0.1.4';

interface Cli {
  path: string;
  json: boolean;
  color: boolean;
  minSeverity: Severity;
  failOn: Severity | 'none';
  all: boolean;
  help: boolean;
  version: boolean;
}

const HELP = `agentscan v${VERSION}
Security & quality scanner for AI agent extensions
(Claude skills, MCP servers, Cursor rules, agent instruction files).

USAGE
  agentscan [path] [options]

ARGUMENTS
  path                    File or directory to scan (default: current directory)

By default agentscan only scans agent extensions and the files that ship with
them: SKILL.md and its skill directory, MCP configs (.mcp.json), Cursor rules,
CLAUDE.md / AGENTS.md, and scripts inside a skills/.claude/.cursor tree. Ordinary
source files elsewhere are left alone. Use --all to scan every file.

OPTIONS
  --all                   Scan every text file, not just agent extensions
  --json                  Output findings as JSON (for CI / tooling)
  --fail-on <severity>    Exit non-zero when a finding is at or above this
                          severity. One of: critical, high, medium, low, none
                          (default: high)
  --min-severity <sev>    Hide findings below this severity in human output
                          (default: info — show everything)
  --no-color              Disable ANSI colors
  -v, --version           Print version and exit
  -h, --help              Show this help

EXIT CODES
  0   scan clean (no findings at or above --fail-on)
  1   findings at or above --fail-on were reported
  2   usage error

EXAMPLES
  npx @meedo01/agentscan .
  npx @meedo01/agentscan ./skills --fail-on critical
  npx @meedo01/agentscan path/to/SKILL.md --json`;

function isSeverity(v: string): v is Severity {
  return (SEVERITY_ORDER as readonly string[]).includes(v);
}

function parseArgs(argv: string[]): Cli | { error: string } {
  const cli: Cli = {
    path: '.',
    json: false,
    color: Boolean(process.stdout.isTTY) && !process.env['NO_COLOR'],
    minSeverity: 'info',
    failOn: 'high',
    all: false,
    help: false,
    version: false,
  };
  let sawPath = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? '';
    switch (arg) {
      case '-h':
      case '--help':
        cli.help = true;
        break;
      case '-v':
      case '--version':
        cli.version = true;
        break;
      case '--json':
        cli.json = true;
        break;
      case '--all':
        cli.all = true;
        break;
      case '--no-color':
        cli.color = false;
        break;
      case '--color':
        cli.color = true;
        break;
      case '--fail-on': {
        const val = argv[++i];
        if (!val || (val !== 'none' && !isSeverity(val))) {
          return { error: `--fail-on expects one of: critical, high, medium, low, none` };
        }
        cli.failOn = val as Severity | 'none';
        break;
      }
      case '--min-severity': {
        const val = argv[++i];
        if (!val || !isSeverity(val)) {
          return { error: `--min-severity expects one of: ${SEVERITY_ORDER.join(', ')}` };
        }
        cli.minSeverity = val;
        break;
      }
      default:
        if (arg.startsWith('-')) {
          return { error: `Unknown option: ${arg}` };
        }
        if (sawPath) {
          return { error: `Unexpected extra argument: ${arg}` };
        }
        cli.path = arg;
        sawPath = true;
    }
  }
  return cli;
}

function main(): void {
  const parsed = parseArgs(process.argv.slice(2));
  if ('error' in parsed) {
    process.stderr.write(parsed.error + '\n\nRun "agentscan --help" for usage.\n');
    process.exit(2);
  }
  if (parsed.help) {
    process.stdout.write(HELP + '\n');
    process.exit(0);
  }
  if (parsed.version) {
    process.stdout.write(VERSION + '\n');
    process.exit(0);
  }

  const summary = scan(parsed.path, { all: parsed.all });

  if (parsed.json) {
    process.stdout.write(renderJson(summary, VERSION) + '\n');
  } else {
    process.stdout.write(
      renderHuman(summary, {
        color: parsed.color,
        minSeverity: parsed.minSeverity,
        version: VERSION,
        failOn: parsed.failOn,
      }) + '\n',
    );
  }

  if (parsed.failOn !== 'none') {
    const blocking = summary.findings.some((f) => severityAtLeast(f.severity, parsed.failOn as Severity));
    process.exit(blocking ? 1 : 0);
  }
  process.exit(0);
}

main();
