#!/usr/bin/env node
/**
 * Reports what a pull request adds to a repository's dependency and
 * configuration findings.
 *
 *   node scan-vulns.mjs --base <report.json> --head <report.json> [--mode block|warn]
 *
 * Both reports come from `trivy fs --format json`: one of the merge base,
 * one of the head. New fixable high or critical vulnerabilities fail the
 * run (exit 1) unless the mode is warn; exit 2 on a usage error.
 */

import { appendFileSync, readFileSync } from "node:fs"
import { compare, describe, summarize, verdict } from "./vulns.mjs"

function arg(name) {
    const i = process.argv.indexOf(`--${name}`)
    return i >= 0 ? process.argv[i + 1] : undefined
}

const baseFile = arg("base")
const headFile = arg("head")
const mode = arg("mode") ?? "block"
if (!baseFile || !headFile || !["block", "warn"].includes(mode)) {
    console.error("usage: scan-vulns.mjs --base <report.json> --head <report.json> [--mode block|warn]")
    process.exit(2)
}

const load = file => JSON.parse(readFileSync(file, "utf8"))
const { added, backlog } = compare(load(baseFile), load(headFile))
const { errors, warnings } = verdict(added, mode)

const where = f => `file=${f.target}${f.line ? `,line=${f.line}` : ""}`
for (const f of errors) console.log(`::error ${where(f)},title=new-${f.kind}::${describe(f)}`)
for (const f of warnings) console.log(`::warning ${where(f)},title=new-${f.kind}::${describe(f)}`)

console.log(
    `\nsecurity-gate: this change adds ${errors.length} blocking and ${warnings.length} warning finding(s); ` +
        `already on the base branch: ${summarize(backlog)}`,
)
if (process.env.GITHUB_STEP_SUMMARY) {
    const rows = [...errors, ...warnings].map(f => `| ${errors.includes(f) ? "blocks" : "warning"} | \`${f.target}\` | ${describe(f)} |`)
    const summary = [
        "### Dependency scan",
        "",
        rows.length > 0 ? "| Outcome | Where | Finding |\n|---|---|---|\n" + rows.join("\n") : "This change adds no findings.",
        "",
        `Already on the base branch, not blocked: ${summarize(backlog)}.`,
        "",
    ].join("\n")
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary)
}
process.exit(errors.length > 0 ? 1 : 0)
