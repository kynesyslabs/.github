#!/usr/bin/env node
/**
 * Flags the shapes malicious pull requests take, in the lines a diff adds.
 *
 *   node scan-diff.mjs --base <sha> --head <sha>   scan a git range
 *   node scan-diff.mjs --diff <file>               scan a saved unified diff
 *
 * High findings fail the run; medium ones are reported as warnings. Exit 1
 * when anything high is found, 2 on a usage or git error.
 *
 * The allowlist is read from the base commit only (`.security-gate-allow`),
 * so a pull request cannot exempt itself.
 */

import { execFileSync } from "node:child_process"
import { readFileSync } from "node:fs"
import { analyze } from "./rules.mjs"

function arg(name) {
    const i = process.argv.indexOf(`--${name}`)
    return i >= 0 ? process.argv[i + 1] : undefined
}

function git(...args) {
    return execFileSync("git", args, {
        encoding: "utf8",
        maxBuffer: 512 * 1024 * 1024,
        stdio: ["ignore", "pipe", "pipe"],
    })
}

function loadDiff() {
    const file = arg("diff")
    if (file) return readFileSync(file, "utf8")
    const base = arg("base")
    const head = arg("head")
    if (!base || !head) {
        console.error("usage: scan-diff.mjs --base <sha> --head <sha> | --diff <file>")
        process.exit(2)
    }
    // Three-dot: only what the pull request adds on top of the merge base.
    return git("diff", "--unified=0", "--no-color", "--no-ext-diff", `${base}...${head}`)
}

function loadAllowlist() {
    const base = arg("base")
    if (!base) return []
    try {
        return git("show", `${base}:.security-gate-allow`)
            .split("\n")
            .map(l => l.trim())
            .filter(l => l && !l.startsWith("#"))
    } catch {
        return []
    }
}

const findings = analyze(loadDiff(), loadAllowlist())
const high = findings.filter(f => f.severity === "high")

for (const f of findings) {
    const level = f.severity === "high" ? "error" : "warning"
    const where = f.line ? `file=${f.file},line=${f.line}` : `file=${f.file}`
    // GitHub Actions annotation; plain text elsewhere is still readable.
    console.log(`::${level} ${where},title=${f.rule}::${f.message}${f.excerpt ? ` — ${f.excerpt}` : ""}`)
}

console.log(`\nsecurity-gate: ${high.length} high, ${findings.length - high.length} medium finding(s)`)
if (process.env.GITHUB_STEP_SUMMARY && findings.length > 0) {
    const rows = findings.map(f => `| ${f.severity} | ${f.rule} | \`${f.file}${f.line ? `:${f.line}` : ""}\` | ${f.message} |`)
    const summary = ["### Malicious-change scan", "", "| Severity | Rule | Where | Why |", "|---|---|---|---|", ...rows, ""].join("\n")
    await import("node:fs").then(fs => fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary))
}
process.exit(high.length > 0 ? 1 : 0)
