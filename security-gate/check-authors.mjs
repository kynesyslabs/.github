#!/usr/bin/env node
/**
 * Checks who wrote the commits in a pull request.
 *
 * The stealer in wallet-extension PR #70 was pushed from a team member's
 * account but authored as an outsider whose email no GitHub account owns and
 * who had never committed to the repository: what a stolen token looks like.
 *
 * - unlinked author email never seen in the base branch's history: fails
 * - unlinked author email the repository already has commits from: warning
 *   (people commit from machines with a work or old email)
 * - a different account than the PR author: warning (co-authored and
 *   cherry-picked work is normal)
 *
 * Env: GH_TOKEN, GITHUB_REPOSITORY, PR_NUMBER, PR_AUTHOR, and
 * KNOWN_AUTHORS_FILE: author emails from the base branch history, one per
 * line (the workflow builds it from the base commit, never from the PR).
 */

import { readFileSync } from "node:fs"

const { GH_TOKEN, GITHUB_REPOSITORY, PR_NUMBER, PR_AUTHOR } = process.env
const knownAuthors = new Set(
    (process.env.KNOWN_AUTHORS_FILE ? readFileSync(process.env.KNOWN_AUTHORS_FILE, "utf8") : "")
        .split("\n").map(s => s.trim().toLowerCase()).filter(Boolean),
)

if (!GH_TOKEN || !GITHUB_REPOSITORY || !PR_NUMBER) {
    console.error("check-authors: GH_TOKEN, GITHUB_REPOSITORY and PR_NUMBER are required")
    process.exit(2)
}

async function prCommits() {
    const commits = []
    for (let page = 1; ; page++) {
        const res = await fetch(
            `https://api.github.com/repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/commits?per_page=100&page=${page}`,
            { headers: { authorization: `Bearer ${GH_TOKEN}`, accept: "application/vnd.github+json" } },
        )
        if (!res.ok) throw new Error(`GitHub API ${res.status}: ${await res.text()}`)
        const batch = await res.json()
        commits.push(...batch)
        if (batch.length < 100) return commits
    }
}

const commits = await prCommits()
let failures = 0
for (const c of commits) {
    const sha = c.sha.slice(0, 10)
    const email = (c.commit.author?.email ?? "").toLowerCase()
    const name = c.commit.author?.name ?? "?"
    const login = c.author?.login ?? null
    if (!login && knownAuthors.has(email)) {
        console.log(`::warning title=unlinked-author::${sha} is authored by "${name} <${email}>", an email no GitHub account owns (seen before in this repository)`)
    } else if (!login) {
        failures++
        console.log(
            `::error title=unknown-author::${sha} is authored by "${name} <${email}>": no GitHub account owns this email and it has never committed here. ` +
                "If this is you, add the email to your GitHub account (Settings → Emails) and push again; otherwise treat the PR as hostile.",
        )
    } else if (PR_AUTHOR && login !== PR_AUTHOR && !login.endsWith("[bot]")) {
        console.log(`::warning title=other-author::${sha} is authored by @${login}, not by the PR author @${PR_AUTHOR}`)
    }
}

console.log(`check-authors: ${commits.length} commit(s), ${failures} by an unknown author`)
process.exit(failures > 0 ? 1 : 0)
