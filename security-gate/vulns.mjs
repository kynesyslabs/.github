/**
 * What a pull request adds to the dependency and configuration findings of
 * a repository, from two Trivy reports: one of the merge base, one of the
 * head.
 *
 * A vulnerability is the same finding across versions: a bump that still
 * carries an old advisory is not new, one that brings a fresh advisory is.
 * Fixable high and critical vulnerabilities the pull request adds fail the
 * run; the rest of what it adds is a warning. What the base already had is
 * counted as backlog and reported, never blocked, so old debt does not stop
 * unrelated work.
 */

const RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 }

const rank = severity => RANK[severity] ?? 0

const oneLine = text => String(text ?? "").replace(/\s+/g, " ").trim()

/** Findings of a Trivy JSON report, keyed so the same finding matches across versions. */
export function findings(report) {
    const out = new Map()
    for (const result of report?.Results ?? []) {
        const target = result.Target ?? "?"
        for (const v of result.Vulnerabilities ?? []) {
            const key = `vulnerability|${target}|${v.PkgName}|${v.VulnerabilityID}`
            out.set(key, {
                kind: "vulnerability",
                key,
                target,
                id: v.VulnerabilityID,
                pkg: v.PkgName,
                version: v.InstalledVersion,
                fixed: v.FixedVersion || null,
                severity: v.Severity ?? "UNKNOWN",
                title: oneLine(v.Title),
            })
        }
        for (const m of result.Misconfigurations ?? []) {
            const key = `misconfiguration|${target}|${m.ID}`
            out.set(key, {
                kind: "misconfiguration",
                key,
                target,
                id: m.ID,
                severity: m.Severity ?? "UNKNOWN",
                title: oneLine(m.Title),
                line: m.CauseMetadata?.StartLine,
            })
        }
    }
    return out
}

/** Splits the head's findings into what the change added and what the base already had. */
export function compare(baseReport, headReport) {
    const before = findings(baseReport)
    const after = [...findings(headReport).values()]
    return {
        added: after.filter(f => !before.has(f.key)),
        backlog: after.filter(f => before.has(f.key)),
    }
}

/** Sorts added findings into what fails the run and what only warns. */
export function verdict(added, mode = "block") {
    const errors = []
    const warnings = []
    for (const f of added) {
        const serious = rank(f.severity) >= RANK.HIGH
        if (f.kind === "vulnerability") {
            if (serious && f.fixed && mode !== "warn") errors.push(f)
            else if (rank(f.severity) >= RANK.MEDIUM) warnings.push(f)
        } else if (serious) {
            warnings.push(f)
        }
    }
    return { errors, warnings }
}

export function describe(f) {
    const severity = f.severity.toLowerCase()
    if (f.kind === "vulnerability") {
        const fix = f.fixed ? `fixed in ${f.fixed}` : "no fix released"
        return `${f.pkg} ${f.version}: ${f.id} (${severity}, ${fix})${f.title ? ` — ${f.title}` : ""}`
    }
    return `${f.id} (${severity}): ${f.title}`
}

/** Findings per severity, most serious first, as "3 critical, 70 high". */
export function summarize(list) {
    const counts = new Map()
    for (const f of list) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1)
    return [...counts]
        .sort((a, b) => rank(b[0]) - rank(a[0]))
        .map(([severity, n]) => `${n} ${severity.toLowerCase()}`)
        .join(", ") || "none"
}
