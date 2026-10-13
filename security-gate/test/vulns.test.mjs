import { test } from "node:test"
import assert from "node:assert/strict"
import { compare, describe, summarize, verdict } from "../vulns.mjs"

/** A Trivy report with one lockfile target. */
function report(vulnerabilities = [], misconfigurations = [], target = "bun.lock") {
    return { Results: [{ Target: target, Vulnerabilities: vulnerabilities, Misconfigurations: misconfigurations }] }
}

const vuln = (pkg, version, id, severity, fixed = "9.9.9") => ({
    PkgName: pkg, InstalledVersion: version, VulnerabilityID: id, Severity: severity, FixedVersion: fixed, Title: `${id} in ${pkg}`,
})
const misconfig = (id, severity, line) => ({ ID: id, Severity: severity, Title: id, CauseMetadata: { StartLine: line } })

const ids = list => list.map(f => f.id).sort()

test("a fixable high vulnerability the change adds blocks", () => {
    const { added, backlog } = compare(report(), report([vuln("lodash", "4.17.15", "CVE-2020-8203", "HIGH", "4.17.19")]))
    assert.deepEqual(ids(added), ["CVE-2020-8203"])
    assert.equal(backlog.length, 0)
    const { errors, warnings } = verdict(added)
    assert.deepEqual(ids(errors), ["CVE-2020-8203"])
    assert.equal(warnings.length, 0)
})

test("what the base branch already has is backlog, never blocked", () => {
    const old = [vuln("axios", "1.11.0", "CVE-2025-1", "CRITICAL"), vuln("fastify", "4.29.1", "CVE-2025-2", "HIGH")]
    const { added, backlog } = compare(report(old), report(old))
    assert.equal(added.length, 0)
    assert.equal(backlog.length, 2)
    assert.equal(summarize(backlog), "1 critical, 1 high")
})

test("a version bump that still carries an old advisory is not new", () => {
    const { added } = compare(
        report([vuln("axios", "1.11.0", "CVE-2025-1", "HIGH")]),
        report([vuln("axios", "1.12.0", "CVE-2025-1", "HIGH")]),
    )
    assert.equal(added.length, 0)
})

test("a version bump that brings a fresh advisory is new", () => {
    const { added } = compare(
        report([vuln("axios", "1.11.0", "CVE-2025-1", "HIGH")]),
        report([vuln("axios", "1.12.0", "CVE-2025-1", "HIGH"), vuln("axios", "1.12.0", "CVE-2025-3", "HIGH")]),
    )
    assert.deepEqual(ids(added), ["CVE-2025-3"])
})

test("the same advisory in another lockfile is another finding", () => {
    const { added } = compare(
        report([vuln("axios", "1.11.0", "CVE-2025-1", "HIGH")], [], "bun.lock"),
        {
            Results: [
                report([vuln("axios", "1.11.0", "CVE-2025-1", "HIGH")], [], "bun.lock").Results[0],
                report([vuln("axios", "1.11.0", "CVE-2025-1", "HIGH")], [], "app/package-lock.json").Results[0],
            ],
        },
    )
    assert.deepEqual(added.map(f => f.target), ["app/package-lock.json"])
})

test("new findings that cannot block are warnings: no fix, medium, misconfiguration", () => {
    const { added } = compare(report(), report(
        [vuln("bigint-buffer", "1.1.5", "CVE-2025-4", "HIGH", ""), vuln("ws", "8.0.0", "CVE-2025-5", "MEDIUM"), vuln("x", "1", "CVE-2025-6", "LOW")],
        [misconfig("DS-0002", "HIGH", 3), misconfig("DS-0026", "LOW", 1)],
    ))
    const { errors, warnings } = verdict(added)
    assert.equal(errors.length, 0)
    assert.deepEqual(ids(warnings), ["CVE-2025-4", "CVE-2025-5", "DS-0002"])
})

test("warn mode turns a blocking finding into a warning", () => {
    const { added } = compare(report(), report([vuln("lodash", "4.17.15", "CVE-2020-8203", "HIGH", "4.17.19")]))
    const { errors, warnings } = verdict(added, "warn")
    assert.equal(errors.length, 0)
    assert.deepEqual(ids(warnings), ["CVE-2020-8203"])
})

test("a removed advisory is neither new nor backlog", () => {
    const { added, backlog } = compare(report([vuln("lodash", "4.17.15", "CVE-2020-8203", "HIGH")]), report())
    assert.equal(added.length + backlog.length, 0)
})

test("descriptions fit on one annotation line", () => {
    const f = compare(report(), report([{ ...vuln("lodash", "4.17.15", "CVE-2020-8203", "HIGH", "4.17.19"), Title: "Prototype\npollution" }])).added[0]
    assert.equal(describe(f), "lodash 4.17.15: CVE-2020-8203 (high, fixed in 4.17.19) — Prototype pollution")
    assert.equal(describe(compare(report(), report([], [misconfig("DS-0002", "HIGH", 3)])).added[0]), "DS-0002 (high): DS-0002")
})

test("an empty report has nothing", () => {
    const { added, backlog } = compare({}, { Results: null })
    assert.equal(added.length + backlog.length, 0)
    assert.equal(summarize(backlog), "none")
})
