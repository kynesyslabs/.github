/**
 * Rules for scan-diff.mjs. Pure: diff text in, findings out, so the rules can
 * be tested against fixtures without git.
 *
 * Each rule looks only at added lines. The most important one is file-level:
 * key material and a network call added to the same file, which is how a
 * stealer hidden in a wallet's send path looks (wallet-extension PR #70).
 */

const CODE = /\.(m?[jt]sx?|cjs|cts|mts|svelte|vue|py|sh|bash|go|rs)$/i
const LOCKFILE = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock)$/
const PACKAGE_JSON = /(^|\/)package\.json$/
const WORKFLOW = /^\.github\/workflows\/.+\.ya?ml$/
// Tests and fixtures legitimately carry odd strings; secret files never belong anywhere.
const TESTISH = /(^|\/)(tests?|__tests__|__fixtures__|fixtures|spec|mocks?)\/|\.(test|spec)\.[^/]+$/i

/** Where stolen data is usually sent: chat bots, webhooks, paste and tunnel services. */
const EXFIL_HOSTS = [
    /api\.telegram\.org/i,
    /discord(?:app)?\.com\/api\/webhooks/i,
    /hooks\.slack\.com\/services/i,
    /webhook\.site/i,
    /pipedream\.net/i,
    /requestbin|requestcatcher\.com|beeceptor\.com/i,
    /pastebin\.com|paste\.ee|hastebin/i,
    /ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|serveo\.net|localtunnel\.me/i,
    /transfer\.sh|file\.io|anonfiles|bashupload\.com/i,
    /interact\.sh|oast\.(?:fun|live|site|me|pro)|burpcollaborator\.net/i,
]

const KEY_MATERIAL = /\b(private_?key|privkey|secret_?key|mnemonic|seed_?phrase|seedPhrase|\.seed\b|keypair\.secret|getPrivateKey|exportPrivateKey|masterSeed)\b/i
const NETWORK_SINK = /\b(fetch|XMLHttpRequest|sendBeacon|axios(?:\.\w+)?|got|superagent|WebSocket|http\.request|https\.request|net\.connect|dgram)\s*\(|new\s+(?:WebSocket|XMLHttpRequest|EventSource)\b|\$\.(?:ajax|post|get)\s*\(/
const OBFUSCATED_IDENT = /\b_0x[0-9a-f]{4,}\b/i
const DYNAMIC_CODE = /\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*["'`]|setTimeout\s*\(\s*["'`]/
const DECODE = /\batob\s*\(|Buffer\.from\([^)]*["'`](?:base64|hex)["'`]|fromCharCode\s*\(|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){8,}/i
const LONG_LITERAL = /["'`][A-Za-z0-9+/=_-]{400,}["'`]/
const INSTALL_SCRIPT = /"(preinstall|install|postinstall|prepare)"\s*:/
const SHELL_DOWNLOAD = /\b(curl|wget)\b[^|\n]*\|\s*(ba|z)?sh\b|child_process|execSync\s*\(|spawn\s*\(\s*["'`](?:sh|bash|cmd|powershell)/
const LOCK_FOREIGN_SOURCE = /(resolved|tarball)["']?\s*[:=]\s*["']?(?!https:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\/)(git\+|git:|https?:\/\/)/
const SECRET_FILE = /(^|\/)(\.env(\.(?!example$|sample$|template$|dist$)[\w.-]+)?|id_(rsa|ed25519|ecdsa)|[^/]*\.(pem|p12|pfx|key|keystore))$/i
// Named like a seed backup and holding data, not a component that handles one.
const SEED_DATA_FILE = /(^|\/)[^/]*(mnemonic|seed[-_]?phrase|wallet[-_]?backup)[^/]*?(\.(txt|json|csv|bak|dat|enc))?$/i
const REGISTRY_RC = /(^|\/)\.(npmrc|yarnrc(\.yml)?|pypirc)$/
const REGISTRY_TOKEN = /_authToken|_auth\s*=|:_password|npmAuthToken|password\s*[:=]/i
// An install hook is routine tooling until it fetches or runs something opaque.
const RISKY_HOOK = /curl|wget|https?:\/\/|node\s+-e|bash\s+-c|sh\s+-c|base64|eval|powershell|\|\s*(ba)?sh/i
const WORKFLOW_RISK = /pull_request_target|ACTIONS_RUNTIME_TOKEN|toJSON\(\s*secrets\s*\)/
const WORKFLOW_SECRET_USE = /\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}/
const WORKFLOW_SECRET_SINK = /\b(curl|wget|echo|printf|base64|nc|tee)\b/

/** Parse a unified diff into files with their added lines and new-file line numbers. */
export function parseDiff(text) {
    const files = []
    let file = null
    let lineNo = 0
    for (const raw of text.split("\n")) {
        if (raw.startsWith("diff --git ")) {
            file = { path: null, added: [], newFile: false, deleted: false }
            files.push(file)
            continue
        }
        if (!file) continue
        if (raw.startsWith("new file mode")) file.newFile = true
        else if (raw.startsWith("deleted file mode")) file.deleted = true
        else if (raw.startsWith("+++ ")) {
            const p = raw.slice(4).trim()
            file.path = p === "/dev/null" ? null : p.replace(/^b\//, "")
        } else if (raw.startsWith("--- ")) {
            if (!file.path) {
                const p = raw.slice(4).trim()
                if (p !== "/dev/null") file.oldPath = p.replace(/^a\//, "")
            }
        } else if (raw.startsWith("@@")) {
            const m = /\+(\d+)/.exec(raw)
            lineNo = m ? Number(m[1]) : 0
        } else if (raw.startsWith("+")) {
            file.added.push({ line: lineNo, text: raw.slice(1) })
            lineNo++
        } else if (!raw.startsWith("-") && !raw.startsWith("\\")) {
            lineNo++
        }
    }
    return files.filter(f => f.path && !f.deleted)
}

function globToRegex(glob) {
    const escaped = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&")
    return new RegExp("^" + escaped.replace(/\*\*\/?/g, "\u0000").replace(/\*/g, "[^/]*").replace(/\u0000/g, ".*") + "$")
}

/** Allowlist lines are `<rule>:<path glob>`, e.g. `long-literal:src/zk/keys/**`. */
function allowed(allowlist, rule, path) {
    return allowlist.some(entry => {
        const i = entry.indexOf(":")
        if (i < 0) return false
        const r = entry.slice(0, i).trim()
        return (r === rule || r === "*") && globToRegex(entry.slice(i + 1).trim()).test(path)
    })
}

function clip(text) {
    const t = text.trim()
    return t.length > 140 ? t.slice(0, 137) + "..." : t
}

export function analyze(diffText, allowlist = []) {
    const findings = []
    const add = (severity, rule, file, line, message, excerpt) => {
        if (allowed(allowlist, rule, file)) return
        findings.push({ severity, rule, file, line, message, excerpt: excerpt === undefined ? undefined : clip(excerpt) })
    }

    for (const f of parseDiff(diffText)) {
        const path = f.path
        const isCode = CODE.test(path)
        const isTest = TESTISH.test(path)

        if (SECRET_FILE.test(path) || (SEED_DATA_FILE.test(path) && !CODE.test(path))) {
            add("high", "secret-file", path, null, "Adds a file that normally holds secrets (env, private key, seed backup)")
        }

        if (REGISTRY_RC.test(path)) {
            for (const l of f.added) {
                if (REGISTRY_TOKEN.test(l.text)) {
                    add("high", "registry-token", path, l.line, "Commits a package registry credential")
                }
            }
        }

        if (PACKAGE_JSON.test(path)) {
            for (const l of f.added) {
                if (INSTALL_SCRIPT.test(l.text)) {
                    const risky = RISKY_HOOK.test(l.text)
                    add(risky ? "high" : "medium", "install-script", path, l.line,
                        risky
                            ? "Install hook downloads or runs opaque code on every machine that installs the package"
                            : "Adds a package install hook; it runs on every developer machine and in CI",
                        l.text)
                }
            }
        }

        if (LOCKFILE.test(path)) {
            for (const l of f.added) {
                if (LOCK_FOREIGN_SOURCE.test(l.text)) {
                    add("medium", "lockfile-source", path, l.line, "A dependency resolves from outside the npm registry", l.text)
                }
            }
            continue
        }

        if (WORKFLOW.test(path)) {
            for (const l of f.added) {
                if (WORKFLOW_RISK.test(l.text) || (WORKFLOW_SECRET_USE.test(l.text) && WORKFLOW_SECRET_SINK.test(l.text))) {
                    add("high", "workflow-secrets", path, l.line, "Workflow change that can expose repository secrets", l.text)
                }
            }
        }

        if (!isCode) continue

        let firstKey = null
        let firstSink = null
        let hardcodedUrl = null
        let decode = null
        let dynamic = null
        for (const l of f.added) {
            const t = l.text
            for (const host of EXFIL_HOSTS) {
                if (host.test(t)) {
                    add(isTest ? "medium" : "high", "exfil-endpoint", path, l.line, "Sends data to a chat bot, webhook, paste or tunnel service", t)
                    break
                }
            }
            if (OBFUSCATED_IDENT.test(t)) {
                add("high", "obfuscated-code", path, l.line, "Obfuscator-style identifiers (_0x...) in source", t)
            }
            if (SHELL_DOWNLOAD.test(t) && !isTest) {
                add("medium", "shell-exec", path, l.line, "Runs shell commands or pipes a download into a shell", t)
            }
            if (LONG_LITERAL.test(t) && !isTest) {
                add("medium", "long-literal", path, l.line, "Very long encoded string literal in source", t)
            }
            if (!hardcodedUrl && /["'`]https?:\/\/(?!localhost|127\.0\.0\.1)[^"'`\s]+/.test(t)) hardcodedUrl = l
            if (!firstKey && KEY_MATERIAL.test(t)) firstKey = l
            if (!firstSink && NETWORK_SINK.test(t)) firstSink = l
            if (!decode && DECODE.test(t)) decode = l
            if (!dynamic && DYNAMIC_CODE.test(t)) dynamic = l
        }

        // Key handling next to a network call is common in wallet code, so on
        // its own it is a warning; with a hard-coded URL added alongside it
        // is the stealer shape and blocks.
        if (firstKey && firstSink && !isTest) {
            add(hardcodedUrl ? "high" : "medium", "key-to-network", path, firstSink.line,
                `Adds both key material (line ${firstKey.line}) and a network call (line ${firstSink.line})` +
                    (hardcodedUrl ? ` with a hard-coded URL (line ${hardcodedUrl.line})` : "") +
                    " to one file; check that no key leaves the process",
                firstKey.text)
        }
        if (dynamic && decode) {
            add("high", "decoded-eval", path, dynamic.line, "Decodes a string and runs it as code", dynamic.text)
        } else if (dynamic && !isTest) {
            add("medium", "dynamic-code", path, dynamic.line, "Runs a string as code (eval / new Function)", dynamic.text)
        }
    }
    return dedupe(findings)
}

/** One finding per rule and file: the first occurrence, with a count of the rest. */
function dedupe(findings) {
    const byKey = new Map()
    for (const f of findings) {
        const key = `${f.rule}\u0000${f.file}`
        const seen = byKey.get(key)
        if (seen) seen.count++
        else byKey.set(key, { ...f, count: 1 })
    }
    return [...byKey.values()].map(({ count, ...f }) =>
        count > 1 ? { ...f, message: `${f.message} (${count} places)` } : f)
}
