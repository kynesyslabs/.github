# Security gate

A pull request check that blocks secrets, malicious changes and commits by unknown authors. It is called from each repository and keeps its rules here, so every repository gets the same rules.

## What it checks

| Check | Fails on | Warns on |
|---|---|---|
| **secrets** | gitleaks default rules (cloud keys, tokens, PEM blocks, Telegram bot tokens) plus raw hex private keys and BIP-39 mnemonics assigned to key-like names | — |
| **malicious changes** | exfiltration endpoints (Telegram bots, webhooks, paste and tunnel services); obfuscated `_0x…` code; key material, a network call and a hard-coded URL added to one file; decoded strings run as code; committed `.env` files, private keys and seed backups; registry tokens in `.npmrc`; install hooks that download or run opaque code; workflow changes that expose secrets | key material next to a network call; `eval`; shell execution; very long encoded literals; ordinary install hooks; lockfile entries outside the npm registry |
| **commit authors** | a commit whose email no GitHub account owns and that has never committed to the repository before | an unlinked email the repository has seen before; a commit by a different account than the PR author |

Only lines the pull request adds are scanned. Nothing from the pull request is executed: the jobs run git, a pinned and checksum-verified gitleaks, and the scripts in this directory, with a read-only token and no secrets.

The rules were checked against:
- **wallet-extension PR #70**, which hid a private-key stealer in the send path. All three checks block it.
- **Real history since April 2026**, scanning every merge on `node`, `sdks` and `wallet-extension` (77 merges). Neither the secrets check nor the malicious-change check blocks any of them.
- **The last 90 merged PRs**, for the authors check. About 5% would have failed: each was someone's first commit from an email not linked to GitHub, and linking the email clears it.

## Adding it to a repository

Add `.github/workflows/security-gate.yml`:

```yaml
name: Security gate

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: read

jobs:
  gate:
    uses: kynesyslabs/.github/.github/workflows/security-gate.yml@main
```

The same file is offered as a template under **Actions → New workflow** for every repository in the organisation.

Inputs:
- `authors: warn` turns the authors check into a warning.
- `gate-ref` pins the rules to a tag or commit instead of `main`.

To make it **block merging**:
1. Open **Settings → Branches** and add a branch protection rule for `main`.
2. Require these status checks: `gate / secrets`, `gate / malicious changes`, `gate / commit authors`.
3. Also require at least one approving review.

On the GitHub Free plan this works only for **public** repositories. A private repository needs GitHub Team or higher for branch protection. Until then, the gate still runs and marks the pull request red, and the `push` trigger flags anything pushed straight to `main`, but nothing stops a merge.

## Exemptions

Every exemption is read from the **base** branch, never from the pull request, so a pull request cannot exempt itself:

- **`.security-gate-allow`** in the repository root: lines of `<rule>:<path glob>`, e.g. `exfil-endpoint:src/features/telegram/**`. Use `*` as the rule to exempt a path from every malicious-change rule.
- **`.gitleaksignore`** in the repository root: gitleaks fingerprints of findings that are known false positives.
- **`security-gate/known-authors.txt`** in this repository: author emails allowed without a linked GitHub account, for every repository. The better fix is for the person to add the email to their GitHub account.

Changes to this directory change the rules for every repository, so `main` here must be protected and reviewed.

## Tests

```sh
node --test security-gate/test/*.test.mjs
GITLEAKS=/path/to/gitleaks ./security-gate/test/gitleaks.test.sh
```

`self-test.yml` runs both on every pull request to this repository.
