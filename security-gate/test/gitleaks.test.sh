#!/usr/bin/env bash
# Runs the gate's gitleaks config over a throwaway repo: one commit per secret
# shape must be caught, the clean commits must not be. Fake secrets are made
# at run time so this repository never holds anything that looks like one.
#
#   GITLEAKS=/path/to/gitleaks ./security-gate/test/gitleaks.test.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="$HERE/../gitleaks.toml"
GITLEAKS="${GITLEAKS:-gitleaks}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$WORK"
git init -q
git config user.email test@example.invalid
git config user.name test
git commit -q --allow-empty -m base
BASE="$(git rev-parse HEAD)"

# Finite generators only: an endless producer cut off by head hangs on GitHub
# runners, where SIGPIPE is ignored.
words() { printf '%s\n' abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual | head -n "$1" | paste -sd' '; }
alnum() { openssl rand -base64 $((2 * $1)) | tr -dc 'A-Za-z0-9' | head -c "$1"; }

fail=0
expect() { # expect <caught|clean> <name> <file> <content>
    local want="$1" name="$2" file="$3" content="$4"
    git reset -q --hard "$BASE"
    mkdir -p "$(dirname "$file")"
    printf '%s\n' "$content" >"$file"
    git add -A && git commit -q -m "$name"
    if "$GITLEAKS" git --no-banner --config "$CONFIG" --log-opts "$BASE..HEAD" --redact --exit-code 1 >/dev/null 2>&1; then
        got=clean
    else
        got=caught
    fi
    if [ "$got" = "$want" ]; then
        echo "ok   $name ($got)"
    else
        echo "FAIL $name: expected $want, got $got"
        fail=1
    fi
}

expect caught "hex ed25519 private key" src/wallet.ts "const privateKey = \"0x$(openssl rand -hex 64)\""
expect caught "hex secp256k1 key in env" .env.local "PRIVATE_KEY=$(openssl rand -hex 32)"
expect caught "mnemonic in code" src/seed.ts "const mnemonic = \"$(words 12)\""
expect caught "mnemonic in env" deploy/node.env "WALLET_MNEMONIC=$(words 24)"
expect caught "telegram bot token" src/notify.ts "const t = \"$(shuf -i 100000000-999999999 -n1):AA$(alnum 33)\""
expect caught "telegram bot token in a URL" src/metrics.ts "const u = \`https://api.telegram.org/bot$(shuf -i 1000000000-9999999999 -n1):AA$(alnum 33)/sendMessage\`"
expect caught "pem private key" keys/server.txt "$(printf -- '-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----' "$(openssl rand -base64 48)")"
expect clean "transaction hash" src/tx.ts "const txHash = \"0x$(openssl rand -hex 32)\""
expect clean "public key" src/peer.ts "const publicKey = \"$(openssl rand -hex 32)\""
expect clean "ordinary prose" README.md "the seed of this idea was a quick note about wallets and keys"

exit "$fail"
