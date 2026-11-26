# Security policy

This policy covers every repository of the kynesyslabs organization.

## Reporting a vulnerability

Report it privately through GitHub: open the affected repository's
**Security** tab and choose **Report a vulnerability**. For the node and the
SDK:

- node: https://github.com/kynesyslabs/node/security/advisories/new
- SDK: https://github.com/kynesyslabs/sdks/security/advisories/new

Only the maintainers see the report. Do not open a public issue, pull
request or discussion for a vulnerability, and do not test it against
mainnet or another operator's node.

Include the affected version or commit, the steps or a proof of concept, and
what an attacker gains.

## What happens next

- We acknowledge the report within 3 days and give a first severity
  assessment within 7 days.
- A fix for a Critical or High issue ships to the validators first, as a
  signed release, before the details are published.
- We credit the reporter in the advisory unless they ask not to be named.

The severity table and the supported versions are in each repository's own
`SECURITY.md`, for example
[node](https://github.com/kynesyslabs/node/blob/stabilisation/SECURITY.md).

## Rewards

There is no public bounty programme yet. Valid Critical and High reports are
rewarded case by case until one is announced.
