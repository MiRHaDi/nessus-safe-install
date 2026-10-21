# Security policy

This project is privileged operator tooling. Version 0.1.x is alpha and requires source review and testing on a disposable VM before production use. It does not replace vendor support, authorization or independent backups.

Report vulnerabilities privately through GitHub's **Report a vulnerability** feature when enabled. If unavailable, use a minimal public issue asking for a private reporting channel; do not include exploitation details or sensitive data in that initial issue.

Never attach actual licenses, activation codes, private feed URLs, passwords, session cookies, scanner backups, registration databases, keys, scan results or unredacted logs. Use synthetic fixtures and a minimal reproduction. Operational receipt hashes alone do not make an entire production backup safe to publish.

Security properties include HTTPS verification, no cross-origin session redirects, root-private state, single-writer operations, no deliberate data deletion, safe archive recovery, preserved current trees and explicit registration/acceptance gates. Contributions that bypass licensing, alter feed identities, disable TLS or remove data to conceal an error will not be accepted.
