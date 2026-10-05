# Security

This is preview software for small, explicitly authorized, self-hosted spaces.
The initial public version is mock-first. Production API support, broad client
compatibility, and an Internet-scale public Hub have not been validated.

## Reporting

Use the repository's private vulnerability reporting feature on GitHub. If private
reporting is unavailable, open an issue requesting a private reporting channel
without including exploit details, credentials, account files, or private data.
There is no promised response-time service agreement.

## Trust boundaries

- Hub and Relay operators can inspect request/response content in memory. TLS
  protects transport; this is not end-to-end encryption.
- The ledger stores authorization, state, usage, and audit metadata, not prompt or
  response bodies. Protect and back up the data directory.
- Local encrypted credentials do not isolate other programs running as the same
  operating-system user. Protect the account and file permissions.
- A pairing code joins a space; it does not automatically authorize inference.
  Providers must approve members and models explicitly.
- Keep source ownership, grants, fixed routes, and UNKNOWN-result handling intact.
  An unknown upstream result must not cause transparent replay or account failover.
- Experimental subscription support is disabled by default. A technical opt-in
  is not provider authorization. See docs/EXPERIMENTAL_SUBSCRIPTION.md.

Use a dedicated personal server and personal credentials. Run one Hub per data
volume, terminate HTTPS/WSS with a valid certificate, restrict administrator
access, and verify authorization isolation before inviting participants.
