# Contributing

Use Node.js 24 and the public npm registry. Start with a mock-only development
environment; no model account, paid API, private Hub, or company network is needed.

```sh
npm ci
npm run typecheck
npm test
npm run build
npm run audit:public
```

Send a focused pull request with the problem, the resulting behavior, and relevant
validation. Keep credentials, real deployment addresses, logs, screenshots of
private data, and model account files out of commits and issue attachments.
Use synthetic fixtures. Do not run real subscription or API calls in CI.

Pull requests run unprivileged checks. Publishing, signing, and deployment belong
to maintainer-controlled release workflows. Pin third-party GitHub Actions to an
audited commit, and use GitHub-hosted runners.

By contributing, you confirm that you may submit the material under this project's
MIT license. Keep existing attribution and third-party notices. Report sensitive
security issues using the process in SECURITY.md instead of a public issue.
