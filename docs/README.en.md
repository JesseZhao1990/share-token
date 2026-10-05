# Share Token

A self-hosted inference gateway and local Codex bridge. A Hub manages device
pairing, explicit grants, fixed source routing, and request state. Consumer tools
run on the consumer's own computer; providers connect through an outbound Relay.

The initial open-source version **0.1.0 is mock-first**. Its default demo uses
synthetic responses without a model account or paid requests. Personal
subscription support is experimental and disabled by default. The HTTP API
fixture is for protocol comparisons, not a validated production API product.

Use Node.js 24 with the public npm registry:

```sh
npm ci
npm run build
npm run dev
```

For the desktop UI, run `npm run desktop` in another terminal. Connect to your
own Hub and authorize participating devices explicitly. Public packages contain
no default Hub, account credentials, or pairing code.

```sh
npm run typecheck
npm test
npm run build
npm run audit:public
npm run hub:deployment:check
```

Hub and Relay process request/response content in memory. TLS is not end-to-end
encryption. The ledger stores metadata rather than prompt/response bodies.
See [SECURITY.md](../SECURITY.md) for trust boundaries.

Desktop packaging currently targets macOS Apple Silicon only. Preview packages
are ad-hoc signed and not notarized by Apple. See the actual GitHub Releases for
availability and signing details; no public package is implied by a build script.

- [Self-hosting](SELF_HOSTING.md)
- [Development](DEVELOPMENT.md)
- [Releases](RELEASING.md)
- [Experimental subscription adapter](EXPERIMENTAL_SUBSCRIPTION.md)
- [MIT license](../LICENSE) and [third-party notices](../THIRD_PARTY_NOTICES.md)
