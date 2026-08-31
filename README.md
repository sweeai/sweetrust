# sweetrust

Swee's open-source packages. Everything published under the **`@swee`** scope lives here.

| Package | What it is |
|---|---|
| [`@swee/trust`](packages/trust) | Trust rails for AI agents — issue authority, enforce it, prove what happened. Zero runtime dependencies. |

## Why one repository

Packages that share code need to share a build, a version bump and a CI run. Splitting them across
repositories trades a directory boundary for a publish cycle, and you pay that cost on every change
that crosses two packages.

A repository is the unit of *visibility*, so there is exactly one public repository here — not one
per package. Swee's private work lives in a separate repository that depends on the published
versions of these.

## Working here

```bash
pnpm install
pnpm build && pnpm test && pnpm typecheck
```

Each package owns its own gates and its own `AGENTS.md`. Start with
[`packages/trust/AGENTS.md`](packages/trust/AGENTS.md).

## Security

Report vulnerabilities through a
[security advisory](https://github.com/sweeai/sweetrust/security/advisories/new), never a public
issue. Each package also ships a `SECURITY.md` with an **Honest limits** section stating what it
does *not* protect — read that before you rely on one.

## License

Apache-2.0. See [LICENSE](LICENSE).
