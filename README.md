# sweetrust

Swee's open-source packages: [`sweetrust`](packages/trust), the kernel, and [`sweetrust-sui`](packages/sui), its first chain adapter. Both unscoped.

| Package | What it is |
|---|---|
| [`sweetrust`](packages/trust) | Trust rails for AI agents — issue authority, enforce it, prove what happened. Zero runtime dependencies. |
| [`sweetrust-sui`](packages/sui) | Delegated spending on Sui's native allowance, with receipts that say which limit Sui held, which the library held, and why a spend was refused. 0.1.0, unreleased. |

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
[`packages/trust/AGENTS.md`](packages/trust/AGENTS.md), then [`packages/sui/AGENTS.md`](packages/sui/AGENTS.md) for the Sui adapter.

## Security

Report vulnerabilities through a
[security advisory](https://github.com/sweeai/sweetrust/security/advisories/new), never a public
issue. Each package also ships a `SECURITY.md` with an **Honest limits** section stating what it
does *not* protect — read that before you rely on one.

## License

Apache-2.0. See [LICENSE](LICENSE).
