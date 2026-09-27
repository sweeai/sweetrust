# sweetrust — AGENTS.md

> Package contract for any agent (human or AI) working inside `sweetrust`. Read
> end-to-end before touching anything here.

## What this package is

**The trust rail: `sweetrust/mandate` issues authority · `sweetrust/gate` enforces it · `sweetrust/verify` proves it happened.** One npm package, three subpath exports, zero runtime dependencies.

Until 2026-07-30 these were three packages (`@sweetrust/mandate`, `@sweetrust/gate`, `@sweetrust/verify`). All three were unpublished, so the merge was free. The reasoning: `npm i sweetrust` is a product; three scoped installs is a build system the user has to assemble. Import-level decoupling was preserved — each subpath is its own bundle entry, and importing one does not pull the others.

## Corrections applied at the merge — do not reintroduce these

The three predecessor `AGENTS.md` files had drifted from the code. If you find any of these claims repeated anywhere, they are wrong:

| Stale claim | Reality |
|---|---|
| *"Effect-TS idioms: all flows are `Effect.gen` generators"* | **Effect was removed on purpose** (DAN-600, 2026-07-20). `src/mandate/mandate.ts` says so at the definition site: `failMandate` is the "plain-TS replacement for the former `Effect.fail`", and `defineCapability` "replaces the former `Context.Tag(...)` (which required Effect)." There is no `effect` dependency and no `effect` import anywhere in this package. **Do not write `Effect.gen` code here.** |
| *"TypeScript source-shipping … no build step"* | There **is** a build step: `tsdown`, four entries, emitting `dist/*.mjs` + `.d.mts`. `main`/`types`/`exports` all point at `dist/`. |
| *"Layer composition is the only authentication primitive"* / `makeXLive` = Effect Layers | The `makeXLive` names survive as plain factory functions. They are not Effect Layers. The dependency-injection *discipline* still holds; the framework is gone. |
| Version `v1.1.0` (mandate) / `v0.1.0` (gate, verify) | The package is **0.3.0**. Predecessors were all 0.2.0. |
| `@sweetrust/verify` has peer deps on gate + mandate | They are internal now — plain relative imports. No peers. |

The lesson worth keeping: **all five of these were true when written.** An `AGENTS.md` is a living document, and a living document that nobody re-reads against the code becomes an instruction to write the wrong thing. Version numbers in prose rot fastest — prefer pointing at `package.json` over restating it.

## Reading order

1. This file
2. `CHANGELOG.md` — last 3 entries
3. `ARCHITECTURE.md` — subsystem shape, with per-section STATUS / FLOW / SOURCE / LAST VERIFIED
4. `SECURITY.md` § *Honest limits* — what this package does NOT protect. Read it before you rely on anything here
5. `src/index.ts` — the public surface, and the note on why verify is listed by hand
6. `test/` — the coverage envelope; the adversarial suites are the interesting ones

## Layout

```
src/
  index.ts        the whole-rail barrel (curated — see below)
  mandate/        authority   → subpath "sweetrust/mandate"
  gate/           enforcement → subpath "sweetrust/gate"
  verify/         evidence    → subpath "sweetrust/verify"
test/
  index-barrel.test.ts   guards the barrel against silent export loss
  mandate/ gate/ verify/ mirror src/
```

| File | Role |
|---|---|
| `src/mandate/types.ts` | exported types: `MandateScope<Caps, Tier, ParentScope>`, the `MandateAuditEvent` union, `MandateError`, `MandateTier` |
| `src/mandate/mandate.ts` | issue / use / revoke across all three tiers |
| `src/mandate/audit.ts` | audit-log factories, signed and unsigned |
| `src/mandate/signer.ts` | Ed25519 signer + verifier, `verifyAuditChain`, `canonicalJSON`, `sha256Hex` |
| `src/mandate/security.ts` | `constitutionalPreCheck` + the MIP-1..MIP-6 catalog |
| `src/gate/trust.ts` | the enforcement kernel — one file, deliberately |
| `src/verify/verify.ts` | signed receipt chains, JSONL, third-party verification, anchor memos |

## Non-negotiables

- **Zero runtime dependencies.** Node builtins only. This is a design property, not an accident: the kernel must be auditable in one sitting and embeddable across repo boundaries. Adding a dependency requires an ADR, full stop.
- **Rule 2 is absolute.** `fromLLM` returns untrusted regardless of model quality, input tiers, or confidence. Confidence is orthogonal metadata; it never substitutes for tier.
- **Rule 3 is structural, not conventional.** The `Sourced` constructor and `ascend` are module-private; the three declassifiers are the only doors. Any change that makes ascent reachable from outside `src/gate/trust.ts` reopens the Session-003 forgery hole. `test/gate/trust.test.ts` "forgery resistance" guards it.
- **One canonicalization across the rail.** `verify` signs *through* mandate's signer and re-exports mandate's `canonicalJSON`/`sha256Hex`. Never grow a second implementation — two canonicalizations means signatures made on one side fail on the other. `test/index-barrel.test.ts` asserts they are the identical function object, not merely the same name.
- **The root barrel is curated on purpose.** `src/index.ts` star-exports mandate and gate but names verify's surface by hand. Two `export *` clauses offering the same name make it ambiguous, and ESM resolves ambiguity by **silently omitting** the name — no error, no warning. Do not "simplify" it to three stars.
- **TCB honesty.** Never claim unforgeability for this package. In-process TypeScript is observe/warn/dev-time authority; the Move cage owns unforgeable enforcement. Keep the honest-limits comment blocks in `src/gate/trust.ts` and `src/verify/verify.ts` intact.
- **Receipt hash discipline.** `ReceiptLog.append`, `verifyChain`, and verify's interior-hash recomputation must agree byte-for-byte on JSON body key order. Changing the body shape is a three-site change — grep before touching.
- **Wrap, never fork.** Integrations that need an external service live *outside* this package, as separate adapter packages. That is what keeps the zero-dependency claim true.
- **Constitutional pre-check before persistence.** Any function that persists an authored string must run `constitutionalPreCheck` first. Inherited v0.0 I9 invariant.
- **No `// @ts-ignore`.** Use `// @ts-expect-error` with a comment saying why the directive is load-bearing, on the line immediately preceding the offending expression. A `@ts-expect-error` in a test is a compile-time invariant proof — if TypeScript ever reports one as unused, that is a five-alarm fire meaning the type-level invariant regressed. Never silently delete one.

## Gates

```bash
pnpm -C packages/trust typecheck   # tsc --noEmit
pnpm -C packages/trust test        # vitest
pnpm -C packages/trust build       # tsdown → dist/
pnpm typecheck                # workspace, honest coverage report
```

Every public-API change ships with a test. When you change the export surface, the subpath entries in `tsdown.config.ts` and the `exports` map in `package.json` must stay in correspondence — nothing checks that but the smoke path in `README.md`.

## When in doubt

- **New primitive or existing one?** Authority → `src/mandate/`. Anything about a value's pedigree or a sink refusing → `src/gate/`. Anything a third party checks after the fact → `src/verify/`.
- **New test file or existing?** New top-level capability → new file, under the matching subdirectory. Extension of existing behaviour → existing file.
- **Does it belong in this package at all?** If it needs a network, a vendor SDK, or an API key, no. That is an adapter, and adapters live outside so this package stays dependency-free.

## Related

- **On-chain revocation.** A Move `RevocationRegistry` is the authoritative kill switch over
  custodied funds. It is a sibling implementation under a shared name and a separate deployment —
  **this package makes zero chain calls by design.** `SECURITY.md` § *Honest limits* explains why
  that distinction decides whether your "Revoke" button actually stops money.
- **Adapters.** Anything that needs a network, a vendor SDK or an API key belongs outside this
  package. That constraint is what makes the zero-dependency claim true.
