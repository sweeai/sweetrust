# sweetrust — AGENTS.md

> Package contract for any agent (human or AI) working inside `sweetrust`. Read
> end-to-end before touching anything here.

## What this package is

**The trust rail: `sweetrust/mandate` issues authority · `sweetrust/gate` enforces it · `sweetrust/verify` proves it happened.** One npm package, three subpath exports, zero runtime dependencies.

Until 2026-07-30 these were three packages (`@sweetrust/mandate`, `@sweetrust/gate`, `@sweetrust/verify`). All three were unpublished, so the merge was free. The reasoning: `npm i sweetrust` is a product; three scoped installs is a build system the user has to assemble. Import-level decoupling was preserved — each subpath is its own bundle entry; importing `gate` or `mandate` pulls in neither of the other two (only the shared `canon` leaf), and `verify` pulls both, by design.

## Corrections applied at the merge — do not reintroduce these

The three predecessor `AGENTS.md` files had drifted from the code. If you find any of these claims repeated anywhere, they are wrong:

| Stale claim | Reality |
|---|---|
| *"Effect-TS idioms: all flows are `Effect.gen` generators"* | **Effect was removed on purpose** (DAN-600, 2026-07-20). `src/mandate/mandate.ts` says so at the definition site: `failMandate` is the "plain-TS replacement for the former `Effect.fail`", and `defineCapability` "replaces the former `Context.Tag(...)` (which required Effect)." There is no `effect` dependency and no `effect` import anywhere in this package. **Do not write `Effect.gen` code here.** |
| *"TypeScript source-shipping … no build step"* | There **is** a build step: `tsdown`, four entries, emitting `dist/*.mjs` + `.d.mts`. `main`/`types`/`exports` all point at `dist/`. |
| *"Layer composition is the only authentication primitive"* / `makeXLive` = Effect Layers | The `makeXLive` names survive as plain factory functions. They are not Effect Layers. The dependency-injection *discipline* still holds; the framework is gone. |
| Version `v1.1.0` (mandate) / `v0.1.0` (gate, verify) | One version for the whole package — read it from `package.json`, never from prose. |
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
  canon.ts        the one canonicalization (canonicalJSON, sha256Hex) — a leaf, node:crypto only
  mandate/        authority   → subpath "sweetrust/mandate"  (types, mandate, audit, signer, security, errors, two demos)
  gate/           enforcement → subpath "sweetrust/gate"     (trust.ts — one file, on purpose)
  verify/         evidence    → subpath "sweetrust/verify"
  cage/           ChainCage types only, no runtime; re-exported as types from the root
  sui/            the ChainCage adapter for Sui → subpath "sweetrust/sui"; the one entry with a peer (@mysten/sui)
scripts/
  readme-typecheck.ts    compiles the README's ts blocks against dist/*.d.mts (a `pnpm typecheck` gate)
  forgery-typecheck.ts   proves an object literal cannot satisfy Sourced in the shipped declarations (same)
examples/
  caged-spend-agent.ts   the Sui cage live on testnet; needs a funded key and runs in no gate
docs/adr/         decisions with force — 0001 authority is possession · 0002 the interior hash is canonical
test/
  index-barrel.test.ts   guards the barrel against silent export loss
  canon.test.ts          one canonicalization across the rail; the leaf imports only node:crypto
  intake-poison.test.ts  every object-taking export under the second-read Proxy in helpers/poison.ts
  mandate/ gate/ verify/ sui/   mirror src/
```

| File | Role |
|---|---|
| `src/canon.ts` | `canonicalJSON` + `sha256Hex`, the bytes every signature and hash in the rail is computed over. Imports only `node:crypto`, so gate, mandate and verify can all import it without importing each other. `signer.ts` re-exports both names |
| `src/mandate/types.ts` | exported types: `MandateScope<Caps, Tier, ParentScope>`, the `MandateAuditEvent` union, `MandateError`, `MandateTier` |
| `src/mandate/mandate.ts` | issue / use / revoke across all three tiers |
| `src/mandate/audit.ts` | audit-log factories, signed and unsigned |
| `src/mandate/signer.ts` | Ed25519 signer + verifier, `verifyAuditChain`, `signedPreimage`; re-exports `canonicalJSON` and `sha256Hex` from `src/canon.ts` |
| `src/mandate/security.ts` | `constitutionalPreCheck` + the MIP-1..MIP-6 catalog |
| `src/mandate/errors.ts` | `MandateFailure`, the `Error` every mandate refusal is thrown as; the union's fields are own properties and `message` is the `_tag` alone |
| `src/mandate/{demo,multi-tier-demo}.ts` | runnable narrations of the flow, `node src/mandate/<demo>.ts`; not shipped |
| `src/gate/trust.ts` | the enforcement kernel — one file, deliberately |
| `src/verify/verify.ts` | signed receipt chains, JSONL, third-party verification, anchor memos |

## Non-negotiables

- **Zero runtime dependencies.** Node builtins only. This is a design property, not an accident: the kernel must be auditable in one sitting and embeddable across repo boundaries. Adding a dependency requires an ADR, full stop.
- **Rule 2 is absolute.** `fromLLM` returns untrusted regardless of model quality, input tiers, or confidence. Confidence is orthogonal metadata; it never substitutes for tier.
- **Rule 3 is structural, not conventional.** The `Sourced` constructor and `ascend` are module-private; the three declassifiers are the only doors. Any change that makes ascent reachable from outside `src/gate/trust.ts` reopens the forgery hole that made Rule 3 structural in the first place. `test/gate/trust.test.ts` "forgery resistance" guards it.
- **One canonicalization across the rail.** `canonicalJSON` and `sha256Hex` are defined once, in `src/canon.ts`, a leaf that imports only `node:crypto`. Mandate's signed preimage and chain link, verify's wrapper link and the gate's interior receipt hash all go through it; `signer.ts` re-exports the two names so `sweetrust/mandate`, `sweetrust/verify` and the root hand out the identical function objects. Never grow a second implementation, and never hash with a bare `JSON.stringify` — two canonicalizations means bytes produced on one side fail on the other, and `JSON.stringify` is a second canonicalization (insertion-order keys). `test/index-barrel.test.ts` and `test/canon.test.ts` assert identity, not name-equality, and `test/canon.test.ts` asserts the leaf has no import but `node:crypto`.
- **The root barrel is curated on purpose.** `src/index.ts` star-exports mandate and gate but names verify's surface by hand. Two `export *` clauses offering the same name make it ambiguous, and ESM resolves ambiguity by **silently omitting** the name — no error, no warning. Do not "simplify" it to three stars.
- **TCB honesty.** Never claim unforgeability for this package. In-process TypeScript is observe/warn/dev-time authority and cannot be unforgeable; money limits belong to the chain's own primitives (on Sui, native `sui::allowance`). Keep the honest-limits comment blocks in `src/gate/trust.ts` and `src/verify/verify.ts` intact.
- **Receipt hash discipline.** The interior receipt hash is `sha256Hex(receiptBody(receipt))`, and `receiptBody` is `canonicalJSON` over the receipt's seven fields (`src/gate/trust.ts`). `ReceiptLog.nextReceipt`, `verifyChain` and verify's recomputation all call that one function, so there is no key order to agree on and no second site to keep in step. Changing the body SHAPE (adding or renaming a field) still changes every hash: it is a 0.x breaking change with a CHANGELOG entry and an ADR, never a quiet edit. `docs/adr/0002-receipt-interior-hash-is-canonical.md` records the move from `JSON.stringify`.
- **Wrap, never fork.** Integrations that need an external service live *outside* this package, as separate adapter packages. That is what keeps the zero-dependency claim true.
- **Constitutional pre-check before persistence.** Any function that persists an authored string must run `constitutionalPreCheck` first. Inherited v0.0 I9 invariant.
- **Intake: caller input is read once, at the boundary.** Every exported function snapshots each field of its argument exactly once — own keys only, no prototype walk — and every check, mint, write and record that follows uses the snapshot, never the argument. A getter or a Proxy can answer differently on each read, so a second read of the same field is a time-of-check/time-of-use hole: the 2026-10-13 mandate CRITICAL was exactly that, `args.mandate` re-read at every site that wanted it, so one getter satisfied the possession check with the genuine scope and fed forged data to everything after. The harness is `test/helpers/poison.ts` (a Proxy that throws `SecondRead` on the second `get` of any key; `Object.keys`, `hasOwn` and `in` do not count, so an own-key snapshot passes) and the test is `test/intake-poison.test.ts`, which runs every object-taking export under it and requires the same verdict as on a plain object. **A new export that takes an object is added to that test in the same commit that adds the export.** The rule covers nested bags the function itself reads (`requires`, `redact`, `judgment`, `anchor`) and each capability object's `key`; it does not reach into values the function stores without reading (a scope keeps the caller's capability objects by reference, and `useCapability` re-resolves their keys against the recorded grant, which is what makes that safe).
- **No `// @ts-ignore`.** Use `// @ts-expect-error` with a comment saying why the directive is load-bearing, on the line immediately preceding the offending expression. A `@ts-expect-error` in a test is a compile-time invariant proof — if TypeScript ever reports one as unused, that is a five-alarm fire meaning the type-level invariant regressed. Never silently delete one.

## Gates

```bash
pnpm -C packages/trust build       # tsdown → dist/ (the two typecheck gates read dist/, so build first)
pnpm -C packages/trust test        # vitest
pnpm -C packages/trust typecheck   # tsc --noEmit, then scripts/readme-typecheck.ts and scripts/forgery-typecheck.ts against dist/
pnpm typecheck                     # from the repository root: every package's typecheck, in turn
```

The demos (`src/mandate/*demo.ts`) and `pnpm typecheck` run TypeScript directly (`node --experimental-strip-types`) and need **Node ≥ 22.18**. The shipped `dist/` needs only `engines`: Node ≥ 20.19. Do not raise `engines` to match the dev tooling; the floor is a promise to consumers.

Every public-API change ships with a test. When you change the export surface, the subpath entries in `tsdown.config.ts` and the `exports` map in `package.json` must stay in correspondence — nothing checks that but the smoke path in `README.md`.

## When in doubt

- **New primitive or existing one?** Authority → `src/mandate/`. Anything about a value's pedigree or a sink refusing → `src/gate/`. Anything a third party checks after the fact → `src/verify/`.
- **New test file or existing?** New top-level capability → new file, under the matching subdirectory. Extension of existing behaviour → existing file.
- **Does it belong in this package at all?** If it needs a network, a vendor SDK, or an API key, no. That is an adapter, and adapters live outside so this package stays dependency-free.

## Related

- **Revocation and money.** `revokeMandate` writes only to this package's audit log; the kernel
  (`mandate`, `gate`, `verify`) makes **zero chain calls by design.** Money limits belong to the
  chain's own primitives (on Sui, native `sui::allowance`), and a "Revoke" button that is supposed
  to stop money must act there. `SECURITY.md` § *Honest limits* explains why that distinction
  decides whether the button does anything.
- **Adapters.** Anything that needs a network, a vendor SDK or an API key belongs outside this
  package. That constraint is what makes the zero-dependency claim true.
