---
title:       "ADR 0002: the receipt's interior hash is over canonical JSON, from one leaf module"
kind:        adr
status:      accepted
updated:     2026-10-13
owner:       sweetrust audit chunk 4
verified_by: "pnpm -C packages/trust test (test/canon.test.ts: 2 watched RED before the fix, 2 controls; test/index-barrel.test.ts identity)"
---

# ADR 0002: the receipt's interior hash is over canonical JSON, from one leaf module

**Status:** Accepted
**Implementation:** shipped (the commit after the red one, 2026-10-13 rail audit, chunk 4 item 1)
**Force:** invariant. `test/canon.test.ts` holds `receiptBody` to `canonicalJSON`, holds mandate,
verify and the root to the identical function objects from `src/canon.ts`, and holds `src/canon.ts`
to a single import, `node:crypto`.
**Date:** 2026-10-13 · **Supersedes:** the "A receipt artifact must be byte-preserved" honest limit

## Context

`AGENTS.md` promises one canonicalization across the rail: mandate's signed preimage and chain
link, verify's wrapper link, all over `canonicalJSON`. The gate's interior receipt hash was the one
place the promise did not reach. `receiptBody` was `JSON.stringify` of a hand-ordered literal. That
pinned the seven top-level keys, and nothing beneath them: `args` is a tree of caller-shaped
objects, written in whatever order the caller built them and in the gate's own
`{ value, tier, provenance }` order, and `JSON.stringify` writes keys as it finds them.

So the hash depended on the layout of the JSON, not only on its values. An honest `exportJSONL`
artifact handed through `jq -S`, a sorted-map round trip or a pretty-printer came back
`hash-mismatch` from `verifySignedChain`, while the signature and the wrapper link over the very
same record verified. The 2026-10-13 verify audit found it, stated it in `SECURITY.md` as an honest
limit, and deferred the fix because it changes every hash.

The gate could not simply import mandate's `canonicalJSON`. Each subpath stands alone on purpose
(`src/index.ts`: importing `sweetrust/gate` does not pull mandate into a bundle), and the function
lived in `src/mandate/signer.ts`.

## Decision

**`canonicalJSON` and `sha256Hex` are defined once, in `src/canon.ts`, a leaf that imports only
`node:crypto`. `receiptBody` is `canonicalJSON` over the receipt's seven fields.**

- `src/canon.ts` holds `canon`, `canonicalJSON` and `sha256Hex`, moved verbatim from `signer.ts`.
  `signer.ts` imports and re-exports the two public names, so `sweetrust/mandate`,
  `sweetrust/verify` and the root export the identical function objects they always did.
- `receiptBody` returns `canonicalJSON({ seq, prevHash, at, sink, decision, args, reason })`. An
  undefined `reason` is dropped by `canonicalJSON` exactly as the old conditional spread dropped
  it. Keys are sorted at every depth, so the bytes depend on values alone.
- Gate's `receiptJSON`, the `{"$bigint":…}` / `{"$number":…}` rendering that runs BEFORE a value
  reaches the receipt, is unchanged. It is a rendering of values, not a canonicalization of bytes,
  and it still lives in gate for the reason its comment gives.

## Consequences

- **Every receipt hash changes.** A log written by 0.3.0 does not verify under 0.4.0, because
  `verifyChain()` and `verifySignedChain` recompute each hash and the recomputation no longer
  matches. A chain written and verified by one version is unaffected. The CHANGELOG says so under
  Changed, as a breaking entry, with the migration (anchor the old head, start a new log).
- **A re-serialized artifact verifies.** The honest limit is replaced by its positive: values must
  survive, layout need not. `SECURITY.md` and the `parseJSONL` comment say so.
- **The rail has one canonicalization in fact, not by convention.** `AGENTS.md`'s "Receipt hash
  discipline" bullet is no longer a three-site key-order agreement; it names one function.
- **The leaf is load-bearing.** If `src/canon.ts` ever imports from a subpath, the gate imports
  that subpath. `test/canon.test.ts` reads the source and refuses any import but `node:crypto`.
- **tsdown emits a shared chunk** for the leaf, imported by `gate.mjs`, `mandate.mjs` and
  `verify.mjs` alike. The subpaths still do not import each other; they import the chunk.

## Alternatives considered

1. **Sort the `args` tree by hand inside `receiptBody` and keep `JSON.stringify`.** Rejected: that
   is a second canonicalization, which is the thing `AGENTS.md` forbids, and every rule
   `canonicalJSON` already encodes (holes, boxed primitives, `toJSON` once with its key) would have
   to be re-derived and kept in step.
2. **Have gate import `canonicalJSON` from `src/mandate/signer.ts`.** Rejected: it couples the gate
   bundle to mandate, which the subpath design exists to prevent.
3. **Keep the limit and tell auditors to byte-preserve the file.** Rejected: a verifier that
   reports tampering on honest evidence because of whitespace or key order is reporting the wrong
   thing, and the artifact is meant to be handed through tooling nobody here controls.
