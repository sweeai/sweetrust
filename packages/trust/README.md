# sweetrust

**Trust rails for AI agents.** Issue authority, enforce it, prove what happened.

```
SweeMandate signs  ──▶  SweeGate enforces  ──▶  SweeVerify proves
   the authority          the boundary            the evidence
```

```bash
npm i sweetrust
```

Zero runtime dependencies. Node builtins only (`node:crypto`, `node:fs`, `node:path`). Nothing else enters your tree.

---

## The problem

Types constrain **shape**. Nothing constrains **pedigree**.

A payee account number extracted from an email by an LLM has the type `string`. So does one you looked up in your own vendor registry. Your type system cannot tell them apart, your payment function cannot tell them apart, and the attacker who planted the email is counting on exactly that.

This package makes three questions answerable at runtime, by the code that actually needs to know:

| Question | Answered by |
|---|---|
| **Who authorized this, and were they allowed to?** | `sweetrust/mandate` |
| **Where did this value come from, and what did it survive?** | `sweetrust/gate` |
| **Can a stranger check any of this after the fact?** | `sweetrust/verify` |

---

## Install one thing, import what you need

```ts
import { issueOrgMandate }  from "sweetrust/mandate"   // authority
import { Sourced, makeSink } from "sweetrust/gate"     // enforcement
import { verifySignedChain } from "sweetrust/verify"   // evidence

import * as trust           from "sweetrust"            // or the whole rail
```

Each subpath is a separate bundle entry. Importing `sweetrust/gate` does **not** pull mandate or verify into your build. Decoupling was sacred before these were one package and it stayed that way through the merge — what changed is that you install one thing instead of assembling three.

---

## `sweetrust/gate` — enforcement

Values carry their provenance, and privileged operations can demand it.

- **`Sourced<T>`** — a value tagged with its trust tier plus full provenance: origin, ancestry, audit chain, optional confidence. The tag rides from the extraction boundary all the way to the sink.
- **The tier lattice** — `untrusted → asserted → corroborated → verified`. Combining taints **down**: mixing anything with untrusted data yields untrusted data. LLM output is born untrusted no matter how good the model. *Inference is not evidence.*
- **Three declassifiers** — the only ways a value can rise, and the constructor is module-private — at runtime too, not only in the types — so there is no fourth. A successful ascent is recorded in the value's provenance; a refusal is not yet recorded anywhere (see `SECURITY.md`): `allowlisted` (matches a registry you control → verified), `corroborate` (independent sources agree → corroborated, never verified), `humanConfirm` (asks a person, with the provenance rendered into the question so the answer is informed rather than reflexive).
- **Sinks that declare their appetite** — `makeSink` refuses under-tier arguments and fails closed, naming the tier gap in the refusal. Adoption ladder: `observe → warn → enforce`, so you can install it into a running system without breaking it on day one; a mode outside the ladder is a `TypeError` at construction, never a guess. `execute()` receives a snapshot of the declared arguments, read once when they were checked.
- **The judgment seam** — a pluggable calibrated scorer that runs *after* the tiers pass, to catch the action that is in-bounds but still wrong. It is allowed to say "unsure" and defer to a human. It never confidently blocks.
- **`ReceiptLog`** — every decision, allow *and* refuse, lands on a hash-chained tamper-evident log.

<!-- readme-check: prelude
import type { Sourced as S } from "sweetrust/gate"
declare const raw: string
declare const extracted: { account: string }
declare const PAYEE_REGISTRY: ReadonlyMap<string, S<string>>
declare const vendor: string
declare const amount: S<number>
declare const settle: (to: string, amount: number) => string
-->
```ts
import { Sourced, allowlisted, makeSink, ReceiptLog } from "sweetrust/gate"

const log = new ReceiptLog()
const pay = makeSink<{ to: Sourced<string>; amount: Sourced<number> }, string>({
  name: "pay",
  requires: { to: "verified", amount: "corroborated" },
  mode: "enforce",
  log,
  execute: ({ to, amount }) => settle(to.value, amount.value),
})

const email   = Sourced.fromChannel(raw, "email-inbound")
const account = Sourced.fromLLM(extracted.account, "ExtractInvoice", [email]) // untrusted, always
const payee   = allowlisted(account, PAYEE_REGISTRY, vendor, "payee-registry") // → verified | refusal

// A declassifier can REFUSE, and the refusal is the interesting branch — it is
// where an injected payee stops. `allowlisted` returns a result, never a bare
// value, so there is no way to spend the output without having looked.
if (!payee.ok) throw new Error(payee.reason)

pay({ to: payee.value, amount })
// Refused? The refusal names the tier gap AND renders the provenance —
// and the refusal itself is on the receipt chain.
```

Implements the trust-types specification §4–§5.

---

## `sweetrust/mandate` — authority

Power of attorney for machines: delegated in bounded tiers, every act on a signed record.

- **Multi-tier hierarchy** — organization → project → agent. Each tier's capabilities are a structurally enforced subset of its parent's, checked by the **compiler** at the call site. Out-of-tier grants do not typecheck.
- **Refused twice** — the same grant is refused again at runtime, so the gate holds for JavaScript callers with no compiler in the loop.
- **Ed25519-signed, hash-chained audit log** — the signature covers the whole envelope (domain + payload + `previousHash` + `signedAt`), so tampering, interior record removal, reordering, and retiming are all detectable *even against an adversary who recomputes the public hash links*. Relinking breaks a signature they cannot forge.
- **Forged-scope rejection** — `useCapability` requires a matching grant in the audit log and re-checks the subset claim. Deserialized payloads and `as any` escapes do not get through.
- **Ancestor-revocation cascade** — revoking an org-tier mandate disables every descendant. The kill switch is structural, not advisory.
- **Constitutional pre-check** — authored strings (rationales, capability identifiers) are screened for prompt-injection patterns *before* persistence.

<!-- readme-check: run - expect true -->
```ts
import {
  defineCapability, issueOrgMandate, issueProjectMandate,
  makeInMemorySignedAuditLive, makeEd25519SignerLive, verifyAuditChain,
  publicKeyHexFromPem,
  type GrantorId,
} from "sweetrust/mandate"
import { generateKeyPairSync } from "node:crypto"

const CapRead  = defineCapability("MyApp/CapRead")
const CapWrite = defineCapability("MyApp/CapWrite")

const { publicKey, privateKey } = generateKeyPairSync("ed25519")
const signer = makeEd25519SignerLive({
  privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
  publicKeyPem:  publicKey.export({ format: "pem", type: "spki" }).toString(),
})
const { mandateAudit, signedAudit } = makeInMemorySignedAuditLive(signer)

const org = issueOrgMandate({
  grantor: "ARTHUR" as GrantorId,
  capabilities: [CapRead, CapWrite] as const,
  rationale: "Workspace charter",
}, mandateAudit)

const project = issueProjectMandate({
  grantor: "PROJECT_LEAD" as GrantorId,
  grantorScope: org,
  capabilities: [CapRead] as const,   // a subset — the type system enforces it
  rationale: "Project Cookie: read-only",
}, mandateAudit)

// `trustedSignerPublicKeyHex` is REQUIRED, and that is the point: verifying a
// record against the key it CARRIES proves internal consistency, not authorship.
// An attacker holding the log can re-sign every event under their own key, set
// each record's `signerPublicKeyHex` to it, and rebuild the chain — locally
// consistent, and valid only until you pin the key you actually trust.
console.log(verifyAuditChain(signedAudit.listAllSigned(), signer, {
  trustedSignerPublicKeyHex: publicKeyHexFromPem(
    publicKey.export({ format: "pem", type: "spki" }).toString(),
  ),
}).valid) // true; tampering flips it
```

**Honest boundary:** this is the *off-chain* authority layer. Its subset gates are compile-time plus audit-log-backed, and a fully compromised host could bypass them. Unforgeable enforcement is the Move `SpendCage`'s job. The two compose; neither claims the other's property.

---

## `sweetrust/verify` — evidence

`gate` ends where the receipt is hashed. This is the next wall.

1. **Sign** — every receipt is Ed25519-signed at append time *through* mandate's signer. One canonicalization across the whole rail, not two that drift. `SignedReceiptLog` drops straight into `makeSink`'s `log:`.
2. **Export** — the chain serializes to JSONL. That file is what you hand an auditor, an insurer, or a court.
3. **Verify** — `verifySignedChain` re-checks every signature, every hash link, and optionally an on-chain anchor, holding **only public material**. The signing machine can be compromised afterwards and the evidence still stands or falls on its own.

<!-- readme-check: prelude
import type { Sourced as S } from "sweetrust/gate"
declare const execute: (args: { to: S<string> }) => string
declare const file: string
declare const publishedKey: string
declare const memoFromChain: string
-->
```ts
import { SignedReceiptLog, makeEd25519ReceiptSigner, generateSigningKeypair,
         verifySignedChain, parseJSONL, parseAnchorMemo } from "sweetrust/verify"
import { makeSink } from "sweetrust/gate"

const log = new SignedReceiptLog(makeEd25519ReceiptSigner(generateSigningKeypair()))
const pay = makeSink({ name: "pay", requires: { to: "verified" }, mode: "enforce", log, execute })

// …session runs. Publish log.exportJSONL() + the PUBLIC key, and seal log.head()
// in an on-chain memo. A stranger verifies:
const report = verifySignedChain(parseJSONL(file), {
  trustedSignerPublicKeyHex: publishedKey,
  anchor: parseAnchorMemo(memoFromChain) ?? undefined,
})
```

### Honest limits — stated, not buried

- **Tail truncation is invisible to a local chain.** Deleting the last K receipts leaves a perfectly valid shorter chain. Only the on-chain anchor catches it. That is *why* the anchor exists, and the tests prove it rather than assert it.
- **A compromised host can sign lies going forward.** What it cannot do is rewrite the past behind an anchor, or forge records under a key it does not hold.
- **Key pinning is structural.** `trustedSignerPublicKeyHex` is required, not optional. Verifying a record against the key it carries proves internal consistency, not authorship.

---

## Proof it runs

```bash
pnpm -C packages/trust test        # 177 tests
pnpm -C packages/trust typecheck
node packages/trust/src/mandate/demo.ts             # grant → invoke → revoke → refuse
node packages/trust/src/mandate/multi-tier-demo.ts  # tamper + chain-break detection, live
```

Both demos are in this repository, not in the published tarball — clone to run them.

The multi-tier demo is the centerpiece: it builds an org → project → agent chain, signs every record, then **rewrites a rationale after signing** and reports the exact corrupted index — followed by removing a middle record and catching the broken hash link.

Beyond the suite, the rail has a live testnet weld: a legitimate invoice settles on-chain, a poisoned one never forms a transaction, a bypassed firewall is still caged, and the receipts verify as third-party evidence — including the refusal that never touched the chain.

---

## What's free, and what isn't

**Everything in this package is free, forever.** That includes the Move modules and on-chain enforcement — not just the TypeScript.

The line is drawn by **who is buying**, never by which language a feature is written in:

> **Free — what one person can run for themselves.**
> **Paid — what an organization needs someone else to operate or vouch for.**

| Free forever | Paid |
|---|---|
| Compile-time provenance checking | Hosted anchoring and verification, with uptime |
| Branded capability types | Org policy administration — delegation hierarchies, multi-tenant issuance, revocation at scale |
| Runtime gate and boundary enforcement | Compliance artifacts — audit export, retention attestation, the bundle a security review asks for |
| **On-chain enforcement and anchoring** | Managed deployment under our `AdminCap`, with a written custody policy |
| Local audit log and self-generated receipts | Support and SLA |

The test for anything new: **could one person self-serve this?** If yes, it is free.

Two reasons the line sits here rather than at the language boundary. Published Move bytecode on a permissionless chain is public and callable by anyone with gas — it was never a sellable artifact, so charging for it would only have taxed adoption. And a free tier without enforcement is an advisory guardrail, which is the exact failure this project exists to eliminate. **Nothing free will ever depend on anything paid.**

**The free column is real today** — six Move modules on testnet, anchoring and chain verification in `sweetrust/verify`, 177 passing tests, a live testnet weld. Use all of it.

**The paid column is not something you can buy yet.** Note what it actually describes: *operating* and *vouching for* what the free column already does. The capabilities exist; the service around them does not. There is no server running, no uptime commitment, and nobody to call. It is listed here so the boundary is legible before there is anything to sell, rather than negotiated later, feature by feature.

---

## Status

**v0.3.0**, unpublished. Formed 2026-07-30 by merging `@sweetrust/mandate`, `@sweetrust/gate` and `@sweetrust/verify` into one package with subpath exports. All three were unpublished, so nothing broke and no migration is owed to anyone.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE). Part of the SWEE open-core substrate.
