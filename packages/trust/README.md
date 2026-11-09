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
import { createTrust }      from "sweetrust/mandate"   // authority
import { Sourced, makeSink } from "sweetrust/gate"     // enforcement
import { verifySignedChain } from "sweetrust/verify"   // evidence

import * as trust           from "sweetrust"            // or the whole rail
```

Each subpath is a separate bundle entry. Importing `sweetrust/gate` does **not** pull mandate or verify into your build. Decoupling was sacred before these were one package and it stayed that way through the merge — what changed is that you install one thing instead of assembling three.

---

## `sweetrust/gate` — enforcement

Values carry their provenance, and privileged operations can demand it.

- **`Sourced<T>`** — a value tagged with its trust tier plus full provenance: origin, ancestry, audit chain, optional confidence. The tag rides from the extraction boundary all the way to the sink.
- **The tier lattice** — `untrusted → corroborated → verified`. `minTier` gives the lowest tier of its inputs, and a value you compute from a `.value` is plain until you wrap it. LLM output is born untrusted no matter how good the model. *Inference is not evidence.*
- **Three declassifiers** — the only ways a value can rise, and the constructor is module-private — at runtime too, not only in the types — so there is no fourth. A successful ascent is recorded in the value's provenance; a refusal is not yet recorded anywhere (see `SECURITY.md`): `allowlisted` (matches a registry you control → verified), `corroborate` (independent sources agree → corroborated, never verified), `humanConfirm` (asks a person, with the provenance rendered into the question so the answer is informed rather than reflexive).
- **Sinks that declare their appetite** — `makeSink` refuses under-tier arguments and fails closed, naming the tier gap in the refusal. Adoption ladder: `observe → warn → enforce`, so you can install it into a running system without breaking it on day one; a mode outside the ladder is a `TypeError` at construction, never a guess. `execute()` receives a snapshot of the declared arguments, read once when they were checked.
- **The judgment seam** — a pluggable calibrated scorer that runs *after* the tiers pass, to catch the action that is in-bounds but still wrong. In `enforce`, only a `match` at or above the sink's `floor` runs and only a `mismatch` at or above it blocks. Everything else is **held** for a human: `unsure`, either answer below the floor, and a provider that times out, throws or cannot score. Nothing runs on doubt. In `observe` and `warn` the action runs, flagged, with the verdict on the receipt. A block stands for an hour by default and a hold stands until it is resolved or expires, so a retry gets the same answer without asking the judge again. In `enforce` an identical action runs once unless the host names a new `{ idempotencyKey }`, which must never come from the agent (ADR 0010).
- **`ReceiptLog`** — every **sink** decision, allow *and* refuse, lands on a hash-chained tamper-evident log. A declassifier's refusal does not (see `SECURITY.md`).

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

await pay({ to: payee.value, amount })
// Refused? The refusal names the tier gap AND renders the provenance —
// and the refusal itself is on the receipt chain.
```

When the registry has no answer, ask a person. `humanConfirm` is async, so the person can answer later, over a phone call, a voice channel or a chat approval. It copies the value and builds the question at the call, provenance first and the value cut to 256 characters, so editing your object while the person decides changes nothing that ascends. Only an answer of exactly `true` confirms. A renderer that throws or rejects is a refusal, never an exception, and a forgotten `await` leaves you holding a Promise whose `.ok` is never `true`.

<!-- readme-check: prelude
import type { Sourced as S } from "sweetrust/gate"
declare const account: S<string>
declare const askOverPhone: (question: string) => Promise<boolean>
-->
```ts
import { humanConfirm } from "sweetrust/gate"

const confirmed = await humanConfirm(account, (question) => askOverPhone(question))
if (!confirmed.ok) throw new Error(confirmed.reason) // declined, hung up or timed out
// confirmed.value is a copy pinned at the call: what the person was asked about,
// now verified, with the confirmation on its chain
```

The wait is yours to bound. A renderer that never settles never confirms; reject it from your own timeout and the silence becomes a refusal.

---

## `sweetrust/mandate` — authority

Power of attorney for machines: delegated in bounded tiers, every act on a signed record.

- **Multi-tier hierarchy** — organization → project → agent. Each tier's capabilities are a structurally enforced subset of its parent's, checked by the **compiler** at the call site. Out-of-tier grants do not typecheck.
- **Refused twice** — the same grant is refused again at runtime, so the gate holds for JavaScript callers with no compiler in the loop.
- **Ed25519-signed, hash-chained audit log** — the signature covers the whole envelope (domain + payload + `previousHash` + `signedAt`), so tampering, interior record removal, reordering, and retiming are all detectable *even against an adversary who recomputes the public hash links*. Relinking breaks a signature they cannot forge.
- **One store, bound once** — `createTrust({ store })` is the only door to issue, use and revoke. The audit store is never a per-call argument, so a caller cannot judge a scope against a log it wrote itself; a scope minted against another store is refused (`MandateScopeForeign`).
- **Forged-scope rejection** — `useCapability` requires a matching grant in the audit log and re-checks the subset claim. Deserialized payloads and `as any` escapes do not get through.
- **Ancestor-revocation cascade** — revoking an org-tier mandate disables every descendant, and it cannot be argued away with a different log. The kill switch is structural, not advisory.
- **Capability limits** — a grant can cap a capability by `amount`, by `count`, or both, optionally over a rolling `windowMs`. The cap is recorded in the grant event, and the spend is summed from the same audit log at every use, so no counter lives next to the agent and a restart alone refunds nothing (a log whose tail was cut does: `SECURITY.md`). Every key is resolved before the log is read, so a caller's getter cannot spend between the check and the record. A child may only tighten its grantor's limits (`LimitNotWithinGrantor`). A metered caller can name a hold with `holdId` and record the real cost later with `trust.settleCapability`, which lowers the counted amount, never the call count (ADR 0011).
- **Resume, never re-mint** — `trust.resume({ resumedBy, mandateId, capabilities })` picks an issued, unrevoked mandate back up from the log after a restart: the same id, so the same budget. A re-mint at boot would be a fresh id with a fresh budget.
- **Constitutional pre-check** — authored strings (rationales, capability identifiers) are screened for prompt-injection patterns *before* persistence.

This block is self-contained: paste it into a `.ts` file and run it with `node` on Node ≥ 22.18, which runs TypeScript directly (on the `engines` floor, Node 20.19, use any TypeScript runner; the library itself needs nothing newer). The README gate does exactly that against the built package, and fails unless it prints the three lines the comments name.

<!-- readme-check: run - expect CapabilityNotInGrantorScope AncestorMandateRevoked true -->
```ts
import {
  createTrust, defineCapability, MandateFailure,
  makeInMemorySignedAuditLive, makeEd25519SignerLive, verifyAuditChain,
  publicKeyHexFromPem,
  grantorId,
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

// The store is bound once. Every grant, invoke and revoke this client makes is
// recorded in it and judged by it; no call names a store again.
const trust = createTrust({ store: mandateAudit })

const ARTHUR = grantorId("ARTHUR")
const LEAD   = grantorId("PROJECT_LEAD")

const org = trust.issueOrgMandate({
  grantor: ARTHUR,
  capabilities: [CapRead, CapWrite] as const,
  rationale: "Workspace charter",
})

const project = trust.issueProjectMandate({
  grantor: ARTHUR,
  grantorScope: org,
  capabilities: [CapRead] as const,   // a subset — the type system enforces it
  rationale: "Project Cookie: read-only",
})

const agent = trust.issueAgentMandate({
  grantor: LEAD,
  grantorScope: project,
  capabilities: [CapRead] as const,
  rationale: "Reader bot",
})

// Hand the agent its scope, never the store or the client. Using a capability
// it holds returns, and records an invoke.
trust.useCapability({ mandate: agent, capability: CapRead })

// Refused twice. The compiler rejects a capability outside the grant, and a
// plain-JavaScript caller with no compiler is refused at runtime.
try {
  // @ts-expect-error CapWrite is not in the agent's grant, so this does not compile
  trust.useCapability({ mandate: agent, capability: CapWrite })
} catch (e) {
  if (MandateFailure.is(e)) console.log(e._tag) // CapabilityNotInGrantorScope
}

// The kill switch. Revoke the org root and every descendant is refused.
trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "Charter suspended" })
try {
  trust.useCapability({ mandate: agent, capability: CapRead })
} catch (e) {
  if (MandateFailure.is(e)) console.log(e._tag) // AncestorMandateRevoked
}

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

### Limits: "under $30, I just trust you"

A limit turns that sentence into a grant. The agent can spend up to $30 a day without asking, and the kernel refuses the purchase that would cross the line. The cap goes on the **agent-tier scope you hand the agent**: a cap binds the scope it is written on, and a holder that can still delegate could mint children with caps of their own.

<!-- readme-check: run - expect allowed allowed MandateLimitExceeded MandateAmountRequired -->
```ts
import { createTrust, defineCapability, grantorId, makeInMemoryAuditLive, MandateFailure } from "sweetrust/mandate"

const Buy = defineCapability("amazon.buy")
const trust = createTrust({ store: makeInMemoryAuditLive() })

const DANNY = grantorId("DANNY")
const org = trust.issueOrgMandate({ grantor: DANNY, capabilities: [Buy] as const, rationale: "Household" })
const errands = trust.issueProjectMandate({ grantor: DANNY, grantorScope: org, capabilities: [Buy] as const, rationale: "Errands" })
const shopper = trust.issueAgentMandate({
  grantor: DANNY,
  grantorScope: errands,
  capabilities: [Buy] as const,
  rationale: "Shopping agent",
  limits: { "amazon.buy": { amount: 30, unit: "USD", windowMs: 86_400_000 } },
})

// The HOST calls this with the real order total, never the agent's own figure.
const buy = (amount?: number): string => {
  try {
    trust.useCapability({ mandate: shopper, capability: Buy, amount })
    return "allowed"
  } catch (e) {
    return MandateFailure.is(e) ? e._tag : "threw"
  }
}

console.log(buy(12), buy(15), buy(5), buy())
// allowed · allowed (27 of 30) · MandateLimitExceeded · MandateAmountRequired
```

The last call is refused because a capped capability will not count a spend it was not told. An amount that is not a finite, non-negative number is refused too (`MandateAmountInvalid`). The kernel records `unit` and compares it at delegation, but never converts it, so "USD", "SUI" and "emails" are all labels.

A child may only tighten. Its `amount` and `count` may not be larger, its `unit` must match, and on windows, no window means the life of the mandate, which is the tightest of all. So a child of a lifetime cap must be lifetime too, and a child of a windowed cap may have no window or a window at least as long; a shorter window is looser, because spend falls out of it sooner.

**Honest limits of a cap**, stated in ADR 0005:

- **A cap binds a leaf.** Spend counts against the capped scope's own budget, and a parent's cap is not yet a shared budget across its children: two agents capped at $20 under a project capped at $30 can spend $40 between them. Cap the agent-tier scope you hand each agent, to the share you mean it to have.
- **`amount` is the host's declaration.** The kernel enforces the spend it is told, so the host, never the agent, must make the `useCapability` call with the true figure.
- **`actual` is the host's declaration too.** `settleCapability` counts the figure it is told, so the host, never the agent, makes that call. Whoever holds the client can settle.
- **Amounts are JavaScript numbers.** The kernel accepts any finite, non-negative number and sums them as floats, so for money use integers in minor units (cents): a cap of 0.3 refuses 0.1 + 0.2. Whole dollars, as above, are integers too.

### Resume after a restart

A scope is an object and does not survive the process. Store the mandate **id**, and in the next process resume it from the same log: the id is the same, so the budget carries on. The resume is recorded in the log, and it never counts toward a limit.

<!-- readme-check: run - expect MandateLimitExceeded allowed -->
```ts
import { createTrust, defineCapability, grantorId, makeJsonlAuditLive, MandateFailure } from "sweetrust/mandate"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const Buy = defineCapability("amazon.buy")
const file = join(mkdtempSync(join(tmpdir(), "sweetrust-")), "audit.jsonl")
const DANNY = grantorId("DANNY")

// Process 1: issue the chain, spend $25 of the $30, keep only the id.
const first = createTrust({ store: makeJsonlAuditLive(file) })
const org = first.issueOrgMandate({ grantor: DANNY, capabilities: [Buy] as const, rationale: "Household" })
const errands = first.issueProjectMandate({ grantor: DANNY, grantorScope: org, capabilities: [Buy] as const, rationale: "Errands" })
const shopper = first.issueAgentMandate({
  grantor: DANNY, grantorScope: errands, capabilities: [Buy] as const, rationale: "Shopping agent",
  limits: { "amazon.buy": { amount: 30, unit: "USD", windowMs: 86_400_000 } },
})
first.useCapability({ mandate: shopper, capability: Buy, amount: 25 })
const savedId = shopper.id

// Process 2: a new store over the same file. Resume declares what you expect,
// and the log confirms it (ResumeMismatch if not).
const second = createTrust({ store: makeJsonlAuditLive(file) })
const resumed = second.resume({
  resumedBy: grantorId("sidecar"), // who resumed, recorded on the resume event
  mandateId: savedId,
  capabilities: [Buy] as const,
  tier: "agent",
})

const buy = (amount: number): string => {
  try {
    second.useCapability({ mandate: resumed, capability: Buy, amount })
    return "allowed"
  } catch (e) {
    return MandateFailure.is(e) ? e._tag : "threw"
  }
}

console.log(buy(10), buy(5)) // MandateLimitExceeded (25 + 10 > 30) · allowed (30 of 30)
```

Resume runs the same revocation walk a use runs, so a revoked mandate, or one under a revoked ancestor, is refused here too. It then re-checks every link of the chain (each child's capabilities within its parent's, each child's limits at least as tight), because a line appended to the log never passed the issuers' checks, and it refuses a cyclic chain as broken. `resumedBy` is the host's word: the kernel records it and never verifies it. Resuming twice gives two genuine objects over one recorded authority, and revoking the id revokes both. Only the id crosses the process boundary; no scope is persisted.

**Honest boundary:** this is in-process authority. Its subset gates are compile-time plus audit-log-backed, and a fully compromised host could bypass them. In-process TypeScript cannot be unforgeable. The same holds for limits: they are counted by this kernel from its own log, so they hold exactly as far as the process boundary does. A cap that must stop money even when the host is compromised belongs to the payment rail itself (on Sui, native `sui::allowance`; for a card, the issuer's limit). This package's `revokeMandate` writes only to this log.

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
pnpm -C packages/trust test        # the whole suite
pnpm -C packages/trust typecheck   # tsc, then the README and forgery gates against dist/
node packages/trust/src/mandate/demo.ts             # grant → invoke → revoke → refuse
node packages/trust/src/mandate/multi-tier-demo.ts  # tamper + chain-break detection, live
```

Both demos are in this repository, not in the published tarball — clone to run them. The demos and `pnpm typecheck` run TypeScript directly and need **Node ≥ 22.18**; the published `dist/` needs only the `engines` floor, Node ≥ 20.19.

The multi-tier demo is the centerpiece: it builds an org → project → agent chain, signs every record, then **rewrites a rationale after signing** and reports the exact corrupted index — followed by removing a middle record and catching the broken hash link.

---

## What's free, and what isn't

**Everything in this package is free, forever**, under Apache-2.0: the mandates, the gate, the receipt chains and their verification.

The line is drawn by **who is buying**, never by which feature it is:

> **Free — what one person can run for themselves.**
> **Paid — what an organization needs someone else to operate or vouch for.**

| Free forever | Paid |
|---|---|
| Compile-time provenance checking | Hosted anchoring and verification, with uptime |
| Branded capability types and tiered mandates | Org policy administration — delegation hierarchies, multi-tenant issuance, revocation at scale |
| Runtime gate and boundary enforcement | Compliance artifacts — audit export, retention attestation, the bundle a security review asks for |
| Signed audit logs, receipt chains, third-party verification and the anchor-memo convention | Support and SLA |

The test for anything new: **could one person self-serve this?** If yes, it is free.

A free tier without enforcement is an advisory guardrail, which is the exact failure this project exists to eliminate, so enforcement sits in the free column. **Nothing free will ever depend on anything paid.**

**The free column is real today** — everything in it is in this package and covered by its test suite. Use all of it.

**The paid column is not something you can buy yet.** Note what it actually describes: *operating* and *vouching for* what the free column already does. The capabilities exist; the service around them does not. There is no server running, no uptime commitment, and nobody to call. It is listed here so the boundary is legible before there is anything to sell, rather than negotiated later, feature by feature.

---

## Status

**This tree is v0.6.0, not yet on npm; v0.5.0 is the latest published.** 0.6.0 adds the intent layer and makes every sink call return a Promise. `CHANGELOG.md` § *[0.6.0]* has the migration. The package was formed 2026-07-30 by merging three unpublished packages (`@sweetrust/mandate`, `@sweetrust/gate`, `@sweetrust/verify`) into one with subpath exports, then hardened through the adversarial passes `SECURITY.md` lists. Before 0.4.0, npm held only a 0.0.1 name placeholder with no code. `CHANGELOG.md` ships in the tarball.

## Versioning

0.x: **a minor version may break.** Until 1.0 these may change in a minor, and are stated here rather than discovered: the `Receipt["decision"]` union, `VerifyFailure` and `VerifyAuditChainResult["reason"]`, the `MandateError` union, the receipt hash body and the signed preimage, the `MandateId` suffix width, and the `swee.*.v1` domain tags. Persisted JSONL is versioned by its `domain` tag. The full statement is at the head of `CHANGELOG.md`.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE). Part of the SWEE open-core substrate.
