# SweeTrust

**Trust rails for AI agents: issue authority, enforce it, prove what happened.**

[![npm](https://img.shields.io/npm/v/sweetrust)](https://www.npmjs.com/package/sweetrust)
[![license](https://img.shields.io/npm/l/sweetrust)](LICENSE)

SweeTrust is a small TypeScript library for agents whose tools spend, send or delete. It grants bounded authority, refuses what falls outside it, and can sign a record a stranger can check. It has zero runtime dependencies.

## The problem

An agent reads an invoice email and pulls out the account number to pay. If an attacker wrote that email, the account number belongs to the attacker, and it reaches your payment function as an ordinary `string`. Types check a value's shape, and nothing checks where it came from.

SweeTrust makes three questions answerable at runtime, by the code about to act:

| Question | Module |
|---|---|
| Where did this value come from, and what checks did it pass? | `sweetrust/gate` |
| Who authorized this action, and were they allowed to? | `sweetrust/mandate` |
| Can someone outside the system check all of this afterward? | `sweetrust/verify` for receipts, `verifyAuditChain` from `sweetrust/mandate` for mandates |

## See it refuse

```bash
npm i sweetrust
```

```ts
import { Sourced, allowlisted, makeSink } from "sweetrust/gate"
import {
  SignedReceiptLog, makeEd25519ReceiptSigner, generateSigningKeypair,
  publicKeyHexFromPem, verifySignedChain, parseJSONL,
} from "sweetrust/verify"

const keys = generateSigningKeypair()
const log = new SignedReceiptLog(makeEd25519ReceiptSigner(keys))

// A sink wraps a risky action. `pay` only runs on a payee whose origin has been verified.
const pay = makeSink<{ to: Sourced<string> }, string>({
  name: "pay",
  requires: { to: "verified" },
  mode: "enforce",
  log,
  execute: ({ to }) => `paid ${to.value}`,
})

// A model read this account number out of an inbound email, so it starts untrusted.
const email = Sourced.fromChannel("Please pay ACCT-666", "email-inbound")
const account = Sourced.fromLLM("ACCT-666", "ExtractInvoice", [email])

const attempt = pay({ to: account })
console.log(attempt.ok ? attempt.result : attempt.refusal)
// ⚠ pay refused: to requires verified but is UNTRUSTED (origin: llm:ExtractInvoice)

// A declassifier is the only way to raise an existing value's trust. This one checks a registry you control.
const vendors = new Map([["acme", Sourced.fromAuthority("ACCT-123", "vendor-db")]])
const payee = allowlisted(account, vendors, "acme", "vendor-db")
console.log(payee.ok) // false: the email's account is not the one on file

// A value the registry minted goes through.
const paid = pay({ to: vendors.get("acme")! })
console.log(paid.ok && paid.result) // paid ACCT-123

// The refusal and the payment are both on a signed chain.
// Anyone with the log and the public key can check it.
const report = verifySignedChain(parseJSONL(log.exportJSONL()), {
  trustedSignerPublicKeyHex: publicKeyHexFromPem(keys.publicKeyPem),
})
console.log(report.valid) // true. Editing a kept record turns it false.
```

Save it as `demo.ts` and run `node demo.ts` on Node 22.18 or later.

## What's inside

**`sweetrust/gate` enforces.** Every value carries a trust tier (`untrusted`, `corroborated`, `verified`) and its full provenance. Taint is not automatic: `Sourced.fromLLM` is always `untrusted`, and anything computed from a `.value` is plain until you wrap it. Three functions called declassifiers are the only way to raise an existing value's trust: `allowlisted` checks a registry you control, `corroborate` requires independent sources to agree, and `humanConfirm` asks a person. Trusted host code mints verified values with `Sourced.fromAuthority`.

Sinks wrap the actions that matter, and in `enforce` mode they refuse anything that falls short. You can adopt them gradually through `observe` and `warn`. An optional `judgment` provider you supply can also block an action that passes the tiers but looks wrong.

**`sweetrust/mandate` delegates.** A mandate is a recorded grant of authority, like a power of attorney for software. Authority flows from organization to project to agent, and each tier can only hold a subset of its parent's capabilities. The compiler rejects an out-of-tier grant, and the runtime refuses it again for plain JavaScript callers.

With `makeJsonlSignedAuditLive`, every grant, use and revoke lands on an Ed25519-signed, hash-chained log.

Caps and revocation work like this:

```ts
import { createTrust, defineCapability, grantorId, makeInMemoryAuditLive, MandateFailure } from "sweetrust/mandate"

const Buy = defineCapability("amazon.buy")
const owner = grantorId("owner")
const trust = createTrust({ store: makeInMemoryAuditLive() }) // Unsigned, for this demo.

const org = trust.issueOrgMandate({ grantor: owner, capabilities: [Buy] as const, rationale: "Household" })
const errands = trust.issueProjectMandate({ grantor: owner, grantorScope: org, capabilities: [Buy] as const, rationale: "Errands" })
const shopper = trust.issueAgentMandate({
  grantor: owner, grantorScope: errands, capabilities: [Buy] as const, rationale: "Shopping agent",
  limits: { "amazon.buy": { amount: 30, unit: "USD", windowMs: 86_400_000 } }, // $30 a day
})

// Your host code calls this with the real order total, never the agent's own figure.
// Use integer cents for real money.
const buy = (amount: number) => {
  try {
    trust.useCapability({ mandate: shopper, capability: Buy, amount })
    return "allowed"
  } catch (e) {
    return MandateFailure.is(e) ? e._tag : "threw"
  }
}

console.log(buy(12), buy(15), buy(5)) // allowed allowed MandateLimitExceeded

// Revoke the root, and everything delegated under it stops.
trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "Trip is over" })
console.log(buy(1)) // AncestorMandateRevoked
```

**`sweetrust/verify` proves.** Every sink decision, allowed or refused, can be signed as it happens and exported as JSONL for an auditor. `verifySignedChain` re-checks each signature and hash link using only public material, and it can also compare the log against an anchor, which is a hash of the log that you posted on a blockchain.

A sink does not consult a mandate. To use both on one tool, call `trust.useCapability` inside `execute`, where a refusal throws and the sink records it as `errored`.

## What it does not do

- **It runs inside your process.** Code that shares the process can get around it, so use it to define and record your trust boundaries, and do not make it the only thing protecting custody of funds.
- **Revoking here does not stop money a chain already holds.** `revokeMandate` writes to this log. A limit that must hold when the host is compromised belongs to the payment rail, such as Sui's native `sui::allowance` or a card issuer's limit.
- **A local log cannot prove it is complete.** Cutting the newest records leaves a valid shorter chain. For receipt chains, an anchor you posted yourself catches a cut back past that anchor. Nothing in the package detects a cut in a mandate log, so protect that store like a key.
- **One process writes each store.** The JSONL stores do not lock across processes. On the signed store, a second writer can fork the chain, and every later read then refuses.
- **Authority is possession.** A scope is the object that carries a mandate's authority. Whoever holds a scope holds its authority. Whoever holds the object `createTrust` returns, or its store, holds authority over every mandate in that store, so hand an agent only its own scope.
- **You bring the judgment.** SweeTrust ships no model, so you plug in your own as the `judgment` provider.
- **It is pre-1.0.** A minor version may break an API.

[`SECURITY.md`](packages/trust/SECURITY.md) has the full list and the history of adversarial reviews.

## Documentation

| Document | Read it for |
|---|---|
| [Package reference](packages/trust/README.md) | The full API, with runnable examples |
| [Architecture](packages/trust/ARCHITECTURE.md) | How the three modules fit together |
| [Decision records](packages/trust/docs/adr) | Why the design is what it is |
| [Changelog](packages/trust/CHANGELOG.md) | What changed, and how to upgrade |

## Development

```bash
pnpm install
pnpm build && pnpm test && pnpm typecheck
```

The published package runs on Node 20.19 or later. The repository's demos and `pnpm typecheck` run TypeScript directly, so they need Node 22.18 or later. Before contributing, read [`packages/trust/AGENTS.md`](packages/trust/AGENTS.md).

## Security

Please report vulnerabilities through a [private security advisory](https://github.com/sweeai/sweetrust/security/advisories/new), never a public issue.

## License

[Apache-2.0](LICENSE).
