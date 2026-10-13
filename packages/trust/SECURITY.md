# Security — `sweetrust`

## Reporting a vulnerability

Open a [security advisory](https://github.com/sweeai/sweetrust/security/advisories/new) rather than
a public issue. We will confirm receipt and tell you what we found, including when we disagree.

---

## Honest limits

This section exists because a security library that only lists its guarantees is telling you half
of what you need. Everything below is a real boundary of what this package can do, stated before
you find it yourself.

### The TypeScript revocation and the on-chain revocation are TWO kill switches, and only one stops money

`revokeMandate()` writes to the audit log. It gates **runtime capability invocations** — an agent
that asks this rail for authority will be refused.

It makes **zero chain calls, by design.** So if funds are custodied in an on-chain `SpendCage`, an
operator who calls `revokeMandate()` believing the agent is dead **has done nothing to stop a
spend.** The delegate key can keep draining an existing cage up to `max_total` until an on-chain
`mandate::revoke` transaction lands.

**The fund kill switch is the on-chain revoke, full stop.** Any "Revoke" control in your product
that is supposed to stop money must emit that transaction. Wire a single button to the TypeScript
half and you have built a kill switch that reports success and stops nothing.

🔑 The layered design is sound — each layer is self-sufficient for its own domain, and the cage
needs no TypeScript input to be safe. The hazard is one word naming two switches.

### In-process TypeScript is dev-time and observe/warn-tier authority

Code that can import this module and lie about an authority name can mint verified values. That is
a property of running in the same process, not a defect we intend to fix here. Unforgeable
enforcement belongs to the on-chain layer.

Use the tiers to find and shape your trust boundaries, and to make refusals auditable. Do not use
them as the only thing standing between an attacker and custody.

### A mandate scope is a capability: whoever holds the object holds the authority

Authority in `sweetrust/mandate` is **possession of a scope object this module issued**. A
copy, a JSON round trip or a hand-written literal is refused, however faithfully it copies the
fields. Two things follow for a host:

- **Hand each agent its own scope and nothing above it.** Passing an agent its parent's scope
  object hands it the parent's authority. A child's `parentScope` is a detached view and carries
  none, so the child itself is safe to hand over.
- **A scope does not survive a process boundary.** A rehydrated scope cannot invoke. Authority
  that must cross processes belongs to the on-chain layer. See `docs/adr/0001-authority-is-possession-of-an-issued-scope.md`.

### Tail truncation is catchable only by an anchor

A signed chain that has had its most recent records removed is a **valid shorter chain.** Nothing
inside the artifact distinguishes it from an honest log that simply ended. Only an on-chain
`"anchor"` seal detects it — a per-decision `"receipt"` memo proves that record through its own
sequence number, never the whole chain.

A compromised host can sign lies going forward. It cannot rewrite the past behind an anchor, and it
cannot forge under a key it does not hold.

**The same holds for a JSONL audit store on disk, and there it can re-arm authority.** Delete the
last line of a signed store and the file still verifies, because it is a valid shorter chain. If
that line was a revoke, the mandate is live again: `isRevoked` returns `false`. Protect the store
file the way you protect the key, or anchor its head somewhere the host cannot write.

### One writer per store file

The JSONL stores do not lock across processes. Two processes appending to one file can both link
to the same predecessor. That forks the chain, and every later read then fails closed as corrupt.
Give each store file exactly one writing process.

The signed store also re-verifies the whole file on every read, and one mandate operation is
several reads: `useCapability` over a delegation chain of depth d does an `isRevoked` and a `query`
per ancestor, so it costs O(d·n) signature verifications per invocation, not O(n). There is no
cache. Measure before putting this store on a hot path with a long log.

### A signer that throws after `execute()` leaves no receipt

Receipt arguments are rendered before the action runs, so nothing the caller passes can stop the
receipt from being written. The signer is different. If `SignedReceiptLog`'s signer throws after
`execute()` has run (an HSM or keychain outage, say), the action has happened and the chain says
nothing. This is a known gap, not a design choice. The planned fix writes an intent record before
the action and the outcome after it. Until then, treat a signer error as "an action may have run
unrecorded", not as a refusal.

### A declassifier's refusal leaves no receipt

`allowlisted`, `corroborate` and `humanConfirm` return `{ ok: false, reason }` when they refuse an
ascent, and they take no log. So a refused ascent records nothing, and an injected payee stopped
at `allowlisted` leaves no evidence that it was ever tried. A successful ascent IS recorded, as an
event in the value's provenance chain. Sink decisions, allowed and refused, all land on the
receipt log.

`Receipt["decision"]` already reserves `"declassify-refused"` so that emitting it later is not a
breaking change. Nothing produces it yet. Until something does, log a declassifier's refusal
yourself if you need the evidence.

### The prompt-injection pre-check is a pattern catalog, not a defense

`constitutionalPreCheck` catches known instruction-override patterns in English, the listed
Latin-lookalike confusables, a cluster of invisible characters, and (since the 2026-10-13 mandate
audit) a keyword split by a single invisible or format character, which used to pass. It runs on
rationales and on capability identifiers before either is persisted. It does not catch paraphrase
("never mind what was said") or other languages, by design. Those need defenses in your own harness, such as
framing untrusted text clearly and constraining what the model may output. Do not rely on forcing
a tool call for that: some current models reject forced `tool_choice`.

### `asserted` is not reachable

Four tiers are documented; three are produced. No factory or declassifier currently emits
`asserted`. Treat the ladder as `untrusted → corroborated → verified` until that changes.

---

## Adversarial history

This package is audited by adversarial passes that attempt real exploits against the **built**
artifact rather than the source, and the findings are recorded rather than quietly fixed:

- **2026-07-25** — five fail-open defects found and closed, including a chain that verified
  vacuously on empty input and a verifier that threw instead of returning a verdict.
- **2026-08-31** — two unconditional fail-opens found in `enforce` mode, **neither covered by the
  169 tests then passing.** `allowlisted()` compared one object and promoted a different one, so a
  value that merely *serialized* like an allowlisted record was acted on while the signed chain
  recorded the legitimate one. And a membership test using `in` walked `Object.prototype`, so an
  argument named `constructor` or `__proto__` was invisible to enforcement and to the receipt.
  Both closed, with regressions proven to fail against the pre-fix code before being accepted.

🔑 **The lesson we keep relearning, offered because it will apply to your code too:** a check and
the decision it authorizes must name the same binding. If you compare A and act on B, you have not
written a weaker check — you have written no check, and the evidence trail will faithfully record
the value you did not use.
