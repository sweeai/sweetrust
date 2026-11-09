/**
 * reconcile: the chain's payments, joined against the gate log and the adapter
 * receipts by transaction digest (spec I8). The chain is the ground truth; a
 * record that cannot be read must come back as an orphan, never as clean.
 */
import { describe, expect, test } from "vitest"

import { paymentDigest, verdictDigest, type Receipt, type Verdict } from "../../src/gate/index.ts"
import { reconcile, type ReconcileChainSpend, type ReconcileSuiReceipt } from "../../src/verify/index.ts"

const network = "sui:testnet"
const asset = "0x2::sui::SUI"
const recipient = "0xabc"
const amount = "600"
const pd = paymentDigest({ network, asset, recipient, amount })

const verdictOf = (over: Partial<Verdict> = {}): Verdict => ({
  assessment: "match",
  confidence: 0.9,
  rationaleHash: "a".repeat(64),
  provider: "p",
  model: "m@1",
  actionDigest: "c".repeat(64),
  unkeyedActionDigest: "c".repeat(64),
  scored: true,
  paymentDigest: pd,
  grantHash: "b".repeat(64),
  purposeHash: "e".repeat(64),
  judgedAt: "2026-01-01T00:00:00.000Z",
  attestation: null,
  ...over,
})
const V = verdictOf()
const vd = verdictDigest(V)

const gateOf = (over: Record<string, unknown> = {}): Receipt =>
  ({ seq: 0, prevHash: "GENESIS", hash: "h", at: "t", sink: "pay", decision: "executed", args: {}, verdict: V, ...over }) as Receipt
const suiOf = (digest: string | null, over: Record<string, unknown> = {}): ReconcileSuiReceipt =>
  ({ schema: "sweetrust-sui/receipt@2", verb: "spend", verdict: "executed", network, asset, digest, amount, recipient, authorizedBy: { verdictDigest: vd, paymentDigest: pd }, ...over }) as ReconcileSuiReceipt
const chainOf = (digest: string, over: Record<string, unknown> = {}): ReconcileChainSpend =>
  ({ digest, status: "success", sender: "0xs", network, asset, recipient, amount, ...over }) as ReconcileChainSpend

type Args = Parameters<typeof reconcile>[0]
const run = (gate: unknown[], sui: unknown[], chain: unknown[]) => reconcile({ gate, sui, chain } as unknown as Args)
const pairs = (r: ReturnType<typeof reconcile>) => r.orphans.map((o) => [o.digest, o.reason])

describe("the four reasons", () => {
  test("a judged spend whose records all agree reports nothing", () => {
    expect(run([gateOf()], [suiOf("D1")], [chainOf("D1")])).toEqual({ ok: true, orphans: [] })
  })

  test("no-receipt: a chain spend with no receipt@2", () => {
    const r = run([gateOf()], [], [chainOf("D1")])
    expect(r.ok).toBe(false)
    expect(pairs(r)).toEqual([["D1", "no-receipt"]])
  })

  test("no-receipt: a receipt under another schema is not a receipt@2", () => {
    expect(pairs(run([gateOf()], [suiOf("D1", { schema: "sweetrust-sui/receipt@1" })], [chainOf("D1")]))).toEqual([["D1", "no-receipt"]])
  })

  test("no-receipt: an open or revoke receipt does not account for a spend", () => {
    expect(pairs(run([gateOf()], [suiOf("D1", { verb: "open" })], [chainOf("D1")]))).toEqual([["D1", "no-receipt"]])
  })

  test("no-verdict: no gate receipt at all", () => {
    expect(pairs(run([], [suiOf("D1")], [chainOf("D1")]))).toEqual([["D1", "no-verdict"]])
  })

  test("no-verdict: the receipt names no verdict", () => {
    expect(pairs(run([gateOf()], [suiOf("D1", { authorizedBy: null })], [chainOf("D1")]))).toEqual([["D1", "no-verdict"]])
  })

  test("no-verdict: a malformed authorizedBy", () => {
    for (const authorizedBy of ["x", 7, [], { verdictDigest: 7, paymentDigest: pd }]) {
      expect(pairs(run([gateOf()], [suiOf("D1", { authorizedBy })], [chainOf("D1")]))).toEqual([["D1", "no-verdict"]])
    }
  })

  // A clean `observed` and an `attempted` do authorize (ADR 0010, test/gate/action-lifecycle.test.ts).
  test.each(["refused", "warned", "judgment-blocked", "judgment-flagged", "judgment-held", "errored", "declassify-refused"])(
    "no-verdict: a gate receipt decided %s is not an execution",
    (decision) => {
      expect(pairs(run([gateOf({ decision })], [suiOf("D1")], [chainOf("D1")]))).toEqual([["D1", "no-verdict"]])
    },
  )

  test("payment-mismatch: the chain moved a different amount, recipient or asset", () => {
    for (const over of [{ amount: "601" }, { recipient: "0xdef" }, { asset: "0x2::usdc::USDC" }, { network: "sui:mainnet" }]) {
      expect(pairs(run([gateOf()], [suiOf("D1")], [chainOf("D1", over)]))).toEqual([["D1", "payment-mismatch"]])
    }
  })

  test("payment-mismatch: the receipt's own paymentDigest differs from the chain's", () => {
    const authorizedBy = { verdictDigest: vd, paymentDigest: "e".repeat(64) }
    expect(pairs(run([gateOf()], [suiOf("D1", { authorizedBy })], [chainOf("D1")]))).toEqual([["D1", "payment-mismatch"]])
  })

  test("payment-mismatch: a successful spend the chain could not read", () => {
    for (const over of [{ amount: null, recipient: null }, { amount: null }, { recipient: null }]) {
      expect(pairs(run([gateOf()], [suiOf("D1")], [chainOf("D1", over)]))).toEqual([["D1", "payment-mismatch"]])
    }
  })

  test("payment-mismatch: chain fields paymentDigest refuses do not crash", () => {
    expect(pairs(run([gateOf()], [suiOf("D1")], [chainOf("D1", { amount: "-5" })]))).toEqual([["D1", "payment-mismatch"]])
    expect(pairs(run([gateOf()], [suiOf("D1")], [chainOf("D1", { asset: 7 })]))).toEqual([["D1", "payment-mismatch"]])
  })

  test("payment-mismatch: a verdict with a null paymentDigest cannot be proven to be this payment", () => {
    const v = verdictOf({ paymentDigest: null })
    const authorizedBy = { verdictDigest: verdictDigest(v), paymentDigest: null }
    expect(pairs(run([gateOf({ verdict: v })], [suiOf("D1", { authorizedBy })], [chainOf("D1")]))).toEqual([["D1", "payment-mismatch"]])
    // Even when the receipt claims the right payment.
    const claimed = { verdictDigest: verdictDigest(v), paymentDigest: pd }
    expect(pairs(run([gateOf({ verdict: v })], [suiOf("D1", { authorizedBy: claimed })], [chainOf("D1")]))).toEqual([["D1", "payment-mismatch"]])
  })

  test("double-spend: each spend after the first under one verdict", () => {
    const r = run([gateOf()], [suiOf("D1"), suiOf("D2"), suiOf("D3")], [chainOf("D1"), chainOf("D2"), chainOf("D3")])
    expect(pairs(r)).toEqual([["D2", "double-spend"], ["D3", "double-spend"]])
  })

  test("double-spend: the first spend is the first in CHAIN order, whatever order the receipts came in", () => {
    const r = run([gateOf()], [suiOf("D1"), suiOf("D2")], [chainOf("D2"), chainOf("D1")])
    expect(pairs(r)).toEqual([["D1", "double-spend"]])
  })

  test("double-spend: a failed attempt does not use the verdict up", () => {
    const r = run([gateOf()], [suiOf("F1", { verdict: "refused" }), suiOf("D1")], [chainOf("F1", { status: "failure", amount: null, recipient: null }), chainOf("D1")])
    expect(r).toEqual({ ok: true, orphans: [] })
  })

  test("double-spend: a second spend is one even when its payment also differs, and a mismatched first still counts", () => {
    expect(pairs(run([gateOf()], [suiOf("D1"), suiOf("D2")], [chainOf("D1"), chainOf("D2", { amount: "601" })]))).toEqual([["D2", "double-spend"]])
    expect(pairs(run([gateOf()], [suiOf("D1"), suiOf("D2")], [chainOf("D1", { amount: "601" }), chainOf("D2")]))).toEqual([["D1", "payment-mismatch"], ["D2", "double-spend"]])
  })

  test("two verdicts for two actions, one spend each, are clean", () => {
    const v2 = verdictOf({ judgedAt: "2026-01-02T00:00:00.000Z", actionDigest: "9".repeat(64) })
    const b = { verdictDigest: verdictDigest(v2), paymentDigest: pd }
    expect(run([gateOf(), gateOf({ verdict: v2 })], [suiOf("D1"), suiOf("D2", { authorizedBy: b })], [chainOf("D1"), chainOf("D2")])).toEqual({ ok: true, orphans: [] })
  })
})

describe("the verdict is recomputed, never believed", () => {
  test("a verdict edited on the gate receipt no longer matches the digest the spend named", () => {
    const tampered = gateOf({ verdict: { ...V, confidence: 0.1 } })
    expect(pairs(run([tampered], [suiOf("D1")], [chainOf("D1")]))).toEqual([["D1", "no-verdict"]])
  })

  test("a digest field on the gate receipt is not consulted", () => {
    const tampered = gateOf({ verdict: { ...V, confidence: 0.1 }, verdictDigest: vd })
    expect(pairs(run([tampered], [suiOf("D1")], [chainOf("D1")]))).toEqual([["D1", "no-verdict"]])
  })

  test("a held verdict released by an owner is an ordinary match target", () => {
    const held = verdictOf({ assessment: "unsure", confidence: 0.4 })
    const approval = { verdictDigest: verdictDigest(held), actionDigest: held.actionDigest, grantHash: held.grantHash, expiresAt: "z", signature: "f".repeat(128) }
    const authorizedBy = { verdictDigest: verdictDigest(held), paymentDigest: pd }
    const log = [gateOf({ decision: "judgment-held", verdict: held }), gateOf({ verdict: held, approval })]
    expect(run(log, [suiOf("D1", { authorizedBy })], [chainOf("D1")])).toEqual({ ok: true, orphans: [] })
  })
})

describe("a chain failure is a refusal", () => {
  const failed = (d: string) => chainOf(d, { status: "failure", amount: null, recipient: null })

  test("with no records at all", () => {
    expect(run([], [], [failed("F1")])).toEqual({ ok: true, orphans: [] })
  })

  test("a receipt that claimed it executed contradicts the chain", () => {
    expect(pairs(run([gateOf()], [suiOf("F1")], [failed("F1")]))).toEqual([["F1", "payment-mismatch"]])
  })

  test("an errored receipt the chain settled as failed stays a refusal", () => {
    expect(run([gateOf()], [suiOf("F1", { verdict: "errored" })], [failed("F1")])).toEqual({ ok: true, orphans: [] })
  })
})

describe("the receipt's verdict field", () => {
  test("an errored receipt is settled by the chain: it landed, and it is accounted for", () => {
    expect(run([gateOf()], [suiOf("D1", { verdict: "errored" })], [chainOf("D1")])).toEqual({ ok: true, orphans: [] })
  })

  test("an errored receipt the chain does not show never landed", () => {
    expect(run([gateOf()], [suiOf("D1", { verdict: "errored" })], [])).toEqual({ ok: true, orphans: [] })
  })

  test("a refused receipt does not account for a spend that succeeded", () => {
    expect(pairs(run([gateOf()], [suiOf("D1", { verdict: "refused" })], [chainOf("D1")]))).toEqual([["D1", "no-receipt"]])
  })

  test("a refused receipt that never reached the chain is nothing to report", () => {
    expect(run([gateOf()], [suiOf(null, { verdict: "refused" })], [])).toEqual({ ok: true, orphans: [] })
  })
})

describe("an executed receipt the chain does not show", () => {
  test("is reported against an empty chain", () => {
    const r = run([gateOf()], [suiOf("D1")], [])
    expect(r.ok).toBe(false)
    expect(pairs(r)).toEqual([["D1", "payment-mismatch"]])
  })

  test("is reported beside a chain that has other spends", () => {
    expect(pairs(run([gateOf()], [suiOf("D1"), suiOf("D2")], [chainOf("D1")]))).toEqual([["D2", "payment-mismatch"]])
  })

  test("is reported once when the receipt is duplicated", () => {
    expect(pairs(run([gateOf()], [suiOf("D1"), suiOf("D1")], []))).toEqual([["D1", "payment-mismatch"]])
  })

  test("open and revoke receipts are not spends and are not looked for", () => {
    expect(run([], [suiOf("O1", { verb: "open", authorizedBy: null }), suiOf("R1", { verb: "revoke", authorizedBy: null })], [])).toEqual({ ok: true, orphans: [] })
  })

  test("an executed spend naming no transaction cannot be joined, so it is reported by position", () => {
    expect(pairs(run([gateOf()], [suiOf(null)], []))).toEqual([["sui[0]", "payment-mismatch"]])
  })

  test("nothing at all is vacuously clean", () => {
    expect(run([], [], [])).toEqual({ ok: true, orphans: [] })
  })
})

describe("a duplicated digest", () => {
  test("in the chain, identical: one transaction, one spend, not a double-spend", () => {
    expect(run([gateOf()], [suiOf("D1")], [chainOf("D1"), chainOf("D1")])).toEqual({ ok: true, orphans: [] })
  })

  test("in the chain, disagreeing: reported once", () => {
    expect(pairs(run([gateOf()], [suiOf("D1")], [chainOf("D1"), chainOf("D1", { amount: "601" })]))).toEqual([["D1", "payment-mismatch"]])
    expect(pairs(run([gateOf()], [suiOf("D1")], [chainOf("D1", { status: "failure", amount: null, recipient: null }), chainOf("D1")]))).toEqual([["D1", "payment-mismatch"]])
  })

  test("in the receipts, agreeing: one receipt", () => {
    expect(run([gateOf()], [suiOf("D1", { verdict: "errored" }), suiOf("D1")], [chainOf("D1")])).toEqual({ ok: true, orphans: [] })
  })

  test("in the receipts, naming different verdicts: neither can be believed", () => {
    const other = { verdictDigest: "d".repeat(64), paymentDigest: pd }
    expect(pairs(run([gateOf()], [suiOf("D1"), suiOf("D1", { authorizedBy: other })], [chainOf("D1")]))).toEqual([["D1", "no-verdict"]])
    expect(pairs(run([gateOf()], [suiOf("D1", { authorizedBy: other }), suiOf("D1")], [chainOf("D1")]))).toEqual([["D1", "no-verdict"]])
  })

  test("in the gate log: one verdict, however many times it is listed", () => {
    expect(run([gateOf(), gateOf({ seq: 1 })], [suiOf("D1")], [chainOf("D1")])).toEqual({ ok: true, orphans: [] })
  })

  test("a digest spelled like an object's own key is only a digest", () => {
    expect(run([gateOf()], [suiOf("__proto__")], [chainOf("__proto__")])).toEqual({ ok: true, orphans: [] })
    expect(pairs(run([gateOf()], [], [chainOf("constructor")]))).toEqual([["constructor", "no-receipt"]])
  })
})

describe("a record that cannot be read is reported, never skipped and never fatal", () => {
  const cyclic = (): Record<string, unknown> => {
    const v: Record<string, unknown> = { ...V }
    v.self = v
    return v
  }

  test.each([
    ["NaN confidence", () => ({ ...V, confidence: NaN })],
    ["a null verdict", () => null],
    ["an array verdict", () => []],
    ["a string verdict", () => "verdict"],
    ["a cycle", cyclic],
    ["a bigint inside", () => ({ ...V, confidence: 1n })],
    ["a class instance", () => new (class Fake { confidence = 0.9 })()],
  ])("an executed gate receipt with %s", (_label, verdict) => {
    const r = run([gateOf({ verdict: verdict() })], [], [])
    expect(r.ok).toBe(false)
    expect(pairs(r)).toEqual([["gate[0]", "no-verdict"]])
  })

  test("beside a clean set, the malformed receipt still stops it reading clean", () => {
    const r = run([gateOf({ verdict: { ...V, confidence: NaN } }), gateOf()], [suiOf("D1")], [chainOf("D1")])
    expect(r.ok).toBe(false)
    expect(pairs(r)).toEqual([["gate[0]", "no-verdict"]])
  })

  test("the spend that named it is reported too", () => {
    const r = run([gateOf({ verdict: { ...V, confidence: NaN } })], [suiOf("D1")], [chainOf("D1")])
    expect(pairs(r)).toEqual([["D1", "no-verdict"], ["gate[0]", "no-verdict"]])
  })

  test("a verdict that throws when read", () => {
    const entry = gateOf()
    Object.defineProperty(entry, "verdict", { enumerable: true, get() { throw new Error("boom") } })
    expect(pairs(run([entry], [], []))).toEqual([["gate[0]", "no-verdict"]])
  })

  test("a verdict with an accessor field is not digested", () => {
    const verdict: Record<string, unknown> = { ...V }
    Object.defineProperty(verdict, "confidence", { enumerable: true, get: () => 0.9 })
    expect(pairs(run([gateOf({ verdict })], [], []))).toEqual([["gate[0]", "no-verdict"]])
  })

  test("a judged receipt on any other decision is not a match target, so it does not matter if it is malformed", () => {
    expect(run([gateOf({ decision: "judgment-held", verdict: { ...V, confidence: NaN } })], [], [])).toEqual({ ok: true, orphans: [] })
  })

  test("an executed gate receipt with no verdict is an unjudged sink, not an error", () => {
    const { verdict: _v, ...unjudged } = gateOf()
    expect(run([unjudged], [], [])).toEqual({ ok: true, orphans: [] })
  })

  test("a gate entry that is not a receipt", () => {
    for (const bad of [null, 7, "x", {}, { decision: 7 }]) {
      expect(pairs(run([bad], [], []))).toEqual([["gate[0]", "no-verdict"]])
    }
  })

  test("a signed envelope is not a gate receipt, and says so", () => {
    expect(pairs(run([{ payload: gateOf(), signature: "s" }], [], []))).toEqual([["gate[0]", "no-verdict"]])
  })

  test("a sui entry that is not a receipt", () => {
    for (const bad of [null, 7, "x", {}, { schema: 7 }]) {
      expect(pairs(run([], [bad], []))).toEqual([["sui[0]", "no-receipt"]])
    }
  })

  test("a receipt@2 spend with an unknown outcome", () => {
    for (const verdict of ["maybe", undefined, null, 1]) {
      expect(pairs(run([gateOf()], [suiOf("D1", { verdict })], []))).toEqual([["sui[0]", "no-receipt"]])
    }
  })

  test("a receipt from an older schema is out of scope, not unreadable", () => {
    expect(run([], [suiOf("D1", { schema: "sweetrust-sui/receipt@1" })], [])).toEqual({ ok: true, orphans: [] })
  })

  test("a chain entry with no readable digest", () => {
    for (const bad of [null, 7, {}, { digest: 7, status: "success" }, { digest: "", status: "success" }]) {
      expect(pairs(run([], [], [bad]))).toEqual([["chain[0]", "payment-mismatch"]])
    }
  })

  test("a chain entry with an unknown status is never read as a refusal", () => {
    for (const status of ["FAILURE", null, undefined, 1]) {
      expect(pairs(run([gateOf()], [suiOf("D1")], [chainOf("D1", { status })]))).toEqual([["D1", "payment-mismatch"]])
    }
  })

  test("own fields only: a field on the prototype does not count", () => {
    const inherited = Object.create(chainOf("D1", { status: "failure", amount: null, recipient: null })) as object
    expect(pairs(run([], [], [inherited]))).toEqual([["chain[0]", "payment-mismatch"]])
  })

  test("positions are positions in the input", () => {
    const r = run([gateOf(), null], [suiOf("D1"), 7], [chainOf("D1"), null])
    expect(pairs(r)).toEqual([["gate[1]", "no-verdict"], ["sui[1]", "no-receipt"], ["chain[1]", "payment-mismatch"]])
  })
})

describe("the argument", () => {
  test.each([
    ["undefined", undefined],
    ["null", null],
    ["an array", []],
    ["a missing chain", { gate: [], sui: [] }],
    ["a missing gate", { sui: [], chain: [] }],
    ["a missing sui", { gate: [], chain: [] }],
    ["a non-array chain", { gate: [], sui: [], chain: {} }],
  ])("%s is a TypeError, never a clean result", (_label, args) => {
    expect(() => reconcile(args as unknown as Args)).toThrow(TypeError)
  })

  test("leaves its inputs as it found them", () => {
    const gate = [gateOf()]
    const sui = [suiOf("D1")]
    const chain = [chainOf("D1")]
    const before = JSON.stringify({ gate, sui, chain })
    reconcile({ gate, sui, chain })
    expect(JSON.stringify({ gate, sui, chain })).toBe(before)
  })
})
