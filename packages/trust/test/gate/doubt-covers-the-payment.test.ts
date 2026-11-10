/**
 * A doubt on a payment covers the same payment with another memo (DAN-1466,
 * amending ADR 0010). A standing doubt used to be keyed on the whole action, so
 * an agent whose payment was held or blocked could send it again with a reworded
 * memo, get a fresh judge, and run on a `match` the owner never saw.
 *
 * Doubt broadly, allow narrowly: a doubt stands on the payment (`paymentDigest`),
 * while dedupe and an owner's approval stay on the exact action. A sink with no
 * payment keeps exact-action stickiness, and two null payment digests never match.
 */
import { generateKeyPairSync, sign } from "node:crypto"
import { afterEach, describe, expect, it, vi } from "vitest"
import { canonicalJSON, sha256Hex } from "../../src/canon.ts"
import { ReceiptLog, Sourced, makeSink, type HeldAction, type JudgmentInput, type JudgmentProvider } from "../../src/gate/index.ts"

const owner = generateKeyPairSync("ed25519")
const approvalKey = owner.publicKey.export({ format: "der", type: "spki" }).toString("hex")
const approve = (h: HeldAction) => {
  const f = {
    verdictDigest: h.verdictDigest,
    actionDigest: h.actionDigest,
    grantHash: h.grantHash,
    expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
  }
  return { ...f, signature: sign(null, Buffer.from(canonicalJSON({ domain: "sweetrust/approval@1", ...f })), owner.privateKey).toString("hex") }
}

const PURPOSE = { statement: "Pay the utility bill" }
const granted = (mandateId = "m1") => ({ purpose: PURPOSE, grantHash: sha256Hex(canonicalJSON({ type: "grant", mandateId, purpose: PURPOSE })) })
const MATCH = { assessment: "match", confidence: 0.95, rationale: "fits" }
const MISMATCH = { assessment: "mismatch", confidence: 0.95, rationale: "not the owner's purpose" }
const UNSURE = { assessment: "unsure", confidence: 0.3, rationale: "ask the owner" }

const HOLD_MS = 15 * 60_000
const BLOCK_MS = 60 * 60_000
const START = new Date("2026-11-09T00:00:00.000Z")

const scripted = (...answers: unknown[]): JudgmentProvider & { calls: number } => {
  const p = {
    name: "j",
    model: "j@1",
    calls: 0,
    async assess() {
      const answer = answers[Math.min(p.calls, answers.length - 1)]
      p.calls += 1
      return answer as never
    },
  }
  return p
}

interface Opts {
  /** false: a judged sink with no `purposeArgs`, so every call's payment digest is null. */
  payment?: boolean
  mode?: "warn" | "enforce"
  key?: string | undefined
}
const build = (provider: JudgmentProvider, log = new ReceiptLog(), opts: Opts = {}) => {
  const runs: unknown[] = []
  const judgment: Record<string, unknown> = { provider, floor: 0.7, granted: granted(), approvalKey: "key" in opts ? opts.key : approvalKey }
  if (opts.payment !== false) Object.assign(judgment, { purposeArgs: { payee: "to", amount: "amount" }, network: "sui:testnet", asset: "0x2::sui::SUI" })
  const sink = makeSink<any, unknown>({
    name: "pay",
    requires: { to: "verified", amount: "verified", memo: "untrusted" },
    mode: opts.mode ?? "enforce",
    log,
    judgment: judgment as never,
    execute: (args: any) => {
      runs.push(args.memo?.value ?? args.memo)
      return "sent"
    },
  })
  return { sink, log, runs }
}
const V = <T>(v: T) => Sourced.fromAuthority(v, "owner")
const pay = (memo: string, amount = "5", to = "0xutility") => ({ to: V(to), amount: V(amount), memo: Sourced.fromLLM(memo, "agent", []) })
const wait = (ms: number) => vi.setSystemTime(new Date(Date.now() + ms))
const clock = () => vi.useFakeTimers({ toFake: ["Date"], now: START })
const heldOf = (r: { ok: boolean; held?: HeldAction }): HeldAction => {
  if (r.ok || r.held === undefined) throw new Error("expected a hold")
  return r.held
}

afterEach(() => {
  vi.useRealTimers()
})

describe("a doubt on a payment covers the same payment under another memo", () => {
  it("a held payment re-sent with another memo is held, unjudged, and nothing runs", async () => {
    const p = scripted(UNSURE, MATCH)
    const { sink, runs } = build(p)
    const first = await sink(pay("invoice 1"))
    const retry = await sink(pay("invoice 1 (resend)"))
    expect(retry.ok).toBe(false)
    expect(retry.receipt.decision).toBe("judgment-held")
    expect(p.calls).toBe(1)
    expect(runs).toHaveLength(0)
    // The hold names the doubted action, so an approval of it resumes what the owner was shown.
    expect(heldOf(retry)).toEqual({ ...heldOf(first), underAnotherAction: true })
    expect(retry.receipt.verdict).toEqual(first.receipt.verdict)
    expect(retry.receipt.reason).toContain("this payment already has this answer, on another action of it")
    expect(retry.receipt.reason).toContain("an approval of it resumes that action and not this one")
    // The agent learns nothing: the refusal is the same fixed sentence as the first one.
    expect(retry.ok === false && first.ok === false && retry.refusal === first.refusal).toBe(true)
  })

  it("the exact retry carries no underAnotherAction flag", async () => {
    const { sink } = build(scripted(UNSURE, MATCH))
    const first = await sink(pay("invoice 1"))
    const same = await sink(pay("invoice 1"))
    expect(heldOf(same)).toEqual(heldOf(first))
    expect(heldOf(same).underAnotherAction).toBeUndefined()
  })

  it("another memo plus a new idempotency key stays held", async () => {
    const p = scripted(UNSURE, MATCH)
    const { sink, runs } = build(p)
    const first = await sink(pay("invoice 1"))
    const keyed = await sink(pay("invoice 1 (again)"), { idempotencyKey: "inv-2" })
    expect(keyed.receipt.decision).toBe("judgment-held")
    expect(heldOf(keyed).actionDigest).toBe(heldOf(first).actionDigest)
    expect(heldOf(keyed).underAnotherAction).toBe(true)
    expect(heldOf(keyed).underAnotherKey).toBeUndefined()
    expect(p.calls).toBe(1)
    expect(runs).toHaveLength(0)
  })

  it("a block covers the same payment with another memo, unjudged", async () => {
    const p = scripted(MISMATCH, MATCH)
    const { sink, runs } = build(p)
    await sink(pay("x"))
    const retry = await sink(pay("y"))
    expect(retry.ok).toBe(false)
    expect(retry.receipt.decision).toBe("judgment-blocked")
    expect(retry.receipt.reason).toContain("this payment already has this answer, on another action of it")
    expect(p.calls).toBe(1)
    expect(runs).toHaveLength(0)
  })

  it("a block covers another memo under a new idempotency key", async () => {
    const { sink, runs } = build(scripted(MISMATCH, MATCH))
    await sink(pay("x"), { idempotencyKey: "inv-1" })
    expect((await sink(pay("y"), { idempotencyKey: "inv-2" })).receipt.decision).toBe("judgment-blocked")
    expect(runs).toHaveLength(0)
  })

  it("a second sink object over the same log holds the memo variant too", async () => {
    const log = new ReceiptLog()
    await build(scripted(UNSURE), log).sink(pay("a"))
    const other = build(scripted(MATCH), log)
    expect((await other.sink(pay("b"))).receipt.decision).toBe("judgment-held")
    expect(other.runs).toHaveLength(0)
  })
})

describe("after the window, a memo variant of a doubted payment needs its owner", () => {
  it("an expired hold: the memo variant is judged again, matches, and is still held", async () => {
    clock()
    const p = scripted(UNSURE, MATCH)
    const { sink, runs } = build(p)
    await sink(pay("invoice 1"))
    wait(HOLD_MS + 1)
    const r = await sink(pay("invoice 1 (resend)"))
    expect(p.calls).toBe(2)
    expect(r.ok).toBe(false)
    expect(r.receipt.decision).toBe("judgment-held")
    expect(r.receipt.verdict?.assessment).toBe("match")
    expect(r.receipt.reason).toContain("an earlier judgment-held (j, unsure, conf 0.3) on another action of this payment needs its owner")
    expect(runs).toHaveLength(0)
  })

  it("an expired block: the memo variant is judged again and held", async () => {
    clock()
    const { sink, runs } = build(scripted(MISMATCH, MATCH))
    await sink(pay("x"))
    wait(BLOCK_MS + 1)
    const r = await sink(pay("y"))
    expect(r.receipt.decision).toBe("judgment-held")
    expect(runs).toHaveLength(0)
  })

  it("rewording every window never runs the payment", async () => {
    clock()
    const { sink, runs } = build(scripted(UNSURE, MATCH))
    await sink(pay("memo 0"))
    for (let i = 1; i <= 10; i++) {
      wait(HOLD_MS + 1)
      expect((await sink(pay(`memo ${i}`), { idempotencyKey: `k-${i}` })).ok).toBe(false)
    }
    expect(runs).toHaveLength(0)
  })

  it("the fresh hold on the memo variant names that variant, and its approval releases it once", async () => {
    clock()
    const { sink, runs } = build(scripted(UNSURE, MATCH))
    const first = heldOf(await sink(pay("a")))
    wait(HOLD_MS + 1)
    const fresh = heldOf(await sink(pay("b")))
    expect(fresh.actionDigest).not.toBe(first.actionDigest)
    expect(fresh.underAnotherAction).toBeUndefined()
    const ap = approve(fresh)
    expect((await sink.resume(pay("b"), ap)).ok).toBe(true)
    expect(runs).toEqual(["b"])
    const again = await sink.resume(pay("b"), ap)
    expect(again.ok === false && /approval-replayed/.test(again.refusal)).toBe(true)
    expect(runs).toEqual(["b"])
  })

  it("with no approvalKey the payment stays held under any memo", async () => {
    clock()
    const { sink, runs } = build(scripted(UNSURE, MATCH), new ReceiptLog(), { key: undefined })
    await sink(pay("a"))
    for (const memo of ["b", "c", "d"]) {
      wait(BLOCK_MS + 1)
      expect((await sink(pay(memo))).receipt.decision).toBe("judgment-held")
    }
    expect(runs).toHaveLength(0)
  })
})

describe("an approval stays on the exact action", () => {
  it("approving a memo variant's hold cannot resume the memo variant", async () => {
    const { sink, runs } = build(scripted(UNSURE, MATCH))
    await sink(pay("a"))
    const variant = heldOf(await sink(pay("b")))
    const ap = approve(variant)
    const wrong = await sink.resume(pay("b"), ap)
    expect(wrong.ok === false && /approval-mismatch/.test(wrong.refusal)).toBe(true)
    expect(runs).toHaveLength(0)
    // The same approval releases the action the owner was shown, once.
    expect((await sink.resume(pay("a"), ap)).ok).toBe(true)
    expect(runs).toEqual(["a"])
    const replay = await sink.resume(pay("a"), ap)
    expect(replay.ok === false && /approval-replayed/.test(replay.refusal)).toBe(true)
    expect(runs).toEqual(["a"])
  })

  it("an approval of memo a does not release memo b", async () => {
    const { sink, runs } = build(scripted(UNSURE, MATCH))
    const ap = approve(heldOf(await sink(pay("a"))))
    const wrong = await sink.resume(pay("b"), ap)
    expect(wrong.ok === false && /approval-mismatch/.test(wrong.refusal)).toBe(true)
    expect(runs).toHaveLength(0)
  })

  it("once the owner approves and the action is attempted, a later memo goes back to the judge", async () => {
    const p = scripted(UNSURE, MATCH, UNSURE)
    const { sink, runs } = build(p)
    const ap = approve(heldOf(await sink(pay("a"))))
    expect((await sink.resume(pay("a"), ap)).ok).toBe(true)
    expect((await sink(pay("c"))).ok).toBe(true)
    expect(p.calls).toBe(2)
    expect(runs).toEqual(["a", "c"])
    // The judge can doubt the next one again, and that doubt covers the payment afresh.
    expect((await sink(pay("d"))).receipt.decision).toBe("judgment-held")
    expect((await sink(pay("e"))).receipt.decision).toBe("judgment-held")
    expect(p.calls).toBe(3)
    expect(runs).toEqual(["a", "c"])
  })

  it("dedupe stays on the exact action: the approved memo repeated unkeyed is a duplicate", async () => {
    const { sink, runs } = build(scripted(UNSURE, MATCH))
    const ap = approve(heldOf(await sink(pay("a"))))
    await sink.resume(pay("a"), ap)
    const dup = await sink(pay("a"))
    expect(dup.ok === false && /duplicate-action/.test(dup.refusal)).toBe(true)
    expect(runs).toEqual(["a"])
  })
})

describe("concurrent memo variants of a payment being judged", () => {
  it("a memo variant sent while the doubt is being judged does not run", async () => {
    const p = {
      name: "j",
      model: "j@1",
      calls: 0,
      async assess(input: JudgmentInput) {
        p.calls++
        if (input.action.args.memo === "slow") {
          await new Promise((r) => setTimeout(r, 30))
          return UNSURE as never
        }
        return MATCH as never
      },
    }
    const { sink, runs } = build(p)
    const [slow, fast] = await Promise.all([sink(pay("slow")), sink(pay("fast"))])
    expect(slow.receipt.decision).toBe("judgment-held")
    expect(fast.ok).toBe(false)
    expect(fast.receipt.decision).toBe("judgment-held")
    expect(heldOf(fast).actionDigest).toBe(heldOf(slow).actionDigest)
    expect(p.calls).toBe(1)
    expect(runs).toHaveLength(0)
  })

  it("five concurrent memo variants yield one judge call and no run", async () => {
    const p = scripted(UNSURE, MATCH)
    const { sink, runs } = build(p)
    const results = await Promise.all(["a", "b", "c", "d", "e"].map((m) => sink(pay(m))))
    expect(results.every((r) => !r.ok)).toBe(true)
    expect(p.calls).toBe(1)
    expect(runs).toHaveLength(0)
  })

  it("on a sink with no payment, concurrent different actions are judged separately", async () => {
    // A null payment digest must not become one shared claim: the fast call
    // would otherwise wait on, and be held by, an unrelated doubt.
    const p = {
      name: "j",
      model: "j@1",
      calls: 0,
      async assess(input: JudgmentInput) {
        p.calls++
        if (input.action.args.memo === "slow") {
          await new Promise((r) => setTimeout(r, 30))
          return UNSURE as never
        }
        return MATCH as never
      },
    }
    const { sink, runs } = build(p, new ReceiptLog(), { payment: false })
    const [slow, fast] = await Promise.all([sink(pay("slow")), sink(pay("fast"))])
    expect(slow.receipt.decision).toBe("judgment-held")
    expect(fast.ok).toBe(true)
    expect(runs).toEqual(["fast"])
  })
})

describe("the doubt is no wider than the payment", () => {
  it("another amount is a new payment, judged afresh", async () => {
    const p = scripted(UNSURE, MATCH)
    const { sink, runs } = build(p)
    await sink(pay("m"))
    expect((await sink(pay("m", "6"))).ok).toBe(true)
    expect(p.calls).toBe(2)
    expect(runs).toEqual(["m"])
  })

  it("another payee is a new payment, judged afresh", async () => {
    const p = scripted(UNSURE, MATCH)
    const { sink, runs } = build(p)
    await sink(pay("m"))
    expect((await sink(pay("m", "5", "0xother"))).ok).toBe(true)
    expect(p.calls).toBe(2)
    expect(runs).toEqual(["m"])
  })

  it("a judged sink with no purposeArgs keeps exact-action stickiness", async () => {
    const p = scripted(UNSURE, MATCH)
    const { sink, runs } = build(p, new ReceiptLog(), { payment: false })
    const a = await sink(pay("a"))
    expect(a.receipt.verdict?.paymentDigest).toBeNull()
    // The exact action is still held without a judge call.
    expect((await sink(pay("a"))).receipt.decision).toBe("judgment-held")
    expect(p.calls).toBe(1)
    // Another action is new: two null payment digests are never one payment.
    const b = await sink(pay("b"))
    expect(b.ok).toBe(true)
    expect(p.calls).toBe(2)
    expect(runs).toEqual(["b"])
  })

  it("on a sink with no purposeArgs an expired doubt does not hold another action", async () => {
    clock()
    const { sink, runs } = build(scripted(UNSURE, MATCH), new ReceiptLog(), { payment: false })
    await sink(pay("a"))
    wait(HOLD_MS + 1)
    expect((await sink(pay("b"))).ok).toBe(true)
    expect(runs).toEqual(["b"])
  })

  it("a doubt under another grant does not cover the payment", async () => {
    const log = new ReceiptLog()
    await build(scripted(UNSURE), log).sink(pay("a"))
    const other = makeSink<any, unknown>({
      name: "pay",
      requires: { to: "verified", amount: "verified", memo: "untrusted" },
      mode: "enforce",
      log,
      judgment: { provider: scripted(MATCH), floor: 0.7, granted: granted("m2"), approvalKey, purposeArgs: { payee: "to", amount: "amount" }, network: "sui:testnet", asset: "0x2::sui::SUI" },
      execute: () => "sent",
    })
    expect((await other(pay("b"))).ok).toBe(true)
  })

  it("warn mode keeps no record, so a memo variant runs as before", async () => {
    const { sink, runs } = build(scripted(UNSURE, MATCH), new ReceiptLog(), { mode: "warn" })
    await sink(pay("a"))
    expect((await sink(pay("b"))).ok).toBe(true)
    expect(runs).toEqual(["a", "b"])
  })
})
