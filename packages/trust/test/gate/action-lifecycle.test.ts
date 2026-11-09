/**
 * The action lifecycle (ADR 0010, the 2026-11-08 audit rows L1 to L7): a judged
 * action is issued once, bound to its purpose, and consumed once.
 */
import { generateKeyPairSync, sign } from "node:crypto"
import { afterEach, describe, expect, it, vi } from "vitest"
import { canonicalJSON, sha256Hex } from "../../src/canon.ts"
import {
  ReceiptLog,
  Sourced,
  SpendAuthorization,
  makeSink,
  paymentDigest,
  purposeHash,
  verdictDigest,
  type HeldAction,
  type JudgmentProvider,
  type Receipt,
} from "../../src/gate/index.ts"
import { reconcile, verifyVerdictPurpose } from "../../src/verify/index.ts"

const owner = generateKeyPairSync("ed25519")
const approvalKey = owner.publicKey.export({ format: "der", type: "spki" }).toString("hex")
const approve = (h: HeldAction, expiresAt = new Date(Date.now() + 5 * 60_000).toISOString()) => {
  const f = { verdictDigest: h.verdictDigest, actionDigest: h.actionDigest, grantHash: h.grantHash, expiresAt }
  return { ...f, signature: sign(null, Buffer.from(canonicalJSON({ domain: "sweetrust/approval@1", ...f })), owner.privateKey).toString("hex") }
}

const PURPOSE = { statement: "Pay the utility bill" }
const GRANT = { type: "grant", mandateId: "m1", purpose: PURPOSE }
const GRANTED = { purpose: PURPOSE, grantHash: sha256Hex(canonicalJSON(GRANT)) }
const NET = "sui:testnet"
const ASSET = "0x2::sui::SUI"
const MATCH = { assessment: "match", confidence: 0.95, rationale: "fits" }
const MISMATCH = { assessment: "mismatch", confidence: 0.95, rationale: "not the owner's purpose" }
const UNSURE = { assessment: "unsure", confidence: 0.3, rationale: "ask the owner" }

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
  mode?: "observe" | "warn" | "enforce"
  log?: ReceiptLog
  execute?: () => unknown
  extra?: Record<string, unknown>
}
const build = (provider: JudgmentProvider, opts: Opts = {}) => {
  const log = opts.log ?? new ReceiptLog()
  const runs: Array<{ ctx: any }> = []
  const sink = makeSink<any, unknown>({
    name: "pay",
    requires: { to: "verified", amount: "verified" },
    mode: opts.mode ?? "enforce",
    log,
    judgment: { provider, floor: 0.7, granted: GRANTED, approvalKey, purposeArgs: { payee: "to", amount: "amount" }, network: NET, asset: ASSET, ...opts.extra } as never,
    execute: (_args: unknown, ctx: unknown) => {
      runs.push({ ctx })
      return opts.execute ? opts.execute() : "sent"
    },
  })
  return { sink, log, runs }
}
const V = <T>(v: T) => Sourced.fromAuthority(v, "owner")
const pay = (to = "0xutility", amount = "5") => ({ to: V(to), amount: V(amount) })

afterEach(() => {
  vi.useRealTimers()
})

describe("a block stands: retrying learns nothing (L1)", () => {
  it("a mismatch never flips to executed by retrying, and the judge is asked once", async () => {
    const p = scripted(MISMATCH, MISMATCH, MATCH)
    const { sink, runs, log } = build(p)
    for (let i = 0; i < 10; i++) {
      const r = await sink(pay())
      expect(r.ok).toBe(false)
      expect(r.receipt.decision).toBe("judgment-blocked")
    }
    expect(p.calls).toBe(1)
    expect(runs).toHaveLength(0)
    expect(log.all()).toHaveLength(10)
    expect(new Set(log.all().map((r) => verdictDigest(r.verdict!))).size).toBe(1)
    expect(log.verifyChain()).toBe(true)
  })

  it("a block ends at its window, and not before", async () => {
    vi.useFakeTimers({ toFake: ["Date"], now: new Date("2026-11-08T00:00:00.000Z") })
    const p = scripted(MISMATCH, MATCH)
    const { sink } = build(p, { extra: { blockWindowMs: 20 * 60_000 } })
    await sink(pay())
    vi.setSystemTime(new Date("2026-11-08T00:19:59.000Z"))
    expect((await sink(pay())).ok).toBe(false)
    expect(p.calls).toBe(1)
    vi.setSystemTime(new Date("2026-11-08T00:20:01.000Z"))
    expect((await sink(pay())).ok).toBe(true)
    expect(p.calls).toBe(2)
  })

  it.each([14 * 60_000, 0, NaN, "1h"])("blockWindowMs of %s is a TypeError at construction", (blockWindowMs) => {
    expect(() => build(scripted(MATCH), { extra: { blockWindowMs } })).toThrow(TypeError)
  })

  it("the block survives a restart: a new sink over the same log answers from it", async () => {
    const log = new ReceiptLog()
    await build(scripted(MISMATCH), { log }).sink(pay())
    const p = scripted(MATCH)
    const second = build(p, { log })
    const r = await second.sink(pay())
    expect(r.ok).toBe(false)
    expect(r.receipt.decision).toBe("judgment-blocked")
    expect(p.calls).toBe(0)
    expect(second.runs).toHaveLength(0)
  })

  it("a block is about one action: a different argument gets its own judgment", async () => {
    const p = scripted(MISMATCH, MATCH)
    const { sink } = build(p)
    await sink(pay("0xutility", "5"))
    expect((await sink(pay("0xutility", "6"))).ok).toBe(true)
    expect(p.calls).toBe(2)
  })

  it("a block under another grant or purpose is not this action's answer", async () => {
    const log = new ReceiptLog()
    await build(scripted(MISMATCH), { log }).sink(pay())
    const p = scripted(MATCH)
    const other = { purpose: { statement: "Pay the electric bill" }, grantHash: "c".repeat(64) }
    const r = await build(p, { log, extra: { granted: other } }).sink(pay())
    expect(r.ok).toBe(true)
    expect(p.calls).toBe(1)
  })
})

describe("a hold stands until resolved or expired (L1, L2)", () => {
  it("hold, retry, approve runs once, and the action cannot run again", async () => {
    const p = scripted(UNSURE, MATCH)
    const { sink, runs, log } = build(p)
    const first = await sink(pay())
    const retried = await sink(pay())
    if (first.ok || !first.held || retried.ok || !retried.held) throw new Error("expected both held")
    expect(retried.held).toEqual(first.held)
    expect(p.calls).toBe(1)
    const resumed = await sink.resume(pay(), approve(first.held))
    expect(resumed.ok).toBe(true)
    expect(runs).toHaveLength(1)
    const again = await sink(pay())
    expect(again.ok).toBe(false)
    if (!again.ok) expect(again.refusal).toContain("duplicate-action")
    expect(runs).toHaveLength(1)
    expect(p.calls).toBe(1)
    expect(log.all().map((r) => r.decision)).toEqual(["judgment-held", "judgment-held", "attempted", "executed", "refused"])
  })

  it("an expired hold is judged again", async () => {
    vi.useFakeTimers({ toFake: ["Date"], now: new Date("2026-11-08T00:00:00.000Z") })
    const p = scripted(UNSURE, MATCH)
    const { sink, runs } = build(p)
    await sink(pay())
    vi.setSystemTime(new Date("2026-11-08T00:15:00.001Z"))
    expect((await sink(pay())).ok).toBe(true)
    expect(p.calls).toBe(2)
    expect(runs).toHaveLength(1)
  })
})

describe("execution dedupe keys on the action plus the host's idempotency key", () => {
  it("two legitimate payments with different keys both run", async () => {
    const p = scripted(MATCH)
    const { sink, runs, log } = build(p)
    const a = await sink(pay(), { idempotencyKey: "invoice-1" })
    const b = await sink(pay(), { idempotencyKey: "invoice-2" })
    expect(a.ok && b.ok).toBe(true)
    expect(runs).toHaveLength(2)
    const [va, vb] = [a.receipt.verdict!, b.receipt.verdict!]
    expect(va.actionDigest).not.toBe(vb.actionDigest)
    expect(va.unkeyedActionDigest).toBe(vb.unkeyedActionDigest)
    expect(log.verifyChain()).toBe(true)
  })

  it("the same key twice is one payment", async () => {
    const { sink, runs } = build(scripted(MATCH))
    expect((await sink(pay(), { idempotencyKey: "invoice-1" })).ok).toBe(true)
    const r = await sink(pay(), { idempotencyKey: "invoice-1" })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.refusal).toContain("duplicate-action")
    expect(r.receipt.decision).toBe("refused")
    expect(r.receipt.verdict).toBeDefined()
    expect(runs).toHaveLength(1)
  })

  it("with no key, an identical action already attempted is a duplicate, under any key it ran with", async () => {
    const { sink, runs } = build(scripted(MATCH))
    expect((await sink(pay(), { idempotencyKey: "invoice-1" })).ok).toBe(true)
    expect((await sink(pay())).ok).toBe(false)
    expect(runs).toHaveLength(1)
  })

  it("a key cannot evade a block or a hold", async () => {
    const blocked = build(scripted(MISMATCH, MATCH))
    await blocked.sink(pay(), { idempotencyKey: "a" })
    expect((await blocked.sink(pay(), { idempotencyKey: "b" })).receipt.decision).toBe("judgment-blocked")
    expect(blocked.runs).toHaveLength(0)

    const held = build(scripted(UNSURE, MATCH))
    await held.sink(pay(), { idempotencyKey: "a" })
    expect((await held.sink(pay(), { idempotencyKey: "b" })).receipt.decision).toBe("judgment-held")
    expect(held.runs).toHaveLength(0)
  })

  it("a held call with a key resumes only under that key", async () => {
    const { sink, runs } = build(scripted(UNSURE))
    const first = await sink(pay(), { idempotencyKey: "a" })
    if (first.ok || !first.held) throw new Error("expected held")
    const wrong = await sink.resume(pay(), approve(first.held), { idempotencyKey: "b" })
    expect(wrong.ok).toBe(false)
    if (!wrong.ok) expect(wrong.refusal).toContain("approval-mismatch")
    expect(runs).toHaveLength(0)
    expect((await sink.resume(pay(), approve(first.held), { idempotencyKey: "a" })).ok).toBe(true)
    expect(runs).toHaveLength(1)
  })

  it.each([[""], [7], [null]])("an idempotencyKey of %j refuses in enforce, with no judge", async (idempotencyKey) => {
    const p = scripted(MATCH)
    const { sink, runs } = build(p)
    const r = await sink(pay(), { idempotencyKey } as never)
    expect(r.ok).toBe(false)
    expect(r.receipt.decision).toBe("refused")
    expect(p.calls).toBe(0)
    expect(runs).toHaveLength(0)
  })

  it("the judge never sees the key, so its input stays { sink, args }", async () => {
    const inputs: Array<{ action: Record<string, unknown> }> = []
    const p: JudgmentProvider = { name: "j", model: "j@1", assess: async (input) => { inputs.push(input as never); return MATCH as never } }
    await build(p).sink(pay(), { idempotencyKey: "invoice-1" })
    expect(Object.keys(inputs[0]!.action)).toEqual(["sink", "args"])
  })
})

describe("the claim is taken before the first await", () => {
  it("five concurrent identical calls judge once and run once", async () => {
    const p = scripted(MATCH)
    const { sink, runs } = build(p)
    const rs = await Promise.all([1, 2, 3, 4, 5].map(() => sink(pay())))
    expect(p.calls).toBe(1)
    expect(runs).toHaveLength(1)
    expect(rs.filter((r) => r.ok)).toHaveLength(1)
    for (const r of rs) expect(r.receipt.verdict).toBeDefined()
  })

  it("concurrent calls on a mismatch all answer blocked, and nothing runs", async () => {
    const p = scripted(MISMATCH, MATCH)
    const { sink, runs } = build(p)
    const rs = await Promise.all([1, 2, 3].map(() => sink(pay())))
    expect(p.calls).toBe(1)
    expect(runs).toHaveLength(0)
    for (const r of rs) expect(r.receipt.decision).toBe("judgment-blocked")
  })

  it("concurrent calls with different keys each run", async () => {
    const p = scripted(MATCH)
    const { sink, runs } = build(p)
    const rs = await Promise.all(["a", "b", "c"].map((idempotencyKey) => sink(pay(), { idempotencyKey })))
    expect(rs.every((r) => r.ok)).toBe(true)
    expect(runs).toHaveLength(3)
    expect(p.calls).toBe(3)
  })
})

describe("the durable intent record (L6)", () => {
  it("attempted is on the log before execute runs", async () => {
    let seen: string[] = []
    const log = new ReceiptLog()
    const { sink } = build(scripted(MATCH), { log, execute: () => { seen = log.all().map((r) => r.decision); return "sent" } })
    await sink(pay())
    expect(seen).toEqual(["attempted"])
  })

  it("a log that refuses the intent write stops the action, and it may be tried again", async () => {
    let fail = true
    class Flaky extends ReceiptLog {
      override append(e: Omit<Receipt, "seq" | "prevHash" | "hash">) {
        if (fail && e.decision === "attempted") throw new Error("disk full")
        return super.append(e)
      }
    }
    const log = new Flaky()
    const { sink, runs } = build(scripted(MATCH), { log })
    await expect(sink(pay())).rejects.toThrow("disk full")
    expect(runs).toHaveLength(0)
    fail = false
    expect((await sink(pay())).ok).toBe(true)
    expect(runs).toHaveLength(1)
  })

  it("a log failure after execute cannot make the approval reusable through a second sink", async () => {
    let fail = false
    class Flaky extends ReceiptLog {
      override append(e: Omit<Receipt, "seq" | "prevHash" | "hash">) {
        if (fail && e.decision === "executed") {
          fail = false
          throw new Error("disk full")
        }
        return super.append(e)
      }
    }
    const log = new Flaky()
    const first = build(scripted(UNSURE), { log })
    const held = await first.sink(pay())
    if (held.ok || !held.held) throw new Error("expected held")
    const approval = approve(held.held)
    fail = true
    await expect(first.sink.resume(pay(), approval)).rejects.toThrow("disk full")
    expect(first.runs).toHaveLength(1)
    const second = build(scripted(UNSURE), { log })
    const r = await second.sink.resume(pay(), approval)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.refusal).toContain("approval-replayed")
    expect(second.runs).toHaveLength(0)
  })
})

describe("the verdict is bound to the purpose judged (L3)", () => {
  it("carries purposeHash, and it differs across purposes under one grant hash", async () => {
    const at = (statement: string) => build(scripted(MATCH), { extra: { granted: { purpose: { statement }, grantHash: "b".repeat(64) } } })
    const a = await at("Pay only the landlord").sink(pay())
    const b = await at("Pay the attacker").sink(pay())
    expect(a.receipt.verdict!.purposeHash).toBe(purposeHash({ statement: "Pay only the landlord" }))
    expect(a.receipt.verdict!.purposeHash).not.toBe(b.receipt.verdict!.purposeHash)
    expect(verdictDigest(a.receipt.verdict!)).not.toBe(verdictDigest(b.receipt.verdict!))
  })

  it("verifyVerdictPurpose accepts the grant that was judged", async () => {
    const r = await build(scripted(MATCH)).sink(pay())
    expect(verifyVerdictPurpose({ verdict: r.receipt.verdict!, grant: GRANT })).toEqual({ ok: true })
  })

  it("verifyVerdictPurpose catches a real grant hash paired with a different purpose", async () => {
    const r = await build(scripted(MATCH), { extra: { granted: { purpose: { statement: "Pay anyone" }, grantHash: GRANTED.grantHash } } }).sink(pay())
    expect(verifyVerdictPurpose({ verdict: r.receipt.verdict!, grant: GRANT })).toEqual({ ok: false, reason: "purpose-mismatch" })
  })

  it("verifyVerdictPurpose reports a different grant, a grant with no purpose, and hostile shapes", async () => {
    const r = await build(scripted(MATCH)).sink(pay())
    const verdict = r.receipt.verdict!
    expect(verifyVerdictPurpose({ verdict, grant: { ...GRANT, mandateId: "m2" } })).toEqual({ ok: false, reason: "grant-mismatch" })
    const bare = { type: "grant", mandateId: "m1" }
    expect(verifyVerdictPurpose({ verdict: { ...verdict, grantHash: sha256Hex(canonicalJSON(bare)) }, grant: bare })).toEqual({ ok: false, reason: "purpose-mismatch" })
    for (const args of [null, 7, { verdict: "x", grant: GRANT }, { verdict, grant: "x" }]) {
      expect(verifyVerdictPurpose(args as never)).toEqual({ ok: false, reason: "malformed" })
    }
  })
})

describe("doubt is not authority (L5, L7)", () => {
  it.each(["warn", "observe"] as const)("%s: a confident mismatch runs with no authorizedBy and no token", async (mode) => {
    const { sink, runs } = build(scripted(MISMATCH), { mode })
    const r = await sink(pay())
    expect(r.ok).toBe(true)
    expect(r.receipt.decision).toBe("judgment-flagged")
    expect(runs[0]!.ctx).toBeUndefined()
  })

  it.each(["warn", "observe"] as const)("%s: a confident match carries authorizedBy and a token", async (mode) => {
    const { sink, runs } = build(scripted(MATCH), { mode })
    await sink(pay())
    expect(runs[0]!.ctx.authorizedBy).toBeDefined()
    expect(SpendAuthorization.is(runs[0]!.ctx.authorization)).toBe(true)
  })

  it.each(["warn", "observe"] as const)("%s: an undeclared argument does not switch the judge off", async (mode) => {
    const p = scripted(MISMATCH)
    const { sink, runs } = build(p, { mode })
    const r = await sink({ ...pay(), junk: Sourced.fromChannel("x", "agent") })
    expect(p.calls).toBe(1)
    expect(r.receipt.verdict).toBeDefined()
    expect(r.receipt.decision).toBe("judgment-flagged")
    expect(r.receipt.reason).toContain("junk")
    expect(runs).toHaveLength(1)
  })

  it("in enforce an undeclared argument still refuses before any judge", async () => {
    const p = scripted(MATCH)
    const r = await build(p).sink({ ...pay(), junk: Sourced.fromChannel("x", "agent") })
    expect(r.receipt.decision).toBe("refused")
    expect(p.calls).toBe(0)
  })

  it.each(["warn", "observe"] as const)("%s keeps no lifecycle: identical calls each run and are each judged", async (mode) => {
    const p = scripted(MATCH)
    const { sink, runs } = build(p, { mode })
    await sink(pay())
    await sink(pay())
    expect(p.calls).toBe(2)
    expect(runs).toHaveLength(2)
  })
})

describe("the spend authorization is one-shot and branded (L4)", () => {
  const issued = async () => {
    const { sink, runs } = build(scripted(MATCH))
    const r = await sink(pay())
    return { token: runs[0]!.ctx.authorization as SpendAuthorization, payment: r.receipt.verdict!.paymentDigest! }
  }

  it("a genuine token spends once, for its own payment", async () => {
    const { token, payment } = await issued()
    expect(SpendAuthorization.consume(token, payment)).toEqual({ ok: true, authorizedBy: token.authorizedBy })
    expect(SpendAuthorization.consume(token, payment)).toEqual({ ok: false, reason: "already-consumed" })
  })

  it("the wrong payment does not spend it", async () => {
    const { token, payment } = await issued()
    const other = paymentDigest({ network: NET, asset: ASSET, recipient: "0xother", amount: "5" })
    expect(SpendAuthorization.consume(token, other)).toEqual({ ok: false, reason: "wrong-payment" })
    expect(SpendAuthorization.consume(token, payment).ok).toBe(true)
  })

  it("a null payment digest authorizes no payment", async () => {
    const { sink, runs } = build(scripted(MATCH), { extra: { purposeArgs: undefined, network: undefined, asset: undefined } })
    await sink(pay())
    const token = runs[0]!.ctx.authorization as SpendAuthorization
    expect(token.authorizedBy.paymentDigest).toBeNull()
    expect(SpendAuthorization.consume(token, null as never)).toEqual({ ok: false, reason: "wrong-payment" })
  })

  it.each<[string, unknown]>([
    ["a digest object", { verdictDigest: "f".repeat(64), paymentDigest: "f".repeat(64) }],
    ["the prototype", Object.create(SpendAuthorization.prototype)],
    ["undefined", undefined],
  ])("%s is not issued", async (_name, forged) => {
    const { payment } = await issued()
    expect(SpendAuthorization.consume(forged, payment)).toEqual({ ok: false, reason: "not-issued" })
    expect(SpendAuthorization.is(forged)).toBe(false)
  })

  it("cannot be constructed or extended from outside", () => {
    expect(() => new (SpendAuthorization as any)(Symbol("x"), {})).toThrow(TypeError)
    class Evil extends (SpendAuthorization as any) {}
    expect(() => new (Evil as any)(Symbol("x"), {})).toThrow(TypeError)
  })

  it("each execution gets its own token", async () => {
    const { sink, runs } = build(scripted(MATCH))
    await sink(pay(), { idempotencyKey: "a" })
    await sink(pay(), { idempotencyKey: "b" })
    expect(runs[0]!.ctx.authorization).not.toBe(runs[1]!.ctx.authorization)
  })
})

describe("the refusal does not teach the agent the rationale (default)", () => {
  it("a block's refusal omits it, the receipt keeps it, and a host can opt in", async () => {
    const quiet = await build(scripted(MISMATCH)).sink(pay())
    if (quiet.ok) throw new Error("expected a block")
    expect(quiet.refusal).not.toContain("not the owner's purpose")
    expect(quiet.receipt.reason).toContain("not the owner's purpose")
    const told = await build(scripted(MISMATCH), { extra: { rationaleInRefusal: true } }).sink(pay())
    if (told.ok) throw new Error("expected a block")
    expect(told.refusal).toContain("not the owner's purpose")
  })

  it("rationaleInRefusal must be a boolean", () => {
    expect(() => build(scripted(MATCH), { extra: { rationaleInRefusal: "yes" } })).toThrow(TypeError)
  })
})

describe("reconcile counts executions per action", () => {
  const verdict = (judgedAt: string, actionDigest = "c".repeat(64)) => ({
    assessment: "match" as const, confidence: 0.9, rationaleHash: "a".repeat(64), provider: "p", model: "m@1",
    actionDigest, unkeyedActionDigest: actionDigest, paymentDigest: PD, grantHash: GRANTED.grantHash,
    purposeHash: purposeHash(PURPOSE), judgedAt, attestation: null,
  })
  const PD = paymentDigest({ network: NET, asset: ASSET, recipient: "0xutility", amount: "5" })
  const receipt = (v: ReturnType<typeof verdict>) => ({ at: v.judgedAt, sink: "pay", decision: "executed", args: {}, verdict: v }) as unknown as Receipt
  const sui = (digest: string, v: ReturnType<typeof verdict>) => ({ schema: "sweetrust-sui/receipt@2", verb: "spend", verdict: "executed", digest, authorizedBy: { verdictDigest: verdictDigest(v), paymentDigest: PD } })
  const chain = (digest: string) => ({ digest, status: "success" as const, network: NET, asset: ASSET, recipient: "0xutility", amount: "5" })

  it("one action executed twice under two verdicts is reported", () => {
    const v1 = verdict("2026-11-08T00:00:00.000Z")
    const v2 = verdict("2026-11-08T00:00:01.000Z")
    const r = reconcile({ gate: [receipt(v1), receipt(v2)], sui: [sui("TX1", v1), sui("TX2", v2)], chain: [chain("TX1"), chain("TX2")] })
    expect(r).toEqual({ ok: false, orphans: [{ digest: "TX2", reason: "duplicate-action" }] })
  })

  it("two payments with different idempotency keys are two actions", () => {
    const v1 = verdict("2026-11-08T00:00:00.000Z", "c".repeat(64))
    const v2 = verdict("2026-11-08T00:00:01.000Z", "d".repeat(64))
    expect(reconcile({ gate: [receipt(v1), receipt(v2)], sui: [sui("TX1", v1), sui("TX2", v2)], chain: [chain("TX1"), chain("TX2")] })).toEqual({ ok: true, orphans: [] })
  })

  it("given the grants, a verdict over another purpose is reported, and the judged grant is clean", () => {
    const v = verdict("2026-11-08T00:00:00.000Z")
    const args = { gate: [receipt(v)], sui: [sui("TX1", v)], chain: [chain("TX1")] }
    expect(reconcile({ ...args, grants: [GRANT] })).toEqual({ ok: true, orphans: [] })
    const other = { ...v, purposeHash: "e".repeat(64) }
    expect(reconcile({ gate: [receipt(other)], sui: [sui("TX1", other)], chain: [chain("TX1")], grants: [GRANT] })).toEqual({ ok: false, orphans: [{ digest: "TX1", reason: "purpose-mismatch" }] })
    expect(reconcile({ ...args, grants: [] })).toEqual({ ok: false, orphans: [{ digest: "TX1", reason: "purpose-mismatch" }] })
  })
})
