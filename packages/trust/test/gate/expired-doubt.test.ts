/**
 * A doubted action needs its owner (DAN-1443, amending ADR 0010). Waiting out a
 * hold or a block used to buy a fresh sample of the judge, and a `match` then ran
 * with nobody's approval, so an agent could retry until the judge agreed.
 */
import { generateKeyPairSync, sign } from "node:crypto"
import { afterEach, describe, expect, it, vi } from "vitest"
import { canonicalJSON, sha256Hex } from "../../src/canon.ts"
import { ReceiptLog, Sourced, makeSink, type HeldAction, type JudgmentProvider } from "../../src/gate/index.ts"

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
const granted = (mandateId: string) => ({ purpose: PURPOSE, grantHash: sha256Hex(canonicalJSON({ type: "grant", mandateId, purpose: PURPOSE })) })
const MATCH = { assessment: "match", confidence: 0.95, rationale: "fits" }
const MISMATCH = { assessment: "mismatch", confidence: 0.95, rationale: "not the owner's purpose" }
const UNSURE = { assessment: "unsure", confidence: 0.3, rationale: "ask the owner" }
const NOT_A_VERDICT = "the judge fell over"

const HOLD_MS = 15 * 60_000
const BLOCK_MS = 60 * 60_000
const START = new Date("2026-11-08T00:00:00.000Z")

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
  mode?: "warn" | "enforce"
  key?: string | undefined
  execute?: () => unknown
}
const build = (provider: JudgmentProvider, log = new ReceiptLog(), mandateId = "m1", opts: Opts = {}) => {
  const runs: unknown[] = []
  const sink = makeSink<any, unknown>({
    name: "pay",
    requires: { to: "verified", amount: "verified" },
    mode: opts.mode ?? "enforce",
    log,
    judgment: { provider, floor: 0.7, granted: granted(mandateId), approvalKey: "key" in opts ? opts.key : approvalKey, purposeArgs: { payee: "to", amount: "amount" }, network: "sui:testnet", asset: "0x2::sui::SUI" },
    execute: () => {
      runs.push(1)
      return opts.execute ? opts.execute() : "sent"
    },
  })
  return { sink, log, runs }
}
const V = <T>(v: T) => Sourced.fromAuthority(v, "owner")
const pay = () => ({ to: V("0xutility"), amount: V("5") })
const wait = (ms: number) => vi.setSystemTime(new Date(Date.now() + ms))

afterEach(() => {
  vi.useRealTimers()
})

describe("a doubted action needs its owner", () => {
  const clock = () => vi.useFakeTimers({ toFake: ["Date"], now: START })

  it("an expired scored hold judged match again is held and does not run", async () => {
    clock()
    const p = scripted(UNSURE, MATCH)
    const { sink, runs } = build(p)
    await sink(pay())
    wait(HOLD_MS + 1)
    const r = await sink(pay())
    expect(r.ok).toBe(false)
    expect(r.receipt.decision).toBe("judgment-held")
    expect(p.calls).toBe(2)
    expect(runs).toHaveLength(0)
  })

  it("an expired block judged match again is held and does not run", async () => {
    clock()
    const p = scripted(MISMATCH, MATCH)
    const { sink, runs } = build(p)
    await sink(pay())
    wait(BLOCK_MS + 1)
    const r = await sink(pay())
    expect(r.ok).toBe(false)
    expect(r.receipt.decision).toBe("judgment-held")
    expect(runs).toHaveLength(0)
  })

  it("retrying every window never runs the action", async () => {
    clock()
    const { sink, runs } = build(scripted(UNSURE, MATCH))
    await sink(pay())
    for (let i = 0; i < 20; i++) {
      wait(HOLD_MS + 1)
      expect((await sink(pay())).ok).toBe(false)
    }
    expect(runs).toHaveLength(0)
  })

  it("a hold issued after expiry releases with a fresh owner approval", async () => {
    clock()
    const { sink, runs } = build(scripted(UNSURE, MATCH))
    await sink(pay())
    wait(HOLD_MS + 1)
    const held = await sink(pay())
    if (held.ok || held.held === undefined) throw new Error("expected a hold")
    const released = await sink.resume(pay(), approve(held.held))
    expect(released.ok).toBe(true)
    expect(runs).toHaveLength(1)
  })

  it("an expired hold judged mismatch is blocked", async () => {
    clock()
    const { sink, runs } = build(scripted(UNSURE, MISMATCH))
    await sink(pay())
    wait(HOLD_MS + 1)
    const r = await sink(pay())
    expect(r.receipt.decision).toBe("judgment-blocked")
    expect(runs).toHaveLength(0)
  })

  it("a judge failure leaves no doubt so a later match runs", async () => {
    clock()
    const { sink, runs } = build(scripted(NOT_A_VERDICT, MATCH))
    const first = await sink(pay())
    expect(first.ok).toBe(false)
    expect(first.receipt.verdict?.scored).toBe(false)
    expect((await sink(pay())).ok).toBe(true)
    expect(runs).toHaveLength(1)
  })

  it("an outage after a real doubt does not erase the doubt", async () => {
    clock()
    const { sink, runs } = build(scripted(UNSURE, NOT_A_VERDICT, MATCH))
    await sink(pay())
    wait(HOLD_MS + 1)
    await sink(pay())
    const r = await sink(pay())
    expect(r.ok).toBe(false)
    expect(runs).toHaveLength(0)
  })

  it("a completed action leaves no doubt on the next keyed payment", async () => {
    clock()
    const { sink, runs } = build(scripted(UNSURE, MATCH))
    const held = await sink(pay(), { idempotencyKey: "invoice-1" })
    if (held.ok || held.held === undefined) throw new Error("expected a hold")
    expect((await sink.resume(pay(), approve(held.held), { idempotencyKey: "invoice-1" })).ok).toBe(true)
    expect((await sink(pay(), { idempotencyKey: "invoice-2" })).ok).toBe(true)
    expect(runs).toHaveLength(2)
  })

  it("approving an outage hold does not answer a real doubt on the same action", async () => {
    clock()
    const { sink, runs } = build(scripted(NOT_A_VERDICT, MISMATCH, MATCH))
    const outage = await sink(pay(), { idempotencyKey: "inv-1" })
    if (outage.ok || outage.held === undefined) throw new Error("expected a hold")
    expect((await sink(pay(), { idempotencyKey: "inv-2" })).receipt.decision).toBe("judgment-blocked")
    expect((await sink.resume(pay(), approve(outage.held), { idempotencyKey: "inv-1" })).ok).toBe(true)
    expect(runs).toHaveLength(1)
    // The owner signed the outage hold and never saw the block, so the block still stands.
    expect((await sink(pay(), { idempotencyKey: "inv-3" })).receipt.decision).toBe("judgment-blocked")
    wait(BLOCK_MS + 1)
    expect((await sink(pay(), { idempotencyKey: "inv-4" })).receipt.decision).toBe("judgment-held")
    expect(runs).toHaveLength(1)
  })

  it("the hold written for a doubted match names the earlier doubt", async () => {
    clock()
    const { sink } = build(scripted(MISMATCH, MATCH))
    await sink(pay())
    wait(BLOCK_MS + 1)
    const r = await sink(pay())
    expect(r.receipt.decision).toBe("judgment-held")
    expect(r.receipt.reason).toContain("an earlier judgment-blocked (j, mismatch, conf 0.95) on this action needs its owner")
  })

  it("a late errored receipt from another payment does not erase a doubt", async () => {
    clock()
    let fail!: (e: Error) => void
    const pending = new Promise((_, reject) => { fail = reject })
    const { sink, runs, log } = build(scripted(MATCH, UNSURE, MATCH), new ReceiptLog(), "m1", { execute: () => pending })
    // The sink's promise settles with the payment, so it is left running here.
    const settled = sink(pay(), { idempotencyKey: "inv-1" }).catch(() => undefined)
    await vi.waitFor(() => expect(runs).toHaveLength(1))
    expect((await sink(pay(), { idempotencyKey: "inv-2" })).receipt.decision).toBe("judgment-held")
    fail(new Error("the rail fell over"))
    await settled
    expect(log.all().map((r) => r.decision)).toContain("errored")
    wait(HOLD_MS + 1)
    expect((await sink(pay(), { idempotencyKey: "inv-3" })).ok).toBe(false)
    expect(runs).toHaveLength(1)
  })

  it("a clean run on a warn sink over the same log does not clear a doubt", async () => {
    clock()
    const log = new ReceiptLog()
    const enforce = build(scripted(UNSURE, MATCH), log)
    await enforce.sink(pay(), { idempotencyKey: "inv-1" })
    wait(HOLD_MS + 1)
    expect((await build(scripted(MATCH), log, "m1", { mode: "warn" }).sink(pay(), { idempotencyKey: "inv-2" })).ok).toBe(true)
    // Keyed, so this is answered by the doubt and not by duplicate detection.
    expect((await enforce.sink(pay(), { idempotencyKey: "inv-3" })).receipt.decision).toBe("judgment-held")
    expect(enforce.runs).toHaveLength(0)
  })

  it("without an approval key a doubted action stays held", async () => {
    clock()
    const { sink, runs } = build(scripted(UNSURE, MATCH), new ReceiptLog(), "m1", { key: undefined })
    await sink(pay())
    for (let i = 0; i < 5; i++) {
      wait(HOLD_MS + 1)
      expect((await sink(pay())).receipt.decision).toBe("judgment-held")
    }
    expect(runs).toHaveLength(0)
  })

  it("a new grant starts without the old doubt", async () => {
    clock()
    const log = new ReceiptLog()
    await build(scripted(UNSURE), log, "m1").sink(pay())
    wait(HOLD_MS + 1)
    const fresh = build(scripted(MATCH), log, "m2")
    expect((await fresh.sink(pay())).ok).toBe(true)
    expect(fresh.runs).toHaveLength(1)
  })
})
