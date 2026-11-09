/**
 * Resume a held action only with one owner-signed approval, usable once
 * (0.6.0, DAN-1387, spec § 3.3 "Resuming", I11).
 *
 * The agent already holds the verdict digest from the held result, so the only
 * thing that may release a hold is a signature it cannot make. These suites
 * walk the check order (signature, then held receipt, then expiry, then action
 * digest, then replay), then the walls that re-run behind it, then the receipt
 * the release leaves.
 */
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto"
import { describe, expect, it } from "vitest"
import { canonicalJSON } from "../../src/canon.ts"
import {
  makeSink,
  ReceiptLog,
  Sourced,
  verdictDigest,
  type Approval,
  type GrantedPurpose,
  type HeldAction,
  type JudgmentProvider,
} from "../../src/gate/index.ts"
import { GRANTED } from "../helpers/granted.ts"

const owner = generateKeyPairSync("ed25519")
const approvalKey = owner.publicKey.export({ format: "der", type: "spki" }).toString("hex")
const stranger = generateKeyPairSync("ed25519").privateKey

const body = (a: Pick<Approval, "verdictDigest" | "actionDigest" | "grantHash" | "expiresAt">, domain = "sweetrust/approval@1") =>
  canonicalJSON({ domain, verdictDigest: a.verdictDigest, actionDigest: a.actionDigest, grantHash: a.grantHash, expiresAt: a.expiresAt })
const signed = (a: Pick<Approval, "verdictDigest" | "actionDigest" | "grantHash" | "expiresAt">, key: KeyObject = owner.privateKey, domain?: string) =>
  sign(null, Buffer.from(body(a, domain)), key).toString("hex")

const inMinutes = (m: number) => new Date(Date.now() + m * 60_000).toISOString()
const approve = (h: HeldAction, expiresAt = inMinutes(1), key: KeyObject = owner.privateKey): Approval => {
  const fields = { verdictDigest: h.verdictDigest, actionDigest: h.actionDigest, grantHash: h.grantHash, expiresAt }
  return { ...fields, signature: signed(fields, key) }
}

const verdictOf = (assessment: string, confidence: number) => ({ assessment, confidence, rationale: `${assessment} at ${confidence}` })
const UNSURE = verdictOf("unsure", 0.5)
const MATCH = verdictOf("match", 0.9)
const MISMATCH = verdictOf("mismatch", 0.9)

const counting = (answer: unknown = UNSURE) => {
  const provider: JudgmentProvider & { calls: number } = {
    name: "judge",
    model: "judge@1",
    calls: 0,
    async assess() {
      provider.calls++
      return answer as never
    },
  }
  return provider
}

interface Opts {
  log?: ReceiptLog
  mode?: "observe" | "warn" | "enforce"
  name?: string
  key?: unknown
  provider?: JudgmentProvider & { calls: number }
  granted?: GrantedPurpose
  judgmentExtra?: Record<string, unknown>
  requires?: Record<string, "untrusted" | "corroborated" | "verified">
  redact?: Record<string, "raw" | "hash" | "truncate">
  execute?: (args: any, ctx: any) => unknown
}
const build = (opts: Opts = {}) => {
  const log = opts.log ?? new ReceiptLog()
  const provider = opts.provider ?? counting()
  const runs: Array<{ args: Record<string, Sourced<unknown>>; ctx: any }> = []
  const sink = makeSink<any, unknown>({
    name: opts.name ?? "pay",
    requires: opts.requires ?? { to: "verified", amount: "verified" },
    mode: opts.mode ?? "enforce",
    log,
    ...(opts.redact === undefined ? {} : { redact: opts.redact }),
    judgment: {
      provider,
      floor: 0.7,
      granted: opts.granted ?? GRANTED,
      ...("key" in opts ? (opts.key === undefined ? {} : { approvalKey: opts.key }) : { approvalKey }),
      ...(opts.judgmentExtra ?? {}),
    } as never,
    execute: (args: any, ctx: any) => {
      runs.push({ args, ctx })
      return opts.execute ? opts.execute(args, ctx) : "sent"
    },
  })
  return { log, runs, sink, provider }
}

const auth = <T>(value: T) => Sourced.fromAuthority(value, "owner")
const args = (to: unknown = "0xabc", amount: unknown = "5") => ({ to: auth(to), amount: auth(amount) })

const held = async (opts: Opts = {}) => {
  const m = build(opts)
  const a = args()
  const r = await m.sink(a)
  if (r.ok || r.held === undefined) throw new Error("the fixture expected a held result")
  return { ...m, a, h: r.held, heldReceipt: r.receipt }
}

const refused = (r: { ok: boolean; refusal?: string; receipt: { decision: string } }, code: string) => {
  expect(r.ok).toBe(false)
  expect(r.refusal).toContain(code)
  expect(r.receipt.decision).toBe("refused")
}

describe("an owner-signed approval releases the held action, once", () => {
  it("runs the frozen values the judge saw, skips the judge, and records the held verdict and the approval", async () => {
    const m = await held()
    const approval = approve(m.h)
    const r = await m.sink.resume(m.a, approval)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.result).toBe("sent")
    expect(r.receipt.decision).toBe("executed")
    expect(m.provider.calls).toBe(1)
    expect(m.runs).toHaveLength(1)
    const { args: ran, ctx } = m.runs[0]!
    expect(Sourced.is(ran.to)).toBe(true)
    expect(ran.to!.tier).toBe("verified")
    expect(ran.to!.value).toBe("0xabc")
    expect(ctx.authorizedBy).toEqual({ verdictDigest: m.h.verdictDigest, paymentDigest: null })
    expect(r.receipt.verdict).toEqual(m.heldReceipt.verdict)
    expect(verdictDigest(r.receipt.verdict!)).toBe(m.h.verdictDigest)
    expect(r.receipt.approval).toEqual(approval)
    expect(Object.keys(r.receipt.approval!).sort()).toEqual(["actionDigest", "expiresAt", "grantHash", "signature", "verdictDigest"])
    expect(m.log.verifyChain()).toBe(true)
  })

  it("the approval is inside the receipt hash", async () => {
    const m = await held()
    const r = await m.sink.resume(m.a, approve(m.h))
    if (!r.ok) throw new Error("expected a release")
    const { receiptBody } = await import("../../src/gate/index.ts")
    const { hash: _hash, approval: _approval, ...rest } = r.receipt
    expect(receiptBody(rest)).not.toBe(receiptBody({ ...rest, approval: r.receipt.approval! }))
  })

  it("a sink called with an approval as a second positional argument does not resume", async () => {
    const m = await held({ provider: counting() })
    const r = await (m.sink as any)(m.a, approve(m.h))
    expect(r.ok).toBe(false)
    expect(r.receipt.decision).toBe("judgment-held")
    // The open hold answered: the second argument is call options, never an approval (ADR 0010).
    expect(m.provider.calls).toBe(1)
    expect(m.runs).toHaveLength(0)
  })

  it("a redacting sink resumes too, and the refusal text carries no value", async () => {
    const m = await held({ redact: { to: "hash" } })
    expect((await m.sink.resume(m.a, approve(m.h))).ok).toBe(true)
    const again = await m.sink.resume(m.a, approve(m.h))
    if (again.ok) throw new Error("expected a refusal")
    refused(again, "approval-replayed")
    expect(again.refusal).not.toContain("0xabc")
    expect(again.receipt.reason).not.toContain("0xabc")
  })

  it("the sink and its resume cannot be replaced", async () => {
    const m = await held()
    expect(Object.isFrozen(m.sink)).toBe(true)
    expect(() => {
      ;(m.sink as any).resume = async () => ({ ok: true })
    }).toThrow(TypeError)
  })
})

describe("I11: one approval, one execution", () => {
  it("the same approval again is approval-replayed", async () => {
    const m = await held()
    const approval = approve(m.h)
    expect((await m.sink.resume(m.a, approval)).ok).toBe(true)
    const again = await m.sink.resume(m.a, approval)
    refused(again, "approval-replayed")
    expect(m.runs).toHaveLength(1)
  })

  it("a fresh approval for the same verdict is approval-replayed", async () => {
    const m = await held()
    expect((await m.sink.resume(m.a, approve(m.h))).ok).toBe(true)
    refused(await m.sink.resume(m.a, approve(m.h, inMinutes(2))), "approval-replayed")
    expect(m.runs).toHaveLength(1)
  })

  it("two concurrent resumes execute exactly once, even when execute is slow", async () => {
    const m = await held({ execute: () => new Promise((resolve) => setTimeout(() => resolve("sent"), 20)) })
    const approval = approve(m.h)
    const results = await Promise.all([m.sink.resume(m.a, approval), m.sink.resume(m.a, approval), m.sink.resume(m.a, approval)])
    expect(m.runs).toHaveLength(1)
    expect(results.filter((r) => r.ok)).toHaveLength(1)
    for (const r of results.filter((x) => !x.ok)) refused(r, "approval-replayed")
    expect(m.log.all().filter((x) => x.decision === "executed")).toHaveLength(1)
  })

  it("a second sink over the same log refuses by reading the executed receipt", async () => {
    const log = new ReceiptLog()
    const m = await held({ log })
    expect((await m.sink.resume(m.a, approve(m.h))).ok).toBe(true)
    const twin = build({ log })
    refused(await twin.sink.resume(m.a, approve(m.h)), "approval-replayed")
    expect(twin.runs).toHaveLength(0)
  })

  it("one approval, one attempt: a synchronous throw burns it, and it is on the errored receipt", async () => {
    const m = await held({
      execute: () => {
        throw new Error("rpc down")
      },
    })
    await expect(m.sink.resume(m.a, approve(m.h))).rejects.toThrow("rpc down")
    const errored = m.log.all().at(-1)!
    expect(errored.decision).toBe("errored")
    expect(errored.approval?.verdictDigest).toBe(m.h.verdictDigest)
    expect(verdictDigest(errored.verdict!)).toBe(m.h.verdictDigest)
    refused(await m.sink.resume(m.a, approve(m.h)), "approval-replayed")
    expect(m.runs).toHaveLength(1)
    // A second sink has no claim set: it reads the same fact from the log.
    const twin = build({ log: m.log })
    refused(await twin.sink.resume(m.a, approve(m.h)), "approval-replayed")
    expect(twin.runs).toHaveLength(0)
  })

  it("one approval, one attempt: a rejected action is not retried", async () => {
    const m = await held({ execute: () => Promise.reject(new Error("settled unknown")) })
    await expect(m.sink.resume(m.a, approve(m.h))).rejects.toThrow("settled unknown")
    expect(m.log.all().map((r) => r.decision)).toEqual(["judgment-held", "attempted", "executed", "errored"])
    expect(m.log.all().at(-1)!.approval).toBeDefined()
    refused(await m.sink.resume(m.a, approve(m.h)), "approval-replayed")
    expect(m.runs).toHaveLength(1)
  })

  it("two holds are two verdicts: each approval releases only its own", async () => {
    const m = build({ provider: counting() })
    const a = args("0xabc", "5")
    const b = args("0xabc", "6")
    const first = await m.sink(a)
    const second = await m.sink(b)
    if (first.ok || second.ok || !first.held || !second.held) throw new Error("expected two holds")
    expect(first.held.verdictDigest).not.toBe(second.held.verdictDigest)
    expect((await m.sink.resume(a, approve(first.held))).ok).toBe(true)
    refused(await m.sink.resume(a, approve(first.held)), "approval-replayed")
    expect((await m.sink.resume(b, approve(second.held))).ok).toBe(true)
    expect(m.runs).toHaveLength(2)
  })
})

describe("approval-unsigned: only the owner's key, over exactly the signed body", () => {
  const cases: Array<[string, (h: HeldAction) => unknown]> = [
    ["a stranger's key", (h) => approve(h, inMinutes(1), stranger)],
    ["an empty signature", (h) => ({ ...approve(h), signature: "" })],
    ["all zeroes", (h) => ({ ...approve(h), signature: "0".repeat(128) })],
    ["uppercase hex of a good signature", (h) => { const a = approve(h); return { ...a, signature: a.signature.toUpperCase() } }],
    ["a signature one byte short", (h) => { const a = approve(h); return { ...a, signature: a.signature.slice(2) } }],
    ["a signature with a trailing newline", (h) => { const a = approve(h); return { ...a, signature: `${a.signature}\n` } }],
    ["a signature with hex junk appended", (h) => { const a = approve(h); return { ...a, signature: `${a.signature}zz` } }],
    ["another domain", (h) => { const f = { verdictDigest: h.verdictDigest, actionDigest: h.actionDigest, grantHash: h.grantHash, expiresAt: inMinutes(1) }; return { ...f, signature: signed(f, owner.privateKey, "sweetrust/receipt@1") } }],
    ["a changed verdictDigest", (h) => ({ ...approve(h), verdictDigest: "c".repeat(64) })],
    ["a changed actionDigest", (h) => ({ ...approve(h), actionDigest: "c".repeat(64) })],
    ["a changed grantHash", (h) => ({ ...approve(h), grantHash: "c".repeat(64) })],
    ["a changed expiresAt", (h) => ({ ...approve(h), expiresAt: inMinutes(9) })],
    ["an uppercase digest, signed as given", (h) => { const f = { verdictDigest: h.verdictDigest.toUpperCase(), actionDigest: h.actionDigest, grantHash: h.grantHash, expiresAt: inMinutes(1) }; return { ...f, signature: signed(f) } }],
    ["a short digest, signed as given", (h) => { const f = { verdictDigest: h.verdictDigest.slice(1), actionDigest: h.actionDigest, grantHash: h.grantHash, expiresAt: inMinutes(1) }; return { ...f, signature: signed(f) } }],
    ["an extra field", (h) => ({ ...approve(h), note: "ride along" })],
    ["a numeric expiresAt", (h) => ({ ...approve(h), expiresAt: Date.now() + 60_000 })],
    ["a missing field", (h) => { const { grantHash: _g, ...rest } = approve(h); return rest }],
    ["an inherited signature", (h) => { const { signature, ...rest } = approve(h); return Object.assign(Object.create({ signature }), rest) }],
    ["a getter signature", (h) => { const a = approve(h); return Object.defineProperty({ ...a }, "signature", { get: () => a.signature, enumerable: true }) }],
    ["null", () => null],
    ["undefined", () => undefined],
    ["a string", () => "approved"],
    ["an array", () => []],
    ["true", () => true],
    ["a class instance", (h) => { const a = approve(h); class C { verdictDigest = a.verdictDigest; actionDigest = a.actionDigest; grantHash = a.grantHash; expiresAt = a.expiresAt; signature = a.signature } return new C() }],
  ]

  it.each(cases)("%s", async (_label, make) => {
    const m = await held()
    refused(await m.sink.resume(m.a, make(m.h) as Approval), "approval-unsigned")
    expect(m.runs).toHaveLength(0)
    // The real owner's approval is still good: a forgery burns nothing.
    expect((await m.sink.resume(m.a, approve(m.h))).ok).toBe(true)
  })

  it("a sink without an approvalKey refuses every resume", async () => {
    const m = await held({ key: undefined })
    refused(await m.sink.resume(m.a, approve(m.h)), "approval-unsigned")
    expect(m.runs).toHaveLength(0)
  })

  it("an unjudged sink has a resume, and it refuses", async () => {
    const log = new ReceiptLog()
    let runs = 0
    const sink = makeSink<any, unknown>({ name: "pay", requires: { to: "verified" }, mode: "enforce", log, execute: () => runs++ })
    const fake: HeldAction = { verdictDigest: "a".repeat(64), actionDigest: "b".repeat(64), grantHash: "c".repeat(64) }
    refused(await sink.resume({ to: auth("0xabc") }, approve(fake)), "approval-unsigned")
    expect(runs).toBe(0)
  })

  it("a signature check runs before anything else is believed", async () => {
    const m = await held()
    const r = await m.sink.resume(m.a, { ...approve(m.h), verdictDigest: "f".repeat(64), expiresAt: "not a date" })
    refused(r, "approval-unsigned")
  })
})

describe("approval-mismatch: the approval must name a hold this sink recorded", () => {
  it("a verdict digest that was never held here", async () => {
    const m = await held()
    const invented: HeldAction = { ...m.h, verdictDigest: "e".repeat(64) }
    refused(await m.sink.resume(m.a, approve(invented)), "approval-mismatch")
    expect(m.runs).toHaveLength(0)
  })

  it("a hold recorded in another log", async () => {
    const a = await held()
    const b = build()
    refused(await b.sink.resume(a.a, approve(a.h)), "approval-mismatch")
    expect(b.runs).toHaveLength(0)
  })

  it("a hold recorded under another sink name in the same log", async () => {
    const log = new ReceiptLog()
    const a = await held({ log, name: "pay" })
    const b = build({ log, name: "refund" })
    refused(await b.sink.resume(a.a, approve(a.h)), "approval-mismatch")
    expect(b.runs).toHaveLength(0)
  })

  it("a hold recorded under another grant in the same log", async () => {
    const log = new ReceiptLog()
    const a = await held({ log })
    const other: GrantedPurpose = { purpose: GRANTED.purpose, grantHash: "9".repeat(64) }
    const b = build({ log, granted: other })
    refused(await b.sink.resume(a.a, approve(a.h)), "approval-mismatch")
    refused(await b.sink.resume(a.a, approve({ ...a.h, grantHash: other.grantHash })), "approval-mismatch")
    expect(b.runs).toHaveLength(0)
  })

  it("a confident mismatch was blocked, not held: an owner signature cannot release it", async () => {
    const m = build({ provider: counting(MISMATCH) })
    const a = args()
    const r = await m.sink(a)
    if (r.ok) throw new Error("expected a block")
    expect(r.receipt.decision).toBe("judgment-blocked")
    const v = r.receipt.verdict!
    refused(await m.sink.resume(a, approve({ verdictDigest: verdictDigest(v), actionDigest: v.actionDigest, grantHash: v.grantHash })), "approval-mismatch")
    expect(m.runs).toHaveLength(0)
  })

  it("a verdict that already executed on a match was never held", async () => {
    const m = build({ provider: counting(MATCH) })
    const a = args()
    const r = await m.sink(a)
    if (!r.ok) throw new Error("expected a run")
    const v = r.receipt.verdict!
    refused(await m.sink.resume(a, approve({ verdictDigest: verdictDigest(v), actionDigest: v.actionDigest, grantHash: v.grantHash })), "approval-mismatch")
    expect(m.runs).toHaveLength(1)
  })

  it("an approval naming another action digest than the held verdict", async () => {
    const m = await held()
    refused(await m.sink.resume(m.a, approve({ ...m.h, actionDigest: "d".repeat(64) })), "approval-mismatch")
    expect(m.runs).toHaveLength(0)
  })

  it("an approval naming another grant hash than the held verdict", async () => {
    const m = await held()
    refused(await m.sink.resume(m.a, approve({ ...m.h, grantHash: "d".repeat(64) })), "approval-mismatch")
    expect(m.runs).toHaveLength(0)
  })

  it.each([
    ["another amount", () => args("0xabc", "6")],
    ["another recipient", () => args("0xevil", "5")],
  ])("%s is a new action, refused without judging", async (_label, altered) => {
    const m = await held()
    refused(await m.sink.resume(altered(), approve(m.h)), "approval-mismatch")
    expect(m.runs).toHaveLength(0)
    expect(m.provider.calls).toBe(1)
  })

  it("args that cannot name the held action: not Sourced, missing, or not digestible", async () => {
    const m = await held()
    const shapes: unknown[] = [
      { to: { value: "0xabc", tier: "verified", provenance: { origin: "x", ancestors: new Set(), chain: [] }, describe: () => "verified" }, amount: auth("5") },
      { to: auth("0xabc") },
      { to: auth({ fn: () => 1 }), amount: auth("5") },
    ]
    for (const bad of shapes) refused(await m.sink.resume(bad as never, approve(m.h)), "approval-mismatch")
    expect(m.runs).toHaveLength(0)
  })

  it("a hold in an enforce sink cannot be released through a warn or observe sink sharing its log", async () => {
    const log = new ReceiptLog()
    const m = await held({ log })
    for (const mode of ["warn", "observe"] as const) {
      const loose = build({ log, mode })
      refused(await loose.sink.resume(m.a, approve(m.h)), "approval-mismatch")
      expect(loose.runs).toHaveLength(0)
    }
    expect((await m.sink.resume(m.a, approve(m.h))).ok).toBe(true)
  })
})

describe("approval-expired: at most 15 minutes after the hold, and strictly parsed", () => {
  it("a past expiresAt", async () => {
    const m = await held()
    refused(await m.sink.resume(m.a, approve(m.h, inMinutes(-1))), "approval-expired")
    expect(m.runs).toHaveLength(0)
  })

  it("past 15 minutes after the held receipt, even when signed", async () => {
    const m = await held()
    refused(await m.sink.resume(m.a, approve(m.h, inMinutes(16))), "approval-expired")
    expect(m.runs).toHaveLength(0)
  })

  it("exactly 15 minutes after the held receipt is allowed", async () => {
    const m = await held()
    const fifteen = new Date(Date.parse(m.heldReceipt.at) + 15 * 60_000).toISOString()
    expect((await m.sink.resume(m.a, approve(m.h, fifteen))).ok).toBe(true)
  })

  it("one millisecond past 15 minutes is refused", async () => {
    const m = await held()
    const over = new Date(Date.parse(m.heldReceipt.at) + 15 * 60_000 + 1).toISOString()
    refused(await m.sink.resume(m.a, approve(m.h, over)), "approval-expired")
  })

  it.each([
    ["no milliseconds", (t: Date) => t.toISOString().replace(/\.\d{3}Z$/, "Z")],
    ["a space for the T", (t: Date) => t.toISOString().replace("T", " ")],
    ["a numeric offset", (t: Date) => t.toISOString().replace("Z", "+00:00")],
    ["lowercase", (t: Date) => t.toISOString().toLowerCase()],
    ["a date alone", (t: Date) => t.toISOString().slice(0, 10)],
    ["a human date", (t: Date) => t.toUTCString()],
    ["surrounding space", (t: Date) => ` ${t.toISOString()}`],
    ["not a date", () => "soon"],
    ["empty", () => ""],
  ])("a correctly signed but lenient expiresAt: %s", async (_label, render) => {
    const m = await held()
    const t = new Date(Date.now() + 60_000)
    refused(await m.sink.resume(m.a, approve(m.h, render(t))), "approval-expired")
    expect(m.runs).toHaveLength(0)
  })

  it("the order: a signed but expired approval for altered args reports expiry", async () => {
    const m = await held()
    refused(await m.sink.resume(args("0xabc", "6"), approve(m.h, inMinutes(-1))), "approval-expired")
  })

  it("the order: a signed, unexpired approval for a held verdict and altered args reports the mismatch", async () => {
    const m = await held()
    refused(await m.sink.resume(args("0xabc", "6"), approve(m.h)), "approval-mismatch")
  })

  it("the order: a replayed approval that has since expired reports expiry", async () => {
    const m = await held()
    const soonGone = new Date(Date.now() + 15).toISOString()
    expect((await m.sink.resume(m.a, approve(m.h, soonGone))).ok).toBe(true)
    await new Promise((r) => setTimeout(r, 20))
    refused(await m.sink.resume(m.a, approve(m.h, soonGone)), "approval-expired")
  })
})

describe("steps 1 and 2 re-run: an approval never launders a violation", () => {
  it("an under-tier value equal to the held one is refused by the tier wall, and the approval survives", async () => {
    const m = await held()
    const approval = approve(m.h)
    const downgraded = { to: Sourced.fromChannel("0xabc", "email"), amount: auth("5") }
    const r = await m.sink.resume(downgraded, approval)
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.receipt.decision).toBe("refused")
    expect(r.refusal).toContain("to requires verified")
    expect(m.runs).toHaveLength(0)
    expect((await m.sink.resume(m.a, approval)).ok).toBe(true)
    expect(m.runs).toHaveLength(1)
  })

  it("an undeclared argument is refused", async () => {
    const m = await held()
    const r = await m.sink.resume({ ...m.a, memo: auth("hi") }, approve(m.h))
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.refusal).toContain("memo was passed but is not declared")
    expect(m.runs).toHaveLength(0)
  })

  it("a changed purpose under the same grant hash cannot release the hold", async () => {
    const log = new ReceiptLog()
    const fields = (payees: string[]) => ({ purpose: { statement: "s", fields: { payees } }, grantHash: "5".repeat(64) })
    const purposeArgs = { purposeArgs: { payee: "to", amount: "amount" }, network: "sui:testnet", asset: "0x2::sui::SUI" }
    const a = await held({ log, granted: fields(["0xabc"]), judgmentExtra: purposeArgs })
    const b = build({ log, granted: fields(["0xother"]), judgmentExtra: purposeArgs })
    const r = await b.sink.resume(a.a, approve(a.h))
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.receipt.decision).toBe("refused")
    expect(r.refusal).toContain("approval-mismatch")
    expect(b.runs).toHaveLength(0)
  })

  it("a sink whose payment mapping differs cannot release under the held payment digest", async () => {
    const log = new ReceiptLog()
    const fields = { purpose: { statement: "s", fields: { payees: ["0xabc"] } }, grantHash: "5".repeat(64) }
    const a = await held({ log, granted: fields, judgmentExtra: { purposeArgs: { payee: "to", amount: "amount" }, network: "sui:testnet", asset: "0x2::sui::SUI" } })
    const b = build({ log, granted: fields, judgmentExtra: { purposeArgs: { payee: "to", amount: "amount" }, network: "sui:mainnet", asset: "0x2::sui::SUI" } })
    refused(await b.sink.resume(a.a, approve(a.h)), "approval-mismatch")
    expect(b.runs).toHaveLength(0)
  })

  it("execute gets the payment digest of the held verdict", async () => {
    const fields = { purpose: { statement: "s", fields: { payees: ["0xabc"] } }, grantHash: "5".repeat(64) }
    const m = await held({ granted: fields, judgmentExtra: { purposeArgs: { payee: "to", amount: "amount" }, network: "sui:testnet", asset: "0x2::sui::SUI" } })
    const r = await m.sink.resume(m.a, approve(m.h))
    if (!r.ok) throw new Error("expected a release")
    expect(m.runs[0]!.ctx.authorizedBy.paymentDigest).toBe(r.receipt.verdict!.paymentDigest)
    expect(r.receipt.verdict!.paymentDigest).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe("the approval key is bound at construction, or the sink does not exist", () => {
  const rsaKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "der", type: "spki" }).toString("hex")
  it.each<[string, unknown]>([
    ["not hex", "not hex"],
    ["empty", ""],
    ["uppercase", approvalKey.toUpperCase()],
    ["truncated", approvalKey.slice(0, -2)],
    ["an RSA key", rsaKey],
    ["a number", 42],
    ["an object", {}],
    ["null", null],
  ])("%s is a TypeError", (_label, key) => {
    expect(() => build({ key })).toThrow(TypeError)
  })

  it("an approvalKey needs a log that can be read back", () => {
    const appendOnly = { append: () => ({}) } as unknown as ReceiptLog
    expect(() => build({ log: appendOnly })).toThrow(TypeError)
    // A judged enforce sink reads its own blocks and attempts back, approval key or not (ADR 0010).
    expect(() => build({ log: appendOnly, key: undefined })).toThrow(TypeError)
    expect(() => build({ log: appendOnly, key: undefined, mode: "warn" })).not.toThrow()
  })

  it("an inherited approvalKey is not an approvalKey", async () => {
    const polluted = Object.create({ approvalKey }) as Record<string, unknown>
    polluted.provider = counting()
    polluted.floor = 0.7
    polluted.granted = GRANTED
    const log = new ReceiptLog()
    let runs = 0
    const sink = makeSink<any, unknown>({ name: "pay", requires: { to: "verified", amount: "verified" }, mode: "enforce", log, judgment: polluted as never, execute: () => runs++ })
    const a = args()
    const r = await sink(a)
    if (r.ok || !r.held) throw new Error("expected a hold")
    refused(await sink.resume(a, approve(r.held)), "approval-unsigned")
    expect(runs).toBe(0)
  })
})
