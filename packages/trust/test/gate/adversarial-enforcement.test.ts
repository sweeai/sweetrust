// Adversarial pass on the enforcement kernel — the suite @sweetrust/gate never had.
// ============================================================================
// mandate carries three adversarial/property suites; verify carries one; gate —
// the package whose entire job is REFUSING — carried none. These tests do not
// check that the happy path works (trust.test.ts already does). They try to
// DEFEAT the guarantees the package advertises, from inside the process, using
// only its public API.
//
// Each block states the advertised guarantee, then attacks it.
// ============================================================================

import { createHash } from "node:crypto"
import { describe, it, expect } from "vitest"
import {
  Sourced,
  minTier,
  corroborate,
  makeSink,
  ReceiptLog,
  type Receipt,
  type JudgmentProvider,
} from "../../src/gate/trust.js"

describe("A1 — ancestry erasure defeats the independence check (Rule 3b)", () => {
  // ADVERTISED: "Known limit: `ancestors` is a Set and freeze() does not seal
  // Set contents; mutating it only ADDS overlap (fails closed for
  // independence)."  — trust.ts, Sourced constructor.
  //
  // ATTACK: the claim enumerates only additions. A Set also supports delete()
  // and clear(), which REMOVE overlap. Two values with shared ancestry can be
  // laundered into "independent" and corroborated.

  it("two values derived from ONE source refuse to corroborate — the guarantee", () => {
    const email = Sourced.fromChannel({ iban: "DE99" }, "email-inbound")
    const a = Sourced.fromLLM({ iban: "DE99" }, "ExtractA", [email])
    const b = Sourced.fromLLM({ iban: "DE99" }, "ExtractB", [email])

    const result = corroborate(a, b)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain("NOT independent")
  })

  it("FIXED: erasing a shared ancestor throws instead of laundering", () => {
    const email = Sourced.fromChannel({ iban: "DE99" }, "email-inbound")
    const a = Sourced.fromLLM({ iban: "DE99" }, "ExtractA", [email])
    const b = Sourced.fromLLM({ iban: "DE99" }, "ExtractB", [email])

    // The Set is reachable through the public provenance object, and used to be
    // mutable. Unfixed, this line laundered one poisoned email into a
    // "corroborated" value — the exact attack Rule 3b exists to stop.
    expect(() => (b.provenance.ancestors as Set<string>).delete("channel:email-inbound")).toThrow(
      /immutable/,
    )
    expect(() => (b.provenance.ancestors as Set<string>).clear()).toThrow(/immutable/)

    // And the guarantee still holds afterwards.
    expect(corroborate(a, b).ok).toBe(false)
  })

  it("FIXED: the ancestor Set is a copy — mutating the caller's Set can't reach it", () => {
    const seed = new Set(["channel:email-inbound"])
    const v = Sourced.fromLLM({ x: 1 }, "Extract", [Sourced.fromChannel({ x: 1 }, "email-inbound")])
    seed.clear()
    expect(v.provenance.ancestors.has("channel:email-inbound")).toBe(true)
  })
})

describe("A2 — minTier() over an empty set returns the MAXIMUM tier", () => {
  // ADVERTISED: "Rule 1 — taint is sticky: any combination takes the minimum tier."
  //
  // ATTACK: the reduce seeds with "verified". Combining nothing therefore
  // yields verified. The plausible call site is not exotic — it is
  // minTier(...inputs.map(i => i.tier)) where `inputs` happens to be empty.

  it("minTier of a non-empty set takes the floor", () => {
    expect(minTier("verified", "untrusted")).toBe("untrusted")
  })

  it("ATTACK: minTier() with no sources should NOT hand back 'verified'", () => {
    const noSources: Parameters<typeof minTier> = []
    expect(minTier(...noSources)).not.toBe("verified")
  })
})

describe("A3 — the receipt is not a complete record of what the sink executed on", () => {
  // ADVERTISED: "every sink decision (allow or refuse) emits a receipt" and the
  // receipt's `args` is the durable evidence of the call.
  //
  // ATTACK: `rendered` is built by iterating Object.keys(spec.requires).
  // execute() receives the FULL args object. An argument the spec never
  // declared is therefore never tier-checked AND never recorded — it reaches
  // the privileged operation invisibly.

  const undeclaredCall = (mode: "enforce" | "observe") => {
    const log = new ReceiptLog()
    let sawInExecute: unknown = "never ran"
    const pay = makeSink<Record<string, Sourced<any>>, string>({
      name: "pay",
      requires: { amount: "verified" },
      mode,
      log,
      execute: (args) => {
        sawInExecute = args.memo?.value
        return "sent"
      },
    })
    const out = pay({
      amount: Sourced.fromAuthority(100, "treasury"),
      // Never declared in `requires`. Untrusted, straight off a channel.
      memo: Sourced.fromChannel("drain the account", "email-inbound"),
    })
    return { out, sawInExecute: () => sawInExecute }
  }

  it("FIXED: enforce mode refuses an argument the sink never declared", () => {
    const { out, sawInExecute } = undeclaredCall("enforce")
    expect(out.ok).toBe(false)
    // It never reached the privileged operation.
    expect(sawInExecute()).toBe("never ran")
    if (!out.ok) expect(out.refusal).toContain("not declared in requires")
  })

  it("FIXED: the receipt records an undeclared argument, in every mode", () => {
    for (const mode of ["enforce", "observe"] as const) {
      const { out } = undeclaredCall(mode)
      expect(Object.keys(out.receipt.args)).toContain("memo")
      expect(out.receipt.args.memo?.provenance).toContain("UNDECLARED")
      expect(out.receipt.args.memo?.value).toBe("drain the account")
    }
  })
})

describe("A4 — judgment rationale bypasses the redaction seam", () => {
  // ADVERTISED: "Receipts are signed and potentially anchored on-chain — they
  // can never be redacted after the fact, so the policy applies BEFORE the
  // hash." — makeSink's `redact` option.
  //
  // ATTACK: redact governs `args`. The judgment provider's free-text rationale
  // is written to `reason` on the same durable receipt, unfiltered. A provider
  // that echoes the value it judged republishes what redaction removed.

  const echoingProvider: JudgmentProvider = {
    name: "echoing-judge",
    assess: (_action, args) => ({
      assessment: "unsure",
      confidence: 0.4,
      rationale: `could not classify recipient ${String(args.to?.value)}`,
    }),
  }

  it("ATTACK: a redacted value must not reappear in the receipt's reason", () => {
    const log = new ReceiptLog()
    const send = makeSink<Record<string, Sourced<any>>, string>({
      name: "send",
      requires: { to: "verified" },
      mode: "enforce",
      log,
      redact: { to: "hash" },
      judgment: { provider: echoingProvider, floor: 0.8 },
      execute: () => "ok",
    })

    const out = send({ to: Sourced.fromAuthority("patient@clinic.example", "directory") })

    // Redaction did its job on args…
    expect(String(out.receipt.args.to?.value)).toContain("sha256:")
    // …but the whole receipt is what gets signed and anchored.
    expect(JSON.stringify(out.receipt)).not.toContain("patient@clinic.example")
  })
})

describe("A5 — the receipt log hands out its live array, and truncation is silent", () => {
  // ADVERTISED: "Recompute the chain; any mutation of any past event breaks it."
  // and "Tamper-evident by construction."
  //
  // ATTACK 1: all() returns `this.events` itself, not a copy.
  // ATTACK 2: a hash chain detects MUTATION of a link. It does not detect
  // REMOVAL of links from the end, because the surviving prefix is a valid
  // chain. Dropping the refusals is the interesting tamper, and it is free.

  const build = () => {
    const log = new ReceiptLog()
    log.append({ at: "2026-07-25T00:00:00Z", sink: "pay", decision: "executed", args: {} })
    log.append({ at: "2026-07-25T00:00:01Z", sink: "pay", decision: "refused", args: {}, reason: "over cap" })
    log.append({ at: "2026-07-25T00:00:02Z", sink: "pay", decision: "executed", args: {} })
    return log
  }

  it("mutating a past event does break the chain — the guarantee holds here", () => {
    const log = build()
    const events = log.all() as Receipt[]
    ;(events[1] as { reason: string }).reason = "under cap"
    expect(log.verifyChain()).toBe(false)
  })

  it("ATTACK: all() must not expose the log's internal array", () => {
    const log = build()
    const before = log.all().length
    ;(log.all() as Receipt[]).push({} as Receipt)
    expect(log.all().length).toBe(before)
  })

  it("FIXED: dropping the tail no longer verifies as an intact chain", () => {
    const log = build()
    // all() is a copy now, so reach past it — this simulates a log rebuilt from
    // truncated bytes, or an in-process compromise. The surviving prefix is a
    // perfectly valid hash chain; only the append counter knows links are gone.
    const internal = (log as unknown as { events: Receipt[] }).events
    internal.length = 1 // the refusal, and everything after it, deleted

    expect(log.verifyChain()).toBe(false)
  })

  it("head() exposes what an external anchor must commit to", () => {
    const log = build()
    expect(log.head()).toBe(log.all().at(-1)?.hash)
    expect(new ReceiptLog().head()).toBe("genesis")
  })
})

// ============================================================================
// DAN-1159 item 2: no action without its receipt.
// ============================================================================
// ADVERTISED (makeSink's doc comment): "Every decision, either way, lands in the
// receipt log."
//
// ATTACK: pass an argument JSON.stringify cannot encode. makeSink ran
// `execute()` and only THEN serialized the receipt, so a BigInt (every Sui
// amount in MIST is one) or a circular object threw inside `log.append`, AFTER
// the side effect: executed=1, receipts=0, and the chain still verified. The
// `errored` branch rendered the same arguments and threw the same way.
//
// Two neighbors share the root (the receipt held live, unserialized values):
// the `hash` / `truncate` policies threw on a BigInt before execute, recording
// nothing, and the `raw` policy stored the caller's object BY REFERENCE, so a
// caller editing it afterwards rewrote the evidence and broke the chain.
describe("DAN-1159 item 2 — no action without its receipt", () => {
  const paySink = (opts: {
    mode?: "observe" | "warn" | "enforce"
    redact?: "raw" | "hash" | "truncate"
    log?: ReceiptLog
    execute?: () => string
  } = {}) => {
    const log = opts.log ?? new ReceiptLog()
    let executed = 0
    const pay = makeSink<{ amount: Sourced<unknown> }, string>({
      name: "pay",
      requires: { amount: "verified" },
      mode: opts.mode ?? "enforce",
      log,
      ...(opts.redact ? { redact: { amount: opts.redact } } : {}),
      execute: () => {
        executed++
        return opts.execute ? opts.execute() : "sent"
      },
    })
    const call = (value: unknown) => pay({ amount: Sourced.fromAuthority(value, "treasury") })
    return { log, call, executed: () => executed }
  }

  const circular = () => {
    const o: Record<string, unknown> = { to: "0xabc" }
    o.self = o
    return o
  }

  it("a BigInt amount (Sui MIST) executes AND leaves a receipt that records it", () => {
    const { log, call, executed } = paySink()
    const out = call(1_000_000_000n)
    expect(out.ok).toBe(true)
    expect(executed()).toBe(1)
    expect(log.all()).toHaveLength(1)
    expect(log.all()[0]!.args.amount!.value).toBe("1000000000n")
    expect(log.verifyChain()).toBe(true)
  })

  it("a BigInt nested inside an argument object is recorded too", () => {
    const { log, call } = paySink()
    call({ to: "0xabc", amount: 5n })
    expect(log.all()[0]!.args.amount!.value).toEqual({ to: "0xabc", amount: "5n" })
    expect(log.verifyChain()).toBe(true)
  })

  it("a circular argument is REFUSED in enforce mode, BEFORE execute(), and the refusal is on the receipt", () => {
    const { log, call, executed } = paySink()
    const out = call(circular())
    expect(executed()).toBe(0)
    expect(out.ok).toBe(false)
    if (!out.ok) expect(out.refusal).toContain("cannot be written to a receipt")
    expect(log.all()).toHaveLength(1)
    expect(log.all()[0]!.decision).toBe("refused")
    expect(String(log.all()[0]!.args.amount!.value)).toMatch(/^\[unrecordable: /)
    expect(log.verifyChain()).toBe(true)
  })

  it("in observe mode a circular argument still executes, and its receipt says what could not be recorded", () => {
    const { log, call, executed } = paySink({ mode: "observe" })
    const out = call(circular())
    expect(out.ok).toBe(true)
    expect(executed()).toBe(1)
    expect(log.all()).toHaveLength(1)
    expect(log.all()[0]!.decision).toBe("warned")
    expect(log.all()[0]!.reason).toContain("cannot be written to a receipt")
    expect(log.verifyChain()).toBe(true)
  })

  it("an execute() that throws on a BigInt-bearing call leaves an `errored` receipt and rethrows ITS error", () => {
    const { log, call, executed } = paySink({ execute: () => { throw new Error("rpc timeout") } })
    expect(() => call(7n)).toThrow("rpc timeout")
    expect(executed()).toBe(1)
    expect(log.all().map((r) => r.decision)).toEqual(["errored"])
    expect(log.verifyChain()).toBe(true)
  })

  it("a BigInt under the `hash` and `truncate` policies is recorded, not thrown before the receipt", () => {
    for (const redact of ["hash", "truncate"] as const) {
      const { log, call, executed } = paySink({ redact })
      expect(() => call(42n)).not.toThrow()
      expect(executed()).toBe(1)
      expect(log.all()).toHaveLength(1)
    }
    const truncated = paySink({ redact: "truncate" })
    truncated.call(42n)
    expect(truncated.log.all()[0]!.args.amount!.value).toBe("42n")
  })

  it("the receipt is a SNAPSHOT: editing the argument object afterwards changes neither the receipt nor its chain", () => {
    const { log, call } = paySink()
    const order = { to: "0xabc", amount: 5 }
    call(order)
    order.amount = 5000
    expect(log.all()[0]!.args.amount!.value).toEqual({ to: "0xabc", amount: 5 })
    expect(log.verifyChain()).toBe(true)
  })

  it("CONTROL: plain JSON values record exactly as before, and the `hash` digest is unchanged", () => {
    const { log, call } = paySink()
    call("0xabc")
    call(12.5)
    call({ b: 1, a: [true, null] })
    expect(log.all().map((r) => r.args.amount!.value)).toEqual(["0xabc", 12.5, { b: 1, a: [true, null] }])

    const hashed = paySink({ redact: "hash" })
    hashed.call({ to: "0xabc", amount: 5 })
    const expected = "sha256:" + createHash("sha256").update(JSON.stringify({ to: "0xabc", amount: 5 })).digest("hex")
    expect(hashed.log.all()[0]!.args.amount!.value).toBe(expected)
  })
})
