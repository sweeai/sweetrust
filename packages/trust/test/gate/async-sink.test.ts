/**
 * The async sink and the async judge (0.6.0, DAN-1205, ADR 0007).
 *
 * Through 0.5.0 `makeSink` returned a function that answered synchronously and
 * `assess` returned a verdict, so no judge behind a network could be asked. A
 * provider that was async anyway was worse than refused: its Promise passed the
 * "is it an object" check, its `assessment` read as undefined, and a confident
 * mismatch EXECUTED, recorded as judgment-flagged (reproduced against 0.5.0 in
 * DAN-1382). These cases pin the replacement:
 *   - one async path, for every sink, on every outcome
 *   - the provider's contract: exactly { purpose, action }, and a signal
 *   - a deadline: the signal fires and a late verdict moves nothing
 *   - no shape of answer reads as a verdict unless it is one
 *   - `execute` is awaited, and its receipt is written before the wait
 *   - nothing is left behind: no rejection unhandled, no timer running
 */
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { afterEach, describe, expect, it, vi } from "vitest"
import { makeSink, mockJudgmentProvider, ReceiptLog, Sourced, type JudgmentProvider, type SinkResult } from "../../src/gate/index.ts"
import { GRANTED } from "../helpers/granted.ts"
import { createTrust, defineCapability, makeInMemoryAuditLive, type GrantorId } from "../../src/mandate/index.ts"

const later = <A>(answer: A, ms = 2) => new Promise<A>((resolve) => setTimeout(() => resolve(answer), ms))
const tick = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms))

const MATCH = { assessment: "match", confidence: 0.9, rationale: "fits" } as const
const MISMATCH = { assessment: "mismatch", confidence: 0.95, rationale: "payee is NOT intended" } as const

const good = () => Sourced.fromAuthority("ACME", "registry")
const bad = () => Sourced.fromLLM("EVIL", "Extract", [])

const provider = (answer: unknown, ms = 1): JudgmentProvider => ({
  name: "j",
  model: "j@1",
  assess: () => later(answer, ms) as never,
})

type Mode = "observe" | "warn" | "enforce"
const judged = (p: JudgmentProvider, opts: { mode?: Mode; timeoutMs?: number; floor?: number; execute?: () => unknown } = {}) => {
  const log = new ReceiptLog()
  const ran = { count: 0 }
  const sink = makeSink<{ to: Sourced<string> }, unknown>({
    name: "pay",
    requires: { to: "verified" },
    mode: opts.mode ?? "enforce",
    log,
    judgment: { provider: p, floor: opts.floor ?? 0.8, granted: GRANTED, ...(opts.timeoutMs === undefined ? {} : { timeoutMs: opts.timeoutMs }) },
    execute:
      opts.execute ??
      (() => {
        ran.count++
        return "sent"
      }),
  })
  return { log, ran, sink }
}
const decisions = (log: ReceiptLog) => log.all().map((r) => r.decision)

/** Every unhandled rejection raised while `run` executes and shortly after. */
const unhandledDuring = async (run: () => Promise<void>): Promise<unknown[]> => {
  const seen: unknown[] = []
  const listener = (reason: unknown) => seen.push(reason)
  process.on("unhandledRejection", listener)
  try {
    await run()
    await tick(10)
  } finally {
    process.off("unhandledRejection", listener)
  }
  return seen
}

afterEach(() => {
  vi.useRealTimers()
})

describe("one async path", () => {
  const unjudged = (execute: () => unknown = () => 1) => makeSink({ name: "x", requires: { to: "verified" }, mode: "enforce", log: new ReceiptLog(), execute })

  it("every sink call returns a real Promise: unjudged, refused, judged", async () => {
    const executed = unjudged()({ to: good() })
    const refused = unjudged()({ to: bad() })
    const blocked = judged(provider(MISMATCH)).sink({ to: good() })
    for (const call of [executed, refused, blocked]) expect(call).toBeInstanceOf(Promise)
    expect(await executed).toMatchObject({ ok: true, result: 1 })
    expect(await refused).toMatchObject({ ok: false })
    expect(await blocked).toMatchObject({ ok: false })
  })

  it("the arguments are read at the call, before any time passes", async () => {
    let reads = 0
    const args = {
      get to() {
        reads++
        return good()
      },
    }
    const pending = judged(provider(MATCH)).sink(args)
    expect(reads).toBe(1)
    await pending
    expect(reads).toBe(1)
  })

  it("a caller who forgets `await` reads no success", async () => {
    const { sink, ran } = judged(provider(MATCH))
    const pending = sink({ to: good() })
    const believed = pending as unknown as SinkResult<unknown>
    expect(believed.ok).not.toBe(true)
    expect((believed as { result?: unknown }).result).toBeUndefined()
    // The SAME call, awaited, is a success: the unawaited read hid a real one.
    expect((await pending).ok).toBe(true)
    expect(ran.count).toBe(1)
  })
})

describe("the 0.5.0 defect: an async provider's Promise read as a verdict (DAN-1382)", () => {
  // TypeScript forbade this shape in 0.5.0 and JavaScript did not. In 0.5.0
  // each of these executed, recorded as judgment-flagged.
  const shapes: Array<[string, JudgmentProvider]> = [
    ["an async function", { name: "j", model: "j@1", assess: async () => MISMATCH }],
    ["a Promise from a plain function", { name: "j", model: "j@1", assess: () => later(MISMATCH) }],
    ["a Promise of a Promise", { name: "j", model: "j@1", assess: () => Promise.resolve(later(MISMATCH)) }],
    ["a non-Promise thenable", { name: "j", model: "j@1", assess: () => ({ then: (ok: (v: unknown) => void) => setTimeout(() => ok(MISMATCH), 1) }) as never }],
  ]

  it.each(shapes)("%s resolving a confident mismatch blocks, and never executes", async (_label, p) => {
    const { sink, ran, log } = judged(p)
    const r = await sink({ to: good() })
    expect(r.ok).toBe(false)
    expect(ran.count).toBe(0)
    expect(decisions(log)).toEqual(["judgment-blocked"])
  })
})

describe("the judge's contract", () => {
  it("(acceptance) an async mismatch above the floor blocks, with the refusal on the receipt", async () => {
    const { sink, ran, log } = judged(provider(MISMATCH, 5))
    const r = await sink({ to: good() })
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(ran.count).toBe(0)
    expect(r.refusal).toContain("stopped by judgment")
    // The refusal goes to the agent: the rationale stays on the receipt (ADR 0010).
    expect(r.refusal).not.toContain("payee is NOT intended")
    expect(r.receipt.decision).toBe("judgment-blocked")
    expect(r.receipt.reason).toContain("judgment-blocked")
    expect(r.receipt.reason).toContain("payee is NOT intended")
    expect(decisions(log)).toEqual(["judgment-blocked"])
    expect(log.verifyChain()).toBe(true)
  })

  it("an async match executes once, and only after the verdict", async () => {
    let answer!: (v: unknown) => void
    const p: JudgmentProvider = { name: "j", model: "j@1", assess: () => new Promise((resolve) => { answer = resolve }) as never }
    const { sink, ran, log } = judged(p)
    const pending = sink({ to: good() })
    await tick(5)
    expect(ran.count).toBe(0)
    expect(log.all()).toHaveLength(0)
    answer(MATCH)
    const r = await pending
    expect(r).toMatchObject({ ok: true, result: "sent" })
    expect(ran.count).toBe(1)
    expect(decisions(log)).toEqual(["attempted", "executed"])
  })

  it("assess receives exactly { purpose, action, trust }, and a signal that has not fired", async () => {
    const calls: Array<{ input: Record<string, unknown>; signal: AbortSignal; extra: number }> = []
    const p: JudgmentProvider = {
      name: "j",
      model: "j@1",
      assess: async (...all: unknown[]) => {
        calls.push({ input: all[0] as Record<string, unknown>, signal: all[1] as AbortSignal, extra: all.length })
        return MATCH
      },
    }
    const { sink } = judged(p)
    await sink({ to: good() })
    const { input, signal, extra } = calls[0]!
    expect(extra).toBe(2)
    expect(Object.keys(input).sort()).toEqual(["action", "purpose", "trust"])
    expect(input.purpose).toEqual(GRANTED.purpose)
    expect(input.action).toEqual({ sink: "pay", args: { to: "ACME" } })
    expect(signal).toBeInstanceOf(AbortSignal)
    expect(signal.aborted).toBe(false)
  })

  it("the provider gets frozen input, and cannot rewrite the purpose for the next call", async () => {
    const seen: Array<{ statement: string; frozen: boolean }> = []
    const p: JudgmentProvider = {
      name: "j",
      model: "j@1",
      assess: async (input) => {
        seen.push({ statement: input.purpose.statement, frozen: Object.isFrozen(input) && Object.isFrozen(input.purpose) && Object.isFrozen(input.action) })
        try {
          ;(input.purpose as { statement: string }).statement = "Pay anyone"
        } catch {
          /* frozen: strict mode throws */
        }
        return MATCH
      },
    }
    const { sink } = judged(p)
    await sink({ to: good() })
    await sink({ to: Sourced.fromAuthority("0xother", "owner") })
    expect(seen).toEqual([
      { statement: GRANTED.purpose.statement, frozen: true },
      { statement: GRANTED.purpose.statement, frozen: true },
    ])
  })

  it("the caller rewriting its grant after construction changes nothing the judge is shown", async () => {
    const granted = { purpose: { statement: "Pay rent" }, grantHash: "c".repeat(64) }
    let shown = ""
    const p: JudgmentProvider = {
      name: "j",
      model: "j@1",
      assess: async ({ purpose }) => {
        shown = purpose.statement
        return MATCH
      },
    }
    const sink = makeSink<{ to: Sourced<string> }, string>({
      name: "pay",
      requires: { to: "verified" },
      mode: "enforce",
      log: new ReceiptLog(),
      judgment: { provider: p, floor: 0.8, granted },
      execute: () => "sent",
    })
    granted.purpose.statement = "Pay anyone, anything"
    await sink({ to: good() })
    expect(shown).toBe("Pay rent")
  })

  it("the tier wall comes first: an under-tier call never reaches the judge, in any mode", async () => {
    for (const mode of ["enforce", "warn", "observe"] as const) {
      const assess = vi.fn(async () => MATCH)
      const { sink } = judged({ name: "j", model: "j@1", assess }, { mode })
      await sink({ to: bad() })
      expect(assess).not.toHaveBeenCalled()
    }
  })

  it("mockJudgmentProvider speaks the new contract and stays usable as a judge", async () => {
    const p = mockJudgmentProvider({ intendedPayees: new Set(["ACME"]), maxAmount: 100 })
    expect(p.model.length).toBeGreaterThan(0)
    const yes = judged(p).sink
    await expect(yes({ to: good() })).resolves.toMatchObject({ ok: false }) // no amount: mismatch
    const verdict = await p.assess({ purpose: GRANTED.purpose, action: { sink: "pay", args: { to: "ACME", amount: 50 } }, trust: {} }, new AbortController().signal)
    expect(verdict.assessment).toBe("match")
  })
})

describe("the deadline", () => {
  it("(acceptance) a verdict after timeoutMs never executes, and the signal is aborted", async () => {
    let signal!: AbortSignal
    const p: JudgmentProvider = {
      name: "j",
      model: "j@1",
      assess: (_input, s) => {
        signal = s
        return later(MATCH, 40)
      },
    }
    const { sink, ran, log } = judged(p, { timeoutMs: 5 })
    const r = await sink({ to: good() })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.refusal).toBe("⚖ pay stopped by judgment")
    expect(r.receipt.reason).toContain("no verdict within 5ms")
    expect(signal.aborted).toBe(true)
    expect(ran.count).toBe(0)
    await tick(60) // well past the late match
    expect(ran.count).toBe(0)
    expect(decisions(log)).toEqual(["judgment-held"])
    expect(log.verifyChain()).toBe(true)
  })

  it("a provider that never resolves ends at the deadline", async () => {
    const { sink, ran, log } = judged({ name: "j", model: "j@1", assess: () => new Promise(() => {}) }, { timeoutMs: 5 })
    const r = await sink({ to: good() })
    expect(r.ok).toBe(false)
    expect(ran.count).toBe(0)
    expect(decisions(log)).toEqual(["judgment-held"])
  })

  it("a provider answering FROM its abort listener is still late", async () => {
    const p: JudgmentProvider = {
      name: "j",
      model: "j@1",
      assess: (_input, signal) =>
        new Promise((resolve) => {
          signal.addEventListener("abort", () => resolve(MATCH))
        }),
    }
    const { sink, ran, log } = judged(p, { timeoutMs: 5 })
    const r = await sink({ to: good() })
    expect(r.ok).toBe(false)
    expect(ran.count).toBe(0)
    expect(decisions(log)).toEqual(["judgment-held"])
  })

  it("an honest provider sees the signal's reason as a timeout", async () => {
    let reason: unknown
    const p: JudgmentProvider = {
      name: "j",
      model: "j@1",
      assess: (_input, signal) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener("abort", () => {
            reason = signal.reason
            reject(signal.reason)
          })
        }),
    }
    const unhandled = await unhandledDuring(async () => {
      const { sink } = judged(p, { timeoutMs: 5 })
      const r = await sink({ to: good() })
      if (!r.ok) expect(r.refusal).toBe("⚖ pay stopped by judgment")
    })
    expect((reason as Error).name).toBe("TimeoutError")
    expect(unhandled).toEqual([])
  })

  it("timeoutMs defaults to 5000", async () => {
    vi.useFakeTimers()
    let signal!: AbortSignal
    const p: JudgmentProvider = {
      name: "j",
      model: "j@1",
      assess: (_input, s) => {
        signal = s
        return new Promise(() => {})
      },
    }
    const { sink } = judged(p)
    let settled = false
    const pending = sink({ to: good() }).then((r) => {
      settled = true
      return r
    })
    await vi.advanceTimersByTimeAsync(4999)
    expect(settled).toBe(false)
    expect(signal.aborted).toBe(false)
    await vi.advanceTimersByTimeAsync(1)
    expect(settled).toBe(true)
    expect(signal.aborted).toBe(true)
    expect((await pending).ok).toBe(false)
  })

  it.each(["observe", "warn"] as const)("in %s a timed-out call runs, flagged, with the signal fired and the failure on the receipt", async (mode) => {
    let signal!: AbortSignal
    const p: JudgmentProvider = {
      name: "j",
      model: "j@1",
      assess: (_input, s) => {
        signal = s
        return new Promise(() => {})
      },
    }
    const { sink, ran, log } = judged(p, { mode, timeoutMs: 5 })
    const r = await sink({ to: good() })
    expect(r.ok).toBe(true)
    expect(ran.count).toBe(1)
    expect(signal.aborted).toBe(true)
    expect(decisions(log)).toEqual(["judgment-flagged"])
    expect(log.all()[0]!.reason).toContain("no verdict within 5ms")
  })

  it("the timer is cleared the moment the judge answers", async () => {
    vi.useFakeTimers()
    const { sink } = judged({ name: "j", model: "j@1", assess: async () => MATCH })
    await sink({ to: good() })
    expect(vi.getTimerCount()).toBe(0)
  })

  it("a judge that throws leaves no timer", async () => {
    vi.useFakeTimers()
    const { sink } = judged({ name: "j", model: "j@1", assess: () => { throw new Error("down") } })
    await sink({ to: good() })
    expect(vi.getTimerCount()).toBe(0)
  })

  // Where the property lives: a Node process that must exit on its own.
  const [major = 0, minor = 0] = process.versions.node.split(".").map(Number)
  const canStripTypes = major >= 23 || (major === 22 && minor >= 6)
  const gateUrl = new URL("../../src/gate/index.ts", import.meta.url).href
  it.skipIf(!canStripTypes)("a process with a long deadline and a fast judge exits at once", () => {
    const script = `
      import { makeSink, ReceiptLog, Sourced } from ${JSON.stringify(gateUrl)}
      const sink = makeSink({
        name: "pay", requires: { to: "verified" }, mode: "enforce", log: new ReceiptLog(),
        judgment: { provider: { name: "j", model: "j@1", assess: async () => ({ assessment: "match", confidence: 0.9, rationale: "ok" }) }, floor: 0.8, timeoutMs: 600000, granted: { purpose: { statement: "s" }, grantHash: "${"a".repeat(64)}" } },
        execute: () => "sent",
      })
      const r = await sink({ to: Sourced.fromAuthority("ACME", "reg") })
      console.log(r.ok)
    `
    const run = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script], {
      encoding: "utf8",
      cwd: fileURLToPath(new URL("../../", import.meta.url)),
      timeout: 20_000,
    })
    expect(run.error).toBeUndefined()
    expect(run.stdout.trim()).toBe("true")
    expect(run.status).toBe(0)
  })
})

describe("no answer, or an answer that is not a verdict, fails closed", () => {
  // DAN-1386: no verdict is doubt, so it holds. It blocked through DAN-1205.
  const heldWith = async (p: JudgmentProvider, text: string | RegExp) => {
    const { sink, ran, log } = judged(p)
    const r = await sink({ to: good() })
    expect(r.ok).toBe(false)
    expect(ran.count).toBe(0)
    expect(decisions(log)).toEqual(["judgment-held"])
    expect(log.all()[0]!.reason).toMatch(text)
  }

  it("a throw before the provider's first await", () => heldWith({ name: "j", model: "j@1", assess: () => { throw new Error("no socket") } }, /no socket/))
  it("a rejected promise", () => heldWith({ name: "j", model: "j@1", assess: async () => { throw new Error("503") } }, /503/))
  it("a rejection with a reason that cannot be rendered", () => heldWith({ name: "j", model: "j@1", assess: () => Promise.reject(Object.create(null)) }, /could not be rendered/))
  it("a thenable whose then throws", () => heldWith({ name: "j", model: "j@1", assess: () => ({ then() { throw new Error("bad then") } }) as never }, /bad then/))

  const malformed: Array<[string, unknown]> = [
    ["an empty object", {}],
    ["an unknown assessment", { assessment: "perhaps", confidence: 0.9, rationale: "" }],
    ["a match with NaN confidence", { assessment: "match", confidence: NaN, rationale: "" }],
    ["a match with confidence 1.5", { assessment: "match", confidence: 1.5, rationale: "" }],
    ["a match with confidence -0.1", { assessment: "match", confidence: -0.1, rationale: "" }],
    ["a match with confidence as a string", { assessment: "match", confidence: "0.9", rationale: "" }],
    ["an array", []],
    ["a string", "match"],
    ["null", null],
    ["a function", () => MATCH],
  ]
  it.each(malformed)("%s", (_label, answer) => heldWith(provider(answer), /gave no verdict/))

  it("a verdict's fields are read once: a getter cannot answer the check with one word and the action with another", async () => {
    let reads = 0
    const flip = {
      get assessment() {
        reads++
        return reads === 1 ? "match" : "mismatch"
      },
      confidence: 0.99,
      rationale: "ok",
    }
    const { sink, ran } = judged(provider(flip))
    const r = await sink({ to: good() })
    expect(reads).toBe(1)
    expect(r.ok).toBe(true)
    expect(ran.count).toBe(1)
  })

  it("a verdict's fields are own keys: a polluted prototype cannot supply a match", async () => {
    Object.defineProperty(Object.prototype, "assessment", { value: "match", configurable: true, enumerable: false })
    Object.defineProperty(Object.prototype, "confidence", { value: 1, configurable: true, enumerable: false })
    try {
      await heldWith(provider({}), /gave no verdict/)
    } finally {
      delete (Object.prototype as Record<string, unknown>).assessment
      delete (Object.prototype as Record<string, unknown>).confidence
    }
  })

  it("a redacting sink withholds the failure text from the receipt, and the refusal never quotes it", async () => {
    const log = new ReceiptLog()
    const sink = makeSink<{ to: Sourced<string> }, string>({
      name: "pay",
      requires: { to: "verified" },
      mode: "enforce",
      log,
      redact: { to: "hash" },
      judgment: { provider: { name: "j", model: "j@1", assess: async () => { throw new Error("cannot score ACME-SECRET") } }, floor: 0.8, granted: GRANTED },
      execute: () => "sent",
    })
    const r = await sink({ to: Sourced.fromAuthority("ACME-SECRET", "registry") })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.refusal).not.toContain("ACME-SECRET")
    expect(JSON.stringify(log.all()[0])).not.toContain("ACME-SECRET")
  })
})

describe("nothing is left behind: the losing side of the race", () => {
  it("a provider that rejects after the deadline raises no unhandled rejection", async () => {
    const unhandled = await unhandledDuring(async () => {
      const { sink, ran } = judged({ name: "j", model: "j@1", assess: () => later(null, 20).then(() => { throw new Error("too late") }) }, { timeoutMs: 2 })
      await sink({ to: good() })
      await tick(40)
      expect(ran.count).toBe(0)
    })
    expect(unhandled).toEqual([])
  })

  it("a provider that resolves after the deadline writes no second receipt", async () => {
    const { sink, log } = judged(provider(MISMATCH, 20), { timeoutMs: 2 })
    await sink({ to: good() })
    await tick(40)
    expect(log.all()).toHaveLength(1)
  })
})

describe("execute is awaited", () => {
  const unjudgedWith = (execute: () => unknown, log = new ReceiptLog()) => ({
    log,
    sink: makeSink<{ to: Sourced<string> }, unknown>({ name: "pay", requires: { to: "verified" }, mode: "enforce", log, execute }),
  })

  it("the caller gets the settled value, not a promise: result is Awaited<R>", async () => {
    const log = new ReceiptLog()
    const sink = makeSink<{ to: Sourced<string> }, Promise<number>>({ name: "pay", requires: { to: "verified" }, mode: "enforce", log, execute: async () => 7 })
    const r = await sink({ to: good() })
    if (!r.ok) throw new Error("refused")
    const n: number = r.result // compile-time: Awaited<Promise<number>> is number
    expect(n).toBe(7)
  })

  it("(pinned) the executed receipt is written the moment execute returns, before its result is awaited", async () => {
    let settle!: (v: string) => void
    const { sink, log } = unjudgedWith(() => new Promise((resolve) => { settle = resolve }))
    const pending = sink({ to: good() })
    await tick(5)
    expect(decisions(log)).toEqual(["executed"]) // the action is still running
    settle("paid")
    await expect(pending).resolves.toMatchObject({ ok: true, result: "paid", receipt: { decision: "executed" } })
    expect(decisions(log)).toEqual(["executed"])
  })

  it("(pinned) a rejection trails: executed first, then errored, and the sink rejects with the same error", async () => {
    const boom = new Error("network down after debit")
    let settle!: (e: Error) => void
    const { sink, log } = unjudgedWith(() => new Promise((_resolve, reject) => { settle = reject }))
    const pending = sink({ to: good() })
    await tick(5)
    expect(decisions(log)).toEqual(["executed"])
    settle(boom)
    await expect(pending).rejects.toBe(boom)
    expect(decisions(log)).toEqual(["executed", "errored"])
    expect(log.all()[1]!.reason).toContain("network down after debit")
    expect(log.verifyChain()).toBe(true)
  })

  it("the same order through the judgment-flagged path", async () => {
    const boom = new Error("rpc timeout")
    const unsure = { assessment: "unsure", confidence: 0.4, rationale: "near the cap" }
    // warn, not enforce: since DAN-1386 an unsure in enforce holds and never runs.
    const { sink, log } = judged(provider(unsure), { mode: "warn", execute: async () => { throw boom } })
    await expect(sink({ to: good() })).rejects.toBe(boom)
    expect(decisions(log)).toEqual(["judgment-flagged", "errored"])
    expect(log.all()[1]!.reason).toContain("near the cap")
  })

  it("a synchronous throw leaves errored alone, with no executed receipt, and rejects with the same error", async () => {
    const boom = new Error("no signer")
    const { sink, log } = unjudgedWith(() => { throw boom })
    await expect(sink({ to: good() })).rejects.toBe(boom)
    expect(decisions(log)).toEqual(["errored"])
  })

  it("a thrown value that cannot be rendered still leaves its receipt and still reaches the caller", async () => {
    const bare = Object.create(null) as object
    const thrown = unjudgedWith(() => { throw bare })
    await expect(thrown.sink({ to: good() })).rejects.toBe(bare)
    expect(decisions(thrown.log)).toEqual(["errored"])
    const rejected = unjudgedWith(() => Promise.reject(bare))
    await expect(rejected.sink({ to: good() })).rejects.toBe(bare)
    expect(decisions(rejected.log)).toEqual(["executed", "errored"])
  })

  it("a log that fails after execute surfaces its own error, and the action's later rejection is not left unhandled", async () => {
    class BrokenLog extends ReceiptLog {
      override append(): never {
        throw new Error("signer offline")
      }
    }
    const unhandled = await unhandledDuring(async () => {
      const sink = makeSink<{ to: Sourced<string> }, Promise<never>>({
        name: "pay",
        requires: { to: "verified" },
        mode: "enforce",
        log: new BrokenLog(),
        execute: () => later(null, 2).then(() => { throw new Error("debit failed") }),
      })
      await expect(sink({ to: good() })).rejects.toThrow("signer offline")
    })
    expect(unhandled).toEqual([])
  })
})

describe("a judged sink is checked at construction", () => {
  const base = (judgment: Record<string, unknown>) =>
    makeSink({ name: "pay", requires: { to: "verified" }, mode: "enforce", log: new ReceiptLog(), execute: () => 1, judgment: judgment as never })
  const p = () => provider(MATCH)

  it("a judged sink with all its parts constructs", () => {
    expect(() => base({ provider: p(), floor: 0.8, granted: GRANTED })).not.toThrow()
    expect(() => base({ provider: p(), floor: 0.8, granted: GRANTED, timeoutMs: 1 })).not.toThrow()
  })

  it.each([
    ["empty", ""],
    ["missing", undefined],
    ["not a string", 7],
  ])("a provider.model that is %s is a TypeError", (_label, model) => {
    expect(() => base({ provider: { name: "j", model, assess: async () => MATCH }, floor: 0.8, granted: GRANTED })).toThrow(TypeError)
    expect(() => base({ provider: { name: "j", model, assess: async () => MATCH }, floor: 0.8, granted: GRANTED })).toThrow(/model/)
  })

  it.each([
    ["absent", undefined],
    ["null", null],
    ["a string", "pay rent"],
    ["without a purpose", { grantHash: "a".repeat(64) }],
    ["with an empty statement", { purpose: { statement: "" }, grantHash: "a".repeat(64) }],
    ["with no hash", { purpose: { statement: "s" } }],
    ["with a hash that is not 64 lowercase hex", { purpose: { statement: "s" }, grantHash: "ABC" }],
    ["with a purpose that is not plain JSON", { purpose: { statement: "s", fields: { payees: [() => 1] } }, grantHash: "a".repeat(64) }],
  ])("judgment.granted %s is a TypeError", (_label, granted) => {
    expect(() => base({ provider: p(), floor: 0.8, granted })).toThrow(TypeError)
    expect(() => base({ provider: p(), floor: 0.8, granted })).toThrow(/granted/)
  })

  it("a polluted Object.prototype.granted does not supply a purpose (I3)", () => {
    Object.defineProperty(Object.prototype, "granted", { value: GRANTED, configurable: true, enumerable: false })
    try {
      expect(() => base({ provider: p(), floor: 0.8 })).toThrow(/granted/)
    } finally {
      delete (Object.prototype as Record<string, unknown>).granted
    }
  })

  // 2 ** 31 is past setTimeout's range: Node clamps it to 1ms, so a generous
  // deadline would silently become a deadline nothing can meet.
  it.each([0, -1, NaN, Infinity, 2 ** 31, "5000", null])("timeoutMs %j is a TypeError", (timeoutMs) => {
    expect(() => base({ provider: p(), floor: 0.8, granted: GRANTED, timeoutMs })).toThrow(TypeError)
    expect(() => base({ provider: p(), floor: 0.8, granted: GRANTED, timeoutMs })).toThrow(/timeoutMs/)
  })

  it("the GrantedPurpose the mandate client hands out is what a judged sink accepts", async () => {
    const Pay = defineCapability("pay")
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({ grantor: "owner" as GrantorId, capabilities: [Pay], rationale: "r", purpose: { statement: "Pay rent", fields: { payees: ["ACME"], maxPerAction: "500" } } })
    let shown = ""
    // DAN-1386: this purpose sets payees and maxPerAction, so the sink must name those args.
    const sink = makeSink<{ to: Sourced<string>; amount: Sourced<string> }, string>({
      name: "pay",
      requires: { to: "verified", amount: "verified" },
      mode: "enforce",
      log: new ReceiptLog(),
      judgment: {
        provider: { name: "j", model: "j@1", assess: async ({ purpose }) => { shown = purpose.statement; return MATCH } },
        floor: 0.8,
        granted: trust.grantedPurpose(org)!,
        purposeArgs: { payee: "to", amount: "amount" },
        network: "sui:testnet",
        asset: "0x2::sui::SUI",
      },
      execute: () => "sent",
    })
    await expect(sink({ to: good(), amount: Sourced.fromAuthority("5", "registry") })).resolves.toMatchObject({ ok: true })
    expect(shown).toBe("Pay rent")
  })

  it("the unjudged sink needs none of it", () => {
    expect(() => makeSink({ name: "x", requires: {}, mode: "enforce", log: new ReceiptLog(), execute: () => 1 })).not.toThrow()
  })
})
