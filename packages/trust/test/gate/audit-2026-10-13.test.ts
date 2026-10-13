// The 2026-10-13 gate audit — regressions for every finding it closed.
// ============================================================================
// An adversarial pass over the BUILT `dist/gate.mjs`, run against this file's
// predecessor at dbb8d56. Twenty findings: one HIGH, six MEDIUM, the rest LOW
// and documentation. Each block below names the finding, states the guarantee
// that was advertised, and replays the exploit the auditor ran — so the test
// fails against the pre-fix kernel for the auditor's reason, not for a reason
// of its own.
//
// Where a finding changed behaviour on purpose (undeclared arguments no longer
// reach `execute()` in any mode; `observe` labels every receipt `observed`; a
// BigInt renders as `{"$bigint":"…"}`), the test says so and CHANGELOG.md
// carries the entry.
// ============================================================================

import { describe, expect, it } from "vitest"
import { Sourced, corroborate, humanConfirm, makeSink, meetsTier, minTier, ReceiptLog } from "../../src/gate/trust.js"

// ── #1 HIGH — sealAncestors' forEach leaked the raw Set ──────────────────────
// ADVERTISED (sealAncestors): "Seal a Set so the mutators throw while reads
// stay ordinary." A1 proved delete/clear throw when called on the sealed view.
//
// ATTACK: `forEach` was bound to the raw inner Set, and a Set's forEach passes
// the Set itself as the callback's THIRD argument. One line recovered the
// unsealed Set, and delete/add/clear worked on it — the exact laundering A1
// exists to stop, through a door A1's test never opened.
describe("#1 — forEach's third argument is the sealed view, not the raw Set", () => {
  const oneEmailTwoExtractions = () => {
    const email = Sourced.fromChannel({ iban: "DE99" }, "email-inbound")
    const a = Sourced.fromLLM({ iban: "DE99" }, "ExtractA", [email])
    const b = Sourced.fromLLM({ iban: "DE99" }, "ExtractB", [email])
    return { a, b }
  }

  it("the guarantee: two extractions of ONE email refuse to corroborate", () => {
    const { a, b } = oneEmailTwoExtractions()
    expect(corroborate(a, b).ok).toBe(false)
  })

  it("ATTACK: the Set forEach hands back cannot erase a shared ancestor, and corroborate still refuses", () => {
    const { a, b } = oneEmailTwoExtractions()
    let leaked: Set<string> | undefined
    b.provenance.ancestors.forEach((_v, _k, set) => {
      leaked = set as Set<string>
    })
    expect(leaked).toBe(b.provenance.ancestors)
    expect(() => leaked!.delete("channel:email-inbound")).toThrow(/immutable/)
    expect(b.provenance.ancestors.has("channel:email-inbound")).toBe(true)
    // The laundering never happens, so the independence check still fires.
    const r = corroborate(a, b)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain("NOT independent")
  })

  it("forEach still iterates every member, honours thisArg, and the key equals the value", () => {
    const { a } = oneEmailTwoExtractions()
    const seen: Array<[string, string]> = []
    const ctx = { tag: "ctx" }
    a.provenance.ancestors.forEach(function (this: typeof ctx, v, k) {
      expect(this).toBe(ctx)
      seen.push([k, v])
    }, ctx)
    expect(seen.map(([k]) => k).sort()).toEqual(["channel:email-inbound", "llm:ExtractA"])
    for (const [k, v] of seen) expect(k).toBe(v)
  })
})

// ── #19 DOC/HARDENING — "module-private constructor" held only at compile time ─
// ADVERTISED (AGENTS.md, README): "the Sourced constructor and ascend are
// module-private; the three declassifiers are the only doors."
//
// ATTACK: `private` is erased. From JavaScript, `new Sourced(v, "verified",
// prov)` and `class Evil extends Sourced` both minted values that carried the
// `#brand` and cleared an enforce sink; `Sourced.is` was reassignable. The
// constructor now demands a module-private token, and the class and its
// prototype are frozen. The in-process honest limit (an importer can still call
// `fromAuthority("anything")`) stands — this closes the door that bypassed even
// that labelled front door.
describe("#19 — the constructor is private at RUNTIME, not only in the types", () => {
  type AnyCtor = new (...a: unknown[]) => Sourced<unknown>
  const forgedProvenance = () => ({ origin: "channel:email-inbound", ancestors: new Set<string>(), chain: [] })

  it("new Sourced(…) from JavaScript throws TypeError instead of minting", () => {
    const Ctor = Sourced as unknown as AnyCtor
    expect(() => new Ctor("attacker@evil.test", "verified", forgedProvenance())).toThrow(TypeError)
    // The positional guess an attacker makes after reading the .d.mts.
    expect(() => new Ctor(undefined, "attacker@evil.test", "verified", forgedProvenance())).toThrow(TypeError)
    expect(() => new Ctor(Symbol("guess"), "attacker@evil.test", "verified", forgedProvenance())).toThrow(TypeError)
  })

  it("a subclass cannot reach super() either", () => {
    const Base = Sourced as unknown as AnyCtor
    class Evil extends Base {
      constructor() {
        super("x", "verified", forgedProvenance())
      }
    }
    expect(() => new Evil()).toThrow(TypeError)
  })

  it("the class and its prototype are frozen: Sourced.is and describe cannot be swapped", () => {
    expect(Object.isFrozen(Sourced)).toBe(true)
    expect(Object.isFrozen(Sourced.prototype)).toBe(true)
    const original = Sourced.is
    expect(() => {
      ;(Sourced as unknown as { is: unknown }).is = () => true
    }).toThrow(TypeError)
    expect(Sourced.is).toBe(original)
    expect(() => {
      ;(Sourced.prototype as unknown as { describe: unknown }).describe = () => "VERIFIED (forged)"
    }).toThrow(TypeError)
  })

  it("CONTROL: the three factories still construct, and the brand still backs Sourced.is", () => {
    const c = Sourced.fromChannel("x", "email")
    const l = Sourced.fromLLM("x", "Fn", [c], 0.5)
    const a = Sourced.fromAuthority("x", "reg")
    for (const v of [c, l, a]) expect(Sourced.is(v)).toBe(true)
    expect([c.tier, l.tier, a.tier]).toEqual(["untrusted", "untrusted", "verified"])
  })
})

// ── #14 LOW — UpgradeEvent objects inside a frozen chain were mutable ────────
// ADVERTISED: `provenance.chain` is "the audit surface: each tier ascent, in
// order. Append-only." The ARRAY was frozen; the event objects in it were not,
// so `chain[0].declassifier = "humanConfirm"` rewrote what describe() renders
// onto every later receipt while `tier` stayed honest.
describe("#14 — every UpgradeEvent on a chain is frozen", () => {
  const corroborated = () => {
    const c = corroborate(Sourced.fromChannel({ iban: "DE99" }, "email"), Sourced.fromChannel({ iban: "DE99" }, "webhook"))
    if (!c.ok) throw new Error("fixture broke")
    return c.value
  }

  it("the event cannot be rewritten into a different declassifier", () => {
    const v = corroborated()
    const ev = v.provenance.chain[0]!
    expect(Object.isFrozen(ev)).toBe(true)
    expect(() => {
      ;(ev as { declassifier: string }).declassifier = "humanConfirm"
    }).toThrow(TypeError)
    expect(() => {
      ;(ev as { to: string }).to = "verified"
    }).toThrow(TypeError)
    expect(v.describe()).toContain("corroborate→corroborated")
    expect(v.describe()).not.toContain("humanConfirm")
  })

  it("a second ascent copies the chain without thawing the earlier event", () => {
    const h = humanConfirm(corroborated(), () => true)
    expect(h.ok).toBe(true)
    if (!h.ok) return
    expect(h.value.provenance.chain).toHaveLength(2)
    for (const ev of h.value.provenance.chain) expect(Object.isFrozen(ev)).toBe(true)
  })
})

// ── #13 LOW — a null confidence made describe() throw, before any receipt ────
// `confidence` is typed `number | undefined`, but a value rehydrated from JSON
// (or any JS caller) hands `null`. `null !== undefined` is true, so describe()
// called `null.toFixed(2)` — and describe() runs inside the enforce sink's
// declared loop, BEFORE the receipt is written. The sink crashed with no
// evidence of the call; humanConfirm crashed building its question.
describe("#13 — describe() tolerates a non-number confidence", () => {
  const nullConf = () => Sourced.fromLLM("attacker@evil.test", "ExtractPayee", [], null as never)

  it("describe() renders without the confidence instead of throwing", () => {
    expect(() => nullConf().describe()).not.toThrow()
    expect(nullConf().describe()).toContain("UNTRUSTED")
    expect(nullConf().describe()).not.toContain("conf")
  })

  it("an enforce sink refuses it WITH a receipt rather than crashing before one", () => {
    const log = new ReceiptLog()
    let ran = 0
    const pay = makeSink<{ to: Sourced<string> }, string>({
      name: "pay",
      requires: { to: "verified" },
      mode: "enforce",
      log,
      execute: () => {
        ran++
        return "sent"
      },
    })
    const r = pay({ to: nullConf() })
    expect(r.ok).toBe(false)
    expect(ran).toBe(0)
    expect(log.all()).toHaveLength(1)
    expect(log.all()[0]!.decision).toBe("refused")
    expect(log.verifyChain()).toBe(true)
  })

  it("humanConfirm returns a verdict for it", () => {
    expect(() => humanConfirm(nullConf(), () => false)).not.toThrow()
    expect(humanConfirm(nullConf(), () => false).ok).toBe(false)
  })
})

// ── #10 LOW — minTier over a tier string outside the lattice returned the MAXIMUM
// ADVERTISED (Rule 1): "any combination takes the minimum tier", and A2 made
// the empty case floor. But `RANK["bogus"]` is undefined, `undefined < 3` is
// false, and the reduce kept its "verified" seed: `minTier("bogus")` was
// `verified`, and so was `minTier("bogus", "verified")`. Prototype-named
// strings (`"constructor"`, `"__proto__"`) read a function or an object off
// RANK's prototype and compared the same way. The deployment that hits this is
// the one whose tier strings come from JSON.
describe("#10 — any tier outside the lattice floors the combination to untrusted", () => {
  it.each(["bogus", "", "VERIFIED", "Verified", "verified ", "constructor", "__proto__", "toString", "valueOf"])(
    "minTier(%j) and every combination containing it is untrusted",
    (bad) => {
      expect(minTier(bad as never)).toBe("untrusted")
      expect(minTier(bad as never, "verified")).toBe("untrusted")
      expect(minTier("verified", bad as never)).toBe("untrusted")
      expect(minTier("corroborated", bad as never, "verified")).toBe("untrusted")
    },
  )

  it("meetsTier fails closed on an unknown tier on EITHER side", () => {
    for (const bad of ["bogus", "constructor", "__proto__"]) {
      expect(meetsTier(bad as never, "untrusted")).toBe(false)
      expect(meetsTier("verified", bad as never)).toBe(false)
    }
  })

  it("CONTROL: the lattice itself is unchanged", () => {
    expect(minTier("verified", "corroborated")).toBe("corroborated")
    expect(minTier("asserted", "verified", "corroborated")).toBe("asserted")
    expect(minTier("verified")).toBe("verified")
    expect(minTier()).toBe("untrusted")
    expect(meetsTier("verified", "verified")).toBe(true)
  })
})

// ── #11 LOW — append() let the caller's entry override seq / prevHash / hash ─
// `nextReceipt` built `{ seq, prevHash, hash, ...entry }`: the spread came
// LAST, so an entry carrying those three fields replaced the log's own. The
// stored receipt said hash "deadbeef", head() returned it, and verifyChain()
// went false on a log nobody had tampered with after the fact. `Omit<>` hides
// the fields from TypeScript, not from JavaScript.
describe("#11 — the log owns seq, prevHash and hash; an entry cannot supply them", () => {
  it("fields smuggled on the entry are ignored, and the chain still verifies", () => {
    const log = new ReceiptLog()
    const r0 = log.append({ at: "t0", sink: "pay", decision: "executed", args: {} })
    const r1 = log.append({
      at: "t1",
      sink: "pay",
      decision: "executed",
      args: {},
      hash: "deadbeef",
      seq: 0,
      prevHash: "genesis",
    } as never)
    expect(r1.seq).toBe(1)
    expect(r1.prevHash).toBe(r0.hash)
    expect(r1.hash).not.toBe("deadbeef")
    expect(r1.hash).toMatch(/^[0-9a-f]{64}$/)
    expect(log.head()).toBe(r1.hash)
    expect(log.verifyChain()).toBe(true)
    expect(log.all().map((r) => r.seq)).toEqual([0, 1])
  })
})

// ── #12 LOW — all() copied the array but handed out the live Receipt objects ─
// A5 (2026-07-25) made all() return a copy of the ARRAY. The elements were
// still the log's own objects, so a holder could edit a receipt in place. The
// sharp version: swap `args` for `{ toJSON: () => original }` — the in-memory
// receipt no longer carries the argument, yet receiptBody() still serializes
// the original and verifyChain() stays green. Receipts are now deep-frozen at
// commit; what append() returns and what all() hands out is the same frozen
// object, and nothing holding it can change what the log says.
describe("#12 — a committed receipt is deep-frozen", () => {
  const paid = () => {
    const log = new ReceiptLog()
    const pay = makeSink<{ to: Sourced<string> }, string>({
      name: "pay",
      requires: { to: "verified" },
      mode: "enforce",
      log,
      execute: () => "sent",
    })
    const r = pay({ to: Sourced.fromAuthority("ACME", "reg") })
    return { log, receipt: r.receipt }
  }

  it("the receipt, its args bag and each argument record are frozen", () => {
    const { log, receipt } = paid()
    expect(Object.isFrozen(receipt)).toBe(true)
    expect(Object.isFrozen(receipt.args)).toBe(true)
    expect(Object.isFrozen(receipt.args.to)).toBe(true)
    expect(log.all()[0]).toBe(receipt) // one object, not a copy that could drift
    expect(Object.isFrozen(log.all()[0])).toBe(true)
  })

  it("ATTACK: the toJSON swap that kept the chain green while hiding the argument now throws", () => {
    const { log, receipt } = paid()
    const original = receipt.args
    expect(() => {
      ;(receipt as { args: unknown }).args = { toJSON: () => original }
    }).toThrow(TypeError)
    expect(() => {
      ;(receipt as { decision: string }).decision = "refused"
    }).toThrow(TypeError)
    expect(() => {
      ;(receipt.args.to as { value: unknown }).value = "attacker@evil.test"
    }).toThrow(TypeError)
    expect(receipt.args.to!.value).toBe("ACME")
    expect(log.verifyChain()).toBe(true)
  })

  it("a receipt appended directly with nested args is frozen all the way down", () => {
    const log = new ReceiptLog()
    const r = log.append({
      at: "t",
      sink: "s",
      decision: "executed",
      args: { k: { value: { nested: [1, { deep: true }] }, tier: "verified", provenance: "p" } },
    })
    const v = r.args.k!.value as { nested: [number, { deep: boolean }] }
    expect(Object.isFrozen(v)).toBe(true)
    expect(Object.isFrozen(v.nested)).toBe(true)
    expect(Object.isFrozen(v.nested[1])).toBe(true)
  })
})
