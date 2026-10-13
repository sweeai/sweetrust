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

import { createHash } from "node:crypto"
import { describe, expect, it } from "vitest"
import { Sourced, allowlisted, corroborate, humanConfirm, makeSink, meetsTier, minTier, ReceiptLog, type JudgmentProvider } from "../../src/gate/trust.js"

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

// ── #17 LOW — receipt rendering was ambiguous for amounts ───────────────────
// A BigInt was written as its digits plus "n" — the same bytes the STRING
// "5n" produces — and JSON.stringify turns NaN and ±Infinity into `null`, the
// same bytes a literal null produces. A receipt is evidence of what reached the
// sink; two different values must not leave identical evidence. The encoding
// is now `{"$bigint":"5"}` and `{"$number":"NaN"|"Infinity"|"-Infinity"}`.
// Every other value renders byte-identically to before (the DAN-1159 CONTROL
// in adversarial-enforcement.test.ts pins that).
describe("#17 — a BigInt and a non-finite number render unambiguously", () => {
  const sink = (redact?: "raw" | "hash" | "truncate") => {
    const log = new ReceiptLog()
    const pay = makeSink<{ amount: Sourced<unknown> }, string>({
      name: "pay",
      requires: { amount: "verified" },
      mode: "enforce",
      log,
      ...(redact ? { redact: { amount: redact } } : {}),
      execute: () => "ok",
    })
    const call = (v: unknown) => pay({ amount: Sourced.fromAuthority(v, "t") }).receipt.args.amount!.value
    return { log, call }
  }

  it("a bigint and the string that used to collide with it are distinct on the receipt", () => {
    const { log, call } = sink()
    expect(call(5n)).toEqual({ $bigint: "5" })
    expect(call("5n")).toBe("5n")
    expect(call(-7n)).toEqual({ $bigint: "-7" })
    expect(log.verifyChain()).toBe(true)
  })

  it("NaN, Infinity and -Infinity are no longer written as null", () => {
    const { log, call } = sink()
    expect(call(NaN)).toEqual({ $number: "NaN" })
    expect(call(Infinity)).toEqual({ $number: "Infinity" })
    expect(call(-Infinity)).toEqual({ $number: "-Infinity" })
    expect(call(null)).toBe(null)
    expect(call({ amount: NaN, memo: 5n })).toEqual({ amount: { $number: "NaN" }, memo: { $bigint: "5" } })
    expect(log.verifyChain()).toBe(true)
  })

  it("the hash and truncate policies use the same encoding", () => {
    const hashed = sink("hash")
    expect(hashed.call(42n)).toBe("sha256:" + createHash("sha256").update('{"$bigint":"42"}').digest("hex"))
    expect(hashed.call(NaN)).toBe("sha256:" + createHash("sha256").update('{"$number":"NaN"}').digest("hex"))
    const truncated = sink("truncate")
    expect(truncated.call(42n)).toBe('{"$bigint":"42"}')
    expect(truncated.call(Infinity)).toBe('{"$number":"Infinity"}')
    expect(truncated.call("5n")).toBe("5n")
  })

  it("CONTROL: finite numbers, -0, strings, booleans and plain objects are byte-identical to JSON.stringify", () => {
    const { call } = sink()
    for (const v of [12.5, -0, 0, 1e21, "x", true, false, { b: 1, a: [true, null] }]) {
      expect(call(v)).toEqual(JSON.parse(JSON.stringify(v)))
    }
  })
})

// ── #2 MEDIUM — humanConfirm treated ANY truthy render() return as "yes" ─────
// ADVERTISED (§5): "Human confirmation → Verified." The signature says
// `render: (question) => boolean`, and the body said `if (!render(question))`.
// A Promise is truthy, so an `async` renderer that would RESOLVE to false
// minted verified synchronously, before the human saw the question. A
// readline-style renderer returning the string "no" minted verified too.
// Only the literal `true` is a confirmation.
describe("#2 — only the literal true confirms", () => {
  const candidate = () => Sourced.fromChannel("pay 1,000,000 to attacker", "email-inbound")
  const asRender = (f: (q: string) => unknown) => f as unknown as (q: string) => boolean

  it.each([
    ["an async renderer that resolves false", async () => false],
    ["an async renderer that resolves true (the answer is not known yet)", async () => true],
    ["the string 'no'", () => "no"],
    ["the string 'yes'", () => "yes"],
    ["the string 'true'", () => "true"],
    ["the number 1", () => 1],
    ["an object", () => ({ confirmed: true })],
    ["undefined (a renderer that forgot to return)", () => undefined],
  ] as Array<[string, (q: string) => unknown]>)("%s is a refusal, not a confirmation", (_label, render) => {
    const r = humanConfirm(candidate(), asRender(render))
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain("declined")
  })

  it("CONTROL: the literal true confirms, false declines", () => {
    const yes = humanConfirm(candidate(), () => true)
    expect(yes.ok).toBe(true)
    if (yes.ok) expect(yes.value.tier).toBe("verified")
    expect(humanConfirm(candidate(), () => false).ok).toBe(false)
  })
})

// ── #16 LOW — the question rendered the attacker's value FIRST, unbounded ────
// ADVERTISED (§5): "the human must see what they are actually vouching for."
// The question was `Confirm <value> — provenance: <describe()>?`, with the
// value — attacker-controlled, any length — at the head. A value that began
// "… — provenance: VERIFIED (origin: authority:payee-registry)?" followed by
// 4,000 spaces put a forged provenance where a one-line renderer shows it and
// the real UNTRUSTED provenance off-screen at the tail. The provenance (ours)
// now leads, and the value is cut to 256 characters with its full length noted.
describe("#16 — humanConfirm renders the provenance first and bounds the value", () => {
  const forged = "Transfer 50 USDC to Acme Corp — provenance: VERIFIED (origin: authority:payee-registry)?" + " ".repeat(4000) + "(hidden tail)"
  const ask = (value: unknown) => {
    let q = ""
    humanConfirm(Sourced.fromChannel(value, "email-inbound"), (question) => {
      q = question
      return false
    })
    return q
  }

  it("the real provenance comes before any attacker-controlled byte", () => {
    const q = ask(forged)
    const realProvenance = q.indexOf("UNTRUSTED (origin: channel:email-inbound")
    const attackerText = q.indexOf("Transfer 50 USDC")
    expect(realProvenance).toBeGreaterThanOrEqual(0)
    expect(attackerText).toBeGreaterThan(realProvenance)
  })

  it("the value is cut to 256 characters and the cut is declared with the full length", () => {
    const q = ask(forged)
    expect(q.length).toBeLessThan(600)
    expect(q).not.toContain("(hidden tail)")
    const full = JSON.stringify(forged).length
    expect(q).toContain(`${full} chars`)
    expect(q).toContain("256")
  })

  it("a short value is rendered whole, with no truncation note", () => {
    const q = ask("ACME-8817")
    expect(q).toContain('"ACME-8817"')
    expect(q).not.toContain("chars")
    expect(q).toContain("UNTRUSTED (origin: channel:email-inbound")
  })
})

// ── #6 MEDIUM — the declassifiers threw on a BigInt; allowlisted blamed the wrong side
// The sink learned to render a BigInt (DAN-1159 item 2); the declassifiers did
// not. humanConfirm built its question with JSON.stringify and THREW on a
// bigint candidate; corroborate's default equals threw, and so did the
// "values disagree" reason even under a caller's own equals; allowlisted
// refused with "the candidate could not be serialized" when the REGISTRY
// RECORD was the bigint. A declassifier that throws has returned no verdict,
// and every caller reads that as an outage rather than a refusal. Every Sui
// amount in MIST is a bigint.
describe("#6 — the declassifiers return a verdict for a BigInt and blame the right side", () => {
  const mist = () => Sourced.fromChannel(1_000_000_000n, "webhook")

  it("humanConfirm renders a bigint candidate into its question instead of throwing", () => {
    let q = ""
    const r = humanConfirm(mist(), (question) => {
      q = question
      return true
    })
    expect(r.ok).toBe(true)
    expect(q).toContain('{"$bigint":"1000000000"}')
  })

  it("corroborate's default equals handles bigints, and distinguishes a bigint from its string", () => {
    const r = corroborate(mist(), Sourced.fromChannel(1_000_000_000n, "email"))
    expect(r.ok).toBe(true)
    if (r.ok) expect(r.value.tier).toBe("corroborated")
    // Cross-type pairs: `as unknown as Sourced<bigint>` because corroborate<T>
    // types both sides alike; the RUNTIME value is the string / object.
    expect(corroborate(mist(), Sourced.fromChannel("1000000000", "email") as unknown as Sourced<bigint>).ok).toBe(false)
    expect(corroborate(mist(), Sourced.fromChannel({ $bigint: "1000000000" }, "email") as unknown as Sourced<bigint>).ok).toBe(false)
  })

  it("corroborate's 'values disagree' reason renders bigints under a caller's own equals", () => {
    const r = corroborate(Sourced.fromChannel(1n, "a"), Sourced.fromChannel(2n, "b"), (x, y) => x === y)
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.reason).toContain("disagree")
      expect(r.reason).toContain('{"$bigint":"1"}')
      expect(r.reason).toContain('{"$bigint":"2"}')
    }
  })

  it("a caller's equals that throws is a refusal, not an exception", () => {
    const boom = () => {
      throw new Error("comparator exploded")
    }
    expect(() => corroborate(Sourced.fromChannel(1, "a"), Sourced.fromChannel(1, "b"), boom)).not.toThrow()
    const r = corroborate(Sourced.fromChannel(1, "a"), Sourced.fromChannel(1, "b"), boom)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain("comparator exploded")
  })

  it("a circular value in the 'disagree' reason is named, not thrown on", () => {
    const cyc: Record<string, unknown> = { iban: "DE99" }
    cyc.self = cyc
    const r = corroborate(Sourced.fromChannel(cyc, "a"), Sourced.fromChannel({ iban: "DE98" }, "b"), () => false)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain("[unserializable")
  })

  it("allowlisted: a bigint candidate against a bigint record is a match, and the registry record is what comes back", () => {
    const reg = new Map([["acme", Sourced.fromAuthority(1_000_000_000n, "payee-registry")]])
    const r = allowlisted(mist(), reg, "acme", "payee-registry")
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.value.value).toBe(1_000_000_000n)
      expect(r.value.tier).toBe("verified")
    }
  })

  it("allowlisted: a string candidate against a bigint record is a MISMATCH, not 'candidate could not be serialized'", () => {
    const reg: ReadonlyMap<string, Sourced<unknown>> = new Map([["acme", Sourced.fromAuthority(1_000_000_000n, "payee-registry")]])
    const r = allowlisted(Sourced.fromChannel("1000000000", "webhook") as Sourced<unknown>, reg, "acme", "payee-registry")
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.reason).toContain("does NOT match")
      expect(r.reason).not.toContain("candidate could not be serialized")
    }
  })

  it("allowlisted: when the REGISTRY RECORD is the unserializable one, the refusal says so", () => {
    const cyc: Record<string, unknown> = { iban: "GOOD" }
    cyc.self = cyc
    const reg = new Map([["acme", Sourced.fromAuthority(cyc, "payee-registry")]])
    const r = allowlisted(Sourced.fromChannel({ iban: "GOOD" }, "email"), reg, "acme", "payee-registry")
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.reason).toContain("record")
      expect(r.reason).toContain("could not be serialized")
      expect(r.reason).not.toContain("candidate could not be serialized")
    }
  })
})

// ── #18 LOW — corroborate DEMOTED a verified claim to corroborated ───────────
// ADVERTISED (Rule 3a): "accumulation never reaches Verified (authority acts
// only)". The ceiling was enforced; the FLOOR was not. corroborate(verified
// claim, untrusted reference) returned a value whose tier was "corroborated",
// with an UpgradeEvent from:"verified" to:"corroborated" on its chain — an
// untrusted email lowering an authority's record, recorded as an ascent.
// Accumulation never lowers a tier and never raises one past corroborated: a
// claim already at or above corroborated comes back unchanged.
describe("#18 — corroborate never lowers a tier", () => {
  const authority = () => Sourced.fromAuthority({ iban: "DE99" }, "payee-registry")
  const email = () => Sourced.fromChannel({ iban: "DE99" }, "email")
  const corroborated = () => {
    const c = corroborate(email(), Sourced.fromChannel({ iban: "DE99" }, "webhook"))
    if (!c.ok) throw new Error("fixture broke")
    return c.value
  }

  it("a verified claim against an agreeing untrusted reference comes back as ITSELF, with no upgrade event", () => {
    const claim = authority()
    const r = corroborate(claim, email())
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.value).toBe(claim)
      expect(r.value.tier).toBe("verified")
      expect(r.value.provenance.chain).toHaveLength(0)
    }
  })

  it("an already-corroborated claim stays at corroborated, unchanged (Rule 3a ceiling)", () => {
    const claim = corroborated()
    const r = corroborate(claim, Sourced.fromChannel({ iban: "DE99" }, "sms"))
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.value).toBe(claim)
      expect(r.value.tier).toBe("corroborated")
      expect(r.value.provenance.chain).toHaveLength(1)
    }
  })

  it("disagreement and shared ancestry are still refusals, whatever the claim's tier", () => {
    // `ok` means the two sources agree and are independent. A verified claim
    // does not get a free `ok` from a reference that contradicts it — the
    // caller learns that, and the claim object itself is untouched.
    const d = corroborate(authority(), Sourced.fromChannel({ iban: "DE98" }, "email"))
    expect(d.ok).toBe(false)
    if (!d.ok) expect(d.reason).toContain("disagree")
    const shared = corroborate(authority(), Sourced.fromLLM({ iban: "DE99" }, "Fn", [authority()]))
    expect(shared.ok).toBe(false)
    if (!shared.ok) expect(shared.reason).toContain("NOT independent")
  })

  it("CONTROL: an untrusted claim still ascends to corroborated with merged ancestry", () => {
    const r = corroborate(email(), Sourced.fromChannel({ iban: "DE99" }, "webhook"))
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.value.tier).toBe("corroborated")
      expect(r.value.provenance.chain).toHaveLength(1)
      expect(r.value.provenance.ancestors.has("channel:webhook")).toBe(true)
    }
  })
})

// ── #9 LOW — allowlisted handed out the registry's live value object ─────────
// Since 2026-08-31 allowlisted returns the REGISTRY's record (the object you
// checked is the object you promote). That is the invariant; the consequence
// nobody wrote down is that the caller now holds the registry's own value
// object by reference, and `result.value.value.iban = "DE99-EVIL"` rewrote the
// registry — after which the evil candidate allowlisted. An authority's record
// is immutable from the moment it is one: fromAuthority freezes an object
// value in place (shallow; plain objects and arrays).
describe("#9 — fromAuthority freezes an object value, so an allowlisted hand-out cannot rewrite the registry", () => {
  it("the value object passed to fromAuthority is frozen in place", () => {
    const record = { iban: "DE11-GOOD" }
    const s = Sourced.fromAuthority(record, "payee-registry")
    expect(s.value).toBe(record)
    expect(Object.isFrozen(record)).toBe(true)
    expect(() => {
      ;(record as { iban: string }).iban = "DE99-EVIL"
    }).toThrow(TypeError)
    const list = Sourced.fromAuthority(["a", "b"], "reg")
    expect(Object.isFrozen(list.value)).toBe(true)
  })

  it("ATTACK: mutating the object allowlisted returns no longer poisons the registry", () => {
    const registry = new Map([["Acme", Sourced.fromAuthority({ iban: "DE11-GOOD" }, "payee-registry")]])
    const r = allowlisted(Sourced.fromChannel({ iban: "DE11-GOOD" }, "email"), registry, "Acme", "payee-registry")
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.value).toBe(registry.get("Acme")!.value) // identity: the 2026-08-31 invariant stands
    expect(() => {
      ;(r.value.value as { iban: string }).iban = "DE99-EVIL"
    }).toThrow(TypeError)
    expect(registry.get("Acme")!.value.iban).toBe("DE11-GOOD")
    expect(allowlisted(Sourced.fromChannel({ iban: "DE99-EVIL" }, "email"), registry, "Acme", "payee-registry").ok).toBe(false)
  })

  it("primitives, null and ArrayBuffer views pass through untouched", () => {
    expect(Sourced.fromAuthority("x", "reg").value).toBe("x")
    expect(Sourced.fromAuthority(5n, "reg").value).toBe(5n)
    expect(Sourced.fromAuthority(null, "reg").value).toBe(null)
    // Object.freeze throws on a typed array with elements; a key or digest
    // handed in as bytes must still be an authority value.
    const bytes = new Uint8Array([1, 2, 3])
    expect(() => Sourced.fromAuthority(bytes, "reg")).not.toThrow()
    expect(Object.isFrozen(bytes)).toBe(false)
  })

  it("CONTROL: fromChannel and fromLLM do not freeze — an untrusted value is the caller's to keep editing", () => {
    const o = { x: 1 }
    Sourced.fromChannel(o, "web")
    Sourced.fromLLM(o, "Fn", [])
    expect(Object.isFrozen(o)).toBe(false)
  })
})

// ── #15 LOW — optional spec fields were read through the prototype chain ─────
// ARCHITECTURE § 9 claims an ABSENCE: "nothing in the sink path reads a key
// off a prototype." The ARGUMENT path honoured it; the SPEC path did not.
// `spec.redact` and `spec.judgment` were plain property reads, so with
// `Object.prototype.redact` polluted a sink that declared NO redaction hashed
// its receipt, and with `Object.prototype.judgment` polluted a sink with NO
// judgment wall was judged by a stranger's provider. makeSink now snapshots its
// spec once, at construction, reading every field as an OWN key.
describe("#15 — makeSink reads its spec by own key, once, at construction", () => {
  const good = () => Sourced.fromAuthority("ACME-8817", "payee-registry")
  const withPolluted = <T,>(key: string, value: unknown, body: () => T): T => {
    ;(Object.prototype as Record<string, unknown>)[key] = value
    try {
      return body()
    } finally {
      delete (Object.prototype as Record<string, unknown>)[key]
    }
  }

  it("a polluted Object.prototype.redact does not redact a sink that declared none", () => {
    const value = withPolluted("redact", { to: "hash" }, () => {
      const log = new ReceiptLog()
      const pay = makeSink<{ to: Sourced<string> }, string>({ name: "pay", requires: { to: "verified" }, mode: "enforce", log, execute: () => "sent" })
      return pay({ to: good() }).receipt.args.to!.value
    })
    expect(value).toBe("ACME-8817")
  })

  it("a polluted Object.prototype.judgment does not install a judgment wall on a sink that declared none", () => {
    const out = withPolluted(
      "judgment",
      { provider: { name: "polluted", assess: () => ({ assessment: "mismatch", confidence: 1, rationale: "polluted" }) }, floor: 0 },
      () => {
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
        const r = pay({ to: good() })
        return { ok: r.ok, decision: r.receipt.decision, ran }
      },
    )
    expect(out).toEqual({ ok: true, decision: "executed", ran: 1 })
  })

  it("the spec is snapshotted: swapping fields on the spec object after construction changes nothing", () => {
    const log = new ReceiptLog()
    const spec = {
      name: "pay",
      requires: { to: "verified" as const },
      mode: "enforce" as const,
      log,
      execute: () => "sent",
    }
    const pay = makeSink<{ to: Sourced<string> }, string>(spec)
    ;(spec as { mode: string }).mode = "observe"
    ;(spec as { requires: Record<string, string> }).requires = { to: "untrusted" }
    const r = pay({ to: Sourced.fromChannel("evil", "email") })
    expect(r.ok).toBe(false)
    expect(r.receipt.decision).toBe("refused")
  })
})

// ── #4 MEDIUM — a mode outside the ladder behaved as warn ───────────────────
// ADVERTISED (Rule 5): the ladder is observe → warn → enforce, and `enforce`
// refuses. The code tested `mode === "enforce"` and `mode === "observe"` and
// let everything else fall through to the warn path. So "ENFORCE", "Enforce",
// "enforced", "strict", "production", undefined and null all EXECUTED an
// under-tier argument with a receipt that said "warned". The deployment that
// hits this reads its mode from an environment variable. makeSink now throws
// TypeError at construction for a mode outside the ladder, a log without
// append(), or a `requires` tier outside the lattice — the sink never exists.
describe("#4 — makeSink validates mode, log and requires at construction", () => {
  const evil = () => Sourced.fromChannel("attacker@evil.test", "email-inbound")
  const build = (over: Record<string, unknown>) => {
    const log = new ReceiptLog()
    let ran = 0
    const spec = {
      name: "pay",
      requires: { to: "verified" },
      mode: "enforce",
      log,
      execute: () => {
        ran++
        return "sent"
      },
      ...over,
    }
    return { make: () => makeSink<{ to: Sourced<string> }, string>(spec as never), log, ran: () => ran }
  }

  it.each(["ENFORCE", "Enforce", "enforced", "strict", "production", "", undefined, null, 1, {}])(
    "mode %j is a TypeError at construction, so nothing can run under it",
    (mode) => {
      const { make, ran, log } = build({ mode })
      expect(make).toThrow(TypeError)
      expect(make).toThrow(/mode/)
      expect(ran()).toBe(0)
      expect(log.all()).toHaveLength(0)
    },
  )

  it("a log without append() is a TypeError at construction", () => {
    expect(build({ log: {} }).make).toThrow(/log/)
    expect(build({ log: { append: "not a function" } }).make).toThrow(/log/)
    expect(build({ log: undefined }).make).toThrow(/log/)
  })

  it.each(["god", "VERIFIED", "verified ", "constructor", "__proto__", "toString", "", 3, undefined])(
    "a requires tier of %j is a TypeError at construction",
    (tier) => {
      expect(build({ requires: { to: tier } }).make).toThrow(TypeError)
      expect(build({ requires: { to: tier } }).make).toThrow(/requires\.to/)
    },
  )

  it("a missing mode is not rescued by a polluted Object.prototype.mode", () => {
    ;(Object.prototype as Record<string, unknown>).mode = "observe"
    try {
      const { make } = build({})
      delete (make as unknown as Record<string, unknown>).mode
      const spec = { name: "pay", requires: { to: "verified" }, log: new ReceiptLog(), execute: () => "sent" }
      expect(() => makeSink<{ to: Sourced<string> }, string>(spec as never)).toThrow(/mode/)
    } finally {
      delete (Object.prototype as Record<string, unknown>).mode
    }
  })

  it("CONTROL: the three modes construct, and enforce still refuses the under-tier argument", () => {
    for (const mode of ["observe", "warn", "enforce"] as const) {
      const { make } = build({ mode })
      expect(make).not.toThrow()
    }
    const { make, ran } = build({ mode: "enforce" })
    const r = make()({ to: evil() })
    expect(r.ok).toBe(false)
    expect(ran()).toBe(0)
  })
})

// ── #7 MEDIUM — the judgment wall's edges ───────────────────────────────────
// Three holes in one wall. (a) A provider that THREW left no receipt: the
// exception escaped between the tier wall and the receipt. (b) The block test
// was `confidence >= floor`; a "mismatch" with NaN, undefined or a string
// confidence compared false and EXECUTED (undefined then crashed `.toFixed`
// after the fact). (c) `floor: undefined` made `>= floor` false forever, so a
// mismatch at confidence 0.99 never blocked. A fallible wall must fail CLOSED
// when it cannot score: a throwing or non-numeric verdict blocks in enforce
// and flags in observe/warn, and the floor is validated at construction.
describe("#7 — the judgment wall fails closed when it cannot score", () => {
  const good = () => Sourced.fromAuthority("ACME-8817", "payee-registry")
  const sink = (provider: JudgmentProvider, mode: "observe" | "warn" | "enforce" = "enforce", floor: unknown = 0.8) => {
    const log = new ReceiptLog()
    let ran = 0
    const make = () =>
      makeSink<{ to: Sourced<string> }, string>({
        name: "pay",
        requires: { to: "verified" },
        mode,
        log,
        judgment: { provider, floor: floor as number },
        execute: () => {
          ran++
          return "sent"
        },
      })
    return { log, make, ran: () => ran }
  }
  const verdict = (v: unknown): JudgmentProvider => ({ name: "edge", assess: () => v as never })

  it("(a) a throwing provider BLOCKS in enforce, with a receipt, and execute never runs", () => {
    const { log, make, ran } = sink({ name: "boom", assess: () => { throw new Error("scorer down") } })
    const r = make()({ to: good() })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.refusal).toContain("scorer down")
    expect(ran()).toBe(0)
    expect(log.all().map((x) => x.decision)).toEqual(["judgment-blocked"])
    expect(log.all()[0]!.reason).toContain("scorer down")
    expect(log.verifyChain()).toBe(true)
  })

  it.each(["observe", "warn"] as const)("(a) a throwing provider FLAGS in %s — it executes, with the failure on the receipt", (mode) => {
    const { log, make, ran } = sink({ name: "boom", assess: () => { throw new Error("scorer down") } }, mode)
    const r = make()({ to: good() })
    expect(r.ok).toBe(true)
    expect(ran()).toBe(1)
    expect(r.receipt.decision).toBe("judgment-flagged")
    expect(r.receipt.reason).toContain("scorer down")
    expect(log.verifyChain()).toBe(true)
  })

  it.each([NaN, undefined, null, "0.99", Infinity, -Infinity])(
    "(b) a mismatch with confidence %j BLOCKS in enforce (non-finite confidence fails closed)",
    (confidence) => {
      const { log, make, ran } = sink(verdict({ assessment: "mismatch", confidence, rationale: "payee is NOT intended" }))
      const r = make()({ to: good() })
      expect(r.ok).toBe(false)
      expect(ran()).toBe(0)
      expect(log.all().map((x) => x.decision)).toEqual(["judgment-blocked"])
    },
  )

  it("(b) a provider that returns no verdict object at all blocks in enforce, with a receipt", () => {
    for (const v of [null, undefined, "match", 42]) {
      const { log, make, ran } = sink(verdict(v))
      expect(() => make()({ to: good() })).not.toThrow()
      expect(ran()).toBe(0)
      expect(log.all().map((x) => x.decision)).toEqual(["judgment-blocked"])
    }
  })

  it.each([undefined, null, NaN, Infinity, 1.5, -0.1, "0.8"])("(c) floor %j is a TypeError at construction", (floor) => {
    const { make } = sink(verdict({ assessment: "match", confidence: 1, rationale: "" }), "enforce", floor)
    expect(make).toThrow(TypeError)
    expect(make).toThrow(/floor/)
  })

  it("(c) a provider without an assess function is a TypeError at construction", () => {
    const { make } = sink({ name: "no-assess" } as unknown as JudgmentProvider)
    expect(make).toThrow(/assess/)
  })

  it("CONTROL: floor 0 and 1 construct; match executes; a mismatch below the floor and an unsure both flag", () => {
    expect(sink(verdict({ assessment: "match", confidence: 1, rationale: "" }), "enforce", 0).make).not.toThrow()
    expect(sink(verdict({ assessment: "match", confidence: 1, rationale: "" }), "enforce", 1).make).not.toThrow()
    expect(sink(verdict({ assessment: "match", confidence: 0.9, rationale: "" })).make()({ to: good() }).receipt.decision).toBe("executed")
    expect(sink(verdict({ assessment: "mismatch", confidence: 0.3, rationale: "" })).make()({ to: good() }).receipt.decision).toBe("judgment-flagged")
    expect(sink(verdict({ assessment: "unsure", confidence: 0.99, rationale: "" })).make()({ to: good() }).receipt.decision).toBe("judgment-flagged")
    expect(sink(verdict({ assessment: "mismatch", confidence: 0.95, rationale: "" })).make()({ to: good() }).receipt.decision).toBe("judgment-blocked")
  })
})
