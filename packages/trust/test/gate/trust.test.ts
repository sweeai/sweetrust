/**
 * Tests for @sweetrust/gate v0.1 — the kernel invariants, extracted from the
 * demo suite that specified them (sweeai trust.demo.ts 11/11 + the §6 attack
 * replay). The demos remain the narrative; these are the regressions.
 *
 * Coverage map (spec rule → test):
 *   Rule 1  — taint is sticky (minTier takes the minimum)
 *   Rule 2  — inference is not evidence (fromLLM is Untrusted, always;
 *             confidence rides along and never affects tier)
 *   Rule 3  — ascent only through the audited declassifier trio; no public
 *             ascent path is importable (Session-003 C6 forgery regression)
 *   Rule 3a — accumulation never reaches Verified (corroborate caps at
 *             Corroborated)
 *   Rule 3b — corroboration requires disjoint ancestry
 *   Rule 4  — sinks declare appetite, fail closed, refuse with provenance
 *   Rule 5  — adoption ladder observe → warn → enforce; confidence field
 *   Judgment seam — mismatch blocks, unsure flags (defers to human), and the
 *             judgment wall only runs AFTER the tier wall passes
 *   Receipts — hash chain verifies; any mutation of a past event breaks it
 */
import { describe, expect, test } from "vitest"
import {
  allowlisted,
  corroborate,
  humanConfirm,
  makeSink,
  meetsTier,
  minTier,
  mockJudgmentProvider,
  ReceiptLog,
  Sourced,
  TIERS,
  type JudgmentProvider,
  type Tier,
} from "../../src/gate/index.ts"

// ── The lattice (§3) ─────────────────────────────────────────────────────────

describe("tier lattice", () => {
  test("TIERS is the spec's four-tier ascent order", () => {
    expect(TIERS).toEqual(["untrusted", "asserted", "corroborated", "verified"])
  })

  test("meetsTier is a ranking, not an equality", () => {
    expect(meetsTier("verified", "corroborated")).toBe(true)
    expect(meetsTier("corroborated", "corroborated")).toBe(true)
    expect(meetsTier("asserted", "corroborated")).toBe(false)
    expect(meetsTier("untrusted", "verified")).toBe(false)
  })

  test("Rule 1 — taint is sticky: combining takes the MINIMUM tier", () => {
    expect(minTier("verified", "untrusted")).toBe("untrusted")
    expect(minTier("corroborated", "asserted", "verified")).toBe("asserted")
    expect(minTier("verified")).toBe("verified")
  })

  test("Rule 1, empty case — combining NOTHING floors, it does not top", () => {
    // Changed 2026-07-25, adversarial pass A2. This previously asserted
    // `verified`, justified as "identity of the meet over the empty set" —
    // which is correct lattice algebra and wrong security. The natural call
    // site is `minTier(...inputs.map(i => i.tier))`, and an empty `inputs`
    // then minted the maximum tier from no evidence at all.
    //
    // Where algebra and fail-closed disagree in a kernel, fail-closed wins.
    expect(minTier()).toBe("untrusted")
  })
})

// ── Birth tiers (§4) ─────────────────────────────────────────────────────────

describe("Sourced factories", () => {
  test("channel input is born Untrusted with its channel as ancestry", () => {
    const v = Sourced.fromChannel("hello", "email-inbound")
    expect(v.tier).toBe("untrusted")
    expect(v.provenance.origin).toBe("channel:email-inbound")
    expect([...v.provenance.ancestors]).toEqual(["channel:email-inbound"])
    expect(v.provenance.chain).toHaveLength(0)
  })

  test("Rule 2 — inference is not evidence: LLM output is Untrusted even from Verified inputs", () => {
    const verifiedInput = Sourced.fromAuthority("ACME-8817", "payee-registry")
    const out = Sourced.fromLLM("extracted", "ExtractInvoice", [verifiedInput], 0.97)
    expect(out.tier).toBe("untrusted")
    // confidence rides along but does NOT change the tier
    expect(out.provenance.confidence).toBe(0.97)
    // ancestry is inherited so downstream independence checks stay honest
    expect(out.provenance.ancestors.has("llm:ExtractInvoice")).toBe(true)
    expect(out.provenance.ancestors.has("authority:payee-registry")).toBe(true)
  })

  test("an authority the deployment governs is Verified at birth", () => {
    const v = Sourced.fromAuthority(1200, "vendor-contracts")
    expect(v.tier).toBe("verified")
    expect(v.provenance.origin).toBe("authority:vendor-contracts")
  })

  test("describe() renders tier, origin, upgrades, and confidence", () => {
    const v = Sourced.fromLLM("x", "Fn", [Sourced.fromChannel("raw", "web")], 0.5)
    expect(v.describe()).toContain("UNTRUSTED")
    expect(v.describe()).toContain("llm:Fn")
    expect(v.describe()).toContain("conf 0.50")
  })
})

// ── Rule 3 structural: no importer can mint or re-tier (Session-003 C6) ──────

describe("forgery resistance", () => {
  test("no public ascent path exists on the class or its instances", () => {
    const v = Sourced.fromChannel("x", "test") as unknown as Record<string, unknown>
    expect(v._ascend).toBeUndefined()
    expect((Sourced as unknown as Record<string, unknown>)._ascend).toBeUndefined()
  })

  test("instances are frozen at runtime — re-tiering throws (strict mode) and never lands", () => {
    const v = Sourced.fromChannel("x", "test")
    expect(Object.isFrozen(v)).toBe(true)
    expect(Object.isFrozen(v.provenance)).toBe(true)
    expect(Object.isFrozen(v.provenance.chain)).toBe(true)
    expect(() => {
      ;(v as unknown as { tier: Tier }).tier = "verified"
    }).toThrow()
    expect(v.tier).toBe("untrusted")
  })
})

// ── The audited declassifier trio (§5) ───────────────────────────────────────

describe("declassifiers", () => {
  const registry = new Map([["Acme Corp", Sourced.fromAuthority("ACME-8817", "payee-registry")]])

  test("allowlisted: registry match → Verified, with the ascent on the audit chain", () => {
    const claim = Sourced.fromLLM("ACME-8817", "ExtractInvoice", [Sourced.fromChannel("…", "email-inbound")])
    const r = allowlisted(claim, registry, "Acme Corp", "payee-registry")
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.value.tier).toBe("verified")
      expect(r.value.provenance.chain).toHaveLength(1)
      // `from` is the REGISTRY RECORD's tier, not the candidate's.
      //
      // This assertion read `from: "untrusted"` until 2026-08-31, and that was
      // the bug written down as the specification: the only way to observe the
      // candidate's tier here was for the candidate to be the object promoted,
      // which is exactly the substitution that made `allowlisted` fail open.
      // The test passed for the same reason the exploit worked.
      //
      // What the caller gets back is the governed record, so what the audit
      // chain reports is the governed record's ascent. The candidate's identity
      // is preserved in `evidence`, which is where a claim under test belongs.
      expect(r.value.provenance.chain[0]).toMatchObject({
        declassifier: "allowlisted",
        from: "verified",
        to: "verified",
      })
      expect(r.value.provenance.chain[0].evidence).toContain("candidate presented was")
    }
  })

  // ── Regression: the value returned is the REGISTRY's, not the caller's ────
  //
  // The comparison is `JSON.stringify(entry.value) === JSON.stringify(candidate.value)`.
  // Serialization is not identity: a candidate can serialize as the good record
  // and BE something else. Before the fix, that candidate was the object
  // promoted to `verified` — so the money moved to the attacker's account while
  // the signed receipt recorded the good one and the chain verified clean.
  //
  // Each case below serializes identically to the registry record and differs
  // in substance by a different mechanism. All three must come back holding the
  // REGISTRY's value.
  test("allowlisted: a candidate that only SERIALIZES like the record cannot smuggle its own value through", () => {
    const iban = new Map([["Acme Corp", Sourced.fromAuthority({ iban: "GOOD-IBAN" }, "payee-registry")]])

    // (a) toJSON lies about the object's contents.
    const toJsonLiar = { iban: "EVIL-IBAN", toJSON: () => ({ iban: "GOOD-IBAN" }) }

    // (b) a getter that answers GOOD while being compared and EVIL afterwards.
    let reads = 0
    const flipFlop = {
      get iban() {
        reads += 1
        return reads === 1 ? "GOOD-IBAN" : "EVIL-IBAN"
      },
    }

    // (c) a non-enumerable field JSON.stringify never visits.
    const hidden: Record<string, unknown> = { iban: "GOOD-IBAN" }
    Object.defineProperty(hidden, "routingOverride", { value: "EVIL-BANK", enumerable: false })

    for (const [label, evil] of [
      ["toJSON", toJsonLiar],
      ["getter", flipFlop],
      ["non-enumerable", hidden],
    ] as const) {
      const candidate = Sourced.fromLLM(evil as unknown as { iban: string }, "ExtractInvoice", [])
      const r = allowlisted(candidate, iban, "Acme Corp", "payee-registry")
      expect(r.ok, label).toBe(true)
      if (r.ok) {
        // The promoted value IS the registry's object — identity, not equality.
        expect(r.value.value, label).toBe(iban.get("Acme Corp")!.value)
        expect(r.value.value.iban, label).toBe("GOOD-IBAN")
        expect(Object.hasOwn(r.value.value, "routingOverride"), label).toBe(false)
      }
    }
  })

  test("allowlisted: a candidate that cannot be serialized is REFUSED, never thrown on", () => {
    const circular: Record<string, unknown> = { iban: "GOOD-IBAN" }
    circular.self = circular
    const iban = new Map([["Acme Corp", Sourced.fromAuthority({ iban: "GOOD-IBAN" }, "payee-registry")]])
    const candidate = Sourced.fromLLM(circular as unknown as { iban: string }, "ExtractInvoice", [])

    // A declassifier that throws has returned no verdict, and every caller
    // reads an exception as transient rather than as a refusal.
    expect(() => allowlisted(candidate, iban, "Acme Corp", "payee-registry")).not.toThrow()
    const r = allowlisted(candidate, iban, "Acme Corp", "payee-registry")
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain("could not be serialized")
  })

  test("allowlisted: key absent from the registry → refusal naming the registry", () => {
    const claim = Sourced.fromLLM("MULE-6660", "ExtractInvoice", [])
    const r = allowlisted(claim, registry, "Mule Corp", "payee-registry")
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain("not in payee-registry")
  })

  test("allowlisted: key present but record disagrees (the poisoned invoice) → refusal", () => {
    const claim = Sourced.fromLLM("MULE-6660", "ExtractInvoice", [])
    const r = allowlisted(claim, registry, "Acme Corp", "payee-registry")
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain("does NOT match")
  })

  test("corroborate: independent agreement → Corroborated, NEVER Verified (Rule 3a)", () => {
    const claim = Sourced.fromLLM(1200, "ExtractInvoice", [Sourced.fromChannel("…", "email-inbound")])
    const reference = Sourced.fromAuthority(1200, "vendor-contracts")
    const r = corroborate(claim, reference)
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.value.tier).toBe("corroborated")
      expect(meetsTier(r.value.tier, "verified")).toBe(false)
      // ancestries merge so a later corroboration against either source fails independence
      expect(r.value.provenance.ancestors.has("authority:vendor-contracts")).toBe(true)
    }
  })

  test("Rule 3b — corroborate refuses non-independent sources (shared ancestry)", () => {
    const email = Sourced.fromChannel("…", "email-inbound")
    const a = Sourced.fromLLM(1200, "ExtractInvoice", [email])
    const b = Sourced.fromLLM(1200, "SummarizeInvoice", [email]) // derived from the SAME email
    const r = corroborate(a, b)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain("NOT independent")
  })

  test("corroborate refuses disagreeing values", () => {
    const claim = Sourced.fromLLM(1200, "ExtractInvoice", [])
    const reference = Sourced.fromAuthority(9999, "vendor-contracts")
    const r = corroborate(claim, reference)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain("disagree")
  })

  test("humanConfirm renders the provenance INTO the question (anti-fatigue, §5)", () => {
    const claim = Sourced.fromLLM("ACME-8817", "ExtractInvoice", [])
    let asked = ""
    const r = humanConfirm(claim, (q) => {
      asked = q
      return true
    })
    expect(asked).toContain("llm:ExtractInvoice") // the human sees what they vouch for
    expect(r.ok).toBe(true)
    if (r.ok) expect(r.value.tier).toBe("verified")
  })

  test("humanConfirm: declined → refusal, no ascent", () => {
    const claim = Sourced.fromLLM("x", "Fn", [])
    const r = humanConfirm(claim, () => false)
    expect(r.ok).toBe(false)
  })
})

// ── Receipts: the hash chain (SweeVerify's lowercase artifact) ───────────────

describe("ReceiptLog", () => {
  const entry = (sink: string, decision: "executed" | "refused") => ({
    at: new Date().toISOString(),
    sink,
    decision,
    args: {},
  })

  test("appends link seq + prevHash and the chain verifies", () => {
    const log = new ReceiptLog()
    const r0 = log.append(entry("pay", "executed"))
    const r1 = log.append(entry("pay", "refused"))
    expect(r0.seq).toBe(0)
    expect(r0.prevHash).toBe("genesis")
    expect(r1.seq).toBe(1)
    expect(r1.prevHash).toBe(r0.hash)
    expect(log.verifyChain()).toBe(true)
  })

  test("tamper-evidence, observed not asserted: mutating a past event breaks the chain", () => {
    const log = new ReceiptLog()
    log.append(entry("pay", "executed"))
    log.append(entry("pay", "executed"))
    const events = (log as unknown as { events: Array<{ decision: string }> }).events
    const original = events[0]!.decision
    events[0]!.decision = "refused"
    expect(log.verifyChain()).toBe(false)
    events[0]!.decision = original
    expect(log.verifyChain()).toBe(true)
  })
})

// ── Sinks: Rule 4 + the adoption ladder + the judgment seam ──────────────────

describe("makeSink", () => {
  type Args = { to: Sourced<string>; amount: Sourced<number> }
  const verified = () => Sourced.fromAuthority("ACME-8817", "payee-registry")
  const corroboratedAmount = () => {
    const r = corroborate(
      Sourced.fromLLM(1200, "ExtractInvoice", [Sourced.fromChannel("…", "email-inbound")]),
      Sourced.fromAuthority(1200, "vendor-contracts"),
    )
    if (!r.ok) throw new Error("fixture broke")
    return r.value
  }
  const untrusted = () => Sourced.fromLLM("MULE-6660", "ExtractInvoice", [])

  const paySink = (log: ReceiptLog, mode: "observe" | "warn" | "enforce", judgment?: { provider: JudgmentProvider; floor: number }) =>
    makeSink<Args, string>({
      name: "pay",
      requires: { to: "verified", amount: "corroborated" },
      mode,
      log,
      ...(judgment ? { judgment } : {}),
      execute: ({ to, amount }) => `paid ${amount.value} to ${to.value}`,
    })

  test("enforce: satisfied appetite executes and the receipt says so", () => {
    const log = new ReceiptLog()
    const r = paySink(log, "enforce")({ to: verified(), amount: corroboratedAmount() })
    expect(r.ok).toBe(true)
    expect(r.receipt.decision).toBe("executed")
    expect(log.verifyChain()).toBe(true)
  })

  // ── Regression: prototype-named arguments are arguments (2026-08-31) ─────
  //
  // The undeclared-argument loop tested membership with `key in spec.requires`.
  // `in` walks the prototype chain, so `"constructor" in { to: "verified" }` is
  // TRUE and the loop `continue`d. The DECLARED loop iterates
  // `Object.keys(spec.requires)` and never saw it either — so an argument named
  // after anything on `Object.prototype` fell through BOTH: no tier check, no
  // receipt entry, no violation, and it still arrived at `execute()`.
  //
  // This is directly reachable for this package's stated target, because when
  // sink arguments come from model tool-calls the argument NAMES are chosen by
  // whatever wrote the schema.
  test.each(["constructor", "__proto__", "toString", "valueOf", "hasOwnProperty", "isPrototypeOf"])(
    "enforce: an undeclared argument named %s is caught, recorded, and refused",
    (evilName) => {
      const log = new ReceiptLog()
      let reached: Record<string, unknown> | undefined
      const sink = makeSink<Record<string, Sourced<unknown>>, string>({
        name: "pay",
        requires: { to: "verified" },
        mode: "enforce",
        log,
        execute: (args) => {
          reached = args
          return "paid"
        },
      })

      const r = sink({ to: verified(), [evilName]: untrusted() } as Record<string, Sourced<unknown>>)

      // Fail CLOSED: the sink has no stated appetite for this argument.
      expect(r.ok).toBe(false)
      expect(reached).toBeUndefined()
      if (!r.ok) {
        expect(r.refusal).toContain(evilName)
        expect(r.refusal).toContain("not declared in requires")
        // And it must be on the durable receipt — an unrecorded argument that
        // reached a privileged operation is the whole guarantee leaking.
        expect(Object.hasOwn(r.receipt.args, evilName)).toBe(true)
        expect(r.receipt.args[evilName].provenance).toContain("UNDECLARED")
      }
      expect(log.verifyChain()).toBe(true)
    },
  )

  test("enforce: under-tier argument refuses, fail-closed, with provenance RENDERED", () => {
    const log = new ReceiptLog()
    const r = paySink(log, "enforce")({ to: untrusted(), amount: corroboratedAmount() })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.refusal).toContain("requires verified")
      expect(r.refusal).toContain("llm:ExtractInvoice") // the human sees the right question
      expect(r.receipt.decision).toBe("refused")
    }
  })

  test("enforce: a MISSING declared argument is a violation (fail closed)", () => {
    const log = new ReceiptLog()
    const r = paySink(log, "enforce")({ to: verified() } as unknown as Args)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.refusal).toContain("was not provided")
  })

  test("observe: violations execute anyway, recorded as observed (Rule 5 on-ramp)", () => {
    const log = new ReceiptLog()
    const r = paySink(log, "observe")({ to: verified(), amount: corroboratedAmount() })
    expect(r.ok).toBe(true)
    expect(r.receipt.decision).toBe("observed")
  })

  test("warn: violations execute but the receipt says warned + carries the reasons", () => {
    const log = new ReceiptLog()
    const r = paySink(log, "warn")({ to: untrusted(), amount: corroboratedAmount() })
    expect(r.ok).toBe(true)
    expect(r.receipt.decision).toBe("warned")
    expect(r.receipt.reason).toContain("requires verified")
  })

  test("judgment wall: in-bounds-but-wrong blocks AFTER tiers pass (the 2nd wall)", () => {
    const log = new ReceiptLog()
    const judgment = { provider: mockJudgmentProvider({ intendedPayees: new Set(["someone-else"]), maxAmount: 5000 }), floor: 0.7 }
    const r = paySink(log, "enforce", judgment)({ to: verified(), amount: corroboratedAmount() })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.refusal).toContain("judgment-blocked")
      expect(r.refusal).not.toContain("requires verified") // tiers passed first
      expect(r.receipt.decision).toBe("judgment-blocked")
    }
  })

  test("judgment wall: unsure FLAGS and defers — it executes with the doubt on the receipt", () => {
    const log = new ReceiptLog()
    // amount 1200 with cap 1100: intended payee, slightly over → the mock's honest "unsure" band
    const judgment = { provider: mockJudgmentProvider({ intendedPayees: new Set(["ACME-8817"]), maxAmount: 1100 }), floor: 0.7 }
    const r = paySink(log, "enforce", judgment)({ to: verified(), amount: corroboratedAmount() })
    expect(r.ok).toBe(true)
    expect(r.receipt.decision).toBe("judgment-flagged")
    expect(r.receipt.reason).toContain("unsure")
  })

  test("judgment wall: never reached when the tier wall refuses (order is load-bearing)", () => {
    const log = new ReceiptLog()
    let judged = 0
    const spy: JudgmentProvider = {
      name: "spy",
      assess: () => {
        judged++
        return { assessment: "match", confidence: 1, rationale: "" }
      },
    }
    const r = paySink(log, "enforce", { provider: spy, floor: 0.7 })({ to: untrusted(), amount: corroboratedAmount() })
    expect(r.ok).toBe(false)
    expect(judged).toBe(0)
  })
})

// ── Redaction seam (receipts are signed + anchorable — policy applies pre-hash) ──

describe("redaction seam", () => {
  test("hash/truncate shape the receipt; execute and judgment see RAW values", () => {
    const log = new ReceiptLog()
    let executedSecret: unknown = null
    let judgedSecret: unknown = null
    const judge: JudgmentProvider = {
      name: "spy",
      assess: (_sink, args) => {
        judgedSecret = args.secret!.value
        return { assessment: "match", confidence: 0.99, rationale: "spy" }
      },
    }
    const sink = makeSink<{ secret: Sourced<string>; memo: Sourced<string> }, string>({
      name: "redacted-sink",
      requires: { secret: "verified", memo: "verified" },
      mode: "enforce",
      log,
      judgment: { provider: judge, floor: 0.8 },
      redact: { secret: "hash", memo: "truncate" },
      execute: (args) => {
        executedSecret = args.secret.value
        return "done"
      },
    })
    const secret = Sourced.fromAuthority("hunter2-super-secret-credential", "vault")
    const memo = Sourced.fromAuthority("m".repeat(200), "vault")
    const r = sink({ secret, memo })
    expect(r.ok).toBe(true)
    // raw values reached execute + judgment
    expect(executedSecret).toBe("hunter2-super-secret-credential")
    expect(judgedSecret).toBe("hunter2-super-secret-credential")
    // the durable receipt carries only the redacted forms
    const rec = log.all().at(-1)!
    expect(String(rec.args.secret!.value)).toMatch(/^sha256:[0-9a-f]{64}$/)
    expect(String(rec.args.memo!.value).length).toBeLessThanOrEqual(65)
    expect(String(rec.args.memo!.value)).not.toBe("m".repeat(200))
    // and the chain still verifies (redaction happened BEFORE hashing)
    expect(log.verifyChain()).toBe(true)
  })

  test("default policy is raw — existing receipts unchanged", () => {
    const log = new ReceiptLog()
    const sink = makeSink<{ amount: Sourced<number> }, string>({
      name: "raw-sink",
      requires: { amount: "verified" },
      mode: "enforce",
      log,
      execute: () => "ok",
    })
    sink({ amount: Sourced.fromAuthority(1200, "ledger") })
    expect(log.all().at(-1)!.args.amount!.value).toBe(1200)
    expect(log.verifyChain()).toBe(true)
  })
})
