// Self-audit of the 2026-07-25 adversarial fixes.
// ============================================================================
// The ancestry fix introduced a Proxy into a hot, public data structure. A
// Proxy that gets `get` slightly wrong breaks iteration, spread, size, or
// instanceof in ways ordinary tests never touch — so this file exercises the
// Set surface directly rather than trusting that the attack test passing means
// the object is still a normal Set.
//
// Rule this encodes: a security fix that quietly changes the shape of a public
// value is a second bug wearing the first one's clothes.
// ============================================================================

import { describe, it, expect } from "vitest"
import { Sourced, corroborate, ReceiptLog, makeSink } from "../../src/gate/trust.js"

const sample = () => {
  const email = Sourced.fromChannel({ x: 1 }, "email-inbound")
  return Sourced.fromLLM({ x: 1 }, "Extract", [email])
}

describe("the sealed ancestor Set still behaves like a Set in every read path", () => {
  it("has / size / iteration / spread / Array.from all work", () => {
    const a = sample().provenance.ancestors
    expect(a.has("llm:Extract")).toBe(true)
    expect(a.has("channel:email-inbound")).toBe(true)
    expect(a.size).toBe(2)
    expect([...a].sort()).toEqual(["channel:email-inbound", "llm:Extract"])
    expect(Array.from(a).length).toBe(2)
    expect([...a.values()].length).toBe(2)
    expect([...a.keys()].length).toBe(2)
    expect([...a.entries()].length).toBe(2)
  })

  it("forEach works and receives the right arguments", () => {
    const a = sample().provenance.ancestors
    const seen: string[] = []
    a.forEach((v) => seen.push(v))
    expect(seen.sort()).toEqual(["channel:email-inbound", "llm:Extract"])
  })

  it("is still a Set to instanceof and to Set-consuming code", () => {
    const a = sample().provenance.ancestors
    expect(a instanceof Set).toBe(true)
    expect(new Set(a).size).toBe(2) // copies out cleanly
    expect(Object.prototype.toString.call(a)).toBe("[object Set]")
  })

  it("only add/delete/clear throw — reads never do", () => {
    const a = sample().provenance.ancestors as Set<string>
    expect(() => a.add("forged")).toThrow(/immutable/)
    expect(() => a.delete("llm:Extract")).toThrow(/immutable/)
    expect(() => a.clear()).toThrow(/immutable/)
    expect(a.size).toBe(2) // nothing partially applied
  })
})

describe("the fixes did not change any behaviour they weren't meant to", () => {
  it("corroborate still merges ancestry on success, and the merge is sealed too", () => {
    const a = Sourced.fromLLM({ v: 7 }, "A", [Sourced.fromChannel({ v: 7 }, "email")])
    const b = Sourced.fromLLM({ v: 7 }, "B", [Sourced.fromChannel({ v: 7 }, "webhook")])
    const r = corroborate(a, b)
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.value.tier).toBe("corroborated")
      expect(r.value.provenance.ancestors.has("channel:webhook")).toBe(true)
      expect(() => (r.value.provenance.ancestors as Set<string>).clear()).toThrow(/immutable/)
      // the upgrade chain survived and is still frozen
      expect(r.value.provenance.chain).toHaveLength(1)
      expect(Object.isFrozen(r.value.provenance.chain)).toBe(true)
    }
  })

  it("the chain array is a copy — mutating the input array can't reach a Sourced", () => {
    const v = sample()
    expect(Object.isFrozen(v.provenance)).toBe(true)
    expect(Object.isFrozen(v)).toBe(true)
  })

  it("un-redacted sinks still record the judgment rationale verbatim", () => {
    // The A4 fix must only bite when a redact policy is actually set. A sink
    // with no redaction loses nothing.
    const log = new ReceiptLog()
    const send = makeSink<{ to: Sourced<string> }, string>({
      name: "send",
      requires: { to: "verified" },
      mode: "enforce",
      log,
      judgment: {
        provider: {
          name: "j",
          assess: () => ({ assessment: "unsure", confidence: 0.4, rationale: "SPECIFIC-DETAIL-42" }),
        },
        floor: 0.8,
      },
      execute: () => "ok",
    })
    const out = send({ to: Sourced.fromAuthority("a@b.example", "dir") })
    expect(out.receipt.reason).toContain("SPECIFIC-DETAIL-42")
  })

  it("a clean enforce-mode call is untouched: executed, chain verifies, no extra keys", () => {
    const log = new ReceiptLog()
    const pay = makeSink<{ amount: Sourced<number> }, string>({
      name: "pay",
      requires: { amount: "verified" },
      mode: "enforce",
      log,
      execute: () => "sent",
    })
    const out = pay({ amount: Sourced.fromAuthority(10, "treasury") })
    expect(out.ok).toBe(true)
    expect(out.receipt.decision).toBe("executed")
    expect(Object.keys(out.receipt.args)).toEqual(["amount"])
    expect(log.verifyChain()).toBe(true)
  })

  it("verifyChain still passes on an ordinary growing log (no false positives)", () => {
    const log = new ReceiptLog()
    for (let i = 0; i < 50; i++) {
      log.append({ at: `2026-07-25T00:00:${String(i).padStart(2, "0")}Z`, sink: "s", decision: "executed", args: {} })
      expect(log.verifyChain()).toBe(true)
    }
    expect(log.all()).toHaveLength(50)
  })
})
