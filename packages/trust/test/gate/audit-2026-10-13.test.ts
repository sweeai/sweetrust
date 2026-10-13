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
import { Sourced, corroborate } from "../../src/gate/trust.js"

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
