/**
 * MandateId — width and issue-time uniqueness (the 2026-10-13 mandate audit).
 *
 * `generateMandateId` drew 8 random bytes and kept 10 hex characters: 40 bits,
 * a birthday bound near 2^20, while types.ts called ids "collision-free" and
 * ARCHITECTURE § 2 "entropy-strong", and nothing consulted the log at issue
 * time. A colliding id would have recorded a SECOND grant under an id the log
 * already knew, and `useCapability` resolves a scope with `find(grant)`, the
 * FIRST one. The three tests marked RED below were watched failing against the
 * pre-fix source; the control was green on both sides.
 *
 * `randomBytes` is mocked so a collision can be MADE to happen; the default
 * implementation is the real one, and only `mockImplementationOnce` is used,
 * so an issuer that draws again gets real randomness.
 */
import { afterEach, describe, expect, test, vi } from "vitest"
import { randomBytes } from "node:crypto"
import { makeInMemoryAuditLive } from "../../src/mandate/audit.ts"
import { defineCapability, issueOrgMandate, useCapability } from "../../src/mandate/mandate.ts"
import type { GrantorId, ISO8601, MandateId } from "../../src/mandate/types.ts"

vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>()
  return { ...actual, randomBytes: vi.fn(actual.randomBytes) }
})
const { randomBytes: actualRandomBytes } = await vi.importActual<typeof import("node:crypto")>("node:crypto")

const Read = defineCapability("mandate-id/read")
const Wire = defineCapability("mandate-id/wire")
const ARTHUR = "ARTHUR" as GrantorId
const FIXED = Buffer.from("0123456789abcdef", "hex")
const ID_FORMAT = /^MAN_[0-9A-Z]{10}_[0-9A-F]{16}$/
const FROZEN_AT = new Date("2026-10-13T12:00:00Z")

const drawFixedOnce = (): void => {
  vi.mocked(randomBytes).mockImplementationOnce((() => FIXED) as any)
}
/** The id `generateMandateId` produces from FIXED at the frozen clock. */
const fixedIdNow = (): MandateId =>
  `MAN_${Date.now().toString(36).padStart(10, "0")}_${FIXED.toString("hex")}`.toUpperCase() as MandateId

afterEach(() => {
  vi.useRealTimers()
  vi.mocked(randomBytes).mockReset()
  vi.mocked(randomBytes).mockImplementation(actualRandomBytes as any)
})

describe("2026-10-13 audit — MandateId width and issue-time uniqueness", () => {
  test("RED: an issued id carries the full 16 hex characters, 64 bits", () => {
    const audit = makeInMemoryAuditLive()
    const scope = issueOrgMandate({ grantor: ARTHUR, capabilities: [Read] as const, rationale: "width" }, audit)
    expect(scope.id).toMatch(ID_FORMAT)
  })

  test("RED: two issues that draw the same bytes in the same millisecond do not share an id", () => {
    vi.useFakeTimers({ now: FROZEN_AT })
    const audit = makeInMemoryAuditLive()
    drawFixedOnce()
    drawFixedOnce()

    const first = issueOrgMandate({ grantor: ARTHUR, capabilities: [Read] as const, rationale: "first" }, audit)
    const second = issueOrgMandate({ grantor: ARTHUR, capabilities: [Read, Wire] as const, rationale: "second" }, audit)

    expect(first.id).toBe(fixedIdNow())
    expect(second.id).not.toBe(first.id)
    expect(second.id).toMatch(ID_FORMAT)
    // The log stays coherent: one grant per id, and each scope resolves to ITS
    // own grant at use. Before the fix the second grant landed under the first
    // id, and `find(grant)` resolved the second scope against the first's caps.
    expect(audit.query(first.id).filter((e) => e.type === "grant").length).toBe(1)
    expect(audit.query(second.id).filter((e) => e.type === "grant").length).toBe(1)
    expect(() => useCapability({ mandate: second, capability: Wire }, audit)).not.toThrow()
  })

  test("RED: an id with ANY event already in the log is taken, not only one with a grant", () => {
    // A stray revoke under an id that was never granted. Adopting that id
    // would mint a mandate born revoked. One `query` answers both questions,
    // so the issuer refuses any id the log has heard of.
    vi.useFakeTimers({ now: FROZEN_AT })
    // Learn the id this module mints from FIXED at the frozen clock, from a
    // throwaway log, so the test witnesses the behaviour at either id width.
    drawFixedOnce()
    const taken = issueOrgMandate(
      { grantor: ARTHUR, capabilities: [Read] as const, rationale: "probe" },
      makeInMemoryAuditLive(),
    ).id
    const audit = makeInMemoryAuditLive()
    audit.record({
      type: "revoke",
      mandateId: taken,
      revokedBy: ARTHUR,
      rationale: "stale revoke under a never-granted id",
      timestamp: FROZEN_AT.toISOString() as ISO8601,
      triggerSource: "code",
    })
    drawFixedOnce()

    const scope = issueOrgMandate({ grantor: ARTHUR, capabilities: [Read] as const, rationale: "fresh" }, audit)

    expect(scope.id).not.toBe(taken)
    expect(audit.isRevoked(scope.id)).toBe(false)
    expect(() => useCapability({ mandate: scope, capability: Read }, audit)).not.toThrow()
  })

  test("CONTROL: an issue with no collision draws exactly one random value", () => {
    const audit = makeInMemoryAuditLive()
    vi.mocked(randomBytes).mockClear()
    issueOrgMandate({ grantor: ARTHUR, capabilities: [Read] as const, rationale: "one draw" }, audit)
    expect(vi.mocked(randomBytes).mock.calls.length).toBe(1)
  })
})
