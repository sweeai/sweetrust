/**
 * Capability limits (DAN-1319): a grant may cap a capability by amount,
 * count and rolling window; the cap lives in the GRANT EVENT and the spend is
 * summed from the AUDIT LOG at every use. Nothing the holder can edit decides
 * the verdict. Every case below was watched RED before the implementation.
 *
 * Why the log and not a counter: a counter in memory dies with the process and
 * can be reset by whoever holds the object. The log is append-only and, when
 * signed, cannot be rewritten; so "how much has this mandate spent" is a
 * question the log answers the same way after a restart as before one.
 */
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterEach, describe, expect, test, vi } from "vitest"
import { MandateFailure } from "../../src/mandate/errors.ts"
import {
  createTrust,
  defineCapability,
  makeInMemoryAuditLive,
  makeJsonlAuditLive,
  type GrantorId,
  type MandateError,
} from "../../src/mandate/index.ts"

const ARTHUR = "arthur" as GrantorId
const Buy = defineCapability("amazon.buy")
const Read = defineCapability("mail.read")

const tagOf = (fn: () => void): MandateError["_tag"] | "none" => {
  try {
    fn()
    return "none"
  } catch (e) {
    if (MandateFailure.is(e)) return e._tag
    throw e
  }
}

const errorOf = (fn: () => void): MandateError => {
  try {
    fn()
  } catch (e) {
    if (MandateFailure.is(e)) return { ...e } as MandateError
    throw e
  }
  throw new Error("expected a MandateFailure")
}

afterEach(() => {
  vi.useRealTimers()
})

describe("amount limit — Danny's rule: under $30, no ask", () => {
  test("spend under the cap is allowed and recorded with its amount", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Buy, Read] as const,
      rationale: "household",
      limits: { [Buy.key]: { amount: 30, unit: "USD" } },
    })
    trust.useCapability({ mandate: org, capability: Buy, amount: 10 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 15 })
    const invokes = trust.audit.query(org.id).filter((e) => e.type === "invoke")
    expect(invokes.map((e) => (e.type === "invoke" ? e.amount : null))).toEqual([10, 15])
  })

  test("the spend that would cross the cap is refused, naming used and requested", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Buy] as const,
      rationale: "household",
      limits: { [Buy.key]: { amount: 30, unit: "USD" } },
    })
    trust.useCapability({ mandate: org, capability: Buy, amount: 10 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 15 })
    const err = errorOf(() => trust.useCapability({ mandate: org, capability: Buy, amount: 10 }))
    expect(err._tag).toBe("MandateLimitExceeded")
    if (err._tag !== "MandateLimitExceeded") return
    expect(err.capability).toBe("amazon.buy")
    expect(err.used).toEqual({ amount: 25, count: 2 })
    expect(err.requested).toBe(10)
    expect(err.limit).toEqual({ amount: 30, unit: "USD" })
    // The refusal recorded nothing: the log still shows two invokes.
    expect(trust.audit.query(org.id).filter((e) => e.type === "invoke")).toHaveLength(2)
  })

  test("exactly the cap is allowed; one more unit is not", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Buy] as const,
      rationale: "household",
      limits: { [Buy.key]: { amount: 30 } },
    })
    trust.useCapability({ mandate: org, capability: Buy, amount: 30 })
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Buy, amount: 0.01 }))).toBe(
      "MandateLimitExceeded",
    )
  })

  test("a capped capability refuses an invoke that declares no amount (fail closed)", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Buy] as const,
      rationale: "household",
      limits: { [Buy.key]: { amount: 30 } },
    })
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Buy }))).toBe("MandateAmountRequired")
  })

  test.each([
    ["NaN", Number.NaN],
    ["negative", -1],
    ["+Infinity", Number.POSITIVE_INFINITY],
    ["-Infinity", Number.NEGATIVE_INFINITY],
    ["a numeric string", "5" as unknown as number],
  ])("an amount that is %s is refused as invalid, capped or not", (_label, amount) => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Buy, Read] as const,
      rationale: "household",
      limits: { [Buy.key]: { amount: 30 } },
    })
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Buy, amount }))).toBe("MandateAmountInvalid")
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Read, amount }))).toBe("MandateAmountInvalid")
  })

  test("an uncapped capability needs no amount and may be used freely", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Buy, Read] as const,
      rationale: "household",
      limits: { [Buy.key]: { amount: 30 } },
    })
    for (let i = 0; i < 50; i++) trust.useCapability({ mandate: org, capability: Read })
    expect(trust.audit.query(org.id).filter((e) => e.type === "invoke")).toHaveLength(50)
  })
})

describe("count limit and rolling window", () => {
  test("the third use under a count of 2 is refused", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Read] as const,
      rationale: "two reads",
      limits: { [Read.key]: { count: 2 } },
    })
    trust.useCapability({ mandate: org, capability: Read })
    trust.useCapability({ mandate: org, capability: Read })
    const err = errorOf(() => trust.useCapability({ mandate: org, capability: Read }))
    expect(err._tag).toBe("MandateLimitExceeded")
    if (err._tag === "MandateLimitExceeded") expect(err.used).toEqual({ amount: 0, count: 2 })
  })

  test("a window forgets spend older than itself, and only that", () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date("2026-11-01T06:00:00.000Z"))
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Buy] as const,
      rationale: "daily",
      limits: { [Buy.key]: { amount: 30, windowMs: 24 * 60 * 60 * 1000 } },
    })
    trust.useCapability({ mandate: org, capability: Buy, amount: 25 })
    vi.advanceTimersByTime(23 * 60 * 60 * 1000)
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Buy, amount: 10 }))).toBe(
      "MandateLimitExceeded",
    )
    vi.advanceTimersByTime(1 * 60 * 60 * 1000 + 1)
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Buy, amount: 10 }))).toBe("none")
    // 10 inside the window; another 25 would cross.
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Buy, amount: 25 }))).toBe(
      "MandateLimitExceeded",
    )
  })
})

describe("the limit lives in the grant event, and the spend lives in the log", () => {
  test("the grant event carries the limits and the scope mirrors them, frozen", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const limits = { [Buy.key]: { amount: 30, unit: "USD" } }
    const org = trust.issueOrgMandate({ grantor: ARTHUR, capabilities: [Buy] as const, rationale: "x", limits })
    const grant = trust.audit.query(org.id).find((e) => e.type === "grant")
    expect(grant?.type === "grant" ? grant.limits : null).toEqual(limits)
    expect(org.limits).toEqual(limits)
    expect(Object.isFrozen(org.limits)).toBe(true)
    expect(Object.isFrozen(org.limits[Buy.key])).toBe(true)
  })

  test("a grant with no limits records none and the scope says so", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({ grantor: ARTHUR, capabilities: [Read] as const, rationale: "x" })
    const grant = trust.audit.query(org.id).find((e) => e.type === "grant")
    expect(grant?.type === "grant" ? grant.limits : "missing").toBeUndefined()
    expect(org.limits).toEqual({})
  })

  test("the spend survives the process: a fresh JSONL store over the same file still holds it", () => {
    const path = join(mkdtempSync(join(tmpdir(), "sweetrust-limits-")), "audit.jsonl")
    const first = createTrust({ store: makeJsonlAuditLive(path) })
    const org = first.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Buy] as const,
      rationale: "household",
      limits: { [Buy.key]: { amount: 30, unit: "USD" } },
    })
    first.useCapability({ mandate: org, capability: Buy, amount: 10 })
    first.useCapability({ mandate: org, capability: Buy, amount: 15 })

    const second = createTrust({ store: makeJsonlAuditLive(path) })
    const events = second.audit.query(org.id)
    const grant = events.find((e) => e.type === "grant")
    expect(grant?.type === "grant" ? grant.limits?.[Buy.key] : null).toEqual({ amount: 30, unit: "USD" })
    const spent = events.reduce((sum, e) => sum + (e.type === "invoke" ? (e.amount ?? 0) : 0), 0)
    expect(spent).toBe(25)
  })
})

describe("delegation: a child may only tighten", () => {
  const seed = () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Buy, Read] as const,
      rationale: "org",
      limits: { [Buy.key]: { amount: 100, count: 10, windowMs: 86_400_000, unit: "USD" } },
    })
    return { trust, org }
  }

  test("a tighter child is issued and enforced at its own cap", () => {
    const { trust, org } = seed()
    const project = trust.issueProjectMandate({
      grantor: ARTHUR,
      grantorScope: org,
      capabilities: [Buy] as const,
      rationale: "groceries",
      limits: { [Buy.key]: { amount: 30, count: 3, windowMs: 7 * 86_400_000, unit: "USD" } },
    })
    trust.useCapability({ mandate: project, capability: Buy, amount: 30 })
    expect(tagOf(() => trust.useCapability({ mandate: project, capability: Buy, amount: 1 }))).toBe(
      "MandateLimitExceeded",
    )
  })

  test.each([
    ["a larger amount", { amount: 150, count: 10, windowMs: 86_400_000, unit: "USD" }, "amount"],
    ["a larger count", { amount: 100, count: 11, windowMs: 86_400_000, unit: "USD" }, "count"],
    ["a shorter window (more per day)", { amount: 100, count: 10, windowMs: 3_600_000, unit: "USD" }, "windowMs"],
    ["no amount where the parent has one", { count: 10, windowMs: 86_400_000, unit: "USD" }, "amount"],
    ["another unit", { amount: 100, count: 10, windowMs: 86_400_000, unit: "EUR" }, "unit"],
  ])("a child with %s is refused, naming the field", (_label, childLimit, field) => {
    const { trust, org } = seed()
    const err = errorOf(() =>
      trust.issueProjectMandate({
        grantor: ARTHUR,
        grantorScope: org,
        capabilities: [Buy] as const,
        rationale: "groceries",
        limits: { [Buy.key]: childLimit },
      }),
    )
    expect(err._tag).toBe("LimitNotWithinGrantor")
    if (err._tag === "LimitNotWithinGrantor") {
      expect(err.capability).toBe("amazon.buy")
      expect(err.field).toBe(field)
    }
  })

  test("a child with no window under a windowed parent is a lifetime cap: tighter, allowed", () => {
    const { trust, org } = seed()
    const project = trust.issueProjectMandate({
      grantor: ARTHUR,
      grantorScope: org,
      capabilities: [Buy] as const,
      rationale: "ever",
      limits: { [Buy.key]: { amount: 100, count: 10, unit: "USD" } },
    })
    vi.useFakeTimers()
    trust.useCapability({ mandate: project, capability: Buy, amount: 100 })
    vi.advanceTimersByTime(365 * 86_400_000)
    expect(tagOf(() => trust.useCapability({ mandate: project, capability: Buy, amount: 1 }))).toBe("MandateLimitExceeded")
  })

  test("a child with a window under a lifetime parent would renew forever: refused", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Buy] as const,
      rationale: "100 ever",
      limits: { [Buy.key]: { amount: 100 } },
    })
    const err = errorOf(() =>
      trust.issueProjectMandate({
        grantor: ARTHUR,
        grantorScope: org,
        capabilities: [Buy] as const,
        rationale: "100 a day",
        limits: { [Buy.key]: { amount: 100, windowMs: 86_400_000 } },
      }),
    )
    expect(err._tag).toBe("LimitNotWithinGrantor")
    if (err._tag === "LimitNotWithinGrantor") expect(err.field).toBe("windowMs")
  })

  test("a child that carries a capped capability with no limit of its own is refused", () => {
    const { trust, org } = seed()
    const err = errorOf(() =>
      trust.issueProjectMandate({ grantor: ARTHUR, grantorScope: org, capabilities: [Buy] as const, rationale: "x" }),
    )
    expect(err._tag).toBe("LimitNotWithinGrantor")
  })

  test("a child that drops the capped capability needs no limit", () => {
    const { trust, org } = seed()
    const project = trust.issueProjectMandate({
      grantor: ARTHUR,
      grantorScope: org,
      capabilities: [Read] as const,
      rationale: "read only",
    })
    trust.useCapability({ mandate: project, capability: Read })
  })

  test("a limit naming a capability outside the grant is a programmer error, not a verdict", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    expect(() =>
      trust.issueOrgMandate({
        grantor: ARTHUR,
        capabilities: [Read] as const,
        rationale: "x",
        limits: { [Buy.key]: { amount: 1 } },
      }),
    ).toThrow(TypeError)
  })

  test.each([
    ["a negative amount", { amount: -1 }],
    ["a NaN count", { count: Number.NaN }],
    ["a fractional count", { count: 1.5 }],
    ["a zero window", { windowMs: 0 }],
    ["an empty limit", {}],
  ])("a limit with %s is a programmer error at issue", (_label, limit) => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    expect(() =>
      trust.issueOrgMandate({ grantor: ARTHUR, capabilities: [Buy] as const, rationale: "x", limits: { [Buy.key]: limit } }),
    ).toThrow(TypeError)
  })
})
