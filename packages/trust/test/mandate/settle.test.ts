/**
 * Settling a hold (DAN-1410, spec-reconcile-v1 § 4, ADR 0011): a metered caller
 * holds the most a call could cost, then records what it really cost. The record
 * book is append-only, so the real cost is a new `settle` event and the invoke is
 * never edited.
 *
 * The rule the counter holds: an invoke counts at its settle's `actual` when one
 * valid settle exists, and at its `amount` otherwise, at the invoke's own time
 * and always as one call. A settle is valid only if it follows the one invoke
 * with its hold id and capability and `actual` is finite and within 0…amount; two
 * settles sharing a hold id are both invalid.
 *
 * Every case was watched RED against the code before this feature. The cases
 * that pin "this must not change" carry a positive control (a real settle, in the
 * same log, that does count), so they could not pass by the feature's absence.
 */
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterEach, describe, expect, test, vi } from "vitest"
import { canonicalJSON } from "../../src/canon.ts"
import { MandateFailure } from "../../src/mandate/errors.ts"
import {
  createTrust,
  defineCapability,
  makeInMemoryAuditLive,
  makeInMemorySignedAuditLive,
  makeInMemorySignerLive,
  makeJsonlAuditLive,
  makeJsonlSignedAuditLive,
  verifyAuditChain,
  type GrantorId,
  type MandateAuditEvent,
  type MandateAuditService,
  type MandateError,
  type MandateId,
  type MandateInvocationEvent,
  type MandateSettleEvent,
} from "../../src/mandate/index.ts"

const ARTHUR = "arthur" as GrantorId
const Buy = defineCapability("amazon.buy")
const Read = defineCapability("mail.read")
const HOLD = "a".repeat(32)
const HOLD_2 = "b".repeat(32)
const HOLD_3 = "c".repeat(32)
const HOUR = 3_600_000

afterEach(() => {
  vi.useRealTimers()
})

const tagOf = (fn: () => unknown): MandateError["_tag"] | "none" => {
  try {
    fn()
    return "none"
  } catch (e) {
    if (MandateFailure.is(e)) return e._tag
    throw e
  }
}

const errorOf = (fn: () => unknown): MandateError => {
  try {
    fn()
  } catch (e) {
    if (MandateFailure.is(e)) return { ...e } as MandateError
    throw e
  }
  throw new Error("expected a MandateFailure")
}

const capped = (limit: { amount?: number; count?: number; windowMs?: number }, store: MandateAuditService = makeInMemoryAuditLive()) => {
  const trust = createTrust({ store })
  const org = trust.issueOrgMandate({
    grantor: ARTHUR,
    capabilities: [Buy, Read] as const,
    rationale: "household",
    limits: { [Buy.key]: limit },
  })
  return { store, trust, org }
}

const settles = (events: ReadonlyArray<MandateAuditEvent>): ReadonlyArray<MandateSettleEvent> =>
  events.filter((e): e is MandateSettleEvent => e.type === "settle")

/** What the counter says is spent, read from the refusal of a spend no cap can admit. */
const spent = (trust: ReturnType<typeof capped>["trust"], org: ReturnType<typeof capped>["org"]) => {
  const refusal = errorOf(() => trust.useCapability({ mandate: org, capability: Buy, amount: 1e12 }))
  if (refusal._tag !== "MandateLimitExceeded") throw new Error(`expected MandateLimitExceeded, got ${refusal._tag}`)
  return refusal.used
}

/** A settle written straight into the store, as a tampered log or a foreign writer would. */
const plant = (
  store: MandateAuditService,
  mandateId: MandateId,
  fields: { holdId: string; actual: unknown; capability?: string },
): void => {
  store.record({
    type: "settle",
    mandateId,
    capability: fields.capability ?? Buy.key,
    holdId: fields.holdId,
    actual: fields.actual,
    timestamp: new Date().toISOString(),
    triggerSource: "code",
  } as unknown as MandateAuditEvent)
}

describe("what a settle does to the count", () => {
  test("a hold settles down and never up", () => {
    const { trust, org } = capped({ amount: 100 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    expect(spent(trust, org).amount).toBe(60)

    expect(tagOf(() => trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 61 }))).toBe(
      "MandateSettleAboveAmount",
    )
    expect(spent(trust, org).amount).toBe(60)

    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 10 })
    expect(spent(trust, org).amount).toBe(10)
    // The freed room is real: 90 more fits under 100, and 91 would not have.
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Buy, amount: 91 }))).toBe("MandateLimitExceeded")
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Buy, amount: 90 }))).toBe("none")
  })

  test("a settle records the fields the spec names, and the invoke is left alone", () => {
    const { trust, org } = capped({ amount: 100 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    const before = trust.audit.query(org.id).find((e) => e.type === "invoke")
    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 10, triggerSource: "external" })
    const events = trust.audit.query(org.id)
    expect(events.find((e) => e.type === "invoke")).toEqual(before)
    expect(settles(events)).toEqual([
      {
        type: "settle",
        mandateId: org.id,
        capability: Buy.key,
        holdId: HOLD,
        actual: 10,
        timestamp: expect.any(String),
        triggerSource: "external",
      },
    ])
  })

  test("a settle to zero counts as zero, and a settle to the full amount counts in full", () => {
    const { trust, org } = capped({ amount: 100 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    trust.useCapability({ mandate: org, capability: Buy, amount: 20, holdId: HOLD_2 })
    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 0 })
    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD_2, actual: 20 })
    expect(spent(trust, org).amount).toBe(20)
  })

  test("a hold settles at most once", () => {
    const { trust, org } = capped({ amount: 100 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 10 })
    expect(() => trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 5 })).toThrow(MandateFailure)
    expect(settles(trust.audit.query(org.id)).map((e) => e.actual)).toEqual([10])
    expect(spent(trust, org).amount).toBe(10)
  })

  test("a settled invoke counts at actual and its own timestamp", () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date("2026-11-08T00:00:00.000Z"))
    const { trust, org } = capped({ amount: 100, windowMs: HOUR })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })

    vi.setSystemTime(new Date("2026-11-08T00:30:00.000Z"))
    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 10 })
    expect(spent(trust, org)).toEqual({ amount: 10, count: 1 })

    // One millisecond past the invoke's hour: the settle is only 30 minutes old,
    // and it still leaves the window with the invoke it belongs to.
    vi.setSystemTime(new Date("2026-11-08T01:00:00.001Z"))
    expect(spent(trust, org)).toEqual({ amount: 0, count: 0 })
  })

  test("a settle inside the window does not pull an old invoke back in", () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date("2026-11-08T00:00:00.000Z"))
    const { trust, org } = capped({ amount: 100, windowMs: HOUR })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    trust.useCapability({ mandate: org, capability: Buy, amount: 1 })

    vi.setSystemTime(new Date("2026-11-08T02:00:00.000Z"))
    trust.useCapability({ mandate: org, capability: Buy, amount: 5, holdId: HOLD_2 })
    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 10 })
    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD_2, actual: 2 })
    expect(spent(trust, org)).toEqual({ amount: 2, count: 1 })
  })

  test("a hold id reused after its settle puts both invokes back at amount", () => {
    const { store, trust, org } = capped({ amount: 1_000 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 10 })
    expect(spent(trust, org).amount).toBe(10)

    // The spec refuses an ambiguous hold at settle and has no refusal at use, so
    // the reuse is recorded. It moves the count up, never down.
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    expect(spent(trust, org).amount).toBe(120)
    expect(settles(store.query(org.id))).toHaveLength(1)
  })

  test("a settled invoke still counts as one call", () => {
    const { trust, org } = capped({ count: 2, amount: 100 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 0 })
    expect(spent(trust, org).count).toBe(1)
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Buy, amount: 1 }))).toBe("none")
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Buy, amount: 0 }))).toBe("MandateLimitExceeded")
    expect(spent(trust, org).count).toBe(2)
  })

  test("a settle moves only its own capability's count", () => {
    const store = makeInMemoryAuditLive()
    const trust = createTrust({ store })
    const org = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Buy, Read] as const,
      rationale: "r",
      limits: { [Buy.key]: { amount: 100 }, [Read.key]: { amount: 100 } },
    })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    trust.useCapability({ mandate: org, capability: Read, amount: 50, holdId: HOLD_2 })
    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 10 })
    expect(spent(trust, org).amount).toBe(10)
    const refusal = errorOf(() => trust.useCapability({ mandate: org, capability: Read, amount: 1e12 }))
    expect(refusal).toMatchObject({ _tag: "MandateLimitExceeded", used: { amount: 50, count: 1 } })
  })
})

describe("what settleCapability refuses", () => {
  test("settle refuses a hold id no invoke carries on this mandate and capability", () => {
    const { store, trust, org } = capped({ amount: 100 })
    const other = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Buy, Read] as const,
      rationale: "other",
    })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    trust.useCapability({ mandate: org, capability: Buy, amount: 5 })

    // Never used anywhere.
    expect(tagOf(() => trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD_2, actual: 1 }))).toBe(
      "MandateSettleUnknownHold",
    )
    // A real hold, named by a different mandate.
    expect(tagOf(() => trust.settleCapability({ mandate: other, capability: Buy, holdId: HOLD, actual: 1 }))).toBe(
      "MandateSettleUnknownHold",
    )
    // A real hold, named through a different capability of the same mandate.
    expect(tagOf(() => trust.settleCapability({ mandate: org, capability: Read, holdId: HOLD, actual: 1 }))).toBe(
      "MandateSettleUnknownHold",
    )
    expect(settles(store.query(org.id))).toEqual([])
  })

  test("settle refuses an invoke with no finite amount", () => {
    const { store, trust, org } = capped({ amount: 100 })
    trust.useCapability({ mandate: org, capability: Read, holdId: HOLD })
    expect(tagOf(() => trust.settleCapability({ mandate: org, capability: Read, holdId: HOLD, actual: 0 }))).toBe(
      "MandateSettleNoAmount",
    )
    // A line no issuer can write; the store holder's own record.
    store.record({
      type: "invoke",
      mandateId: org.id,
      capability: Buy.key,
      timestamp: new Date().toISOString(),
      triggerSource: "code",
      amount: Number.POSITIVE_INFINITY,
      holdId: HOLD_2,
    } as unknown as MandateAuditEvent)
    expect(tagOf(() => trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD_2, actual: 0 }))).toBe(
      "MandateSettleNoAmount",
    )
    expect(settles(store.query(org.id))).toEqual([])
  })

  test("settle refuses an actual above the amount", () => {
    const { store, trust, org } = capped({ amount: 100 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    const refusal = errorOf(() => trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 60.01 }))
    expect(refusal).toMatchObject({
      _tag: "MandateSettleAboveAmount",
      mandateId: org.id,
      capability: Buy.key,
      holdId: HOLD,
      amount: 60,
      actual: 60.01,
    })
    expect(settles(store.query(org.id))).toEqual([])
  })

  test("settle refuses a second settle for the same hold id", () => {
    const { store, trust, org } = capped({ amount: 100 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 10 })
    expect(tagOf(() => trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 10 }))).toBe(
      "MandateSettleDuplicate",
    )
    expect(settles(store.query(org.id))).toHaveLength(1)
  })

  test("a second settle is refused when the first is one the counter ignores", () => {
    const { store, trust, org } = capped({ amount: 100 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    plant(store, org.id, { holdId: HOLD, actual: 1_000 })
    expect(tagOf(() => trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 10 }))).toBe(
      "MandateSettleDuplicate",
    )
    expect(settles(store.query(org.id))).toHaveLength(1)
  })

  test.each([
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["negative", -1],
    ["a numeric string", "1"],
    ["null", null],
    ["a bigint", 1n],
    ["an object with valueOf", { valueOf: (): number => 1 }],
  ])("settle refuses a non-finite or negative actual (%s)", (_label, actual) => {
    const { store, trust, org } = capped({ amount: 100 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    const refusal = errorOf(() => trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual } as never))
    expect(refusal).toMatchObject({ _tag: "MandateAmountInvalid", mandateId: org.id, capability: Buy.key })
    expect(settles(store.query(org.id))).toEqual([])
  })

  test("settle refuses when two invokes share the hold id", () => {
    const { store, trust, org } = capped({ amount: 100 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 30, holdId: HOLD })
    trust.useCapability({ mandate: org, capability: Buy, amount: 30, holdId: HOLD })
    expect(tagOf(() => trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 1 }))).toBe(
      "MandateSettleAmbiguousHold",
    )
    // Same refusal when the twin sits on another capability of this mandate.
    trust.useCapability({ mandate: org, capability: Buy, amount: 30, holdId: HOLD_2 })
    trust.useCapability({ mandate: org, capability: Read, amount: 30, holdId: HOLD_2 })
    expect(tagOf(() => trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD_2, actual: 1 }))).toBe(
      "MandateSettleAmbiguousHold",
    )
    expect(settles(store.query(org.id))).toEqual([])
    expect(spent(trust, org).amount).toBe(90)
  })

  test("a refused settle writes nothing", () => {
    const { store, trust, org } = capped({ amount: 100 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    trust.useCapability({ mandate: org, capability: Read, holdId: HOLD_2 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 5, holdId: HOLD_3 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 5, holdId: HOLD_3 })
    const foreign = createTrust({ store: makeInMemoryAuditLive() }).issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Buy] as const,
      rationale: "foreign",
    })
    const before = store.query(org.id).length

    const refused: ReadonlyArray<readonly [MandateError["_tag"], () => void]> = [
      ["MandateSettleUnknownHold", () => trust.settleCapability({ mandate: org, capability: Buy, holdId: "d".repeat(32), actual: 1 })],
      ["MandateSettleNoAmount", () => trust.settleCapability({ mandate: org, capability: Read, holdId: HOLD_2, actual: 0 })],
      ["MandateSettleAboveAmount", () => trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 61 })],
      ["MandateAmountInvalid", () => trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: Number.NaN })],
      ["MandateSettleAmbiguousHold", () => trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD_3, actual: 1 })],
      ["MandateScopeForged", () => trust.settleCapability({ mandate: { ...org }, capability: Buy, holdId: HOLD, actual: 1 } as never)],
      ["MandateScopeForeign", () => trust.settleCapability({ mandate: foreign, capability: Buy, holdId: HOLD, actual: 1 } as never)],
      ["CapabilityNotInGrantorScope", () => trust.settleCapability({ mandate: org, capability: defineCapability("wire.send"), holdId: HOLD, actual: 1 } as never)],
    ]
    for (const [tag, call] of refused) {
      expect([tag, tagOf(call)]).toEqual([tag, tag])
      expect(store.query(org.id)).toHaveLength(before)
    }

    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 10 })
    const settled = store.query(org.id).length
    expect(settled).toBe(before + 1)
    expect(tagOf(() => trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 1 }))).toBe(
      "MandateSettleDuplicate",
    )
    expect(store.query(org.id)).toHaveLength(settled)
  })
})

describe("what settleCapability reads, and when", () => {
  test.each([
    ["too short", "a".repeat(31)],
    ["too long", "a".repeat(33)],
    ["uppercase", "A".repeat(32)],
    ["not hex", "g".repeat(32)],
    ["a trailing newline", `${"a".repeat(32)}\n`],
    ["the empty string", ""],
    ["a number", 7],
    ["null", null],
    ["an array", ["a".repeat(32)]],
    ["a String object", new String("a".repeat(32))],
    ["an object with toJSON", { toJSON: () => "a".repeat(32) }],
  ])("a malformed hold id throws TypeError on use and on settle (%s)", (_label, holdId) => {
    const { store, trust, org } = capped({ amount: 100 })
    expect(() => trust.useCapability({ mandate: org, capability: Buy, amount: 1, holdId } as never)).toThrow(TypeError)
    expect(() => trust.useCapability({ mandate: org, capability: Buy, amount: 1, holdId } as never)).toThrow(/holdId/)
    expect(store.query(org.id).filter((e) => e.type === "invoke")).toEqual([])

    trust.useCapability({ mandate: org, capability: Buy, amount: 1, holdId: HOLD })
    const before = store.query(org.id).length
    expect(() => trust.settleCapability({ mandate: org, capability: Buy, holdId, actual: 0 } as never)).toThrow(TypeError)
    expect(() => trust.settleCapability({ mandate: org, capability: Buy, holdId, actual: 0 } as never)).toThrow(/holdId/)
    expect(store.query(org.id)).toHaveLength(before)
  })

  test("settle requires a hold id; use does not", () => {
    const { trust, org } = capped({ amount: 100 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 1 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 1, holdId: undefined })
    for (const args of [{ actual: 0 }, { holdId: undefined, actual: 0 }]) {
      expect(() => trust.settleCapability({ mandate: org, capability: Buy, ...args } as never)).toThrow(TypeError)
      expect(() => trust.settleCapability({ mandate: org, capability: Buy, ...args } as never)).toThrow(/holdId/)
    }
  })

  const spyStore = (log: string[]): MandateAuditService => {
    const inner = makeInMemoryAuditLive()
    return {
      record: (e) => {
        log.push("store:record")
        inner.record(e)
      },
      query: (id) => {
        log.push("store:query")
        return inner.query(id)
      },
      isRevoked: (id) => {
        log.push("store:isRevoked")
        return inner.isRevoked(id)
      },
    }
  }

  /** Every read of a field is logged as `read:<key>`, in order with the store's reads. */
  const logged = <T extends object>(input: T, log: string[], prefix = "read"): T =>
    new Proxy(input, {
      get(target, key) {
        log.push(`${prefix}:${String(key)}`)
        return Reflect.get(target, key)
      },
    })

  const assertReadOnceBeforeLog = (log: ReadonlyArray<string>, fields: ReadonlyArray<string>): void => {
    const firstStore = log.findIndex((entry) => entry.startsWith("store:"))
    expect(firstStore).toBeGreaterThanOrEqual(0)
    for (const field of fields) {
      expect([field, log.filter((entry) => entry === field).length]).toEqual([field, 1])
      expect(log.indexOf(field)).toBeLessThan(firstStore)
    }
  }

  test("each field is read once before the first log read", () => {
    const log: string[] = []
    const store = spyStore(log)
    const trust = createTrust({ store })
    const org = trust.issueOrgMandate({ grantor: ARTHUR, capabilities: [Buy] as const, rationale: "r", limits: { [Buy.key]: { amount: 100 } } })

    log.length = 0
    trust.useCapability(
      logged({ mandate: org, capability: logged(Buy, log, "cap"), amount: 60, holdId: HOLD, triggerSource: "code" as const }, log),
    )
    assertReadOnceBeforeLog(log, ["read:mandate", "read:capability", "read:amount", "read:holdId", "read:triggerSource", "cap:key"])

    log.length = 0
    trust.settleCapability(
      logged({ mandate: org, capability: logged(Buy, log, "cap"), holdId: HOLD, actual: 10, triggerSource: "code" as const }, log),
    )
    assertReadOnceBeforeLog(log, ["read:mandate", "read:capability", "read:holdId", "read:actual", "read:triggerSource", "cap:key"])
    expect(log).toContain("store:record")

    const settle = settles(trust.audit.query(org.id))[0]!
    expect(typeof settle.holdId).toBe("string")
    expect(typeof settle.actual).toBe("number")
    expect(typeof settle.capability).toBe("string")
  })

  test("a getter answering differently on a later read cannot reach the record", () => {
    const { store, trust, org } = capped({ amount: 100 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    let holdReads = 0
    let actualReads = 0
    trust.settleCapability({
      mandate: org,
      capability: Buy,
      get holdId() {
        holdReads += 1
        return holdReads === 1 ? HOLD : "not hex"
      },
      get actual() {
        actualReads += 1
        return actualReads === 1 ? 10 : 1_000
      },
    } as never)
    expect([holdReads, actualReads]).toEqual([1, 1])
    expect(settles(store.query(org.id))).toMatchObject([{ holdId: HOLD, actual: 10 }])
  })

  test("a holdId from the prototype does not count as present", () => {
    const { trust, org } = capped({ amount: 100 })
    const args = Object.create({ holdId: HOLD }) as { mandate: typeof org; capability: typeof Buy; amount: number }
    args.mandate = org
    args.capability = Buy
    args.amount = 1
    trust.useCapability(args)
    trust.useCapability({ mandate: org, capability: Buy, amount: 1, holdId: HOLD })
    const [inherited, own] = trust.audit.query(org.id).filter((e) => e.type === "invoke")
    expect(inherited).not.toHaveProperty("holdId")
    expect(own).toHaveProperty("holdId", HOLD)
  })

  test("settleCapability is on the frozen client and is a function", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    expect(Object.isFrozen(trust)).toBe(true)
    expect(typeof trust.settleCapability).toBe("function")
  })
})

describe("revocation and possession", () => {
  test("settle is allowed on a revoked mandate", () => {
    const { store, trust, org } = capped({ amount: 100 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "stop" })

    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Buy, amount: 1 }))).toBe("MandateRevoked")
    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 10 })
    expect(settles(store.query(org.id))).toMatchObject([{ holdId: HOLD, actual: 10 }])
  })

  test("a child can settle after its ancestor is revoked", () => {
    const store = makeInMemoryAuditLive()
    const trust = createTrust({ store })
    const org = trust.issueOrgMandate({ grantor: ARTHUR, capabilities: [Buy] as const, rationale: "org" })
    const project = trust.issueProjectMandate({ grantor: ARTHUR, grantorScope: org, capabilities: [Buy] as const, rationale: "p" })
    const agent = trust.issueAgentMandate({ grantor: ARTHUR, grantorScope: project, capabilities: [Buy] as const, rationale: "a" })
    trust.useCapability({ mandate: agent, capability: Buy, amount: 60, holdId: HOLD })
    trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "stop" })

    expect(tagOf(() => trust.useCapability({ mandate: agent, capability: Buy, amount: 1 }))).toBe("AncestorMandateRevoked")
    trust.settleCapability({ mandate: agent, capability: Buy, holdId: HOLD, actual: 10 })
    expect(settles(store.query(agent.id))).toHaveLength(1)
  })

  test("a copy of a scope cannot settle, and a scope from another store cannot either", () => {
    const { trust, org } = capped({ amount: 100 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    expect(tagOf(() => trust.settleCapability({ mandate: { ...org }, capability: Buy, holdId: HOLD, actual: 1 } as never))).toBe(
      "MandateScopeForged",
    )
    const elsewhere = createTrust({ store: makeInMemoryAuditLive() })
    expect(tagOf(() => elsewhere.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 1 }))).toBe(
      "MandateScopeForeign",
    )
  })

  test("a resumed scope can settle a hold taken before the restart", () => {
    const store = makeInMemoryAuditLive()
    const first = createTrust({ store })
    const org = first.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Buy] as const,
      rationale: "r",
      limits: { [Buy.key]: { amount: 100 } },
    })
    first.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })

    const second = createTrust({ store })
    const resumed = second.resume({ mandateId: org.id, capabilities: [Buy] as const, resumedBy: ARTHUR })
    second.settleCapability({ mandate: resumed, capability: Buy, holdId: HOLD, actual: 10 })
    expect(tagOf(() => second.useCapability({ mandate: resumed, capability: Buy, amount: 90 }))).toBe("none")
  })
})

describe("a settle the counter must not honor", () => {
  /** One settled hold the counter does honor, so a pass here cannot be a counter that ignores settles. */
  const withControl = () => {
    const ctx = capped({ amount: 1_000 })
    ctx.trust.useCapability({ mandate: ctx.org, capability: Buy, amount: 200, holdId: HOLD_3 })
    ctx.trust.settleCapability({ mandate: ctx.org, capability: Buy, holdId: HOLD_3, actual: 5 })
    return ctx
  }

  test("a settle before its invoke is ignored by the counter", () => {
    const { store, trust, org } = withControl()
    plant(store, org.id, { holdId: HOLD, actual: 1 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    expect(spent(trust, org).amount).toBe(65)
  })

  test("two settles sharing a hold id are both ignored by the counter", () => {
    const { store, trust, org } = withControl()
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    plant(store, org.id, { holdId: HOLD, actual: 1 })
    plant(store, org.id, { holdId: HOLD, actual: 2 })
    expect(spent(trust, org).amount).toBe(65)
  })

  test.each([
    ["above the amount", 61],
    ["negative", -1],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["a string", "1"],
    ["missing", undefined],
  ])("an out of range settle in the log is ignored by the counter (%s)", (_label, actual) => {
    const { store, trust, org } = withControl()
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    plant(store, org.id, { holdId: HOLD, actual })
    expect(spent(trust, org).amount).toBe(65)
  })

  test("a settle naming another capability is ignored by the counter", () => {
    const { store, trust, org } = withControl()
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    plant(store, org.id, { holdId: HOLD, actual: 1, capability: Read.key })
    expect(spent(trust, org).amount).toBe(65)
  })

  test("a settle on a hold two invokes share is ignored by the counter, across capabilities too", () => {
    const { store, trust, org } = withControl()
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    trust.useCapability({ mandate: org, capability: Read, amount: 1, holdId: HOLD })
    plant(store, org.id, { holdId: HOLD, actual: 1 })
    expect(spent(trust, org).amount).toBe(65)
  })

  test.each([
    ["Infinity", Number.POSITIVE_INFINITY, Number.POSITIVE_INFINITY],
    ["no amount", undefined, 5],
  ])("a settle on an invoke with no finite amount is ignored by the counter (%s)", (_label, amount, expected) => {
    const { store, trust, org } = withControl()
    // Lines no issuer can write: a store holder's own record, with a settle the
    // rule must not honor, or the Infinity would drop to 1 and the missing
    // amount would rise to 1.
    store.record({
      type: "invoke",
      mandateId: org.id,
      capability: Buy.key,
      timestamp: new Date().toISOString(),
      triggerSource: "code",
      amount,
      holdId: HOLD,
    } as unknown as MandateAuditEvent)
    plant(store, org.id, { holdId: HOLD, actual: 1 })
    expect(spent(trust, org).amount).toBe(expected)
  })

  test("a settle on another mandate's hold is ignored by the counter", () => {
    const { store, trust, org } = withControl()
    const other = trust.issueOrgMandate({ grantor: ARTHUR, capabilities: [Buy] as const, rationale: "o" })
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    plant(store, other.id, { holdId: HOLD, actual: 1 })
    expect(spent(trust, org).amount).toBe(65)
  })
})

describe("the record itself", () => {
  const signedRun = () => {
    const signer = makeInMemorySignerLive()
    const { mandateAudit, signedAudit } = makeInMemorySignedAuditLive(signer)
    const trust = createTrust({ store: mandateAudit })
    const org = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Buy] as const,
      rationale: "r",
      limits: { [Buy.key]: { amount: 100 } },
    })
    return { signer, signedAudit, trust, org, pin: { trustedSignerPublicKeyHex: signer.publicKeyHex } }
  }

  test("a log holding settle events still verifies", () => {
    const { signer, signedAudit, trust, org, pin } = signedRun()
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 10 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 1 })
    const records = signedAudit.listAllSigned()
    expect(records.map((r) => r.payload.type)).toEqual(["grant", "invoke", "settle", "invoke"])
    expect(verifyAuditChain(records, signer, pin)).toMatchObject({ valid: true, reason: "ok" })
  })

  test("an edited settle fails signature verification", () => {
    const { signer, signedAudit, trust, org, pin } = signedRun()
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 10 })
    const records = signedAudit.listAllSigned().map((r, i) =>
      i === 2 ? { ...r, payload: { ...r.payload, actual: 0 } as MandateAuditEvent } : r,
    )
    expect(verifyAuditChain(records, signer, pin)).toMatchObject({ valid: false, reason: "signature-mismatch" })
  })

  test("an invoke without a hold id keeps its signed bytes", () => {
    const { signedAudit, trust, org } = signedRun()
    trust.useCapability({ mandate: org, capability: Buy, amount: 60 })
    trust.useCapability({ mandate: org, capability: Buy, amount: 1, holdId: undefined })
    trust.useCapability({ mandate: org, capability: Buy, amount: 2, holdId: HOLD })
    const [bare, undefinedKey, held] = signedAudit.listAllSigned().slice(1).map((r) => r.payload as MandateInvocationEvent)

    const expected = (e: MandateInvocationEvent, amount: number) =>
      canonicalJSON({
        type: "invoke",
        mandateId: org.id,
        capability: Buy.key,
        timestamp: e.timestamp,
        triggerSource: "code",
        amount,
      })
    expect(canonicalJSON(bare!)).toBe(expected(bare!, 60))
    expect(canonicalJSON(undefinedKey!)).toBe(expected(undefinedKey!, 1))
    // The control: a hold id, when given, is inside the signed bytes.
    expect(canonicalJSON(held!)).toContain(`"holdId":"${HOLD}"`)
    expect(held!.holdId).toBe(HOLD)
  })

  const freshPath = () => join(mkdtempSync(join(tmpdir(), "sweetrust-settle-")), "audit.jsonl")

  test.each([
    ["in-memory", (): MandateAuditService => makeInMemoryAuditLive()],
    ["jsonl", (): MandateAuditService => makeJsonlAuditLive(freshPath())],
    ["in-memory signed", (): MandateAuditService => makeInMemorySignedAuditLive(makeInMemorySignerLive()).mandateAudit],
    ["jsonl signed", (): MandateAuditService => makeJsonlSignedAuditLive(freshPath(), makeInMemorySignerLive()).mandateAudit],
  ])("a settle counts the same on every store (%s)", (_label, makeStore) => {
    const { store, trust, org } = capped({ amount: 100, count: 5 }, makeStore())
    trust.useCapability({ mandate: org, capability: Buy, amount: 60, holdId: HOLD })
    trust.useCapability({ mandate: org, capability: Buy, amount: 30, holdId: HOLD_2 })
    trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 10 })
    expect(spent(trust, org)).toEqual({ amount: 40, count: 2 })
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Buy, amount: 61 }))).toBe("MandateLimitExceeded")
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Buy, amount: 60 }))).toBe("none")
    expect(tagOf(() => trust.settleCapability({ mandate: org, capability: Buy, holdId: HOLD, actual: 1 }))).toBe(
      "MandateSettleDuplicate",
    )
    expect(store.query(org.id).map((e) => e.type)).toEqual(["grant", "invoke", "invoke", "settle", "invoke"])
  })
})
