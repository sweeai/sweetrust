/**
 * The verdict digest on the invoke event (DAN-1385): a host that ran a judged
 * sink names the verdict that approved the action on the mandate's own record,
 * so the mandate log joins the gate receipt and the Sui receipt on one value
 * (spec 3.1). The field is optional on the argument and on the event. An
 * invoke without one is byte-for-byte what it was (spec 5, Migration). Each
 * case that asserts the field or its format was watched RED before the
 * implementation; the absent-key and unchanged-authority cases pass on the old
 * code by design, because they pin what must not move.
 */
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, test } from "vitest"
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
  type MandateError,
  type MandateInvocationEvent,
  type SignedMandateAuditEvent,
} from "../../src/mandate/index.ts"

const ARTHUR = "arthur" as GrantorId
const HOST = "host" as GrantorId
const Pay = defineCapability("pay")
const DIGEST = "d".repeat(64)
const OTHER = "e".repeat(64)

const freshPath = () => join(mkdtempSync(join(tmpdir(), "sweetrust-verdict-digest-")), "audit.jsonl")
const invokes = (events: ReadonlyArray<MandateAuditEvent>): ReadonlyArray<MandateInvocationEvent> =>
  events.filter((e): e is MandateInvocationEvent => e.type === "invoke")

const orgOn = (store = makeInMemoryAuditLive()) => {
  const trust = createTrust({ store })
  const org = trust.issueOrgMandate({ grantor: ARTHUR, capabilities: [Pay] as const, rationale: "r" })
  return { trust, org }
}

const tagOf = (fn: () => unknown): MandateError["_tag"] | "none" => {
  try {
    fn()
    return "none"
  } catch (e) {
    if (MandateFailure.is(e)) return e._tag
    throw e
  }
}

describe("the field on the event", () => {
  test("recorded on the invoke event when given", () => {
    const { trust, org } = orgOn()
    trust.useCapability({ mandate: org, capability: Pay, verdictDigest: DIGEST })
    expect(invokes(trust.audit.query(org.id))[0]!.verdictDigest).toBe(DIGEST)
  })

  test.each([
    ["omitted", {}],
    ["explicitly undefined", { verdictDigest: undefined }],
  ])("an invoke with the digest %s does not gain the key", (_label, extra) => {
    const { trust, org } = orgOn()
    trust.useCapability({ mandate: org, capability: Pay, ...extra })
    expect(Object.keys(invokes(trust.audit.query(org.id))[0]!)).not.toContain("verdictDigest")
  })

  test("an inherited digest is not the caller's field and is not recorded (own keys only)", () => {
    const { trust, org } = orgOn()
    const args = Object.create({ verdictDigest: DIGEST }) as { mandate: typeof org; capability: typeof Pay }
    args.mandate = org
    args.capability = Pay
    trust.useCapability(args)
    expect(Object.keys(invokes(trust.audit.query(org.id))[0]!)).not.toContain("verdictDigest")
  })

  test("a getter is read once: the value checked is the value recorded", () => {
    const { trust, org } = orgOn()
    let reads = 0
    const args = {
      mandate: org,
      capability: Pay,
      get verdictDigest() {
        reads++
        return reads === 1 ? DIGEST : "forged"
      },
    }
    trust.useCapability(args)
    expect(reads).toBe(1)
    expect(invokes(trust.audit.query(org.id))[0]!.verdictDigest).toBe(DIGEST)
  })

  test("the recorded event is frozen, so a reader cannot rewrite the link", () => {
    const { trust, org } = orgOn()
    trust.useCapability({ mandate: org, capability: Pay, verdictDigest: DIGEST })
    expect(Object.isFrozen(invokes(trust.audit.query(org.id))[0])).toBe(true)
  })
})

describe("the format: 64 lowercase hex, else a TypeError", () => {
  test.each<[string, unknown]>([
    ["not hex", "nope"],
    ["empty", ""],
    ["63 characters", "d".repeat(63)],
    ["65 characters", "d".repeat(65)],
    ["uppercase", "D".repeat(64)],
    ["mixed case", `${"d".repeat(63)}A`],
    ["a 0x prefix", `0x${"d".repeat(62)}`],
    ["a non-hex letter", `${"d".repeat(63)}g`],
    ["a trailing newline", `${"d".repeat(64)}\n`],
    ["leading whitespace", ` ${"d".repeat(63)}`],
    ["null", null],
    ["a number", 7],
    ["a boolean", true],
    ["an array holding a valid digest", [DIGEST]],
    ["a String object", new String(DIGEST)],
    ["an object whose toString is a valid digest", { toString: () => DIGEST }],
  ])("%s is refused and nothing is recorded", (_label, verdictDigest) => {
    const { trust, org } = orgOn()
    expect(() => trust.useCapability({ mandate: org, capability: Pay, verdictDigest } as never)).toThrow(TypeError)
    expect(invokes(trust.audit.query(org.id))).toHaveLength(0)
  })

  test("the TypeError does not echo the caller's value into the message", () => {
    const { trust, org } = orgOn()
    const secret = "sk-this-is-not-a-digest"
    let message = ""
    try {
      trust.useCapability({ mandate: org, capability: Pay, verdictDigest: secret })
    } catch (e) {
      message = (e as Error).message
    }
    expect(message).toMatch(/verdictDigest/)
    expect(message).not.toContain(secret)
  })
})

describe("the digest changes no authority decision", () => {
  test("a revoked mandate is refused with a valid digest, and records nothing", () => {
    const { trust, org } = orgOn()
    trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "stop" })
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Pay, verdictDigest: DIGEST }))).toBe("MandateRevoked")
    expect(invokes(trust.audit.query(org.id))).toHaveLength(0)
  })

  test("an amount limit sums the same with and without digests", () => {
    const store = makeInMemoryAuditLive()
    const trust = createTrust({ store })
    const org = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Pay] as const,
      rationale: "r",
      limits: { [Pay.key]: { amount: 30 } },
    })
    trust.useCapability({ mandate: org, capability: Pay, amount: 10, verdictDigest: DIGEST })
    trust.useCapability({ mandate: org, capability: Pay, amount: 10 })
    trust.useCapability({ mandate: org, capability: Pay, amount: 10, verdictDigest: OTHER })
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Pay, amount: 1, verdictDigest: DIGEST }))).toBe(
      "MandateLimitExceeded",
    )
    const recorded = invokes(trust.audit.query(org.id))
    expect(recorded.map((e) => e.amount)).toEqual([10, 10, 10])
    expect(recorded.map((e) => e.verdictDigest)).toEqual([DIGEST, undefined, OTHER])
  })

  test("a count limit counts a digest-bearing invoke once", () => {
    const store = makeInMemoryAuditLive()
    const trust = createTrust({ store })
    const org = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Pay] as const,
      rationale: "r",
      limits: { [Pay.key]: { count: 1 } },
    })
    trust.useCapability({ mandate: org, capability: Pay, verdictDigest: DIGEST })
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: Pay, verdictDigest: DIGEST }))).toBe(
      "MandateLimitExceeded",
    )
  })

  test("a resumed scope records the digest, after a reopen of the store", () => {
    const path = freshPath()
    const first = createTrust({ store: makeJsonlAuditLive(path) })
    const org = first.issueOrgMandate({ grantor: ARTHUR, capabilities: [Pay] as const, rationale: "r" })
    const second = createTrust({ store: makeJsonlAuditLive(path) })
    const resumed = second.resume({ resumedBy: HOST, mandateId: org.id, capabilities: [Pay] as const, tier: "organization" })
    second.useCapability({ mandate: resumed, capability: Pay, verdictDigest: DIGEST })
    const third = createTrust({ store: makeJsonlAuditLive(path) })
    expect(invokes(third.audit.query(org.id)).map((e) => e.verdictDigest)).toEqual([DIGEST])
  })
})

describe("under a signed store", () => {
  const signedRun = () => {
    const signer = makeInMemorySignerLive()
    const { mandateAudit, signedAudit } = makeInMemorySignedAuditLive(signer)
    const trust = createTrust({ store: mandateAudit })
    const org = trust.issueOrgMandate({ grantor: ARTHUR, capabilities: [Pay] as const, rationale: "r" })
    trust.useCapability({ mandate: org, capability: Pay, verdictDigest: DIGEST })
    trust.useCapability({ mandate: org, capability: Pay })
    return { signer, records: signedAudit.listAllSigned(), pin: { trustedSignerPublicKeyHex: signer.publicKeyHex } }
  }

  /** A copy of the chain with the payload at `index` replaced, every other byte unchanged. */
  const withPayload = (
    records: ReadonlyArray<SignedMandateAuditEvent>,
    index: number,
    edit: (payload: Record<string, unknown>) => void,
  ): SignedMandateAuditEvent[] =>
    records.map((r, i) => {
      if (i !== index) return r
      const payload = { ...(r.payload as unknown as Record<string, unknown>) }
      edit(payload)
      return { ...r, payload: payload as unknown as MandateAuditEvent }
    })

  test("the field is inside the signed payload and the chain verifies", () => {
    const { signer, records, pin } = signedRun()
    expect(records[1]!.payload).toMatchObject({ type: "invoke", verdictDigest: DIGEST })
    expect(verifyAuditChain(records, signer, pin)).toMatchObject({ valid: true, reason: "ok" })
  })

  test("changing the digest on a signed event fails signature verification", () => {
    const { signer, records, pin } = signedRun()
    const tampered = withPayload(records, 1, (p) => {
      p.verdictDigest = OTHER
    })
    expect(verifyAuditChain(tampered, signer, pin)).toMatchObject({
      valid: false,
      firstInvalidIndex: 1,
      reason: "signature-mismatch",
    })
  })

  test("stripping the digest from a signed event fails signature verification", () => {
    const { signer, records, pin } = signedRun()
    const stripped = withPayload(records, 1, (p) => {
      delete p.verdictDigest
    })
    expect(verifyAuditChain(stripped, signer, pin)).toMatchObject({
      valid: false,
      firstInvalidIndex: 1,
      reason: "signature-mismatch",
    })
  })

  test("adding a digest to a signed event that had none fails signature verification", () => {
    const { signer, records, pin } = signedRun()
    const added = withPayload(records, 2, (p) => {
      p.verdictDigest = DIGEST
    })
    expect(verifyAuditChain(added, signer, pin)).toMatchObject({
      valid: false,
      firstInvalidIndex: 2,
      reason: "signature-mismatch",
    })
  })

  test("an event without a digest signs over bytes that never name the field", () => {
    const { records } = signedRun()
    expect(canonicalJSON(records[2]!.payload)).not.toContain("verdictDigest")
  })

  test("a durable signed store refuses a file whose digest was edited", () => {
    const path = freshPath()
    const signer = makeInMemorySignerLive()
    const trust = createTrust({ store: makeJsonlSignedAuditLive(path, signer).mandateAudit })
    const org = trust.issueOrgMandate({ grantor: ARTHUR, capabilities: [Pay] as const, rationale: "r" })
    trust.useCapability({ mandate: org, capability: Pay, verdictDigest: DIGEST })

    const reopened = makeJsonlSignedAuditLive(path, signer).mandateAudit
    expect(invokes(reopened.query(org.id)).map((e) => e.verdictDigest)).toEqual([DIGEST])

    const body = readFileSync(path, "utf8")
    expect(body).toContain(DIGEST)
    writeFileSync(path, body.replace(DIGEST, OTHER))
    expect(tagOf(() => makeJsonlSignedAuditLive(path, signer).mandateAudit.query(org.id))).toBe("AuditLogCorrupt")
  })
})
