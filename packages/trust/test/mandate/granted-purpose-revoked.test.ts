/**
 * `grantedPurpose` refuses a revoked scope, including a revoked ancestor (the
 * 2026-11-08 audit, K6). A judged sink built from a revoked grant used to
 * execute, and reconcile reported it clean. Watched red on the base commit.
 */
import { describe, expect, test } from "vitest"
import { makeSink, ReceiptLog, Sourced, type GrantedPurpose, type JudgmentProvider } from "../../src/gate/index.ts"
import { MandateFailure } from "../../src/mandate/errors.ts"
import {
  createTrust,
  defineCapability,
  makeInMemoryAuditLive,
  type GrantorId,
  type MandateError,
} from "../../src/mandate/index.ts"

const OWNER = "owner" as GrantorId
const Buy = defineCapability("x.buy")
const purpose = { statement: "pay vendors" }

const tagOf = (fn: () => void): MandateError["_tag"] | "none" => {
  try {
    fn()
    return "none"
  } catch (e) {
    if (MandateFailure.is(e)) return e._tag
    throw e
  }
}

const delegate = () => {
  const trust = createTrust({ store: makeInMemoryAuditLive() })
  const org = trust.issueOrgMandate({ grantor: OWNER, capabilities: [Buy] as const, rationale: "root", purpose })
  const project = trust.issueProjectMandate({ grantor: OWNER, grantorScope: org, capabilities: [Buy] as const, rationale: "p", purpose })
  const agent = trust.issueAgentMandate({ grantor: OWNER, grantorScope: project, capabilities: [Buy] as const, rationale: "a", purpose })
  return { trust, org, project, agent }
}

describe("grantedPurpose and revocation", () => {
  test("answers for a live mandate", () => {
    const { trust, agent } = delegate()
    expect(trust.grantedPurpose(agent).purpose.statement).toBe("pay vendors")
  })

  test("refuses a revoked mandate", () => {
    const { trust, agent } = delegate()
    trust.revokeMandate({ mandateId: agent.id, revokerScope: agent, rationale: "kill" })
    expect(tagOf(() => trust.grantedPurpose(agent))).toBe("MandateRevoked")
  })

  test("refuses when any ancestor is revoked", () => {
    const { trust, org, project, agent } = delegate()
    trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "kill" })
    expect(tagOf(() => trust.grantedPurpose(agent))).toBe("AncestorMandateRevoked")
    expect(tagOf(() => trust.grantedPurpose(project))).toBe("AncestorMandateRevoked")
    expect(tagOf(() => trust.grantedPurpose(org))).toBe("MandateRevoked")
  })

  test("a revoke of a sibling leaves it answering", () => {
    const { trust, project, agent } = delegate()
    const sibling = trust.issueAgentMandate({ grantor: OWNER, grantorScope: project, capabilities: [Buy] as const, rationale: "s", purpose })
    trust.revokeMandate({ mandateId: sibling.id, revokerScope: sibling, rationale: "kill" })
    expect(tagOf(() => trust.grantedPurpose(agent))).toBe("none")
  })
})

describe("a judged sink built before the revoke (DAN-1407, K6)", () => {
  const MATCH = { assessment: "match", confidence: 0.9, rationale: "ok" } as const
  const judgedSink = (granted: GrantedPurpose, mode: "enforce" | "warn" | "observe" = "enforce", onJudge?: () => void) => {
    const log = new ReceiptLog()
    let judged = 0
    let runs = 0
    const provider: JudgmentProvider = {
      name: "j",
      model: "j@1",
      assess: async () => {
        judged++
        onJudge?.()
        return MATCH
      },
    }
    const sink = makeSink<{ to: Sourced<string> }, string>({
      name: "pay",
      requires: { to: "verified" },
      mode,
      log,
      execute: () => {
        runs++
        return "sent"
      },
      judgment: { provider, floor: 0.5, granted },
    })
    return { sink, log, judged: () => judged, runs: () => runs }
  }
  const to = (v = "0xvendor") => ({ to: Sourced.fromAuthority(v, "reg") })

  test("isLive tracks the store: true, then false after a revoke", () => {
    const { trust, org } = delegate()
    const granted = trust.grantedPurpose(org)
    expect(granted.isLive!()).toBe(true)
    trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "kill" })
    expect(granted.isLive!()).toBe(false)
  })

  test("isLive is false once the log no longer shows the grant", () => {
    const inner = makeInMemoryAuditLive()
    let wiped = false
    const store = { ...inner, query: (id: Parameters<typeof inner.query>[0]) => (wiped ? [] : inner.query(id)) }
    const trust = createTrust({ store })
    const org = trust.issueOrgMandate({ grantor: OWNER, capabilities: [Buy] as const, rationale: "root", purpose })
    const granted = trust.grantedPurpose(org)
    expect(granted.isLive!()).toBe(true)
    wiped = true
    expect(granted.isLive!()).toBe(false)
  })

  test("a revoke reaches the sink: refused with a receipt, the judge not asked, nothing run", async () => {
    const { trust, org } = delegate()
    const { sink, log, judged, runs } = judgedSink(trust.grantedPurpose(org))
    expect((await sink(to("0xa"))).ok).toBe(true)
    trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "kill" })
    const r = await sink(to("0xb"))
    expect(r.ok).toBe(false)
    expect(r.receipt.decision).toBe("refused")
    expect(!r.ok && r.refusal).toContain("grant-not-live")
    expect(judged()).toBe(1)
    expect(runs()).toBe(1)
    expect(log.verifyChain()).toBe(true)
  })

  test("a revoke of an ancestor reaches a sink built from the leaf", async () => {
    const { trust, org, agent } = delegate()
    const { sink, runs } = judgedSink(trust.grantedPurpose(agent))
    trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "kill" })
    expect((await sink(to())).receipt.decision).toBe("refused")
    expect(runs()).toBe(0)
  })

  test("a revoke while the judge is out is caught immediately before execute, and the receipt keeps the verdict", async () => {
    const { trust, org } = delegate()
    const { sink, runs, judged, log } = judgedSink(trust.grantedPurpose(org), "enforce", () => trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "kill" }))
    const r = await sink(to())
    expect(judged()).toBe(1)
    expect(runs()).toBe(0)
    expect(r.receipt.decision).toBe("refused")
    expect(r.receipt.verdict?.assessment).toBe("match")
    expect(log.all().map((e) => e.decision)).toEqual(["refused"])
  })

  test.each(["warn", "observe"] as const)("%s refuses too: the ladder relaxes tiers, not a revoke", async (mode) => {
    const { trust, org } = delegate()
    const { sink, runs } = judgedSink(trust.grantedPurpose(org), mode)
    trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "kill" })
    expect((await sink(to())).receipt.decision).toBe("refused")
    expect(runs()).toBe(0)
  })

  const HAND_BUILT = { purpose, grantHash: "a".repeat(64) }

  test("a hand-built granted with no check keeps working", async () => {
    const { sink, runs } = judgedSink(HAND_BUILT)
    expect((await sink(to())).ok).toBe(true)
    expect(runs()).toBe(1)
  })

  test.each([
    ["throws", () => { throw new Error("store down") }],
    ["answers false", () => false],
    ["answers a truthy non-boolean", () => "yes" as unknown as boolean],
    ["answers with a Promise", () => Promise.resolve(true) as unknown as boolean],
  ])("a check that %s is not a live grant", async (_label, isLive) => {
    const { sink, runs } = judgedSink({ ...HAND_BUILT, isLive })
    expect((await sink(to())).receipt.decision).toBe("refused")
    expect(runs()).toBe(0)
  })

  test("an isLive that is not a function is a TypeError at construction", () => {
    expect(() => judgedSink({ ...HAND_BUILT, isLive: true as never })).toThrow(/isLive/)
  })
})
