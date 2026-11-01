/**
 * trust.resume() (DAN-1320): a mandate this store recorded can be picked up
 * again by a later process, as the SAME mandate, with the SAME budget. Until
 * now a restart re-minted, which gave the new process a fresh id and, with
 * DAN-1319, a fresh budget. Every case below was watched RED before the
 * implementation.
 *
 * Resume grants no power the store did not already have (ADR 0004: the store
 * is the root credential; it could mint a fresh org mandate). It removes the
 * reason to.
 */
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, test } from "vitest"
import { MandateFailure } from "../../src/mandate/errors.ts"
import {
  createTrust,
  defineCapability,
  makeInMemoryAuditLive,
  makeJsonlAuditLive,
  type GrantorId,
  type MandateError,
  type MandateId,
} from "../../src/mandate/index.ts"

const ARTHUR = "arthur" as GrantorId
const LEAD = "lead" as GrantorId
const BOT = "bot" as GrantorId
const Buy = defineCapability("amazon.buy")
const Read = defineCapability("mail.read")
const Deploy = defineCapability("deploy")

const errorOf = (fn: () => unknown): MandateError => {
  try {
    fn()
  } catch (e) {
    if (MandateFailure.is(e)) return { ...e } as MandateError
    throw e
  }
  throw new Error("expected a MandateFailure")
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

/** org(Buy, Read, Deploy) → project(Buy, Read) → agent(Buy), Buy capped at 30/day down the chain. */
const chain = (store = makeInMemoryAuditLive()) => {
  const trust = createTrust({ store })
  const cap = { [Buy.key]: { amount: 30, unit: "USD", windowMs: 86_400_000 } }
  const org = trust.issueOrgMandate({ grantor: ARTHUR, capabilities: [Buy, Read, Deploy] as const, rationale: "org", limits: cap })
  const project = trust.issueProjectMandate({ grantor: LEAD, grantorScope: org, capabilities: [Buy, Read] as const, rationale: "project", limits: cap })
  const agent = trust.issueAgentMandate({ grantor: BOT, grantorScope: project, capabilities: [Buy] as const, rationale: "agent", limits: cap })
  return { store, trust, org, project, agent }
}

describe("resume picks the mandate up where the log left it", () => {
  test("a second process over the same JSONL file continues the budget, not a fresh one", () => {
    const path = join(mkdtempSync(join(tmpdir(), "sweetrust-resume-")), "audit.jsonl")
    const first = chain(makeJsonlAuditLive(path))
    first.trust.useCapability({ mandate: first.agent, capability: Buy, amount: 25 })

    // The process restarts. No scope object survives; the id does.
    const second = createTrust({ store: makeJsonlAuditLive(path) })
    const agent = second.resume({ mandateId: first.agent.id, capabilities: [Buy] as const, tier: "agent" })
    expect(agent.id).toBe(first.agent.id)
    expect(agent.tier).toBe("agent")
    expect(agent.limits).toEqual({ [Buy.key]: { amount: 30, unit: "USD", windowMs: 86_400_000 } })
    expect(tagOf(() => second.useCapability({ mandate: agent, capability: Buy, amount: 10 }))).toBe("MandateLimitExceeded")
    expect(tagOf(() => second.useCapability({ mandate: agent, capability: Buy, amount: 5 }))).toBe("none")
  })

  test("the resumed scope is genuine for its own store and foreign to another", () => {
    const { store, trust, agent } = chain()
    const again = createTrust({ store }).resume({ mandateId: agent.id, capabilities: [Buy] as const })
    expect(again).not.toBe(agent)
    expect(Object.isFrozen(again)).toBe(true)
    trust.useCapability({ mandate: again, capability: Buy, amount: 1 })
    // A store holding a faithful COPY of the log still is not the store the
    // scope was minted against (ADR 0004); an empty store would answer
    // "never issued" first, which is the more specific verdict.
    const copy = makeInMemoryAuditLive()
    for (const id of [agent.parentMandateId, agent.id]) for (const e of store.query(id!)) copy.record(e)
    const orgId = store.query(agent.parentMandateId!).find((e) => e.type === "grant")
    if (orgId?.type === "grant" && orgId.parentMandateId) for (const e of store.query(orgId.parentMandateId)) copy.record(e)
    const other = createTrust({ store: copy })
    expect(tagOf(() => other.useCapability({ mandate: again, capability: Buy, amount: 1 }))).toBe("MandateScopeForeign")
  })

  test("the chain is rebuilt from the log: a resumed project can still delegate, a resumed agent cannot", () => {
    const { store, trust } = chain()
    const { project, agent } = chain(store)
    const p = trust.resume({ mandateId: project.id, capabilities: [Buy, Read] as const, tier: "project" })
    expect(p.tier).toBe("project")
    expect(p.parentMandateId).toBe(project.parentMandateId)
    const child = trust.issueAgentMandate({
      grantor: BOT,
      grantorScope: p,
      capabilities: [Read] as const,
      rationale: "from a resumed project",
    })
    trust.useCapability({ mandate: child, capability: Read })
    const a = trust.resume({ mandateId: agent.id, capabilities: [Buy] as const })
    expect(a.tier).toBe("agent")
    expect(
      tagOf(() =>
        trust.issueAgentMandate({
          grantor: BOT,
          grantorScope: a as any,
          capabilities: [Buy] as const,
          rationale: "x",
          limits: { [Buy.key]: { amount: 1, unit: "USD", windowMs: 86_400_000 } },
        }),
      ),
    ).toBe("TierLadderViolation")
  })

  test("resume is on the record and does not count toward a limit", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({
      grantor: ARTHUR,
      capabilities: [Read] as const,
      rationale: "two reads",
      limits: { [Read.key]: { count: 2 } },
    })
    trust.useCapability({ mandate: org, capability: Read })
    const again = trust.resume({ mandateId: org.id, capabilities: [Read] as const, triggerSource: "external" })
    const events = trust.audit.query(org.id)
    const resumeEvent = events.find((e) => e.type === "resume")
    expect(resumeEvent?.type === "resume" ? resumeEvent.triggerSource : null).toBe("external")
    trust.useCapability({ mandate: again, capability: Read })
    expect(tagOf(() => trust.useCapability({ mandate: again, capability: Read }))).toBe("MandateLimitExceeded")
  })
})

describe("resume refuses what use would refuse", () => {
  test("a revoked mandate", () => {
    const { trust, project, agent } = chain()
    trust.revokeMandate({ mandateId: agent.id, revokerScope: project, rationale: "done" })
    expect(tagOf(() => trust.resume({ mandateId: agent.id, capabilities: [Buy] as const }))).toBe("MandateRevoked")
  })

  test("a mandate under a revoked ancestor", () => {
    const { trust, org, agent } = chain()
    trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "kill switch" })
    expect(tagOf(() => trust.resume({ mandateId: agent.id, capabilities: [Buy] as const }))).toBe("AncestorMandateRevoked")
  })

  test("an id the log never issued", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    expect(tagOf(() => trust.resume({ mandateId: "MAN_NOPE" as MandateId, capabilities: [Buy] as const }))).toBe(
      "MandateNotIssued",
    )
  })

  test("a chain with a missing ancestor grant", () => {
    const store = makeInMemoryAuditLive()
    const { trust, project, agent } = chain(store)
    // A log with the agent's grant but a parent the log never recorded.
    const forged = makeInMemoryAuditLive()
    for (const e of store.query(agent.id)) forged.record(e)
    void project
    expect(tagOf(() => createTrust({ store: forged }).resume({ mandateId: agent.id, capabilities: [Buy] as const }))).toBe(
      "DelegationChainBroken",
    )
  })
})

describe("resume refuses a declaration that does not match the record", () => {
  test.each([
    ["an extra capability", [Buy, Read] as const],
    ["a missing capability", [] as const],
    ["a different capability", [Deploy] as const],
  ])("%s", (_label, declared) => {
    const { trust, agent } = chain()
    const err = errorOf(() => trust.resume({ mandateId: agent.id, capabilities: declared }))
    expect(err._tag).toBe("ResumeMismatch")
    if (err._tag === "ResumeMismatch") {
      expect(err.field).toBe("capabilities")
      expect(err.recorded).toEqual(["amazon.buy"])
      expect(err.declared).toEqual([...declared].map((c) => c.key).sort())
    }
  })

  test("the same capabilities in another order match", () => {
    const { trust, project } = chain()
    const p = trust.resume({ mandateId: project.id, capabilities: [Read, Buy] as const })
    expect(p.capabilities.map((c) => c.key)).toEqual(["mail.read", "amazon.buy"])
  })

  test("a declared tier that is not the recorded one", () => {
    const { trust, agent } = chain()
    const err = errorOf(() => trust.resume({ mandateId: agent.id, capabilities: [Buy] as const, tier: "project" }))
    expect(err._tag).toBe("ResumeMismatch")
    if (err._tag === "ResumeMismatch") {
      expect(err.field).toBe("tier")
      expect(err.declared).toEqual(["project"])
      expect(err.recorded).toEqual(["agent"])
    }
  })
})
