/**
 * The audit log is bound at construction, not passed per call.
 *
 * 🔑 WHY THIS FILE EXISTS. On 2026-10-31 a stranger's review of the published
 * 0.4.0 found, and a second reader reproduced against `dist/`, that
 * `useCapability(args, audit)` took the audit log from the CALLER on every
 * call. An agent holding its own genuine, revoked scope built a fresh
 * in-memory log, recorded one forged `grant` line for its own id, passed that
 * log in, and was ALLOWED. README said "the kill switch is structural, not
 * advisory." It was advisory: only as strong as the second argument.
 *
 * The fix: `createTrust({ store })` binds the store once. Issue, use and revoke
 * are methods on the client; the store is never again a parameter. And a scope
 * is bound to the store that recorded its grant, so a genuine scope presented
 * to a client over a DIFFERENT store is refused as `MandateScopeForeign`, however
 * faithfully that other store's log describes it.
 *
 * Every test below was watched RED before the fix existed (2026-10-31, the
 * import of `createTrust` failed because nothing exported it).
 */
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, test } from "vitest"
import * as mandate from "../../src/mandate/index.ts"
import {
  createTrust,
  defineCapability,
  makeInMemoryAuditLive,
  makeInMemorySignedAuditLive,
  makeInMemorySignerLive,
  makeJsonlAuditLive,
  MandateFailure,
  type GrantorId,
  type ISO8601,
} from "../../src/mandate/index.ts"

const Buy = defineCapability("bound/amazon.buy")
const Read = defineCapability("bound/read")
const DANNY = "DANNY" as GrantorId
const LEAD = "LEAD" as GrantorId
const BOT = "BOT" as GrantorId

const thrown = (fn: () => unknown): any => {
  try {
    fn()
  } catch (e) {
    return e
  }
  throw new Error("expected a throw, and nothing was thrown")
}

/** org(Buy, Read) → project(Buy) → agent(Buy), on one store, through one client. */
const chain = (store = makeInMemoryAuditLive()) => {
  const trust = createTrust({ store })
  const org = trust.issueOrgMandate({ grantor: DANNY, capabilities: [Buy, Read] as const, rationale: "org charter" })
  const project = trust.issueProjectMandate({ grantor: LEAD, grantorScope: org, capabilities: [Buy] as const, rationale: "swee project" })
  const agent = trust.issueAgentMandate({ grantor: BOT, grantorScope: project, capabilities: [Buy] as const, rationale: "swee agent" })
  return { store, trust, org, project, agent }
}

/**
 * The attacker's move: a log of their own holding one forged grant line per
 * held scope, parents first, so the forged log describes the real chain
 * faithfully. Nothing in the kernel can tell this log from the host's by
 * content, which is the whole point: it has to be refused by IDENTITY.
 */
const forgedStoreFor = (...scopes: ReadonlyArray<{ id: mandate.MandateId; grantor: GrantorId; parentMandateId: mandate.MandateId | null }>) => {
  const mine = makeInMemoryAuditLive()
  for (const scope of scopes) {
    mine.record({
      type: "grant",
      mandateId: scope.id,
      grantor: scope.grantor,
      capabilities: ["bound/amazon.buy", "bound/read"],
      rationale: "self-issued",
      parentMandateId: scope.parentMandateId,
      timestamp: new Date().toISOString() as ISO8601,
      triggerSource: "code",
    })
  }
  return mine
}

describe("audit bound at construction — the 2026-10-31 audit-swap bypass", () => {
  test("(a) REPRODUCTION: a genuine scope, revoked at the root, presented to a client over a forged store is refused as MandateScopeForeign and nothing is recorded there", () => {
    const { trust, org, project, agent } = chain()
    trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "kill switch pulled" })

    const mine = forgedStoreFor(org, project, agent)
    const foreign = createTrust({ store: mine })
    const e = thrown(() => foreign.useCapability({ mandate: agent, capability: Buy }))
    expect(MandateFailure.is(e)).toBe(true)
    expect(e._tag).toBe("MandateScopeForeign")
    expect(e.mandateId).toBe(agent.id)
    expect(mine.query(agent.id).filter((ev) => ev.type === "invoke")).toEqual([])
  })

  test("(a2) a foreign scope is refused as a revoker and as a grantor too", () => {
    const { org, project } = chain()
    const foreign = createTrust({ store: forgedStoreFor(org, project) })
    expect(thrown(() => foreign.revokeMandate({ mandateId: project.id, revokerScope: org, rationale: "x" }))._tag).toBe("MandateScopeForeign")
    expect(thrown(() => foreign.issueProjectMandate({ grantor: LEAD, grantorScope: org, capabilities: [Buy] as const, rationale: "x" }))._tag).toBe("MandateScopeForeign")
    expect(thrown(() => foreign.issueAgentMandate({ grantor: BOT, grantorScope: project, capabilities: [Buy] as const, rationale: "x" }))._tag).toBe("MandateScopeForeign")
  })

  test("(b) same client: revoking the org root still cascades to the agent leaf", () => {
    const { trust, org, agent } = chain()
    trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "kill switch pulled" })
    const e = thrown(() => trust.useCapability({ mandate: agent, capability: Buy }))
    expect(e._tag).toBe("AncestorMandateRevoked")
    expect(e.revokedAncestorId).toBe(org.id)
  })

  test("(c) happy path: the invoke is allowed and recorded once; a second client over the SAME store agrees, because the binding is to the store", () => {
    const { store, trust, agent } = chain()
    trust.useCapability({ mandate: agent, capability: Buy })
    expect(store.query(agent.id).filter((ev) => ev.type === "invoke")).toHaveLength(1)

    const again = createTrust({ store })
    again.useCapability({ mandate: agent, capability: Buy })
    expect(store.query(agent.id).filter((ev) => ev.type === "invoke")).toHaveLength(2)
  })

  test("(d) the client's audit view reads and never writes: no record, and a returned event cannot be edited into an un-revoke", () => {
    const { trust, agent, org } = chain()
    expect("record" in trust.audit).toBe(false)
    expect(trust.audit.isRevoked(agent.id)).toBe(false)
    expect(trust.audit.query(agent.id).some((ev) => ev.type === "grant")).toBe(true)
    trust.revokeMandate({ mandateId: agent.id, revokerScope: org, rationale: "retire" })
    expect(trust.audit.isRevoked(agent.id)).toBe(true)
    expect(Object.isFrozen(trust)).toBe(true)
    expect(Object.isFrozen(trust.audit)).toBe(true)

    // The 2026-10-31 pre-review: the view returned the stored objects, so
    // `revoke.type = "noop"` flipped isRevoked to false and the use was
    // allowed. Every stored event is frozen now; in strict mode the write
    // throws, and either way the verdict does not move.
    const revoke = trust.audit.query(agent.id).find((ev) => ev.type === "revoke")!
    expect(Object.isFrozen(revoke)).toBe(true)
    expect(() => {
      ;(revoke as { type: string }).type = "noop"
    }).toThrow(TypeError)
    expect(trust.audit.isRevoked(agent.id)).toBe(true)
    expect(thrown(() => trust.useCapability({ mandate: agent, capability: Buy }))._tag).toBe("MandateRevoked")
  })

  test("(d2) the same holds on the signed in-memory store, through payload and envelope", () => {
    const signer = makeInMemorySignerLive()
    const { mandateAudit, signedAudit } = makeInMemorySignedAuditLive(signer)
    const trust = createTrust({ store: mandateAudit })
    const org = trust.issueOrgMandate({ grantor: DANNY, capabilities: [Buy] as const, rationale: "org" })
    trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "retire" })
    const payload = trust.audit.query(org.id).find((ev) => ev.type === "revoke")!
    const envelope = signedAudit.listAllSigned().at(-1)!
    expect(Object.isFrozen(payload)).toBe(true)
    expect(Object.isFrozen(envelope)).toBe(true)
    expect(() => {
      ;(payload as { type: string }).type = "noop"
    }).toThrow(TypeError)
    expect(trust.audit.isRevoked(org.id)).toBe(true)
  })

  test("(h) two store OBJECTS over one JSONL path are two stores: the second refuses the first's scopes as foreign, fail-closed", () => {
    const path = join(mkdtempSync(join(tmpdir(), "sweetrust-bound-")), "audit.jsonl")
    const a = createTrust({ store: makeJsonlAuditLive(path) })
    const org = a.issueOrgMandate({ grantor: DANNY, capabilities: [Buy] as const, rationale: "org" })
    a.useCapability({ mandate: org, capability: Buy })
    const b = createTrust({ store: makeJsonlAuditLive(path) })
    expect(b.audit.query(org.id).some((ev) => ev.type === "grant")).toBe(true) // same file, same facts
    expect(thrown(() => b.useCapability({ mandate: org, capability: Buy }))._tag).toBe("MandateScopeForeign")
    expect(b.audit.query(org.id).filter((ev) => ev.type === "invoke")).toHaveLength(1) // b recorded nothing
  })

  test("(e) surface: sweetrust/mandate exports createTrust and no longer exports the five free functions", () => {
    expect(typeof mandate.createTrust).toBe("function")
    for (const name of ["useCapability", "revokeMandate", "issueOrgMandate", "issueProjectMandate", "issueAgentMandate"]) {
      expect(name in mandate, `${name} must not be exported: the audit log would be a caller argument again`).toBe(false)
    }
  })

  test("(f) a forged literal keeps its more specific verdict, MandateScopeForged, and is not reported as merely foreign", () => {
    const { trust, agent } = chain()
    const literal = { ...agent }
    expect(thrown(() => trust.useCapability({ mandate: literal, capability: Buy }))._tag).toBe("MandateScopeForged")
  })

  test("(g) createTrust refuses a config without a store", () => {
    expect(() => createTrust({} as any)).toThrow(TypeError)
    expect(() => createTrust({ store: { query: () => [] } } as any)).toThrow(TypeError)
  })
})
