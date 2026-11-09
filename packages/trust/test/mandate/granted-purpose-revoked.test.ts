/**
 * `grantedPurpose` refuses a revoked scope, including a revoked ancestor (the
 * 2026-11-08 audit, K6). A judged sink built from a revoked grant used to
 * execute, and reconcile reported it clean. Watched red on the base commit.
 */
import { describe, expect, test } from "vitest"
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
