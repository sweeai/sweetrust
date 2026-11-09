/**
 * `grantor` is a string or the issue is refused (0.5.1 review, 2026-11-08). A
 * `toJSON` on it otherwise ran between the limit check and the record.
 */
import { describe, expect, it } from "vitest"
import { createTrust, defineCapability, grantorId, makeInMemoryAuditLive } from "../../src/mandate/index.ts"

const Buy = defineCapability("x.buy")
const OWNER = grantorId("owner")
const poison = { toJSON: () => "owner" } as never

describe("a grantor that is not a string is refused at every tier", () => {
  it("org, project and agent", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({ grantor: OWNER, capabilities: [Buy] as const, rationale: "root" })
    const project = trust.issueProjectMandate({ grantor: OWNER, grantorScope: org, capabilities: [Buy] as const, rationale: "p" })
    expect(() => trust.issueOrgMandate({ grantor: poison, capabilities: [Buy] as const, rationale: "r" })).toThrow(TypeError)
    expect(() => trust.issueProjectMandate({ grantor: poison, grantorScope: org, capabilities: [Buy] as const, rationale: "r" })).toThrow(TypeError)
    expect(() => trust.issueAgentMandate({ grantor: poison, grantorScope: project, capabilities: [Buy] as const, rationale: "r" })).toThrow(TypeError)
  })
})
