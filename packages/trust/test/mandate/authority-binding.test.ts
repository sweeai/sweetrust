/**
 * F1 / F2 / F3 — the authority defects from
 * ~/workspace/SWEETRUST-AUDIT-2026-08-30-STOPSHIP.md.
 *
 * 🔑 WHY THIS FILE EXISTS AT ALL.
 *
 * 177 tests passed while none of F1-F8 was covered by any of them. The nearest
 * existing test, `audit-log-is-truth.test.ts:153`, forges a scope for a mandate
 * the caller ALREADY HOLDS — the case that was already safe. The suite encoded
 * the bug's ABSENCE as its specification, so a reviewer reading it to judge
 * rigor came away more confident, not less.
 *
 * Every test below was watched going RED before any fix existed. A green suite
 * proves nothing otherwise.
 *
 * The shared property, stated once: **authority must be bound to something the
 * caller cannot mint.** Today it is bound to `args.mandate.id` and
 * `args.revoker` — both plain strings, both caller-supplied, both printed in
 * the audit log the attacker can read.
 */
import { describe, expect, test } from "vitest"
import { makeInMemoryAuditLive } from "../../src/mandate/audit.ts"
import {
  defineCapability,
  issueAgentMandate,
  issueOrgMandate,
  issueProjectMandate,
  revokeMandate,
  useCapability,
} from "../../src/mandate/mandate.ts"
import type { GrantorId } from "../../src/mandate/types.ts"

const Read = defineCapability("authority-binding/read.email")
const Wire = defineCapability("authority-binding/wire.transfer.unlimited")
const Deploy = defineCapability("authority-binding/deploy.prod")

const ARTHUR: GrantorId = "ARTHUR" as GrantorId
const PROJECT_LEAD: GrantorId = "PROJECT_LEAD" as GrantorId
const AGENT_BOT: GrantorId = "AGENT_BOT" as GrantorId

const either = <T>(
  fn: () => T,
): { readonly _tag: "Right"; readonly right: T } | { readonly _tag: "Left"; readonly left: any } => {
  try {
    return { _tag: "Right", right: fn() }
  } catch (e) {
    return { _tag: "Left", left: e }
  }
}

/** org(Read,Wire,Deploy) -> project(Read,Wire) -> agent(Read). */
const chain = () => {
  const audit = makeInMemoryAuditLive()
  const orgScope = issueOrgMandate(
    { grantor: ARTHUR, capabilities: [Read, Wire, Deploy] as const, rationale: "org root" },
    audit,
  )
  const projectScope = issueProjectMandate(
    {
      grantor: PROJECT_LEAD,
      grantorScope: orgScope,
      capabilities: [Read, Wire] as const,
      rationale: "project",
    },
    audit,
  )
  const agentScope = issueAgentMandate(
    {
      grantor: AGENT_BOT,
      grantorScope: projectScope,
      capabilities: [Read] as const,
      rationale: "least privilege: read only",
    },
    audit,
  )
  return { audit, orgScope, projectScope, agentScope }
}

describe("F1 — authority must not be bound to a caller-supplied string", () => {
  test("an agent cannot invoke a parent capability by NAMING the parent's mandate id", () => {
    const { audit, projectScope, agentScope } = chain()

    // The whole exploit. The agent's own scope hands it the parent's id at
    // `parentMandateId` — no guessing, no cast, no audit read. It then claims a
    // capability that is genuinely in the PARENT's grant, so the subset check
    // passes trivially. Nothing anywhere asks whether this caller holds that
    // mandate.
    const forged = {
      ...agentScope,
      id: agentScope.parentMandateId,
      capabilities: [Wire],
    } as any

    const result = either(() =>
      useCapability({ mandate: forged, capability: Wire }, audit),
    )

    expect(result._tag).toBe("Left")
    expect(result.left?._tag).toBe("MandateScopeForged")

    // Forensic erasure is the second half of the finding: the invoke is
    // recorded against the PARENT's id, so the compromised agent never appears
    // in the evidence artifact. Nothing may be written for a refused call.
    const invokes = audit.query(projectScope.id).filter((e) => e.type === "invoke")
    expect(invokes.length).toBe(0)
  })

  test("escalation all the way to the org root is refused", () => {
    const { audit, orgScope, agentScope } = chain()
    const forged = { ...agentScope, id: orgScope.id, capabilities: [Deploy] } as any

    const result = either(() =>
      useCapability({ mandate: forged, capability: Deploy }, audit),
    )
    expect(result._tag).toBe("Left")
  })

  test("the legitimate holder is unaffected — the fix must not break the happy path", () => {
    const { audit, agentScope } = chain()
    const ok = either(() => useCapability({ mandate: agentScope, capability: Read }, audit))
    expect(ok._tag).toBe("Right")
  })
})

describe("F2 — revocation must not accept an unauthenticated grantor string", () => {
  test("an agent-tier principal cannot revoke the org root by naming its grantor", () => {
    const { audit, orgScope, agentScope } = chain()

    // ARTHUR is printed in the org's own grant event, which any holder of the
    // audit service can read. `revoker` is a bare string, so nothing proves the
    // caller IS ARTHUR. isRevoked is monotone and the log append-only, so this
    // is a PERMANENT shutdown of the entire tree by the least-privileged
    // principal in it — there is no un-revoke.
    const result = either(() =>
      revokeMandate(
        {
          mandateId: orgScope.id,
          revoker: ARTHUR,
          rationale: "revoked by a principal that only holds a read-only agent scope",
          // The caller can only prove it holds THIS. A fix must require it.
          revokerScope: agentScope,
        } as any,
        audit,
      ),
    )

    expect(result._tag).toBe("Left")
    expect(audit.isRevoked(orgScope.id)).toBe(false)
  })

  test("the real grantor, presenting the scope it holds, can still revoke", () => {
    const { audit, orgScope } = chain()
    const ok = either(() =>
      revokeMandate(
        {
          mandateId: orgScope.id,
          revoker: ARTHUR,
          rationale: "legitimate revocation by the org grantor",
          revokerScope: orgScope,
        } as any,
        audit,
      ),
    )
    expect(ok._tag).toBe("Right")
    expect(audit.isRevoked(orgScope.id)).toBe(true)
  })
})

describe("F3 — the tier ladder must be enforced at runtime, not merely recorded", () => {
  test("agent -> agent is refused (tier is written but never read)", () => {
    const { audit, agentScope } = chain()

    // `tier` exists on every scope and is set on issue, but nothing reads it
    // when deciding whether a delegation is legal. That makes an unbounded
    // agent -> agent -> agent chain acceptable, which is the runtime half of
    // README line 106's "refused twice" claim simply not existing.
    const result = either(() =>
      issueAgentMandate(
        {
          grantor: AGENT_BOT,
          grantorScope: agentScope as any,
          capabilities: [Read] as const,
          rationale: "an agent delegating to another agent",
        },
        audit,
      ),
    )
    expect(result._tag).toBe("Left")
  })

  test("org -> agent, skipping the project tier, is refused", () => {
    const { audit, orgScope } = chain()
    const result = either(() =>
      issueAgentMandate(
        {
          grantor: AGENT_BOT,
          grantorScope: orgScope as any,
          capabilities: [Read] as const,
          rationale: "skipping a rung of the ladder",
        },
        audit,
      ),
    )
    expect(result._tag).toBe("Left")
  })
})
