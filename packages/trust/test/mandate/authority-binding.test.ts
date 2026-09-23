/**
 * F1 / F2 / F3 — the authority defects found by the 2026-08-30 pre-publish
 * stop-ship audit.
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
 *
 * DAN-1157 widened it: authority must also not be bound to something the
 * caller can merely REACH. `issueProjectMandate`/`issueAgentMandate` embedded
 * the genuine grantor object in `parentScope`, so an agent held its ancestors'
 * authority by reference — no cast, no forgery, a property read. And matching
 * a presented scope against its grant event cannot help: every field a grant
 * event records is printed in the log, so a full-field copy matches by
 * construction. The later describe blocks pin both, and every one of them
 * names two principals.
 */
import { describe, expect, test } from "vitest"
import { makeInMemoryAuditLive } from "../../src/mandate/audit.ts"
import {
  defineCapability,
  issueAgentMandate,
  issueMandate,
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

// `left?: undefined` on the Right arm lets `result.left?._tag` typecheck without
// narrowing first. Its absence made `tsc` — and so `prepublishOnly` — red at
// 7893cc3 independently of the five failing assertions.
const either = <T>(
  fn: () => T,
):
  | { readonly _tag: "Right"; readonly right: T; readonly left?: undefined }
  | { readonly _tag: "Left"; readonly left: any } => {
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

// ---------------------------------------------------------------------------
// DAN-1157 — authority by REFERENCE. Found 2026-09-23. Every test in this block
// was watched RED against the unfixed module before the fix existed.
// ---------------------------------------------------------------------------

describe("DAN-1157 — a child scope must not carry its ancestors' authority by reference", () => {
  test("an agent cannot invoke through agent.parentScope — no cast, just a property read", () => {
    const { audit, projectScope, agentScope } = chain()

    // No `as any`: `parentScope` is TYPED as the project scope, so the compiler
    // accepts this call. Before the fix the embedded object WAS the genuine
    // project scope, so every runtime check passed as well.
    const result = either(() =>
      useCapability({ mandate: agentScope.parentScope, capability: Wire }, audit),
    )
    expect(result._tag).toBe("Left")
    expect(result.left?._tag).toBe("MandateScopeForged")
    expect(audit.query(projectScope.id).filter((e) => e.type === "invoke").length).toBe(0)
  })

  test("…nor reach the org root two property reads up", () => {
    const { audit, orgScope, agentScope } = chain()
    const result = either(() =>
      useCapability({ mandate: agentScope.parentScope.parentScope, capability: Deploy }, audit),
    )
    expect(result._tag).toBe("Left")
    expect(audit.query(orgScope.id).filter((e) => e.type === "invoke").length).toBe(0)
  })

  test("an agent cannot revoke the org root by presenting the org scope it reached by reference", () => {
    const { audit, orgScope, agentScope } = chain()
    const result = either(() =>
      revokeMandate(
        {
          mandateId: orgScope.id,
          // Present only so the PRE-fix module (which read this string) accepts
          // the call and the test can go red. The fix must not read it.
          revoker: ARTHUR,
          rationale: "kill switch pulled through a pointer",
          revokerScope: agentScope.parentScope.parentScope,
        } as any,
        audit,
      ),
    )
    expect(result._tag).toBe("Left")
    expect(audit.isRevoked(orgScope.id)).toBe(false)
  })

  test("an agent cannot mint itself a project mandate from the org scope it reached by reference", () => {
    const { audit, agentScope } = chain()
    // Also cast-free. This is the PERSISTENCE half: a genuine grant event would
    // be written, carrying `deploy.prod`, for a principal that holds read only.
    const result = either(() =>
      issueProjectMandate(
        {
          grantor: AGENT_BOT,
          grantorScope: agentScope.parentScope.parentScope,
          capabilities: [Deploy] as const,
          rationale: "self-promotion to a project that may deploy",
        },
        audit,
      ),
    )
    expect(result._tag).toBe("Left")
  })
})

describe("DAN-1157 — a FULL-FIELD forgery (every field copied from the public log) is refused", () => {
  // The fix shape proposed in 7893cc3 was "require the presented scope to MATCH
  // its grant event". These two tests are why that shape was rejected: grantor
  // and parentMandateId are printed in the grant event, `tier` is not recorded
  // at all, so a copy of every public field matches by construction.

  test("at use: the project's public fields, re-typed, do not invoke as the project", () => {
    const { audit, orgScope, projectScope, agentScope } = chain()
    const forged = {
      ...agentScope,
      id: projectScope.id,
      grantor: PROJECT_LEAD,
      tier: "project",
      parentMandateId: orgScope.id,
      capabilities: [Read, Wire],
      parentScope: null,
    } as any
    const result = either(() => useCapability({ mandate: forged, capability: Wire }, audit))
    expect(result._tag).toBe("Left")
    expect(result.left?._tag).toBe("MandateScopeForged")
  })

  test("at issue: the org's public fields, re-typed, do not delegate as the org", () => {
    const { audit, orgScope, agentScope } = chain()
    const forgedOrg = {
      ...agentScope,
      id: orgScope.id,
      grantor: ARTHUR,
      tier: "organization",
      parentMandateId: null,
      capabilities: [Read, Wire, Deploy],
      parentScope: null,
    } as any
    const result = either(() =>
      issueProjectMandate(
        {
          grantor: AGENT_BOT,
          grantorScope: forgedOrg,
          capabilities: [Deploy] as any,
          rationale: "persistence through a re-typed org",
        },
        audit,
      ),
    )
    expect(result._tag).toBe("Left")
  })
})

describe("DAN-1157 — the tier ladder has no side door, and a holder cannot rewrite its tier", () => {
  test("legacy issueMandate cannot launder an agent into a delegator", () => {
    const { audit, agentScope } = chain()
    // issueMandate stamps tier "organization" on whatever it mints, so an agent
    // grantor here would ascend two rungs in one call.
    const result = either(() =>
      issueMandate(
        {
          grantor: AGENT_BOT,
          grantorScope: agentScope as any,
          capabilities: [Read] as any,
          rationale: "an agent delegating through the v0 door",
        },
        audit,
      ),
    )
    expect(result._tag).toBe("Left")
  })

  test("legacy issueMandate cannot turn a project's child into an organization", () => {
    const { audit, projectScope } = chain()
    const result = either(() =>
      issueMandate(
        {
          grantor: PROJECT_LEAD,
          grantorScope: projectScope as any,
          capabilities: [Read] as any,
          rationale: "a project minting an org-tier child",
        },
        audit,
      ),
    )
    expect(result._tag).toBe("Left")
  })

  test("an issued scope and its capability list are frozen", () => {
    const { agentScope } = chain()
    expect(Object.isFrozen(agentScope)).toBe(true)
    expect(Object.isFrozen(agentScope.capabilities)).toBe(true)
  })
})

describe("DAN-1157 — two principals: one agent cannot act as its sibling", () => {
  const WIRER: GrantorId = "AGENT_WIRER" as GrantorId

  const siblings = () => {
    const c = chain()
    const wirer = issueAgentMandate(
      {
        grantor: WIRER,
        grantorScope: c.projectScope,
        capabilities: [Wire] as const,
        rationale: "a sibling that may wire",
      },
      c.audit,
    )
    return { ...c, reader: c.agentScope, wirer }
  }

  test("the reader cannot present a forged copy of the wirer's scope", () => {
    const { audit, reader, wirer } = siblings()
    const forged = { ...reader, id: wirer.id, grantor: WIRER, capabilities: [Wire] } as any
    const result = either(() => useCapability({ mandate: forged, capability: Wire }, audit))
    expect(result._tag).toBe("Left")
    expect(result.left?._tag).toBe("MandateScopeForged")
    expect(audit.query(wirer.id).filter((e) => e.type === "invoke").length).toBe(0)

    // …and the wirer, holding its own scope, is unaffected.
    const ok = either(() => useCapability({ mandate: wirer, capability: Wire }, audit))
    expect(ok._tag).toBe("Right")
  })

  test("the reader cannot revoke the wirer, whatever grantor string it names", () => {
    const { audit, reader, wirer } = siblings()
    const result = either(() =>
      revokeMandate(
        {
          mandateId: wirer.id,
          // PROJECT_LEAD is printed in the wirer's chain, so the pre-fix module
          // accepted it. The reader's genuine scope is not in that chain.
          revoker: PROJECT_LEAD,
          rationale: "sibling sabotage",
          revokerScope: reader,
        } as any,
        audit,
      ),
    )
    expect(result._tag).toBe("Left")
    expect(result.left?._tag).toBe("RevokerNotInDelegationChain")
    expect(audit.isRevoked(wirer.id)).toBe(false)
  })

  test("HAPPY PATH — the project holder, presenting the project scope, can revoke either child", () => {
    const { audit, projectScope, reader, wirer } = siblings()
    for (const target of [reader, wirer]) {
      const ok = either(() =>
        revokeMandate(
          {
            mandateId: target.id,
            revoker: PROJECT_LEAD,
            rationale: "the project lead retires a worker",
            revokerScope: projectScope,
          } as any,
          audit,
        ),
      )
      expect(ok._tag).toBe("Right")
      expect(audit.isRevoked(target.id)).toBe(true)
    }
  })
})
