/**
 * Regression tests for the 2026-07-22 pre-publish battle-test findings
 * (DAN-637 + DAN-638). Shared spine: the audit log is the runtime source of
 * truth — EVERY security decision must consult it, never the mutable
 * in-memory object (DAN-637: parentScope pointer) or attacker-controllable
 * embedded material (DAN-638: per-record signerPublicKeyHex).
 *
 * DAN-637 — useCapability ancestor-revocation must reconstruct the delegation
 * chain from grant events' parentMandateId, not walk scope.parentScope:
 *   - the v0.0 `issueMandate` (removed in the 2026-10-13 rail audit) set
 *     parentScope: null, so the pointer walk terminated at the leaf and the org
 *     kill switch never reached children.
 *   - A forged {...realScope, parentScope: null} severed the walk on purpose.
 *   - Persistence (JSONL, cross-process handoff) stores parentMandateId, not
 *     the object graph, so every deserialized mandate had the same hole.
 *
 * DAN-638 — verifyAuditChain must verify against a PINNED trusted key. Each
 * record verified against its own embedded signerPublicKeyHex proves internal
 * consistency, not authorship: a whole chain rewritten and re-signed under an
 * attacker's key returned valid:true.
 */
import { generateKeyPairSync } from "node:crypto"
import { describe, expect, test } from "vitest"
import { makeInMemoryAuditLive, makeInMemorySignedAuditLive } from "../../src/mandate/audit.ts"
import {
  defineCapability,
  issueAgentMandate,
  issueOrgMandate,
  issueProjectMandate,
  revokeMandate,
  useCapability,
} from "../../src/mandate/mandate.ts"
import {
  canonicalJSON,
  makeEd25519SignerLive,
  makeEd25519VerifierLive,
  MANDATE_AUDIT_DOMAIN,
  sha256Hex,
  verifyAuditChain,
} from "../../src/mandate/signer.ts"
import type {
  GrantorId,
  MandateAuditEvent,
  MandateAuditService,
  MandateId,
  SignedMandateAuditEvent,
} from "../../src/mandate/types.ts"

const CapA = defineCapability("truth-test/CapA")
const CapB = defineCapability("truth-test/CapB")

const ARTHUR: GrantorId = "ARTHUR" as GrantorId
const PROJECT_LEAD: GrantorId = "PROJECT_LEAD" as GrantorId
const AGENT_BOT: GrantorId = "AGENT_BOT" as GrantorId

/** Capture a typed MandateError throw as a Left (mirrors sibling test files). */
const either = <T>(
  fn: () => T,
): { readonly _tag: "Right"; readonly right: T } | { readonly _tag: "Left"; readonly left: any } => {
  try {
    return { _tag: "Right", right: fn() }
  } catch (e) {
    return { _tag: "Left", left: e }
  }
}

/** org → project → agent chain via the typed v1.0 issue functions. */
const issueTypedChain = (audit: MandateAuditService) => {
  const orgScope = issueOrgMandate(
    { grantor: ARTHUR, capabilities: [CapA, CapB] as const, rationale: "org root" },
    audit,
  )
  const projectScope = issueProjectMandate(
    {
      grantor: PROJECT_LEAD,
      grantorScope: orgScope,
      capabilities: [CapA] as const,
      rationale: "project subset",
    },
    audit,
  )
  const agentScope = issueAgentMandate(
    {
      grantor: AGENT_BOT,
      grantorScope: projectScope,
      capabilities: [CapA] as const,
      rationale: "agent leaf",
    },
    audit,
  )
  return { orgScope, projectScope, agentScope }
}

// ---------------------------------------------------------------------------
// DAN-637 — ancestor revocation reconstructed from the audit log
// ---------------------------------------------------------------------------

describe("DAN-637: useCapability ancestor-revocation reconstructs from the audit log", () => {
  test("revoke org, then use an agent-tier mandate issued via the typed path → AncestorMandateRevoked", () => {
    const audit = makeInMemoryAuditLive()
    const { orgScope, agentScope } = issueTypedChain(audit)
    revokeMandate({ mandateId: orgScope.id, revokerScope: orgScope, rationale: "org kill switch" }, audit)

    const result = either(() => useCapability({ mandate: agentScope, capability: CapA }, audit))
    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("AncestorMandateRevoked")
      expect(result.left.revokedAncestorId).toBe(orgScope.id)
    }
  })

  test("revoke the MID-chain project tier, then use the agent leaf → AncestorMandateRevoked", () => {
    const audit = makeInMemoryAuditLive()
    const { projectScope, agentScope } = issueTypedChain(audit)
    revokeMandate(
      { mandateId: projectScope.id, revokerScope: projectScope, rationale: "project shutdown" },
      audit,
    )

    const result = either(() => useCapability({ mandate: agentScope, capability: CapA }, audit))
    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("AncestorMandateRevoked")
      expect(result.left.revokedAncestorId).toBe(projectScope.id)
    }
  })

  test("forged {...realScope, parentScope:null} does NOT sever the revocation chain → AncestorMandateRevoked", () => {
    const audit = makeInMemoryAuditLive()
    const { orgScope, agentScope } = issueTypedChain(audit)
    revokeMandate({ mandateId: orgScope.id, revokerScope: orgScope, rationale: "org kill switch" }, audit)

    // The battle-test PoC: real id + real capabilities pass the grant-event
    // subset check; the severed pointer used to defeat the ancestor walk.
    const forged = { ...agentScope, parentScope: null }
    const result = either(() =>
      useCapability({ mandate: forged as any, capability: CapA }, audit),
    )
    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("AncestorMandateRevoked")
      expect(result.left.revokedAncestorId).toBe(orgScope.id)
    }
  })

  test("serialize→deserialize round-trip (object graph lost), revoke org, use descendant → AncestorMandateRevoked", () => {
    const audit = makeInMemoryAuditLive()
    const { orgScope, agentScope } = issueTypedChain(audit)

    // Persistence convention (JSONL, Linear round-trip, cross-process handoff)
    // stores the parentMandateId LINK, not the in-memory object graph — the
    // rehydrated scope arrives with parentScope: null.
    const wire = JSON.stringify({ ...agentScope, parentScope: null })
    const rehydrated = JSON.parse(wire)

    revokeMandate({ mandateId: orgScope.id, revokerScope: orgScope, rationale: "org kill switch" }, audit)

    const result = either(() =>
      useCapability({ mandate: rehydrated as any, capability: CapA }, audit),
    )
    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("AncestorMandateRevoked")
      expect(result.left.revokedAncestorId).toBe(orgScope.id)
    }
  })

  test("leaf revoked directly still reports MandateRevoked (error-taxonomy precedence preserved)", () => {
    const audit = makeInMemoryAuditLive()
    const { agentScope } = issueTypedChain(audit)
    revokeMandate({ mandateId: agentScope.id, revokerScope: agentScope, rationale: "leaf revoke" }, audit)

    const result = either(() => useCapability({ mandate: agentScope, capability: CapA }, audit))
    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("MandateRevoked")
    }
  })

  test("positive: fully unrevoked chain still invokes and records", () => {
    const audit = makeInMemoryAuditLive()
    const { agentScope } = issueTypedChain(audit)
    useCapability({ mandate: agentScope, capability: CapA }, audit)
    const events = audit.query(agentScope.id)
    expect(events.filter((e) => e.type === "invoke").length).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// DAN-637 hardening — the audit-log walk must terminate on a cyclic /
// self-referential parentMandateId in a corrupted/tampered log. A legitimate
// chain is always a DAG, so a cycle only arises from log tampering — but since
// the walk is now the load-bearing revocation decision, an unguarded walk is an
// unkillable synchronous hang. These tests prove the `seen`-set guard makes
// both walks terminate with correct behavior. (A regression would re-introduce
// the hang and wedge the whole suite — a loud CI signal by design.)
// ---------------------------------------------------------------------------

describe("DAN-637 hardening: audit-log walks terminate on a cyclic parentMandateId", () => {
  /** Directly forge a self-referential grant event into an in-memory log. */
  const recordSelfCyclicGrant = (audit: MandateAuditService, id: string) =>
    audit.record({
      type: "grant",
      mandateId: id as any,
      grantor: ARTHUR,
      capabilities: [CapA.key],
      rationale: "corrupted: self-referential parent",
      parentMandateId: id as any, // cycle: points at itself
      timestamp: "2026-07-22T00:00:00Z" as any,
      triggerSource: "code",
    })

  const cyclicScope = (id: string) =>
    ({
      _tag: "MandateScope",
      tier: "agent",
      id: id as any,
      capabilities: [CapA] as const,
      grantor: ARTHUR,
      grantTimestamp: "2026-07-22T00:00:00Z" as any,
      grantRationale: "corrupted",
      parentMandateId: id as any,
      parentScope: null,
    }) as any

  /**
   * A GENUINE org scope whose log is then tampered so that its grant event
   * names the org as its own parent.
   *
   * Until DAN-1157 these tests hand-built a scope literal for a grant written
   * straight into the log. After DAN-1157 such a literal is a forgery by
   * definition (it was never issued), so it could no longer exercise the
   * success or revocation paths. The cycle therefore lives in the LOG, where an
   * attacker with write access would put it, around a real scope. The literal
   * survives in the last test below, pinned as a refusal.
   */
  const selfCyclicOrg = () => {
    const base = makeInMemoryAuditLive()
    let cyclicId: MandateId | null = null
    const audit: MandateAuditService = {
      record: (event) => base.record(event),
      isRevoked: (id) => base.isRevoked(id),
      query: (id) =>
        id === cyclicId
          ? base.query(id).map((e) => (e.type === "grant" ? { ...e, parentMandateId: id } : e))
          : base.query(id),
    }
    const org = issueOrgMandate(
      { grantor: ARTHUR, capabilities: [CapA] as const, rationale: "org" },
      audit,
    )
    cyclicId = org.id // from here on, the log says the org is its own parent
    return { audit, org }
  }

  test("useCapability terminates (and records) on a self-cyclic log when unrevoked", () => {
    const { audit, org } = selfCyclicOrg()
    // If the guard is missing this hangs forever; reaching the assertion proves termination.
    useCapability({ mandate: org, capability: CapA }, audit)
    expect(audit.query(org.id).filter((e) => e.type === "invoke").length).toBe(1)
  })

  test("useCapability terminates AND still enforces revocation on a self-cyclic log", () => {
    const { audit, org } = selfCyclicOrg()
    revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "kill" }, audit)
    const result = either(() => useCapability({ mandate: org, capability: CapA }, audit))
    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("MandateRevoked")
    }
  })

  test("revokeMandate terminates on a self-cyclic log", () => {
    const { audit, org } = selfCyclicOrg()
    // The org's holder presents the org scope, which is in the (cyclic) chain,
    // so revocation is authorized and must complete rather than loop.
    revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "kill" }, audit)
    expect(audit.isRevoked(org.id)).toBe(true)
  })

  test("a hand-built scope for a log-only mandate terminates AND is refused — it was never issued (DAN-1157)", () => {
    const audit = makeInMemoryAuditLive()
    recordSelfCyclicGrant(audit, "MAN_CYCLE")
    // Before DAN-1157 this exact call SUCCEEDED and recorded an invoke. The
    // literal copies every field of a grant event an attacker can write or
    // read, which is precisely the credential DAN-1157 stopped accepting.
    const result = either(() =>
      useCapability({ mandate: cyclicScope("MAN_CYCLE"), capability: CapA }, audit),
    )
    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("MandateScopeForged")
    }
    expect(audit.query("MAN_CYCLE" as any).filter((e) => e.type === "invoke").length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// DAN-638 — verifyAuditChain requires a pinned trusted signer key
// ---------------------------------------------------------------------------

describe("DAN-638: verifyAuditChain rejects chains not signed by the pinned key", () => {
  const makeKeyPair = () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519")
    return {
      privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }) as string,
      publicKeyPem: publicKey.export({ format: "pem", type: "spki" }) as string,
    }
  }

  const buildHonestLog = (signer: ReturnType<typeof makeEd25519SignerLive>) => {
    const { signedAudit } = makeInMemorySignedAuditLive(signer)
    signedAudit.recordSigned({
      type: "grant" as const,
      mandateId: "MAN_TRUTH" as any,
      grantor: ARTHUR,
      capabilities: ["truth-test/CapA"],
      rationale: "honest grant",
      parentMandateId: null,
      timestamp: "2026-07-22T00:00:01Z" as any,
      triggerSource: "code" as const,
    })
    signedAudit.recordSigned({
      type: "invoke" as const,
      mandateId: "MAN_TRUTH" as any,
      capability: "truth-test/CapA",
      timestamp: "2026-07-22T00:00:02Z" as any,
      triggerSource: "code" as const,
    })
    signedAudit.recordSigned({
      type: "revoke" as const,
      mandateId: "MAN_TRUTH" as any,
      revokedBy: ARTHUR,
      rationale: "honest revoke",
      timestamp: "2026-07-22T00:00:03Z" as any,
      triggerSource: "code" as const,
    })
    return signedAudit.listAllSigned()
  }

  test("whole-chain attacker substitution (battle-test PoC H): rewritten history re-signed under the attacker's key → untrusted-signer", () => {
    const honestConfig = makeKeyPair()
    const attackerConfig = makeKeyPair()
    const honestSigner = makeEd25519SignerLive(honestConfig)
    const attackerSigner = makeEd25519SignerLive(attackerConfig)

    const honestLog = buildHonestLog(honestSigner)

    // The attacker holds the JSONL: rewrite the history (erase the revoke),
    // re-sign every record under their own key, rebuild the hash chain. The
    // result is internally consistent — every signature valid against its own
    // embedded key, every previousHash correct.
    let previousHash: string | null = null
    const forgedLog: SignedMandateAuditEvent[] = honestLog.map((record) => {
      const payload =
        record.payload.type === "revoke"
          ? { ...record.payload, rationale: "history rewritten" }
          : record.payload
      const resigned = attackerSigner.sign({ payload, previousHash, domain: MANDATE_AUDIT_DOMAIN })
      previousHash = sha256Hex(canonicalJSON(resigned))
      return resigned
    })

    const verifier = makeEd25519VerifierLive({ publicKeyPem: honestConfig.publicKeyPem })
    const result = verifyAuditChain(forgedLog, verifier, {
      trustedSignerPublicKeyHex: honestSigner.publicKeyHex,
    })
    expect(result.valid).toBe(false)
    expect(result.reason).toBe("untrusted-signer")
    expect(result.firstInvalidIndex).toBe(0)
  })

  test("positive: honest chain verifies with the honest key pinned", () => {
    const honestConfig = makeKeyPair()
    const honestSigner = makeEd25519SignerLive(honestConfig)
    const honestLog = buildHonestLog(honestSigner)

    const verifier = makeEd25519VerifierLive({ publicKeyPem: honestConfig.publicKeyPem })
    const result = verifyAuditChain(honestLog, verifier, {
      trustedSignerPublicKeyHex: honestSigner.publicKeyHex,
    })
    expect(result.valid).toBe(true)
    expect(result.firstInvalidIndex).toBeNull()
    expect(result.reason).toBe("ok")
  })
})

// ---------------------------------------------------------------------------
// DAN-639 — issue-time subset check must consult the grantor's RECORDED grant,
// not the in-memory grantorScope.capabilities. The in-memory list is
// attacker-forgeable (any-cast / untrusted deserialization); trusting it lets
// a caller mint a capability the grantor never actually held, laundering the
// forgery into a real, legitimate-looking child grant event.
// ---------------------------------------------------------------------------

describe("DAN-639: issue-time subset check consults the grantor's recorded grant", () => {
  test("issueProjectMandate: forged org-scope caps cannot mint an unheld capability", () => {
    const audit = makeInMemoryAuditLive()
    const org = issueOrgMandate(
      { grantor: ARTHUR, capabilities: [CapA] as const, rationale: "org holds only CapA" },
      audit,
    )
    const forgedOrg = { ...org, capabilities: [CapA, CapB] } as any
    const result = either(() =>
      issueProjectMandate(
        {
          grantor: PROJECT_LEAD,
          grantorScope: forgedOrg,
          capabilities: [CapB] as any,
          rationale: "mint CapB org never held",
        },
        audit,
      ),
    )
    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("MandateScopeForged")
      expect(result.left.capability).toBe(CapB.key)
    }
    // Laundering is unreachable: the throw means no child scope was returned,
    // so there is no CapB-bearing mandate to hand to useCapability. The org's
    // own grant is untouched — still exactly one grant, granting only CapA.
    const orgGrants = audit.query(org.id).filter((e) => e.type === "grant")
    expect(orgGrants.length).toBe(1)
    expect((orgGrants[0] as any).capabilities).toEqual([CapA.key])
  })

  test("issueAgentMandate: forged project-scope caps cannot mint an unheld capability", () => {
    const audit = makeInMemoryAuditLive()
    const org = issueOrgMandate(
      { grantor: ARTHUR, capabilities: [CapA, CapB] as const, rationale: "org" },
      audit,
    )
    const project = issueProjectMandate(
      { grantor: PROJECT_LEAD, grantorScope: org, capabilities: [CapA] as const, rationale: "project holds only CapA" },
      audit,
    )
    const forgedProject = { ...project, capabilities: [CapA, CapB] } as any
    const result = either(() =>
      issueAgentMandate(
        {
          grantor: AGENT_BOT,
          grantorScope: forgedProject,
          capabilities: [CapB] as any,
          rationale: "mint CapB project never held",
        },
        audit,
      ),
    )
    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("MandateScopeForged")
    }
  })

  test("wholly-forged grantor (no grant event at all) is rejected as MandateNotIssued", () => {
    const audit = makeInMemoryAuditLive()
    const fakeGrantor = {
      _tag: "MandateScope",
      tier: "organization",
      id: "MAN_NEVER_ISSUED" as any,
      capabilities: [CapA],
      grantor: ARTHUR,
      grantTimestamp: "2026-07-22T00:00:00Z" as any,
      grantRationale: "fabricated",
      parentMandateId: null,
      parentScope: null,
    } as any
    const result = either(() =>
      issueProjectMandate(
        { grantor: PROJECT_LEAD, grantorScope: fakeGrantor, capabilities: [CapA] as any, rationale: "derive from a fake grantor" },
        audit,
      ),
    )
    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("MandateNotIssued")
    }
  })

  test("positive: a legitimately-held capability still delegates and the child can use it", () => {
    const audit = makeInMemoryAuditLive()
    const root = issueOrgMandate(
      { grantor: ARTHUR, capabilities: [CapA, CapB] as const, rationale: "root holds A and B" },
      audit,
    )
    const child = issueProjectMandate(
      { grantor: PROJECT_LEAD, grantorScope: root, capabilities: [CapB] as const, rationale: "legit delegate B" },
      audit,
    )
    // The child genuinely holds CapB (recorded), so use succeeds.
    useCapability({ mandate: child, capability: CapB }, audit)
    expect(audit.query(child.id).filter((e) => e.type === "invoke").length).toBe(1)
  })

  test("regression: honest over-request (grantor really lacks the cap) still throws CapabilityNotInGrantorScope", () => {
    const audit = makeInMemoryAuditLive()
    const org = issueOrgMandate(
      { grantor: ARTHUR, capabilities: [CapA] as const, rationale: "org with only CapA" },
      audit,
    )
    // grantorScope NOT forged (really [CapA]); caller over-requests CapB via any-cast.
    const result = either(() =>
      issueProjectMandate(
        { grantor: PROJECT_LEAD, grantorScope: org, capabilities: [CapB] as any, rationale: "honest over-request" },
        audit,
      ),
    )
    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("CapabilityNotInGrantorScope")
    }
  })
})

// ---------------------------------------------------------------------------
// DAN-640 — the ancestor-revocation walk must FAIL CLOSED when it cannot fully
// reconstruct the delegation chain. DAN-637 made the audit-log walk the
// load-bearing revocation decision; if a NON-leaf ancestor's grant event is
// missing (a tampered/truncated log), the walk used to stop silently, hiding a
// revoked ancestor ABOVE the break — fail-OPEN. A missing mid-chain grant
// cannot arise from the legitimate append-only API (parents are recorded
// before children), so this only fires on a corrupted log; but fail-open on a
// revocation check is strictly worse than fail-closed.
// ---------------------------------------------------------------------------

describe("DAN-640: useCapability fails CLOSED on a broken (missing mid-chain grant) log", () => {
  const ORG = "MAN_ORG" as MandateId
  const PROJECT = "MAN_PROJECT" as MandateId
  const AGENT = "MAN_AGENT" as MandateId
  const TS = "2026-07-22T00:00:00Z" as any

  /** A hand-built audit whose PROJECT grant event is MISSING (tampered log). */
  const tamperedAuditMissingProject = (opts: { orgRevoked: boolean }): MandateAuditService => {
    const events: MandateAuditEvent[] = [
      { type: "grant", mandateId: ORG, grantor: ARTHUR, capabilities: [CapA.key], rationale: "org", parentMandateId: null, timestamp: TS, triggerSource: "code" },
      // PROJECT's grant event is intentionally ABSENT (truncation / tampering).
      { type: "grant", mandateId: AGENT, grantor: AGENT_BOT, capabilities: [CapA.key], rationale: "agent", parentMandateId: PROJECT, timestamp: TS, triggerSource: "code" },
    ]
    if (opts.orgRevoked) {
      events.push({ type: "revoke", mandateId: ORG, revokedBy: ARTHUR, rationale: "org kill switch", timestamp: TS, triggerSource: "code" })
    }
    return {
      record: () => {},
      query: (id) => events.filter((e) => e.mandateId === id),
      isRevoked: (id) => events.some((e) => e.type === "revoke" && e.mandateId === id),
    }
  }

  const agentScope = {
    _tag: "MandateScope",
    tier: "agent",
    id: AGENT,
    capabilities: [CapA] as const,
    grantor: AGENT_BOT,
    grantTimestamp: TS,
    grantRationale: "agent",
    parentMandateId: PROJECT,
    parentScope: null,
  } as any

  test("revoked ORG above a missing PROJECT grant → throws (fail-closed), not silently allowed", () => {
    const audit = tamperedAuditMissingProject({ orgRevoked: true })
    const result = either(() => useCapability({ mandate: agentScope, capability: CapA }, audit))
    // Pre-fix this returned normally (fail-open): the walk stopped at the missing
    // PROJECT grant and never checked the revoked ORG above it.
    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("DelegationChainBroken")
      expect(result.left.brokenAncestorId).toBe(PROJECT)
    }
  })

  test("even with ORG NOT revoked, a broken chain is denied (cannot certify integrity)", () => {
    const audit = tamperedAuditMissingProject({ orgRevoked: false })
    const result = either(() => useCapability({ mandate: agentScope, capability: CapA }, audit))
    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("DelegationChainBroken")
    }
  })

  test("leaf with no grant event still reports MandateNotIssued (leaf carve-out intact)", () => {
    const audit = makeInMemoryAuditLive()
    const forgedLeaf = {
      _tag: "MandateScope",
      tier: "organization",
      id: "MAN_FORGED_LEAF" as MandateId,
      capabilities: [CapA] as const,
      grantor: ARTHUR,
      grantTimestamp: TS,
      grantRationale: "forged",
      parentMandateId: null,
      parentScope: null,
    } as any
    const result = either(() => useCapability({ mandate: forgedLeaf, capability: CapA }, audit))
    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      // A leaf with no grant event is the legitimate forged-fake-id case — it
      // must stay MandateNotIssued, NOT the new broken-chain error.
      expect(result.left._tag).toBe("MandateNotIssued")
    }
  })

  test("a complete, valid chain with ORG revoked still throws AncestorMandateRevoked (fix only fires on ACTUAL breaks)", () => {
    const audit = makeInMemoryAuditLive()
    const { orgScope, agentScope: realAgent } = issueTypedChain(audit)
    revokeMandate({ mandateId: orgScope.id, revokerScope: orgScope, rationale: "kill" }, audit)
    const result = either(() => useCapability({ mandate: realAgent, capability: CapA }, audit))
    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("AncestorMandateRevoked")
      expect(result.left.revokedAncestorId).toBe(orgScope.id)
    }
  })
})
