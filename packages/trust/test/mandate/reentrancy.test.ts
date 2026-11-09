/**
 * Re-entrancy (the 2026-11-08 audit, K1): a capability key is resolved to a
 * primitive before `useCapability` first reads the log, and an issued scope's
 * keys live where its holder cannot reach them. So a caller's getter cannot run
 * between the limit check and the record that check authorizes.
 *
 * Before the fix a `key` getter called `useCapability` again from inside the
 * call, after the outer call had taken its snapshot of the log: 150 spent
 * against a cap of 30, on a signed chain that verified. The attack cases were
 * watched red on the base commit, on all four stores; the controls pass on both.
 */
import { generateKeyPairSync } from "node:crypto"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, test } from "vitest"
import { MandateFailure } from "../../src/mandate/errors.ts"
import {
  capabilityKey,
  createTrust,
  defineCapability,
  makeEd25519SignerLive,
  makeInMemoryAuditLive,
  makeInMemorySignedAuditLive,
  makeJsonlAuditLive,
  makeJsonlSignedAuditLive,
  verifyAuditChain,
  type Capability,
  type GrantorId,
  type MandateAuditService,
  type MandateError,
  type SignedMandateAuditService,
} from "../../src/mandate/index.ts"

const OWNER = "owner" as GrantorId
const Buy = defineCapability("amazon.buy")

const tagOf = (fn: () => void): MandateError["_tag"] | "none" => {
  try {
    fn()
    return "none"
  } catch (e) {
    if (MandateFailure.is(e)) return e._tag
    throw e
  }
}

const tmp = (): string => join(mkdtempSync(join(tmpdir(), "reentrancy-")), "audit.jsonl")

const signerKeys = () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519")
  return makeEd25519SignerLive({
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
    publicKeyPem: publicKey.export({ format: "pem", type: "spki" }).toString(),
  })
}

interface StoreUnderTest {
  readonly store: MandateAuditService
  readonly chainValid: () => boolean
}

const signedCheck = (signed: SignedMandateAuditService, signer: ReturnType<typeof signerKeys>) => (): boolean =>
  verifyAuditChain(signed.listAllSigned(), signer, { trustedSignerPublicKeyHex: signer.publicKeyHex }).valid

const stores: ReadonlyArray<readonly [string, () => StoreUnderTest]> = [
  ["in-memory", () => ({ store: makeInMemoryAuditLive(), chainValid: () => true })],
  ["jsonl", () => ({ store: makeJsonlAuditLive(tmp()), chainValid: () => true })],
  [
    "in-memory signed",
    () => {
      const signer = signerKeys()
      const { mandateAudit, signedAudit } = makeInMemorySignedAuditLive(signer)
      return { store: mandateAudit, chainValid: signedCheck(signedAudit, signer) }
    },
  ],
  [
    "jsonl signed",
    () => {
      const signer = signerKeys()
      const { mandateAudit, signedAudit } = makeJsonlSignedAuditLive(tmp(), signer)
      return { store: mandateAudit, chainValid: signedCheck(signedAudit, signer) }
    },
  ],
]

const delegate = (trust: ReturnType<typeof createTrust>, limits: Record<string, { amount?: number; count?: number }>) => {
  const org = trust.issueOrgMandate({ grantor: OWNER, capabilities: [Buy] as const, rationale: "root" })
  const project = trust.issueProjectMandate({ grantor: OWNER, grantorScope: org, capabilities: [Buy] as const, rationale: "project" })
  const agent = trust.issueAgentMandate({
    grantor: OWNER,
    grantorScope: project,
    capabilities: [Buy] as const,
    rationale: "agent",
    limits,
  })
  return { org, project, agent }
}

describe.each(stores)("re-entrant capability getters on the %s store", (_name, make) => {
  test("a getter on the presented capability cannot overrun an amount cap", () => {
    const { store, chainValid } = make()
    const trust = createTrust({ store })
    const { agent } = delegate(trust, { "amazon.buy": { amount: 30 } })

    let depth = 0
    const evil: Capability<"amazon.buy"> = {
      get key() {
        if (depth < 4) {
          depth += 1
          trust.useCapability({ mandate: agent, capability: evil, amount: 30 })
        }
        return "amazon.buy" as const
      },
    }

    expect(tagOf(() => trust.useCapability({ mandate: agent, capability: evil, amount: 30 }))).toBe("MandateLimitExceeded")

    const invokes = store.query(agent.id).filter((e) => e.type === "invoke")
    expect(invokes).toHaveLength(1)
    expect(invokes.reduce((sum, e) => sum + (e.type === "invoke" ? (e.amount ?? 0) : 0), 0)).toBe(30)
    expect(chainValid()).toBe(true)
  })

  test("a getter planted on the scope's own element cannot overrun a count cap", () => {
    const { store, chainValid } = make()
    const trust = createTrust({ store })
    const { agent } = delegate(trust, { "amazon.buy": { count: 1 } })

    // The host keeps the capability object. The agent holds only its scope and
    // a tool closed over `trust`, and edits the one object it can reach.
    const buy = (): void => trust.useCapability({ mandate: agent, capability: Buy })
    let fired = 0
    Object.defineProperty(agent.capabilities[0], "key", {
      configurable: true,
      get() {
        fired += 1
        if (fired === 1) buy()
        return "amazon.buy"
      },
    })

    expect(tagOf(buy)).toBe("none")
    expect(store.query(agent.id).filter((e) => e.type === "invoke")).toHaveLength(1)
    // Nothing the holder planted on its own element ever runs.
    expect(fired).toBe(0)
    expect(chainValid()).toBe(true)
  })
})

describe("what a scope hands out", () => {
  const issue = () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    return { trust, ...delegate(trust, {}) }
  }

  test("a scope keeps none of the caller's capability objects", () => {
    const { org } = issue()
    expect(org.capabilities[0]).not.toBe(Buy)
    expect(capabilityKey(org.capabilities[0]!)).toBe("amazon.buy")
  })

  test("no two scopes share an element, so a child's holder cannot break its grantor", () => {
    const { trust, org, project, agent } = issue()
    expect(agent.capabilities[0]).not.toBe(project.capabilities[0])
    expect(agent.parentScope.capabilities[0]).not.toBe(project.capabilities[0])
    expect(agent.parentScope.parentScope.capabilities[0]).not.toBe(org.capabilities[0])

    ;(agent.capabilities[0] as { key: string }).key = "nope"
    ;(agent.parentScope.capabilities[0] as { key: string }).key = "nope"

    expect(tagOf(() => trust.useCapability({ mandate: project, capability: Buy }))).toBe("none")
    expect(tagOf(() => trust.useCapability({ mandate: agent, capability: Buy }))).toBe("none")
    expect(
      tagOf(() => trust.issueAgentMandate({ grantor: OWNER, grantorScope: project, capabilities: [Buy] as const, rationale: "r" })),
    ).toBe("none")
  })

  test("a resumed scope hands out rebuilt elements as well", () => {
    const { trust, agent } = issue()
    const resumed = trust.resume({ mandateId: agent.id, capabilities: [Buy] as const, resumedBy: OWNER })
    expect(resumed.capabilities[0]).not.toBe(Buy)
    expect(tagOf(() => trust.useCapability({ mandate: resumed as never, capability: Buy as never }))).toBe("none")
  })
})

describe("a capability key is a primitive string", () => {
  test("capabilityKey refuses a key that is not a string", () => {
    const hostile = { key: { toString: () => "amazon.buy", toJSON: () => "other" } } as unknown as Capability
    expect(() => capabilityKey(hostile)).toThrow(TypeError)
  })

  test("capabilityKey still reads a bare string", () => {
    expect(capabilityKey("x.read" as unknown as Capability)).toBe("x.read")
  })

  test("a non-string key is refused at issue", () => {
    const store = makeInMemoryAuditLive()
    const trust = createTrust({ store })
    const hostile = { key: { toJSON: () => "amazon.buy" } } as unknown as Capability
    expect(() => trust.issueOrgMandate({ grantor: OWNER, capabilities: [hostile] as const, rationale: "r" })).toThrow(TypeError)
  })

  test("capabilityKey refuses a key-less object instead of naming it [object Object]", () => {
    expect(() => capabilityKey({ id: "x.read" } as unknown as Capability)).toThrow(TypeError)
    expect(() => capabilityKey(5 as unknown as Capability)).toThrow(TypeError)
  })

  test("a malformed capability at use is a typed refusal, and a revoke still outranks it", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({ grantor: OWNER, capabilities: [Buy] as const, rationale: "root" })
    for (const bad of [{ key: 42 }, { key: { toString: () => "amazon.buy" } }, {}, 7, null, undefined]) {
      expect(tagOf(() => trust.useCapability({ mandate: org, capability: bad as never }))).toBe("CapabilityNotInGrantorScope")
    }
    expect(org.id).toBeTypeOf("string")
    trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "kill" })
    expect(tagOf(() => trust.useCapability({ mandate: org, capability: { key: 42 } as never }))).toBe("MandateRevoked")
  })

  test("a copy of a scope with a malformed element is refused as forged", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const org = trust.issueOrgMandate({ grantor: OWNER, capabilities: [Buy] as const, rationale: "root" })
    for (const element of [{ key: 42 }, null]) {
      const copy = { ...org, capabilities: [element] } as never
      expect(tagOf(() => trust.useCapability({ mandate: copy, capability: Buy as never }))).toBe("MandateScopeForged")
    }
  })

  test("a forged scope with no capability list keeps its specific refusal", () => {
    const trust = createTrust({ store: makeInMemoryAuditLive() })
    const forged = { id: "MAN_FAKE", grantor: OWNER } as never
    expect(tagOf(() => trust.useCapability({ mandate: forged, capability: Buy as never }))).toBe("MandateNotIssued")
  })

  test("a forged scope whose id is not a string is refused before any log read", () => {
    const reads: string[] = []
    const inner = makeInMemoryAuditLive()
    const store: MandateAuditService = {
      record: inner.record,
      query: (id) => {
        reads.push("query")
        return inner.query(id)
      },
      isRevoked: (id) => {
        reads.push("isRevoked")
        return inner.isRevoked(id)
      },
    }
    const trust = createTrust({ store })
    const forged = { id: { toString: () => "MAN_X" }, grantor: OWNER, capabilities: [] } as never
    expect(tagOf(() => trust.useCapability({ mandate: forged, capability: Buy as never }))).toBe("MandateNotIssued")
    expect(reads).toEqual([])
  })
})
