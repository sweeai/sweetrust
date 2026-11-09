/**
 * No read surface can alter the log (the 2026-11-08 audit, K3).
 * `listAllSigned()` used to return the store's live array, so `.pop()` on a read
 * result un-revoked a mandate and the shorter chain still verified. Watched red
 * on the base commit.
 */
import { generateKeyPairSync } from "node:crypto"
import { describe, expect, test } from "vitest"
import {
  createTrust,
  defineCapability,
  makeEd25519SignerLive,
  makeInMemorySignedAuditLive,
  verifyAuditChain,
  type GrantorId,
  type SignedMandateAuditEvent,
} from "../../src/mandate/index.ts"

const OWNER = "owner" as GrantorId
const Buy = defineCapability("x.buy")

const setup = () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519")
  const signer = makeEd25519SignerLive({
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
    publicKeyPem: publicKey.export({ format: "pem", type: "spki" }).toString(),
  })
  const { mandateAudit: store, signedAudit } = makeInMemorySignedAuditLive(signer)
  const trust = createTrust({ store })
  const org = trust.issueOrgMandate({ grantor: OWNER, capabilities: [Buy] as const, rationale: "root" })
  trust.revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "kill" })
  return { signer, store, signedAudit, trust, org }
}

describe("the in-memory signed store's read surfaces", () => {
  test("popping a listAllSigned result leaves revocation intact", () => {
    const { store, signedAudit, trust, org } = setup()
    const before = signedAudit.listAllSigned().length

    ;(signedAudit.listAllSigned() as SignedMandateAuditEvent[]).pop()

    expect(signedAudit.listAllSigned()).toHaveLength(before)
    expect(store.isRevoked(org.id)).toBe(true)
    expect(() => trust.useCapability({ mandate: org, capability: Buy })).toThrow()
  })

  test("each listAllSigned call returns a different array over the same records", () => {
    const { signedAudit } = setup()
    const a = signedAudit.listAllSigned()
    const b = signedAudit.listAllSigned()
    expect(a).not.toBe(b)
    expect(a).toEqual(b)
  })

  test("a truncated read result does not change what the chain verifies to", () => {
    const { signer, signedAudit } = setup()
    const list = signedAudit.listAllSigned() as SignedMandateAuditEvent[]
    list.length = 0
    expect(verifyAuditChain(signedAudit.listAllSigned(), signer, { trustedSignerPublicKeyHex: signer.publicKeyHex }).valid).toBe(true)
  })

  test("a querySigned result is detached and its records are frozen", () => {
    const { store, signedAudit, org } = setup()
    const rows = signedAudit.querySigned(org.id) as SignedMandateAuditEvent[]
    const last = rows[rows.length - 1]!
    rows.pop()
    expect(store.isRevoked(org.id)).toBe(true)
    expect(Object.isFrozen(last)).toBe(true)
    expect(Object.isFrozen(last.payload)).toBe(true)
  })
})
