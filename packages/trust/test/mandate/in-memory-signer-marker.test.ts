/**
 * The in-memory signer cannot satisfy a real pin (the 2026-11-08 audit, K4).
 * Its signature is a public function of the envelope, and its `verify` used to
 * ignore the key a record carried, so a forgery naming the operator's real key
 * came back valid:true from `verifyAuditChain` under the operator's real pin.
 * Watched red on the base commit.
 */
import { generateKeyPairSync } from "node:crypto"
import { describe, expect, test } from "vitest"
import {
  MANDATE_AUDIT_DOMAIN,
  makeEd25519SignerLive,
  makeInMemorySignerLive,
  sha256Hex,
  signedPreimage,
  verifyAuditChain,
  type SignedMandateAuditEvent,
} from "../../src/mandate/index.ts"

const realSigner = () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519")
  return makeEd25519SignerLive({
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
    publicKeyPem: publicKey.export({ format: "pem", type: "spki" }).toString(),
  })
}

const forge = (claimedKeyHex: string): SignedMandateAuditEvent => {
  const payload = {
    type: "revoke",
    mandateId: "MAN_X",
    revokedBy: "attacker",
    rationale: "forged",
    timestamp: new Date().toISOString(),
    triggerSource: "code",
  } as unknown as SignedMandateAuditEvent["payload"]
  const signedAt = new Date().toISOString() as SignedMandateAuditEvent["signedAt"]
  return {
    payload,
    signature: "inmem-" + sha256Hex(signedPreimage({ domain: MANDATE_AUDIT_DOMAIN, payload, previousHash: null, signedAt })),
    signerPublicKeyHex: claimedKeyHex,
    signedAt,
    previousHash: null,
    domain: MANDATE_AUDIT_DOMAIN,
  }
}

describe("makeInMemorySignerLive.verify", () => {
  test("a forgery naming the operator's key does not pass the operator's pin", () => {
    const real = realSigner()
    const verdict = verifyAuditChain([forge(real.publicKeyHex)], makeInMemorySignerLive(), {
      trustedSignerPublicKeyHex: real.publicKeyHex,
    })
    expect(verdict.valid).toBe(false)
    expect(verdict.reason).toBe("signature-mismatch")
  })

  test("refuses a record carrying another marker", () => {
    const signer = makeInMemorySignerLive("inmem-a")
    const other = makeInMemorySignerLive("inmem-b")
    const record = other.sign({ payload: { n: 1 }, previousHash: null, domain: MANDATE_AUDIT_DOMAIN })
    expect(signer.verify(record)).toBe(false)
    expect(other.verify(record)).toBe(true)
  })

  test("still verifies its own records, across two instances with one marker", () => {
    const a = makeInMemorySignerLive()
    const b = makeInMemorySignerLive()
    const record = a.sign({ payload: { n: 1 }, previousHash: null, domain: MANDATE_AUDIT_DOMAIN })
    expect(a.verify(record)).toBe(true)
    expect(b.verify(record)).toBe(true)
  })
})
