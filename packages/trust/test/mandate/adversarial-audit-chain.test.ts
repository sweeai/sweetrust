/**
 * Adversarial regression tests for the signed audit chain (DAN-641).
 *
 * Before envelope-signing, the Ed25519 signature covered `canonicalJSON(payload)`
 * ONLY. Because MandateAuditEvent carries no signed position (no seq / self-hash),
 * an attacker with NO signing key could delete/reorder/retime records and relink
 * the publicly-recomputable `previousHash` chain — every signature stayed valid and
 * `verifyAuditChain` returned `valid:true`. See the review repro:
 *
 *   deletion+relink -> valid:true  *** REVOKE ERASED ***
 *   reorder         -> valid:true
 *   retime signedAt -> valid:true
 *
 * The fix signs the full envelope (domain + payload + previousHash + signedAt) via
 * the single shared `signedPreimage`. These tests pin the closed attacks (deletion,
 * reorder, retime, domain-confusion) plus key-substitution (closed by the sibling
 * DAN-638 pinned-key fix) as CAUGHT, and the sole residual — tail-truncation, which
 * needs an external anchor — as documented-open.
 */
import { generateKeyPairSync } from "node:crypto"
import { describe, expect, test } from "vitest"
import {
  canonicalJSON,
  makeEd25519SignerLive,
  MANDATE_AUDIT_DOMAIN,
  sha256Hex,
  verifyAuditChain,
  type MandateSignerService,
} from "../../src/mandate/index.ts"
import type { MandateAuditEvent, SignedMandateAuditEvent } from "../../src/mandate/types.ts"

function ed25519Signer(): MandateSignerService {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519")
  return makeEd25519SignerLive({
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }) as string,
    publicKeyPem: publicKey.export({ format: "pem", type: "spki" }) as string,
  })
}

const EVENTS: MandateAuditEvent[] = [
  { type: "grant", mandateId: "M1" as any, grantor: "org" as any, capabilities: ["pay"], rationale: "issue", parentMandateId: null, timestamp: "2026-07-22T00:00:00Z" as any, triggerSource: "code" },
  { type: "revoke", mandateId: "M1" as any, revokedBy: "org" as any, rationale: "kill", timestamp: "2026-07-22T01:00:00Z" as any, triggerSource: "code" },
  { type: "invoke", mandateId: "M1" as any, capability: "pay", timestamp: "2026-07-22T02:00:00Z" as any, triggerSource: "code" },
]

// Build a chain exactly as the signed audit Layer does: previousHash =
// sha256(canonicalJSON(previous SIGNED record)), null for the first.
function buildChain(signer: MandateSignerService, events: MandateAuditEvent[], domain = MANDATE_AUDIT_DOMAIN): SignedMandateAuditEvent[] {
  const out: SignedMandateAuditEvent[] = []
  let prev: string | null = null
  for (const e of events) {
    const rec = signer.sign({ payload: e, previousHash: prev, domain })
    out.push(rec)
    prev = sha256Hex(canonicalJSON(rec))
  }
  return out
}

// verifyAuditChain with the operator key pinned to the signer that built the chain
// (the honest configuration — DAN-638 made trustedSignerPublicKeyHex required).
const check = (chain: SignedMandateAuditEvent[], signer: MandateSignerService) =>
  verifyAuditChain(chain, signer, { trustedSignerPublicKeyHex: signer.publicKeyHex })

describe("verifyAuditChain — adversarial (DAN-641 envelope signing)", () => {
  test("baseline: an honestly-built chain verifies", () => {
    const signer = ed25519Signer()
    expect(check(buildChain(signer, EVENTS), signer).valid).toBe(true)
  })

  test("CLOSED (DAN-641): interior deletion + relink is caught (the headline bug — revoke can no longer be erased)", () => {
    const signer = ed25519Signer()
    const chain = buildChain(signer, EVENTS)
    // drop the middle `revoke`, relink the survivor's previousHash to the new predecessor (public, no key)
    const attacked: SignedMandateAuditEvent[] = [chain[0]!, { ...chain[2]!, previousHash: sha256Hex(canonicalJSON(chain[0]!)) }]
    expect(check(attacked, signer).valid).toBe(false)
  })

  test("CLOSED (DAN-641): record reorder is caught", () => {
    const signer = ed25519Signer()
    const chain = buildChain(signer, EVENTS)
    const swapped = [chain[1]!, chain[0]!, chain[2]!]
    expect(check(swapped, signer).valid).toBe(false)
  })

  test("CLOSED (DAN-641): retiming signedAt is caught (evidence timestamp is authenticated)", () => {
    const signer = ed25519Signer()
    const chain = buildChain(signer, EVENTS)
    const retimed = chain.map((r) => ({ ...r, signedAt: "1999-01-01T00:00:00Z" as any }))
    expect(check(retimed, signer).valid).toBe(false)
  })

  test("CLOSED (DAN-641): a receipt-domain record cannot masquerade as an audit event (domain separation)", () => {
    const signer = ed25519Signer()
    const wrongDomain = buildChain(signer, EVENTS, "swee.receipt.v1")
    const report = check(wrongDomain, signer)
    expect(report.valid).toBe(false)
    expect(report.reason).toBe("domain-mismatch")
  })

  test("CLOSED (DAN-638): key-substitution is caught — a whole chain re-signed under an attacker key is rejected", () => {
    const attacker = ed25519Signer()
    const honest = ed25519Signer()
    const forged = buildChain(attacker, [EVENTS[0]!]) // forged under the attacker's own key
    // Pin the HONEST operator key: verifyAuditChain rejects the attacker-keyed records before the signature check.
    const report = verifyAuditChain(forged, honest, { trustedSignerPublicKeyHex: honest.publicKeyHex })
    expect(report.valid).toBe(false)
    expect(report.reason).toBe("untrusted-signer")
  })

  test("CONTROL: naive payload mutation is caught (verifier is live)", () => {
    const signer = ed25519Signer()
    const chain = buildChain(signer, EVENTS)
    const mutated = chain.map((r, i) => (i === 1 ? { ...r, payload: { ...r.payload, rationale: "TAMPERED" } } : r))
    expect(check(mutated, signer).valid).toBe(false)
  })

  // ── Sole documented residual: tail truncation (needs an external anchor) ─────
  test("RESIDUAL (needs anchor): tail truncation of the most recent records still passes", () => {
    const signer = ed25519Signer()
    const chain = buildChain(signer, EVENTS)
    // drop the final record — the shorter chain is still internally consistent, validly signed,
    // AND signed by the pinned key. Only an external anchor over the head can catch this
    // (as @sweetrust/verify documents for its receipt chain).
    expect(check(chain.slice(0, 2), signer).valid).toBe(true)
  })
})
