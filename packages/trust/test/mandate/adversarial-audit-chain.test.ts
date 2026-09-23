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

// ============================================================================
// DAN-1159 item 3: every input comes back as a verdict.
// ============================================================================
// verifyAuditChain is what an operator points at a log that someone else could
// have written to. Its sibling verifySignedChain learned this on 2026-07-25
// (adversarial passes V2, V3): an empty chain is not a clean bill of health, and
// a verifier that THROWS on hostile input cannot be told apart from a broken
// verifier. This function never got either fix. `[]` folded to valid:true, and
// null, a non-SPKI key and a BigInt all crashed it.
describe("verifyAuditChain — every input comes back as a verdict (DAN-1159 item 3)", () => {
  /** Run the verifier and fail the test with the thrown message instead of crashing it. */
  const verdict = (log: unknown[], signer: MandateSignerService, pinned = signer.publicKeyHex) => {
    let result: ReturnType<typeof verifyAuditChain> | undefined
    expect(() => {
      result = verifyAuditChain(log as SignedMandateAuditEvent[], signer, { trustedSignerPublicKeyHex: pinned })
    }).not.toThrow()
    return result!
  }

  test("an empty log is NOT valid: nothing to check is not a pass", () => {
    const signer = ed25519Signer()
    const result = verdict([], signer)
    expect(result.valid).toBe(false)
    expect(result.reason).toBe("empty-chain")
    expect(result.firstInvalidIndex).toBeNull()
  })

  test("a null record is malformed, not a crash", () => {
    const signer = ed25519Signer()
    const result = verdict([null], signer)
    expect(result).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "malformed-record" })
  })

  test("a non-object record (a string, a number) is malformed", () => {
    const signer = ed25519Signer()
    const [good] = buildChain(signer, EVENTS)
    expect(verdict([good, "revoke M1"], signer)).toMatchObject({ valid: false, firstInvalidIndex: 1, reason: "malformed-record" })
    expect(verdict([42], signer)).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "malformed-record" })
  })

  test("a pinned key that is not an SPKI key comes back malformed, not 'Failed to read asymmetric key'", () => {
    // The pin is a string comparison, so a record carrying the same junk as the
    // pin passes it and reaches createPublicKey. That is where it used to throw.
    const signer = ed25519Signer()
    const [good] = buildChain(signer, EVENTS)
    const result = verdict([{ ...good!, signerPublicKeyHex: "abcd" }], signer, "abcd")
    expect(result).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "malformed-record" })
  })

  test("a BigInt in a payload is malformed (canonicalJSON cannot encode it), not a crash", () => {
    const signer = ed25519Signer()
    const [good] = buildChain(signer, EVENTS)
    const result = verdict([{ ...good!, payload: { ...good!.payload, amount: 10n } }], signer)
    expect(result).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "malformed-record" })
  })

  test("a record that verifies but cannot be HASHED for the next link is malformed, not a crash", () => {
    // The signature covers domain, payload, previousHash and signedAt. A field
    // OUTSIDE that preimage leaves the signature valid, and only the next
    // record's link computation (canonicalJSON of the whole record) meets it.
    const signer = ed25519Signer()
    const chain = buildChain(signer, EVENTS)
    const hostile = [{ ...chain[0]!, extra: 1n }, chain[1]!]
    const result = verdict(hostile, signer)
    expect(result.valid).toBe(false)
    expect(result.reason).toBe("malformed-record")
  })

  test("a malformed verdict says what could not be checked", () => {
    const signer = ed25519Signer()
    expect(verdict([null], signer)).toHaveProperty("detail", expect.stringContaining("record 0"))
  })

  test("CONTROL: an honest chain still verifies through the same wrapper", () => {
    const signer = ed25519Signer()
    expect(verdict(buildChain(signer, EVENTS), signer)).toMatchObject({ valid: true, reason: "ok" })
  })
})

describe("verifyAuditChain — the CONTAINER gets a verdict too (DAN-1159 item 5, the F6 residual)", () => {
  // Item 3 made every ELEMENT shape a verdict and measured it on arrays. The
  // container itself was never checked: `{}.length` is undefined, so the
  // empty-chain guard and the loop both skip it and the function returns
  // valid:true for a log nobody read.
  // `opts` is a rest slot, not a default parameter: an explicit `undefined`
  // must reach the verifier as undefined, and a default would silently swap
  // in the honest pin.
  const verdict = (log: unknown, signer: MandateSignerService, ...rest: [opts?: unknown]) => {
    const opts = rest.length === 0 ? { trustedSignerPublicKeyHex: signer.publicKeyHex } : rest[0]
    let result: ReturnType<typeof verifyAuditChain> | undefined
    expect(() => {
      result = verifyAuditChain(log as SignedMandateAuditEvent[], signer, opts as { readonly trustedSignerPublicKeyHex: string })
    }).not.toThrow()
    return result!
  }
  const MALFORMED_LOG = { valid: false, firstInvalidIndex: null, reason: "malformed-record" }

  test("a plain object is not a log, and it used to verify as one", () => {
    const signer = ed25519Signer()
    expect(verdict({}, signer)).toMatchObject(MALFORMED_LOG)
    expect(verdict({ records: buildChain(signer, EVENTS) }, signer)).toMatchObject(MALFORMED_LOG)
  })

  test("null in place of the log is malformed, not a crash", () => {
    expect(verdict(null, ed25519Signer())).toMatchObject(MALFORMED_LOG)
  })

  test("a missing opts pins nothing, so nothing verifies: fail-closed, as a verdict", () => {
    const signer = ed25519Signer()
    expect(verdict(buildChain(signer, EVENTS), signer, undefined)).toMatchObject({
      valid: false, firstInvalidIndex: 0, reason: "untrusted-signer",
    })
  })
})
