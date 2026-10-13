// The 2026-10-13 verify audit: the envelope, the pin, and the reads.
// ============================================================================
// adversarial-evidence hardened verifySignedChain against hostile INPUT SHAPES
// and adversarial-seam against hostile CHAINS. This pass went after the record
// itself, as a JS object the verifier reads:
//
//   · the six-field envelope is signed, but a record is a bag: a SEVENTH key is
//     never read by any check, so it rides into the next link hash unexamined
//   · the pin gate is a `!==` between two values that can both be undefined
//   · each field is read several times, and a getter can answer differently
//     each time
//   · the options bag accepts names it does not know, including the retired
//     anchor option, and silently verifies without an anchor
//   · the JSONL reader counts lines after dropping the blank ones
// ============================================================================

import { describe, expect, it } from "vitest"
import { makeSink, Sourced } from "../../src/gate/index.ts"
import {
  SignedReceiptLog,
  canonicalJSON,
  generateSigningKeypair,
  makeEd25519ReceiptSigner,
  parseJSONL,
  publicKeyHexFromPem,
  sha256Hex,
  verifySignedChain,
  type SignedReceipt,
  type VerifyReport,
} from "../../src/verify/index.ts"
import { MANDATE_AUDIT_DOMAIN, makeEd25519SignerLive, verifyAuditChain } from "../../src/mandate/index.ts"
import type { SignedMandateAuditEvent } from "../../src/mandate/types.ts"

const keys = generateSigningKeypair()
const trusted = publicKeyHexFromPem(keys.publicKeyPem)
const mandateSigner = makeEd25519SignerLive(keys)

/** A three-decision session, exported and re-parsed so every record is plain JSON. */
const session = (n = 3) => {
  const log = new SignedReceiptLog(makeEd25519ReceiptSigner(keys))
  const pay = makeSink<{ to: Sourced<string> }, string>({
    name: "pay", requires: { to: "verified" }, mode: "enforce", log, execute: ({ to }) => `paid ${to.value}`,
  })
  for (let i = 0; i < n; i++) pay({ to: Sourced.fromAuthority(`acct-${i}`, "registry") })
  return { log, records: parseJSONL(log.exportJSONL()) }
}

/** A two-event mandate audit chain under the same key: grant, then revoke. */
const auditChain = (): SignedMandateAuditEvent[] => {
  const r0 = mandateSigner.sign({ payload: { type: "grant", mandateId: "M1" }, previousHash: null, domain: MANDATE_AUDIT_DOMAIN })
  const r1 = mandateSigner.sign({ payload: { type: "revoke", mandateId: "M1" }, previousHash: sha256Hex(canonicalJSON(r0)), domain: MANDATE_AUDIT_DOMAIN })
  return [r0, r1] as unknown as SignedMandateAuditEvent[]
}

/** A JSON round-trip, typed loosely so a test can add or delete keys on it. */
const loose = (x: unknown): Array<Record<string, unknown>> => JSON.parse(JSON.stringify(x))

/**
 * Run verifySignedChain and fail the test with the thrown message instead of
 * crashing it. `opts` is a rest slot, not a default parameter: an explicit
 * `undefined` must reach the verifier as undefined, and a default would
 * silently swap in the honest pin.
 */
const verdict = (records: unknown, ...rest: [opts?: unknown]): VerifyReport => {
  const opts = rest.length === 0 ? { trustedSignerPublicKeyHex: trusted } : rest[0]
  let report: VerifyReport | undefined
  expect(() => {
    report = verifySignedChain(records as SignedReceipt[], opts as Parameters<typeof verifySignedChain>[1])
  }).not.toThrow()
  return report!
}

/** Same for verifyAuditChain, through the Ed25519 signer. */
const auditVerdict = (log: unknown, ...rest: [opts?: unknown]) => {
  const opts = rest.length === 0 ? { trustedSignerPublicKeyHex: trusted } : rest[0]
  let out: ReturnType<typeof verifyAuditChain> | undefined
  expect(() => {
    out = verifyAuditChain(log as SignedMandateAuditEvent[], mandateSigner, opts as { readonly trustedSignerPublicKeyHex: string })
  }).not.toThrow()
  return out!
}

const sameVerdict = (a: { valid: boolean; reason: string; firstInvalidIndex: number | null }, b: typeof a) =>
  expect({ valid: a.valid, reason: a.reason, firstInvalidIndex: a.firstInvalidIndex })
    .toEqual({ valid: b.valid, reason: b.reason, firstInvalidIndex: b.firstInvalidIndex })

describe("finding 1 — the head record is not byte-pinned: keys outside the envelope", () => {
  // The signature covers domain, payload, previousHash and signedAt. The next
  // record's previousHash covers the WHOLE previous record. A seventh key on
  // the LAST record therefore sits under neither: both verifiers ignored it and
  // returned valid:true, and a store that re-verifies on read then signed the
  // next record's link OVER the injected text, making it permanent.

  it("ATTACK: an extra key on the LAST receipt record is malformed, and the detail names it", () => {
    const t = loose(session().records)
    t[2]!["auditor_note"] = "reviewed and approved 2026-10-13"
    const report = verdict(t)
    expect(report).toMatchObject({ valid: false, firstInvalidIndex: 2, reason: "malformed-record" })
    expect(report.detail).toContain("auditor_note")
  })

  it("ATTACK: an extra key on a MIDDLE record is malformed AT THAT RECORD, not hash-chain-broken at the next", () => {
    // Before the fix this surfaced one record late and under the wrong reason:
    // the stray key changed record 1's link hash, so record 2 reported
    // hash-chain-broken, and an operator went looking for a splice.
    const t = loose(session().records)
    t[1]!["auditor_note"] = "x"
    const report = verdict(t)
    expect(report).toMatchObject({ valid: false, firstInvalidIndex: 1, reason: "malformed-record" })
    expect(report.detail).toContain("auditor_note")
  })

  it("ATTACK: a record MISSING an envelope key is malformed, and the detail names the missing key", () => {
    const t = loose(session(1).records)
    delete t[0]!["domain"]
    const report = verdict(t)
    expect(report).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "malformed-record" })
    expect(report.detail).toContain("domain")
  })

  it("CONTROL: the honest chain, re-parsed from JSONL, still verifies", () => {
    expect(verdict(session().records)).toMatchObject({ valid: true, reason: "ok" })
  })

  it("ATTACK (mandate side): an extra key on the LAST audit record → malformed-record naming it", () => {
    const t = loose(auditChain())
    t[1]!["operator_comment"] = "revocation was a mistake, ignore"
    const report = auditVerdict(t)
    expect(report).toMatchObject({ valid: false, firstInvalidIndex: 1, reason: "malformed-record" })
    expect(report.detail).toContain("operator_comment")
  })

  it("ATTACK (mandate side): an extra key on the FIRST of two → malformed-record at 0, not hash-chain-broken at 1", () => {
    const t = loose(auditChain())
    t[0]!["operator_comment"] = "x"
    expect(auditVerdict(t)).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "malformed-record" })
  })

  it("parity: both verifiers give the same verdict for a record with a stray key", () => {
    const t = loose(session(1).records)
    t[0]!["extra"] = 1
    const a = verdict(t)
    sameVerdict(a, auditVerdict(t))
    expect(a.reason).toBe("malformed-record")
  })
})

describe("finding 2 — the pin gate passes when the pin and the record's key are both absent", () => {
  // `r.signerPublicKeyHex !== pin` is false when both sides are undefined (or
  // both null). A keyless record then walked through the gate. Under
  // verifySignedChain, createPublicKey(undefined) happened to throw afterwards,
  // so the verdict came back malformed-record by accident; under
  // verifyAuditChain with the in-memory signer nothing threw and a keyless
  // forgery was VALID. The gate must refuse on its own: a pin that is not a
  // string pins nothing, and the verdict is untrusted-signer, not a crash
  // somewhere downstream.

  const keyless = () => {
    const [r] = loose(session(1).records)
    delete r!["signerPublicKeyHex"]
    return [r!]
  }

  it("ATTACK: a keyless record with no opts, an undefined pin, or an empty opts bag is untrusted-signer at the gate", () => {
    for (const opts of [undefined, { trustedSignerPublicKeyHex: undefined }, {}]) {
      expect(verdict(keyless(), opts), `opts ${JSON.stringify(opts)}`).toMatchObject({
        valid: false, firstInvalidIndex: 0, reason: "untrusted-signer",
      })
    }
  })

  it("ATTACK: a null key against a null pin is untrusted-signer, not a match", () => {
    const [r] = loose(session(1).records)
    r!["signerPublicKeyHex"] = null
    expect(verdict([r], { trustedSignerPublicKeyHex: null })).toMatchObject({
      valid: false, firstInvalidIndex: 0, reason: "untrusted-signer",
    })
  })

  it("parity: verifyAuditChain gives the same verdict for a keyless record and no pin", () => {
    const a = verdict(keyless(), undefined)
    const b = auditVerdict(keyless(), undefined)
    sameVerdict(a, b)
    expect(a.reason).toBe("untrusted-signer")
  })

  it("CONTROL: a genuine record against its genuine pin still verifies", () => {
    expect(verdict(session(1).records)).toMatchObject({ valid: true, reason: "ok" })
  })
})
