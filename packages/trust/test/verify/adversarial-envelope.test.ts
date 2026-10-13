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
import { makeSink, Sourced, receiptBody } from "../../src/gate/index.ts"
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

describe("finding 5 — each field was read several times, and a getter can answer differently each time", () => {
  // Precondition: the attacker supplies a LIVE object, never reachable through
  // parseJSONL. In-process callers do hand the verifier live objects, so the
  // verifier reads every field exactly once and judges only what it read.
  const attacker = generateSigningKeypair()
  const attackerPin = publicKeyHexFromPem(attacker.publicKeyPem)
  const attackerSigned = () => {
    const log = new SignedReceiptLog(makeEd25519ReceiptSigner(attacker))
    log.append({ at: "2026-10-13T00:00:00.000Z", sink: "pay", decision: "executed", args: {} })
    return parseJSONL(log.exportJSONL())[0]!
  }
  /** `base` with `field` replaced by a getter that answers `answers[n]` on its n-th read (the last answer repeats). */
  const withGetter = (base: object, field: string, answers: ReadonlyArray<unknown>) => {
    let reads = 0
    const rec: Record<string, unknown> = { ...base }
    Object.defineProperty(rec, field, {
      enumerable: true,
      get() {
        const v = answers[Math.min(reads, answers.length - 1)]
        reads++
        return v
      },
    })
    return { rec, reads: () => reads }
  }

  it("ATTACK: a key getter that answers the pin with the operator's key and the crypto with the attacker's does not verify", () => {
    const { rec } = withGetter(attackerSigned(), "signerPublicKeyHex", [trusted, attackerPin])
    const report = verdict([rec])
    expect(report.valid).toBe(false)
    expect(report.reason).toBe("signature-mismatch")
  })

  it("ATTACK: a payload getter that swaps in a forged payload after the signature check cannot satisfy a seal over the forgery", () => {
    const honest = session(1).records[0]!
    const P1 = honest.payload
    const P2 = loose([P1])[0]! as unknown as typeof P1
    ;(P2.args as Record<string, { value: unknown }>)["to"]!.value = "acct-EVIL"
    ;(P2 as { hash: string }).hash = sha256Hex(receiptBody(P2))
    for (const kind of ["anchor", "receipt"] as const) {
      // A fresh getter per kind: the record's read counter is the attack.
      const { rec } = withGetter(honest, "payload", [P1, P2])
      const report = verdict([rec], { trustedSignerPublicKeyHex: trusted, anchor: { kind, head: P2.hash } })
      expect(report, kind).toMatchObject({ valid: false, reason: "anchor-not-found", anchoredThrough: null })
    }
  })

  it("ATTACK: a getter that throws is malformed-record, not an exception out of the verifier", () => {
    const base = attackerSigned()
    const rec: Record<string, unknown> = { ...base }
    Object.defineProperty(rec, "payload", { enumerable: true, get() { throw new Error("boom") } })
    const report = verdict([rec], { trustedSignerPublicKeyHex: attackerPin })
    expect(report).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "malformed-record" })
    expect(report.detail).toContain("boom")
  })

  it("every envelope field is read exactly once per record, by both verifiers", () => {
    const honest = session(1).records[0]!
    const fields = ["payload", "signature", "signerPublicKeyHex", "signedAt", "previousHash", "domain"] as const
    for (const field of fields) {
      const { rec, reads } = withGetter(honest, field, [honest[field]])
      expect(verdict([rec]).valid, `verifySignedChain, ${field}`).toBe(true)
      expect(reads(), `verifySignedChain read ${field}`).toBe(1)
    }
    const audit = auditChain()[0]!
    for (const field of fields) {
      const { rec, reads } = withGetter(audit, field, [audit[field]])
      expect(auditVerdict([rec]).valid, `verifyAuditChain, ${field}`).toBe(true)
      expect(reads(), `verifyAuditChain read ${field}`).toBe(1)
    }
  })
})

describe("finding 3 — the signature is decoded leniently, so byte-different signatures verify", () => {
  // Buffer.from(s, "hex") stops at the first non-hex character and accepts an
  // array or a {type:"Buffer"} object outright, so many strings that are not
  // the signature decode to the signature's bytes. On the last record nothing
  // else pins those bytes. An Ed25519 signature is exactly 64 bytes: 128
  // lowercase hex characters, or it is not a signature.
  const variants: ReadonlyArray<readonly [string, (s: string) => unknown]> = [
    ["uppercase hex", (s) => s.toUpperCase()],
    ["trailing non-hex garbage", (s) => s + "zz-not-hex"],
    ["trailing space", (s) => s + " "],
    ["trailing newline", (s) => s + "\n"],
    ["byte array instead of hex", (s) => Array.from(Buffer.from(s, "hex"))],
    ["{type:'Buffer',data:[...]}", (s) => ({ type: "Buffer", data: Array.from(Buffer.from(s, "hex")) })],
    ["odd length (extra nibble)", (s) => s + "a"],
    ["inmem- prefixed", (s) => "inmem-" + s],
    ["127 characters", (s) => s.slice(1)],
  ]

  it.each(variants)("ATTACK: %s on the LAST record is malformed-record, on a MIDDLE record too", (_label, mutate) => {
    const last = loose(session().records)
    last[2]!["signature"] = mutate(last[2]!["signature"] as string)
    expect(verdict(last)).toMatchObject({ valid: false, firstInvalidIndex: 2, reason: "malformed-record" })
    const mid = loose(session().records)
    mid[1]!["signature"] = mutate(mid[1]!["signature"] as string)
    expect(verdict(mid)).toMatchObject({ valid: false, firstInvalidIndex: 1, reason: "malformed-record" })
  })

  it("an empty signature is still missing-signature, not malformed", () => {
    const t = loose(session(1).records)
    t[0]!["signature"] = ""
    expect(verdict(t)).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "missing-signature" })
  })

  it("parity: verifyAuditChain refuses an uppercase-plus-garbage signature for the same reason", () => {
    const t = loose(auditChain())
    t[1]!["signature"] = (t[1]!["signature"] as string).toUpperCase() + "GARBAGE"
    const b = auditVerdict(t)
    expect(b).toMatchObject({ valid: false, firstInvalidIndex: 1, reason: "malformed-record" })
    const r = loose(session(1).records)
    r[0]!["signature"] = (r[0]!["signature"] as string).toUpperCase() + "GARBAGE"
    sameVerdict(verdict(r), auditVerdict(r))
  })
})

describe("finding 9 — an unknown opts key is ignored, so the retired anchor option verifies a truncated chain", () => {
  // `anchoredHead` was the anchor option before the kind-carrying `anchor`
  // object. A JS caller still passing it got no anchor check and no signal:
  // a truncated chain came back valid. The options bag is {trustedSignerPublicKeyHex,
  // anchor}; anything else is a caller error and the verdict says so.
  it("ATTACK: {anchoredHead} on a truncated chain is malformed-record naming the key, not a silent pass", () => {
    const { log, records } = session()
    const truncated = records.slice(0, 2)
    const report = verdict(truncated, { trustedSignerPublicKeyHex: trusted, anchoredHead: log.head() })
    expect(report).toMatchObject({ valid: false, firstInvalidIndex: null, reason: "malformed-record", anchoredThrough: null })
    expect(report.detail).toContain("anchoredHead")
  })

  it("any other unknown key is refused the same way, even beside a correct anchor", () => {
    const { log, records } = session()
    const report = verdict(records, { trustedSignerPublicKeyHex: trusted, anchor: { kind: "anchor", head: log.head() }, extra: 1 })
    expect(report).toMatchObject({ valid: false, firstInvalidIndex: null, reason: "malformed-record" })
    expect(report.detail).toContain("extra")
  })

  it("CONTROL: the two known keys, with anchor present or explicitly undefined, still verify", () => {
    const { log, records } = session()
    expect(verdict(records, { trustedSignerPublicKeyHex: trusted, anchor: { kind: "anchor", head: log.head() } })).toMatchObject({ valid: true, anchoredThrough: 2 })
    expect(verdict(records, { trustedSignerPublicKeyHex: trusted, anchor: undefined })).toMatchObject({ valid: true, anchoredThrough: null })
  })
})
