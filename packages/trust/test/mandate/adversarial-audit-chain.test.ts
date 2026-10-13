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

// ============================================================================
// The 2026-10-13 verify audit, mandate side.
// ============================================================================
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { makeJsonlSignedAuditLive } from "../../src/mandate/audit.ts"
import { makeEd25519VerifierLive, makeInMemorySignerLive, publicKeyHexFromPem, signedPreimage } from "../../src/mandate/index.ts"

describe("2026-10-13 verify audit, finding 1 — a stray key on the head record is refused, and the store inherits it", () => {
  // The durable store re-verifies the whole file on every read and then signs
  // the next record's previousHash over the LAST line as it stands. An attacker
  // with file-write access who adds an unsigned key to that line used to get it
  // accepted on the next read and then sealed in by the operator's own
  // signature, so it could never be removed without breaking the chain.
  const freshPath = () => join(mkdtempSync(join(tmpdir(), "sweetrust-audit-")), "audit.jsonl")

  test("verifyAuditChain: a stray key on the LAST record is malformed-record, with its name in the detail", () => {
    const signer = ed25519Signer()
    const chain = buildChain(signer, EVENTS)
    const injected = [chain[0]!, chain[1]!, { ...chain[2]!, operator_comment: "revocation issued in error, disregard" }]
    const report = check(injected as SignedMandateAuditEvent[], signer)
    expect(report).toMatchObject({ valid: false, firstInvalidIndex: 2, reason: "malformed-record" })
    expect(report.detail).toContain("operator_comment")
  })

  test("verifyAuditChain: a stray key in the MIDDLE is malformed AT that record, not hash-chain-broken at the next", () => {
    const signer = ed25519Signer()
    const chain = buildChain(signer, EVENTS)
    const injected = [chain[0]!, { ...chain[1]!, operator_comment: "x" }, chain[2]!]
    expect(check(injected as SignedMandateAuditEvent[], signer)).toMatchObject({ valid: false, firstInvalidIndex: 1, reason: "malformed-record" })
  })

  test("verifyAuditChain: the in-memory signer's verdict is the same", () => {
    const signer = makeInMemorySignerLive()
    const chain = buildChain(signer, EVENTS)
    const injected = [chain[0]!, chain[1]!, { ...chain[2]!, operator_comment: "x" }]
    expect(check(injected as SignedMandateAuditEvent[], signer)).toMatchObject({ valid: false, firstInvalidIndex: 2, reason: "malformed-record" })
  })

  test("the durable store refuses to read past an injected key on its last line, so it never signs over it", () => {
    const signer = ed25519Signer()
    const path = freshPath()
    const { signedAudit } = makeJsonlSignedAuditLive(path, signer)
    signedAudit.recordSigned(EVENTS[0]!)
    signedAudit.recordSigned(EVENTS[1]!)

    // The attacker edits the LAST line only: one unsigned key.
    const lines = readFileSync(path, "utf-8").split("\n").filter(Boolean)
    const last = JSON.parse(lines[1]!)
    last.operator_comment = "revocation issued in error, mandate M1 remains active"
    lines[1] = JSON.stringify(last)
    writeFileSync(path, lines.join("\n") + "\n")

    const reopened = makeJsonlSignedAuditLive(path, signer)
    let thrown: unknown
    try {
      reopened.signedAudit.listAllSigned()
    } catch (e) {
      thrown = e
    }
    expect(thrown).toMatchObject({ _tag: "AuditLogCorrupt", line: 2, reason: "malformed-record" })
    // And the append is refused too, so the injected line is never sealed in.
    expect(() => reopened.signedAudit.recordSigned(EVENTS[2]!)).toThrow()
    expect(readFileSync(path, "utf-8").split("\n").filter(Boolean)).toHaveLength(2)
  })
})

describe("2026-10-13 verify audit, finding 2 — a missing pin matches a missing key, and the in-memory signer made that VALID", () => {
  // The in-memory signer's signature is a public function of the envelope, so a
  // forger needs no key at all: build a keyless revoke, compute its "inmem-"
  // signature, and hand it to verifyAuditChain with no opts. The pin gate
  // compared undefined to undefined and let it through; nothing downstream
  // threw; the verdict was valid:true.
  const forgedKeylessRevoke = (): Record<string, unknown> => {
    const forged: Record<string, unknown> = {
      payload: { type: "revoke", mandateId: "ORG-ROOT", revokedBy: "attacker", timestamp: "2026-10-13T00:00:00Z" },
      previousHash: null,
      domain: MANDATE_AUDIT_DOMAIN,
      signedAt: "2026-10-13T00:00:00.000Z",
    }
    forged["signature"] = "inmem-" + sha256Hex(signedPreimage(forged as Parameters<typeof signedPreimage>[0]))
    return forged
  }

  test("ATTACK: keyless forged revoke, in-memory signer, no opts → untrusted-signer, never valid", () => {
    const signer = makeInMemorySignerLive()
    for (const opts of [undefined, { trustedSignerPublicKeyHex: undefined }, {}]) {
      const report = verifyAuditChain([forgedKeylessRevoke()] as unknown as SignedMandateAuditEvent[], signer, opts as unknown as { readonly trustedSignerPublicKeyHex: string })
      expect(report, `opts ${JSON.stringify(opts)}`).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "untrusted-signer" })
    }
  })

  test("ATTACK: the same under the Ed25519 signer is untrusted-signer at the gate, not malformed by accident downstream", () => {
    const signer = ed25519Signer()
    const [good] = buildChain(signer, EVENTS)
    const keyless: Record<string, unknown> = { ...good! }
    delete keyless["signerPublicKeyHex"]
    const report = verifyAuditChain([keyless] as unknown as SignedMandateAuditEvent[], signer, undefined as unknown as { readonly trustedSignerPublicKeyHex: string })
    expect(report).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "untrusted-signer" })
  })

  test("CONTROL: the forged record against the in-memory signer's real marker is untrusted-signer too, and an honest in-memory chain verifies", () => {
    const signer = makeInMemorySignerLive()
    expect(verifyAuditChain([forgedKeylessRevoke()] as unknown as SignedMandateAuditEvent[], signer, { trustedSignerPublicKeyHex: signer.publicKeyHex }).reason).toBe("untrusted-signer")
    expect(check(buildChain(signer, EVENTS), signer)).toMatchObject({ valid: true, reason: "ok" })
  })
})

describe("2026-10-13 verify audit, finding 5 — a getter record is read once, by the chain verifier and by signer.verify()", () => {
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
  const asLog = (r: Record<string, unknown>) => [r] as unknown as SignedMandateAuditEvent[]

  test("ATTACK: an attacker-signed revoke whose key getter answers the gate with the operator's key is NOT attributed to the operator", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519")
    const operatorPem = publicKey.export({ format: "pem", type: "spki" }) as string
    void privateKey
    const operator = makeEd25519VerifierLive({ publicKeyPem: operatorPem })
    const attacker = ed25519Signer()
    const signed = attacker.sign({ payload: EVENTS[1]!, previousHash: null, domain: MANDATE_AUDIT_DOMAIN })
    const { rec } = withGetter(signed, "signerPublicKeyHex", [operator.publicKeyHex, attacker.publicKeyHex])
    const report = verifyAuditChain(asLog(rec), operator, { trustedSignerPublicKeyHex: operator.publicKeyHex })
    expect(report.valid).toBe(false)
    expect(report.reason).toBe("signature-mismatch")
  })

  test("ATTACK: a getter that throws is malformed-record from verifyAuditChain, not an exception", () => {
    const signer = ed25519Signer()
    const [good] = buildChain(signer, EVENTS)
    const rec: Record<string, unknown> = { ...good! }
    Object.defineProperty(rec, "payload", { enumerable: true, get() { throw new Error("boom") } })
    let report: ReturnType<typeof verifyAuditChain> | undefined
    expect(() => { report = check(asLog(rec), signer) }).not.toThrow()
    expect(report).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "malformed-record" })
  })

  test("signer.verify() reads each envelope field exactly once: Ed25519 signer, Ed25519 verifier, in-memory", () => {
    const ed = ed25519Signer()
    const { publicKey, privateKey } = generateKeyPairSync("ed25519")
    void privateKey
    const edVerifier = makeEd25519VerifierLive({ publicKeyPem: publicKey.export({ format: "pem", type: "spki" }) as string })
    const inmem = makeInMemorySignerLive()
    const fields = ["payload", "signature", "signerPublicKeyHex", "signedAt", "previousHash", "domain"] as const
    for (const [label, signer] of [["Ed25519 signer", ed], ["Ed25519 verifier", edVerifier], ["in-memory", inmem]] as const) {
      const signed = (label === "in-memory" ? inmem : ed).sign({ payload: EVENTS[0]!, previousHash: null, domain: MANDATE_AUDIT_DOMAIN })
      for (const field of fields) {
        const { rec, reads } = withGetter(signed, field, [signed[field]])
        expect(signer.verify(rec as unknown as SignedMandateAuditEvent), `${label}: ${field}`).toBe(true)
        // The in-memory signer never needs the record's key: its signature is
        // a function of the other five fields alone. Zero reads there is the
        // honest count, not a regression.
        expect(reads(), `${label} read ${field}`).toBe(label === "in-memory" && field === "signerPublicKeyHex" ? 0 : 1)
      }
    }
  })
})

describe("2026-10-13 verify audit, finding 3 — each signer's verify() pins its own signature shape", () => {
  test("Ed25519 signer and verifier: a signature that is not 128 lowercase hex characters throws, so the chain reports malformed-record", () => {
    const signer = ed25519Signer()
    const { publicKey, privateKey } = generateKeyPairSync("ed25519")
    void privateKey
    const verifier = makeEd25519VerifierLive({ publicKeyPem: publicKey.export({ format: "pem", type: "spki" }) as string })
    const [good] = buildChain(signer, EVENTS)
    for (const bad of [good!.signature.toUpperCase(), good!.signature + "zz", good!.signature + "a", good!.signature.slice(1), " " + good!.signature]) {
      const rec = { ...good!, signature: bad }
      expect(() => signer.verify(rec), bad).toThrow(/128 lowercase hex/)
      expect(() => verifier.verify(rec), bad).toThrow(/128 lowercase hex/)
      expect(check([rec], signer), bad).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "malformed-record" })
    }
    expect(signer.verify(good!)).toBe(true)
  })

  test("in-memory signer: a signature that is not inmem- plus 64 lowercase hex characters throws, so the chain reports malformed-record", () => {
    const signer = makeInMemorySignerLive()
    const [good] = buildChain(signer, EVENTS)
    for (const bad of [good!.signature.toUpperCase(), good!.signature + "zz", "inmem-", good!.signature.slice("inmem-".length)]) {
      const rec = { ...good!, signature: bad }
      expect(() => signer.verify(rec), bad).toThrow(/inmem-/)
      expect(check([rec], signer), bad).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "malformed-record" })
    }
    // A well-formed but WRONG signature is still a mismatch, not malformed.
    const wrong = { ...good!, signature: "inmem-" + "0".repeat(64) }
    expect(signer.verify(wrong)).toBe(false)
    expect(check([wrong], signer).reason).toBe("signature-mismatch")
  })
})

describe("2026-10-13 verify audit, finding 4 — a test marker can never be a real key", () => {
  // verifyAuditChain trusts whatever the caller's signer.verify says. With
  // makeInMemorySignerLive(realSpkiHex) an attacker-built "inmem-" signature
  // verified under the operator's REAL pin: the signer's marker was the pin,
  // so the gate passed, and the in-memory algorithm accepted a signature anyone
  // can compute. The marker is refused at construction if it parses as an
  // SPKI public key.
  test("ATTACK: makeInMemorySignerLive(<real Ed25519 SPKI hex>) throws at construction", () => {
    const real = ed25519Signer().publicKeyHex
    expect(() => makeInMemorySignerLive(real)).toThrow(/public key/)
  })

  test("the default marker and an arbitrary non-key marker still work end to end", () => {
    for (const signer of [makeInMemorySignerLive(), makeInMemorySignerLive("my-test-marker")]) {
      expect(check(buildChain(signer, EVENTS), signer)).toMatchObject({ valid: true, reason: "ok" })
    }
  })
})

describe("2026-10-13 verify audit, finding 8 — key material is validated where it is handed over", () => {
  // Construction accepted a private key and a public key that were not a pair
  // (every record then failed to verify, after the actions had run), keys of
  // the wrong algorithm, and a PRIVATE key where a public one was asked for
  // (publicKeyHexFromPem happily derived the public half, so a verifier wired
  // with the operator's private key kept working and nobody noticed).
  const pemPair = (gen: () => { publicKey: import("node:crypto").KeyObject; privateKey: import("node:crypto").KeyObject }) => {
    const { publicKey, privateKey } = gen()
    return {
      privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }) as string,
      publicKeyPem: publicKey.export({ format: "pem", type: "spki" }) as string,
    }
  }
  const ed = () => pemPair(() => generateKeyPairSync("ed25519"))

  test("a private key and a public key that are not a pair are refused at construction", () => {
    const a = ed(), b = ed()
    expect(() => makeEd25519SignerLive({ privateKeyPem: a.privateKeyPem, publicKeyPem: b.publicKeyPem })).toThrow(/pair/)
  })

  test("ed448, x25519, P-256 and RSA keys are refused by both factories", () => {
    const foreign: ReadonlyArray<readonly [string, () => { publicKey: import("node:crypto").KeyObject; privateKey: import("node:crypto").KeyObject }]> = [
      ["ed448", () => generateKeyPairSync("ed448")],
      ["x25519", () => generateKeyPairSync("x25519")],
      ["P-256", () => generateKeyPairSync("ec", { namedCurve: "P-256" })],
      ["rsa", () => generateKeyPairSync("rsa", { modulusLength: 2048 })],
    ]
    for (const [label, gen] of foreign) {
      const cfg = pemPair(gen)
      expect(() => makeEd25519SignerLive(cfg), label).toThrow(/ed25519/)
      expect(() => makeEd25519VerifierLive({ publicKeyPem: cfg.publicKeyPem }), label).toThrow(/ed25519/)
    }
  })

  test("a PRIVATE key PEM where a public key is expected is refused by publicKeyHexFromPem and the verifier factory", () => {
    const k = ed()
    expect(() => publicKeyHexFromPem(k.privateKeyPem)).toThrow(/PRIVATE/)
    expect(() => makeEd25519VerifierLive({ publicKeyPem: k.privateKeyPem })).toThrow(/PRIVATE/)
  })

  test("CONTROL: a matched Ed25519 pair constructs, signs, verifies, and pins through publicKeyHexFromPem", () => {
    const k = ed()
    const signer = makeEd25519SignerLive(k)
    const verifier = makeEd25519VerifierLive({ publicKeyPem: k.publicKeyPem })
    const chain = buildChain(signer, EVENTS)
    expect(verifyAuditChain(chain, verifier, { trustedSignerPublicKeyHex: publicKeyHexFromPem(k.publicKeyPem) })).toMatchObject({ valid: true })
  })
})
