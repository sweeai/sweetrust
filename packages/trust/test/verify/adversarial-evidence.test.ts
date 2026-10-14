// Adversarial pass on the evidence layer.
// ============================================================================
// verify already survives the obvious attacks — DAN-641 closed envelope signing
// and domain separation, DAN-643 closed the receipt-memo-as-seal hole, and
// trustedSignerPublicKeyHex is required rather than optional. adversarial-seam
// covers those. So this file goes after what is left:
//
//   · the verifier as a piece of software handed hostile INPUT, not just a
//     hostile chain — an auditor's tool that throws instead of returning a
//     verdict has failed at its one job
//   · vacuous success — the empty-input case, which is exactly the shape of
//     bug the gate pass found in minTier()
//   · state desync between the two chains SignedReceiptLog maintains
// ============================================================================

import { describe, it, expect } from "vitest"
import { Sourced, makeSink, type Receipt } from "../../src/gate/index.ts"
import {
  SignedReceiptLog,
  makeEd25519ReceiptSigner,
  generateSigningKeypair,
  publicKeyHexFromPem,
  verifySignedChain,
  parseJSONL,
  type SignedReceipt,
  type ReceiptSigner,
  type VerifyReport,
} from "../../src/verify/verify.js"
import { makeEd25519SignerLive, verifyAuditChain } from "../../src/mandate/index.ts"
import type { SignedMandateAuditEvent } from "../../src/mandate/types.ts"

const keys = generateSigningKeypair()
const signer = makeEd25519ReceiptSigner(keys)
const trusted = publicKeyHexFromPem(keys.publicKeyPem)

const logWith = (n: number) => {
  const log = new SignedReceiptLog(signer)
  for (let i = 0; i < n; i++) {
    log.append({ at: `2026-07-25T00:00:0${i}Z`, sink: "pay", decision: "executed", args: {} })
  }
  return log
}

describe("V1 — the signed log hands out its live internal array", () => {
  // gate's ReceiptLog.all() had exactly this defect and it was fixed. The
  // SUBCLASS repeats it one level up, on the array that holds the signatures —
  // which is the array that actually becomes the auditor's artifact.

  it("ATTACK: signed() must not expose the array exportJSONL() reads from", () => {
    const log = logWith(3)
    const before = log.signed().length
    ;(log.signed() as SignedReceipt[]).length = 1

    expect(log.signed().length).toBe(before)
    expect(log.exportJSONL().trim().split("\n")).toHaveLength(before)
  })
})

describe("V2 — an empty chain reports valid", () => {
  // Same shape as the gate pass's minTier() finding: the identity element of a
  // fold is the MAXIMUM claim. Handing an auditor an empty file and receiving
  // "valid: true" is vacuous truth doing real-world work.

  it("ATTACK: verifying zero records should not come back a clean bill of health", () => {
    const report = verifySignedChain([], { trustedSignerPublicKeyHex: trusted })
    expect(report.valid).toBe(false)
  })

  it("an empty chain WITH a seal already fails — the anchor path is fine", () => {
    const report = verifySignedChain([], {
      trustedSignerPublicKeyHex: trusted,
      anchor: { kind: "anchor", head: "deadbeef" },
    })
    expect(report.valid).toBe(false)
  })
})

describe("V3 — the verifier throws instead of returning a verdict", () => {
  // verifySignedChain is the function an auditor points at a file from an
  // UNTRUSTED party. Every malformed input must produce a VerifyReport saying
  // invalid. An exception is a crash in someone else's tool, and — worse — a
  // caller with a try/catch around it cannot tell "malformed" from "bug".

  it("ATTACK: a non-key hex string in signerPublicKeyHex must not throw", () => {
    const good = logWith(1).signed()[0]!
    // Syntactically valid hex, structurally not an SPKI key.
    const forged = { ...good, signerPublicKeyHex: "abcdef0123456789" }

    expect(() =>
      verifySignedChain([forged], { trustedSignerPublicKeyHex: "abcdef0123456789" }),
    ).not.toThrow()
  })

  it("ATTACK: non-hex characters in signerPublicKeyHex must not throw", () => {
    const good = logWith(1).signed()[0]!
    const forged = { ...good, signerPublicKeyHex: "zzzz-not-hex-at-all" }

    expect(() =>
      verifySignedChain([forged], { trustedSignerPublicKeyHex: "zzzz-not-hex-at-all" }),
    ).not.toThrow()
  })

  it("ATTACK: a non-hex signature must not throw", () => {
    const good = logWith(1).signed()[0]!
    const forged = { ...good, signature: "not-hex" }

    expect(() => verifySignedChain([forged], { trustedSignerPublicKeyHex: trusted })).not.toThrow()
  })

  it("ATTACK: a payload missing its fields must not throw", () => {
    const good = logWith(1).signed()[0]!
    const forged = { ...good, payload: { seq: 0 } as unknown as Receipt }

    expect(() => verifySignedChain([forged], { trustedSignerPublicKeyHex: trusted })).not.toThrow()
  })
})

describe("V4 — a signing failure desyncs the two chains permanently", () => {
  // SignedReceiptLog.append() calls super.append() FIRST (which commits to the
  // interior chain) and signs SECOND. If signing throws, the interior chain has
  // grown and the signed chain has not. Every later record then builds its
  // wrapper link on a stale predecessor, and exportJSONL() silently omits a
  // receipt that the kernel chain says exists.

  const flakySigner = (failOn: number): ReceiptSigner => {
    let n = 0
    return {
      publicKeyHex: signer.publicKeyHex,
      sign: (receipt, previousHash) => {
        if (n++ === failOn) throw new Error("HSM unavailable")
        return signer.sign(receipt, previousHash)
      },
    }
  }

  it("ATTACK: after a failed signature the two chains must not silently disagree", () => {
    const log = new SignedReceiptLog(flakySigner(1))
    log.append({ at: "t0", sink: "pay", decision: "executed", args: {} })
    expect(() => log.append({ at: "t1", sink: "pay", decision: "refused", args: {} })).toThrow()
    log.append({ at: "t2", sink: "pay", decision: "executed", args: {} })

    // The interior chain believes there are three events; the evidence artifact
    // carries two, and nothing reports the gap.
    expect(log.signed().length).toBe(log.all().length)
  })
})

describe("V5 — an action that throws leaves no receipt at all", () => {
  // This one is in sweetrust/gate's makeSink but only shows up here, because here
  // is where the receipt is the DELIVERABLE. makeSink does:
  //     const result = spec.execute(args)   // the irreversible thing happens
  //     const receipt = spec.log.append(…)  // the evidence is written
  // If execute() throws — network died after the money moved, API returned 500
  // on a request that landed — the action was attempted and the log is silent.
  //
  // "Verifiable evidence of what the agent did" cannot have a hole shaped like
  // "everything that went wrong".

  it("ATTACK: a throwing sink operation must still land on the receipt log", () => {
    const log = new SignedReceiptLog(signer)
    const pay = makeSink<{ amount: Sourced<number> }, string>({
      name: "pay",
      requires: { amount: "verified" },
      mode: "enforce",
      log,
      execute: () => {
        throw new Error("payment gateway 500 — may or may not have settled")
      },
    })

    expect(() => pay({ amount: Sourced.fromAuthority(500, "treasury") })).toThrow()

    // The attempt must be discoverable by an auditor.
    expect(log.all().length).toBeGreaterThan(0)
  })
})

describe("V6 — parseJSONL rejects hostile input without crashing the caller", () => {
  it("malformed JSON reports the line, and does not leak a raw SyntaxError", () => {
    const good = logWith(1).exportJSONL()
    expect(() => parseJSONL(good + "{not json\n")).toThrow(/line 2/)
  })
})

describe("V7 — every input SHAPE comes back as a verdict (DAN-1159 item 5)", () => {
  // V3 made a malformed key or signature ENCODING a verdict. It never covered
  // the shapes around them: a chain that is not an array, a record that is not
  // an object, a key that is not a string, an anchor head that is not a string.
  // Probed on the built dist/ before this block existed: every shape below
  // threw, except the plain object, which verifySignedChain certified VALID.

  /**
   * Run the verifier and fail the test with the thrown message instead of
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
  const MALFORMED_CHAIN = { valid: false, firstInvalidIndex: null, reason: "malformed-record", anchoredThrough: null }

  it("ATTACK: a plain object is not a chain, and it used to verify as one", () => {
    // `{}.length` is undefined: `=== 0` misses the empty-chain guard, `i <
    // undefined` never enters the loop, and control falls through to valid:true.
    // A caller that hands over the parsed wrapper instead of its array gets a
    // clean bill of health for evidence nobody checked.
    expect(verdict({})).toMatchObject(MALFORMED_CHAIN)
    expect(verdict({ records: logWith(2).signed() })).toMatchObject(MALFORMED_CHAIN)
  })

  it("ATTACK: null or undefined in place of the chain is malformed, not a crash", () => {
    expect(verdict(null)).toMatchObject(MALFORMED_CHAIN)
    expect(verdict(undefined)).toMatchObject(MALFORMED_CHAIN)
  })

  it("ATTACK: a null or undefined record is malformed at its index, not a crash", () => {
    const [good] = logWith(1).signed()
    expect(verdict([null])).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "malformed-record" })
    expect(verdict([undefined])).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "malformed-record" })
    expect(verdict([good, null])).toMatchObject({ valid: false, firstInvalidIndex: 1, reason: "malformed-record" })
  })

  it("ATTACK: a signer key that is missing or not a string is untrusted, and the detail does not crash on it", () => {
    // The pin comparison already rejects these. It was the `.slice` in the
    // detail message that threw, so the verdict was lost inside its own reason.
    const [good] = logWith(1).signed()
    const keyless: Record<string, unknown> = { ...good! }
    delete keyless["signerPublicKeyHex"]
    for (const record of [keyless, { ...good!, signerPublicKeyHex: null }, { ...good!, signerPublicKeyHex: 123 }]) {
      const report = verdict([record])
      expect(report).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "untrusted-signer" })
      expect(report.detail).toContain("record 0")
    }
  })

  it("a pin that is missing or not a string verifies NOTHING: fail-closed, as a verdict", () => {
    const chain = logWith(1).signed()
    for (const opts of [{ trustedSignerPublicKeyHex: undefined }, { trustedSignerPublicKeyHex: 123 }, undefined]) {
      expect(verdict(chain, opts)).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "untrusted-signer" })
    }
  })

  it("ATTACK: a genuine record carrying a field canonicalJSON cannot encode is malformed at THAT record", () => {
    // The field sits outside the signed preimage, so the signature still
    // verifies and only the wrapper link hash meets it. verifyAuditChain learned
    // this in DAN-1159 item 3; this is the same lesson, carried across.
    const chain = logWith(2).signed()
    expect(verdict([{ ...chain[0]!, extra: 1n }, chain[1]!])).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "malformed-record" })
    expect(verdict([chain[0]!, { ...chain[1]!, extra: 1n }])).toMatchObject({ valid: false, firstInvalidIndex: 1, reason: "malformed-record" })
  })

  it("a validly SIGNED record whose payload is not a receipt is malformed, not a crash", () => {
    // Only the key holder can produce this (a buggy signer, not a forger). The
    // auditor still gets a verdict instead of a TypeError from receiptBody.
    const bogus = signer.sign(null as unknown as Receipt, null)
    expect(verdict([bogus])).toMatchObject({ valid: false, firstInvalidIndex: 0, reason: "malformed-record" })
  })

  it("ATTACK: an anchor whose head is not a string fails the ANCHOR, not the verifier", () => {
    // An anchor that is present but unusable proves nothing, so the verdict is
    // anchor-not-found: the same fail-closed reading the `kind` dispatch gives
    // an unknown kind. `null` is present, not absent.
    const chain = logWith(2).signed()
    for (const anchor of [{ kind: "anchor", head: undefined }, { kind: "anchor", head: 123 }, { kind: "receipt", head: 123 }, null]) {
      expect(verdict(chain, { trustedSignerPublicKeyHex: trusted, anchor })).toMatchObject({
        valid: false, reason: "anchor-not-found", anchoredThrough: null,
      })
    }
  })

  it("CONTROL: an honest sealed chain still verifies through the same wrapper", () => {
    const chain = logWith(2).signed()
    const head = chain.at(-1)!.payload.hash
    expect(verdict(chain, { trustedSignerPublicKeyHex: trusted, anchor: { kind: "anchor", head } })).toMatchObject({
      valid: true, reason: "ok", anchoredThrough: 1,
    })
  })
})

describe("V7 parity — both verifiers give the SAME verdict for the same hostile shape", () => {
  // The stop-ship audit's root pattern: a fix made in one verifier never
  // reached its sibling. V2 and V3 hardened verifySignedChain in July and
  // verifyAuditChain waited until DAN-1159 item 3; item 3's link-hash guard then
  // waited for item 5. This is the tripwire: harden one, and the other goes red.
  const mandateSigner = makeEd25519SignerLive(keys)
  const outcome = (fn: () => { valid: boolean; reason: string; firstInvalidIndex: number | null }) => {
    try {
      const { valid, reason, firstInvalidIndex } = fn()
      return { valid, reason, firstInvalidIndex }
    } catch (err) {
      return { threw: err instanceof Error ? err.message : String(err) }
    }
  }
  const shapes: ReadonlyArray<readonly [string, unknown]> = [
    ["{}", {}], ["null", null], ["undefined", undefined],
    ["[null]", [null]], ["[undefined]", [undefined]], ["[42]", [42]], ['["revoke"]', ["revoke"]],
  ]

  it.each(shapes)("%s", (_label, shape) => {
    const receipt = outcome(() => verifySignedChain(shape as SignedReceipt[], { trustedSignerPublicKeyHex: trusted }))
    const audit = outcome(() => verifyAuditChain(shape as SignedMandateAuditEvent[], mandateSigner, { trustedSignerPublicKeyHex: trusted }))
    expect(receipt).toMatchObject({ valid: false })
    expect(receipt).toEqual(audit)
  })
})
