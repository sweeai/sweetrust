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
} from "../../src/verify/verify.js"

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
  // This one is in @sweetrust/gate's makeSink but only shows up here, because here
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
