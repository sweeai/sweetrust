/**
 * The root barrel must not silently lose a symbol.
 *
 * ESM's rule for `export *`: when two star-exports offer the same name and the
 * names do NOT resolve to the same binding, the name is excluded from the
 * re-exporting module. Not an error. Not a warning. The symbol just is not
 * there, and the first anyone hears about it is a consumer's import coming back
 * `undefined`.
 *
 * `sweetrust/verify` re-exports `canonicalJSON` and `sha256Hex` from
 * `sweetrust/mandate` on purpose — one canonicalization across the rail. That
 * makes this failure mode LIVE in this package rather than hypothetical, and it
 * is why `src/index.ts` names verify's surface by hand.
 *
 * This suite is the enforcement half of that decision. The comment in
 * src/index.ts explains the rule; this file is what actually checks it.
 */
import { describe, expect, it } from "vitest"

import * as root from "../src/index.ts"
import * as gate from "../src/gate/index.ts"
import * as mandate from "../src/mandate/index.ts"
import * as verify from "../src/verify/index.ts"

// Re-exported from mandate by verify BY DESIGN. Present at the root exactly
// once, sourced from mandate. If this list grows, the growth was deliberate.
// `signedPreimage` joined on 2026-10-13: a bring-your-own ReceiptSigner must
// sign the exact bytes verifySignedChain checks, and that definition is
// mandate's, so verify re-exports it rather than restating it.
const INTENTIONAL_DUPLICATES = ["canonicalJSON", "sha256Hex", "signedPreimage"] as const

const runtimeNames = (m: object) => Object.keys(m).sort()

describe("root barrel", () => {
  it("re-exports every runtime symbol from mandate", () => {
    const missing = runtimeNames(mandate).filter((n) => !(n in root))
    expect(missing).toEqual([])
  })

  it("re-exports every runtime symbol from gate", () => {
    const missing = runtimeNames(gate).filter((n) => !(n in root))
    expect(missing).toEqual([])
  })

  it("re-exports every runtime symbol from verify", () => {
    const missing = runtimeNames(verify).filter((n) => !(n in root))
    expect(missing).toEqual([])
  })

  it("keeps the shared canonicalization identical across subpaths", () => {
    // Not merely present under the same name — the SAME function. If verify
    // ever grew its own copy, the rail would have two canonicalizations and
    // signatures produced on one side would fail on the other. That is the
    // actual bug this guards; name-equality alone would not catch it.
    for (const name of INTENTIONAL_DUPLICATES) {
      expect(verify[name as keyof typeof verify]).toBe(
        mandate[name as keyof typeof mandate],
      )
      expect(root[name as keyof typeof root]).toBe(
        mandate[name as keyof typeof mandate],
      )
    }
  })

  it("exposes what a bring-your-own ReceiptSigner needs: the receipt domain tag and the preimage (2026-10-13 verify audit)", () => {
    // ReceiptSigner is public, so a consumer can supply one, but until this
    // test it could not import the domain tag its sign() must emit nor the
    // preimage definition its signature must cover, from the subpath or the root.
    expect(typeof verify.RECEIPT_DOMAIN).toBe("string")
    expect(root.RECEIPT_DOMAIN).toBe(verify.RECEIPT_DOMAIN)
    expect(verify.signedPreimage).toBe(mandate.signedPreimage)
    expect(root.signedPreimage).toBe(mandate.signedPreimage)
  })

  it("has no undefined export — the signature of a silent star collision", () => {
    const dropped = Object.keys(root).filter(
      (n) => root[n as keyof typeof root] === undefined,
    )
    expect(dropped).toEqual([])
  })
})
