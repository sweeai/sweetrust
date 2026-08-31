/**
 * @swee/trust — the whole rail, in import order.
 *
 *   SweeMandate signs  ->  SweeGate enforces  ->  SweeVerify proves
 *
 * This is the convenience entry. Each primitive is also reachable on its own
 * subpath, and importing one does NOT pull the others into your bundle:
 *
 *   import { issueOrgMandate } from "@swee/trust/mandate"
 *   import { Sourced, makeSink } from "@swee/trust/gate"
 *   import { verifySignedChain } from "@swee/trust/verify"
 *
 * Decoupling stayed sacred through the 2026-07-30 merge: the three used to be
 * three npm packages, and every one of them still stands alone. What changed is
 * that you install one thing instead of assembling three.
 *
 * WHY VERIFY IS LISTED BY HAND while mandate and gate are star-exported:
 * `verify` deliberately re-exports `canonicalJSON` and `sha256Hex` from
 * `mandate`, so that there is exactly ONE canonicalization across the rail.
 * Two `export *` clauses offering the same name make it AMBIGUOUS, and ESM
 * resolves ambiguity by silently omitting the name — no error, no warning, the
 * symbol simply stops existing at the root. Naming verify's surface explicitly
 * is what keeps that from happening by accident. `test/index-barrel.test.ts`
 * enforces it; a comment alone would be a rule the computer never checks.
 */

// ── SweeMandate — authority ───────────────────────────────────────────────
export * from "./mandate/index.ts"

// ── SweeGate — enforcement ────────────────────────────────────────────────
export * from "./gate/index.ts"

// ── SweeVerify — evidence ─────────────────────────────────────────────────
// canonicalJSON and sha256Hex are omitted here ON PURPOSE — they are mandate's,
// and the star export above already provides the identical binding.
export {
  generateSigningKeypair,
  publicKeyHexFromPem,
  makeEd25519ReceiptSigner,
  SignedReceiptLog,
  parseJSONL,
  verifySignedChain,
  RECEIPT_MEMO_PREFIX,
  ANCHOR_MEMO_PREFIX,
  receiptMemo,
  anchorMemo,
  parseAnchorMemo,
  type SignedReceipt,
  type ReceiptSigner,
  type VerifyFailure,
  type VerifyReport,
} from "./verify/index.ts"
