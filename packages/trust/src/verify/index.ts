/**
 * sweetrust/verify — public API surface
 *
 * The evidence kernel of SWEE AI's vertical trust rails — the SweeVerify
 * seed. Ed25519-signed receipt chains (signed THROUGH sweetrust/mandate's
 * signer), JSONL export, verifier-only re-checking with key pinning, and the
 * anchor-memo convention that makes tail truncation detectable.
 *
 * "SweeMandate signs, the firewall enforces, SweeVerify proves."
 */

export {
  // one canonicalization, and one signed preimage, across the rail
  // (re-exported from sweetrust/mandate)
  canonicalJSON,
  sha256Hex,
  signedPreimage,
  // signing. RECEIPT_DOMAIN is what a bring-your-own ReceiptSigner must fold
  // into the preimage; it was unreachable from this entry until 2026-10-13.
  RECEIPT_DOMAIN,
  generateSigningKeypair,
  publicKeyHexFromPem,
  makeEd25519ReceiptSigner,
  SignedReceiptLog,
  // export / import
  parseJSONL,
  // third-party verification
  verifySignedChain,
  // the anchor-memo convention
  RECEIPT_MEMO_PREFIX,
  ANCHOR_MEMO_PREFIX,
  receiptMemo,
  anchorMemo,
  parseAnchorMemo,
  type SignedReceipt,
  type ReceiptSigner,
  type VerifyFailure,
  type VerifyReport,
} from "./verify.ts"
