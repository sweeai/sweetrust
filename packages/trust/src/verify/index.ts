/**
 * @sweetrust/verify — public API surface
 *
 * The evidence kernel of SWEE AI's vertical trust rails — the SweeVerify
 * seed. Ed25519-signed receipt chains (signed THROUGH @sweetrust/mandate's
 * signer), JSONL export, verifier-only re-checking with key pinning, and the
 * Sui anchor-memo convention that makes tail truncation detectable.
 *
 * "SweeMandate signs, the firewall enforces, SweeVerify proves."
 */

export {
  // one canonicalization across the rail (re-exported from @sweetrust/mandate)
  canonicalJSON,
  sha256Hex,
  // signing
  generateSigningKeypair,
  publicKeyHexFromPem,
  makeEd25519ReceiptSigner,
  SignedReceiptLog,
  // export / import
  parseJSONL,
  // third-party verification
  verifySignedChain,
  // the Sui anchor-memo convention
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
