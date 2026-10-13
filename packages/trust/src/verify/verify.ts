// @sweetrust/verify — SweeVerify's kernel (signed receipts + third-party verification)
// ============================================================================
// @sweetrust/gate ends where the receipt is hashed. This package is the next wall:
//   1. SIGN    — every receipt is Ed25519-signed at append time BY
//                @sweetrust/mandate's signer (the company sentence is literal:
//                SweeMandate signs, the firewall enforces, SweeVerify proves).
//   2. EXPORT  — the signed chain serializes to JSONL: the artifact you hand
//                an auditor, an insurer, or a court.
//   3. VERIFY  — a verifier holding ONLY the public key re-checks every
//                signature, every hash link, and (optionally) an on-chain
//                anchor. The signer's machine can be fully compromised after
//                the fact; the evidence still stands or falls on its own.
//
// Honest limits (stated, not hidden):
//   - TAIL TRUNCATION is invisible to the local chain: deleting the last K
//     receipts leaves a perfectly valid shorter chain. Only the on-chain
//     anchor (the chain head carried in a Sui PaymentReceipt memo) catches
//     it. This is WHY the anchor exists — the demo proves it, not just says it.
//   - The signing key lives with the agent runtime; a compromised host can
//     sign lies going FORWARD. What it cannot do is rewrite the PAST behind
//     an anchor, or forge records under a key it doesn't hold.
//
// Wraps @sweetrust/gate, never forks it (SignedReceiptLog extends ReceiptLog).
// Chain shape: TWO chains, both signed —
//   · interior (kernel) chain: Receipt.prevHash/hash, computed by @sweetrust/gate
//   · wrapper chain: Signed.previousHash = sha256(canonicalJSON(previous
//     signed record)) — @sweetrust/mandate audit-chain semantics (spec I8), so
//     mandate's own verifyAuditChain tooling can walk a receipt log too.
// @sweetrust/gate stays dependency-free; THIS package is the integration layer
// (peers: @sweetrust/gate for the kernel, @sweetrust/mandate for the
// signing discipline — one canonicalization across the whole rail).
// ============================================================================

import { createPublicKey, generateKeyPairSync, verify as edVerify } from "node:crypto"
import {
  canonicalJSON,
  makeEd25519SignerLive,
  sha256Hex,
  signedPreimage,
  type Signed,
} from "../mandate/index.ts"
import { type Receipt, ReceiptLog, receiptBody } from "../gate/index.ts"

// Re-exported so consumers of the receipt rail share ONE canonicalization.
export { canonicalJSON, sha256Hex }

/**
 * RECEIPT_DOMAIN — domain-separation tag folded into the signed preimage of
 * every SweeVerify receipt (the mirror of mandate's MANDATE_AUDIT_DOMAIN).
 * Because the tag is inside the signature, a receipt cannot be replayed as a
 * mandate audit event (or vice-versa) even under a shared operator key. (DAN-641.)
 */
export const RECEIPT_DOMAIN = "swee.receipt.v1"

// ── Signed receipts ──────────────────────────────────────────────────────────

/**
 * A Receipt wrapped with authorship — @sweetrust/mandate's Signed<P> record
 * (payload-generic since mandate v1.1). The public key rides on every record
 * (spec I10) so a verifier-only consumer needs no key distribution channel.
 */
export type SignedReceipt = Signed<Receipt>

export interface ReceiptSigner {
  readonly publicKeyHex: string
  sign(receipt: Receipt, previousHash: string | null): SignedReceipt
}

/** Ephemeral keypair for demos/tests. Production: operator-held PEM (Keychain). */
export function generateSigningKeypair(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519")
  return {
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
    publicKeyPem: publicKey.export({ format: "pem", type: "spki" }).toString(),
  }
}

// Moved to `mandate/signer.ts` (DAN-905) so `sweetrust/mandate` can satisfy its
// own `verifyAuditChain`, whose `trustedSignerPublicKeyHex` is required. Still
// exported here — this is a published entry point and dropping the name would
// break consumers for no gain.
export { publicKeyHexFromPem } from "../mandate/index.ts"

/**
 * The receipt signer IS @sweetrust/mandate's Ed25519 signer (construction +
 * sign are pure synchronous operations).
 */
export function makeEd25519ReceiptSigner(config: {
  privateKeyPem: string
  publicKeyPem: string
}): ReceiptSigner {
  const service = makeEd25519SignerLive(config)
  return {
    publicKeyHex: service.publicKeyHex,
    sign: (receipt, previousHash) => service.sign({ payload: receipt, previousHash, domain: RECEIPT_DOMAIN }),
  }
}

/**
 * ReceiptLog that signs every receipt as it lands. Drop-in for makeSink's
 * `log:` — the kernel's interior hash chain is computed by super.append();
 * this adds authorship + the mandate-semantic wrapper chain. Wrap, never fork.
 */
export class SignedReceiptLog extends ReceiptLog {
  private signedEvents: SignedReceipt[] = []
  // explicit field, not a constructor parameter property: kernel source must
  // stay erasable-syntax-only so Node strip-types consumers (demos) can run it
  private readonly signer: ReceiptSigner

  constructor(signer: ReceiptSigner) {
    super()
    this.signer = signer
  }

  /**
   * Sign FIRST, commit second — the two chains move together or not at all.
   *
   * This used to call `super.append()` and sign afterwards. Signing is fallible
   * (an HSM goes away, a key is revoked mid-run), and a throw left the interior
   * chain one record ahead of the signed chain — permanently, since every later
   * wrapper link then hung off a stale predecessor, and `exportJSONL()` handed
   * an auditor an artifact silently short a receipt. Found by the 2026-07-25
   * adversarial pass; `nextReceipt`/`commit` exist in @sweetrust/gate to make this
   * orderable.
   */
  override append(entry: Parameters<ReceiptLog["append"]>[0]): Receipt {
    const receipt = this.nextReceipt(entry)
    const prev = this.signedEvents.at(-1)
    // Wrapper chain per @sweetrust/mandate spec I8: hash of the previous SIGNED
    // record (signature included), null for the first.
    const previousHash = prev ? sha256Hex(canonicalJSON(prev)) : null
    const signedRecord = this.signer.sign(receipt, previousHash) // may throw — nothing committed yet
    this.commit(receipt)
    this.signedEvents.push(signedRecord)
    return receipt
  }

  /** A copy. Handing out the live array let any caller truncate the artifact. */
  signed(): ReadonlyArray<SignedReceipt> {
    return [...this.signedEvents]
  }

  /** Current interior chain head — what an on-chain anchor commits to. */
  head(): string {
    return this.all().at(-1)?.hash ?? "genesis"
  }

  /** The auditor artifact: one signed receipt per line. */
  exportJSONL(): string {
    return this.signedEvents.map((r) => JSON.stringify(r)).join("\n") + (this.signedEvents.length ? "\n" : "")
  }
}

export function parseJSONL(text: string): SignedReceipt[] {
  return text
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line, i) => {
      // Say WHICH line. A bare SyntaxError from JSON.parse tells an auditor
      // holding a 40,000-line artifact nothing they can act on.
      let parsed: unknown
      try {
        parsed = JSON.parse(line)
      } catch (err) {
        throw new Error(`line ${i + 1}: not valid JSON — ${err instanceof Error ? err.message : String(err)}`)
      }
      const r = parsed as SignedReceipt
      if (
        typeof r !== "object" || r === null ||
        typeof r.signature !== "string" || typeof r.signerPublicKeyHex !== "string" ||
        typeof r.payload !== "object" || r.payload === null || typeof r.payload.hash !== "string"
      ) {
        throw new Error(`line ${i + 1}: not a SignedReceipt`)
      }
      return r
    })
}

// ── Third-party verification ─────────────────────────────────────────────────

export type VerifyFailure =
  | "missing-signature"
  | "untrusted-signer"
  | "signature-mismatch"
  | "domain-mismatch"
  | "hash-mismatch"
  | "hash-chain-broken"
  | "anchor-not-found"
  /** No records at all. Vacuous truth is not a clean bill of health — see below. */
  | "empty-chain"
  /** The record is not well-formed enough to be checked (bad key/signature encoding). */
  | "malformed-record"

export interface VerifyReport {
  readonly valid: boolean
  readonly firstInvalidIndex: number | null
  readonly reason: VerifyFailure | "ok"
  /**
   * Highest seq the anchor PROVES (null when no `anchor` was supplied). Under a
   * `kind:"anchor"` seal this is the last record's seq (full chain); under a
   * `kind:"receipt"` memo it is that receipt's seq — anything beyond it is
   * unproven and may have been truncated.
   */
  readonly anchoredThrough: number | null
  readonly detail?: string
}

// How a verdict's `detail` names a value it could not use, without ever
// dereferencing it. The detail used to `.slice` the signer key and the anchor
// head directly, so a non-string threw from inside the very message that was
// reporting it, and the verdict was lost (DAN-1159 item 5).
const typeName = (v: unknown): string => (v === null ? "null" : typeof v)
const preview = (v: unknown): string => (typeof v === "string" ? `${v.slice(0, 16)}…` : `<${typeName(v)}>`)

// A signed record is EXACTLY these six own keys. The signature covers four of
// them and the next record's link hash covers all six, so a seventh key sits
// under neither: on the last record nothing ever read it, and a store that
// re-verifies on read then signed the next link over it, making the injected
// text permanent (the 2026-10-13 verify audit). verifyAuditChain keeps the same
// list; the parity test in test/verify/adversarial-envelope.test.ts holds the
// two verdicts together.
const ENVELOPE_KEYS: ReadonlyArray<string> = ["payload", "signature", "signerPublicKeyHex", "signedAt", "previousHash", "domain"]
// The exact text of an Ed25519 signature as mandate's signer emits it. The
// Ed25519 factories in mandate/signer.ts hold the same literal; it is a fact
// about the algorithm (64 bytes), not a convention that can drift.
const ED25519_SIGNATURE_HEX = /^[0-9a-f]{128}$/
// The whole of verifySignedChain's options bag. Grows only with the signature.
const VERIFY_OPTS_KEYS: ReadonlyArray<string> = ["trustedSignerPublicKeyHex", "anchor"]
const envelopeKeyProblem = (keys: ReadonlyArray<string>): string | null => {
  const stray = keys.filter((k) => !ENVELOPE_KEYS.includes(k))
  if (stray.length > 0) return `carries a key outside the signed envelope: ${stray.map((k) => JSON.stringify(k)).join(", ")}`
  const missing = ENVELOPE_KEYS.filter((k) => !keys.includes(k))
  if (missing.length > 0) return `is missing envelope key ${missing.map((k) => JSON.stringify(k)).join(", ")}`
  return null
}

/**
 * Re-verify an exported chain holding ONLY public material.
 *
 * `trustedSignerPublicKeyHex` is REQUIRED, not optional: verifying a record
 * against the key it carries proves internal consistency, not authorship —
 * an attacker who re-signs a forged record with their own key passes that
 * check. Pinning the expected key closes the hole (@sweetrust/mandate documents
 * this same gap as caller responsibility; here it is structural).
 *
 * `anchor`, when supplied (parsed from the on-chain PaymentReceipt memo via
 * `parseAnchorMemo`), is the ONLY check that catches tail truncation, which a
 * locally-consistent chain cannot reveal. Its `kind` is load-bearing (DAN-643):
 *   - `kind: "anchor"` — a SEAL over the whole chain (`swee:anchor:`). The head
 *     must EQUAL the last record's hash. This is what actually catches tail
 *     truncation: a shorter chain has a different last record.
 *   - `kind: "receipt"` — a per-decision head-as-of-settlement (`swee:rcpt:`).
 *     It only proves the chain THROUGH that record's seq (membership); anything
 *     after it can still be truncated undetectably. `anchoredThrough` reports how
 *     far it proves. NEVER treat a receipt memo as full-chain proof — that was the
 *     old hole (DAN-643): every settlement writes a `swee:rcpt:` memo, so an attacker
 *     could truncate the tail and point an auditor at any earlier receipt memo,
 *     which still "appeared in" the truncated chain under the old membership check.
 *
 * The `kind` dispatch fails CLOSED: only an explicit `"receipt"` gets the weaker
 * membership check, so an unknown/absent kind arriving from an untyped JS
 * consumer is checked as a seal rather than silently downgraded.
 *
 * Every input SHAPE returns a verdict, never a throw: a chain that is not an
 * array, a record that is not an object, a key or anchor head that is not a
 * string (DAN-1159 item 5). `verifyAuditChain` makes the same promise, and a
 * parity test holds the two to the same verdict for the same hostile shape.
 */
export function verifySignedChain(
  records: ReadonlyArray<SignedReceipt>,
  opts: {
    trustedSignerPublicKeyHex: string
    anchor?: { kind: "anchor" | "receipt"; head: string }
  },
): VerifyReport {
  // The options bag is exactly {trustedSignerPublicKeyHex, anchor?}. An
  // unknown key used to be ignored: a JS caller still passing the retired
  // `anchoredHead` got no anchor check and no signal, so a truncated chain
  // verified (the 2026-10-13 verify audit). A caller error is a verdict that
  // names the key, before the chain is read at all.
  const bag: unknown = opts
  if (typeof bag === "object" && bag !== null) {
    const unknownKeys = Object.keys(bag).filter((k) => !VERIFY_OPTS_KEYS.includes(k))
    if (unknownKeys.length > 0) {
      return {
        valid: false, firstInvalidIndex: null, reason: "malformed-record", anchoredThrough: null,
        detail: `unknown option ${unknownKeys.map((k) => JSON.stringify(k)).join(", ")}: verifySignedChain takes trustedSignerPublicKeyHex and anchor`,
      }
    }
  }

  // The container is checked before anything is read from it. A plain object
  // used to VERIFY: `{}.length` is undefined, so `=== 0` missed the empty-chain
  // guard below, `i < undefined` never entered the loop, and control fell
  // through to valid:true for evidence nobody checked (DAN-1159 item 5).
  // `input` is `unknown` so the narrowing cannot leak `any[]` into `records`.
  const input: unknown = records
  if (!Array.isArray(input)) {
    return {
      valid: false, firstInvalidIndex: null, reason: "malformed-record", anchoredThrough: null,
      detail: `expected an array of signed records (got ${typeName(input)})`,
    }
  }

  // An empty chain used to fold to `valid: true` — the identity element of the
  // loop is the strongest possible claim (adversarial pass V2, 2026-07-25; the
  // same shape as @sweetrust/gate's minTier() returning "verified" over an empty
  // list). An auditor handed an empty file and told "valid" has been told
  // something false in every sense that matters. Nothing to check is not a pass.
  if (records.length === 0) {
    return {
      valid: false, firstInvalidIndex: null, reason: "empty-chain", anchoredThrough: null,
      detail: "no records were presented — there is nothing here to verify, which is not the same as nothing being wrong",
    }
  }

  // The pin is only ever COMPARED, never assumed to be a string, and a pin that
  // is not a string pins NOTHING. The comparison alone was not enough: a record
  // with no key matched a missing pin (undefined === undefined), and only
  // createPublicKey(undefined) throwing downstream kept that forgery out, as
  // malformed-record by accident (the 2026-10-13 verify audit). The gate below
  // refuses a non-string pin on its own, as untrusted-signer.
  const pin: unknown = opts?.trustedSignerPublicKeyHex
  const malformed = (i: number, what: string, err?: unknown): VerifyReport => ({
    valid: false, firstInvalidIndex: i, reason: "malformed-record", anchoredThrough: null,
    detail: err === undefined ? what : `${what}: ${err instanceof Error ? err.message : String(err)}`,
  })

  let prevInteriorHash = "genesis"
  let prevWrapperHash: string | null = null
  // The interior head of every VERIFIED record, taken from its snapshot. The
  // anchor checks below read these, never the live records again: a payload
  // getter that swapped in a forgery after the signature check used to satisfy
  // a seal over the forgery (the 2026-10-13 verify audit).
  const verifiedHeads: Array<{ readonly hash: string; readonly seq: number }> = []
  for (let i = 0; i < records.length; i++) {
    const candidate: unknown = records[i]
    if (typeof candidate !== "object" || candidate === null) {
      return malformed(i, `record ${i} is not a signed record (got ${typeName(candidate)})`)
    }
    // Every field is read ONCE, here, and only these locals are judged. A
    // getter or Proxy used to answer the pin check with one key and the
    // signature with another, or swap the payload after it was verified, and a
    // getter that threw on a later read escaped as an exception (the
    // 2026-10-13 verify audit). `r` is a plain snapshot; `keys` is the own-key
    // set the envelope check judges. Object.keys runs in the same try, so a
    // hostile ownKeys trap is a verdict too.
    let r: SignedReceipt
    let keys: ReadonlyArray<string>
    try {
      const { payload, signature, signerPublicKeyHex, signedAt, previousHash, domain } = candidate as SignedReceipt
      keys = Object.keys(candidate)
      r = { payload, signature, signerPublicKeyHex, signedAt, previousHash, domain }
    } catch (err) {
      return malformed(i, `record ${i} could not be read`, err)
    }
    if (!r.signature || r.signature.length === 0) {
      return { valid: false, firstInvalidIndex: i, reason: "missing-signature", anchoredThrough: null }
    }
    if (typeof pin !== "string" || r.signerPublicKeyHex !== pin) {
      return {
        valid: false, firstInvalidIndex: i, reason: "untrusted-signer", anchoredThrough: null,
        detail: `record ${i} signed by ${preview(r.signerPublicKeyHex)}, expected ${preview(pin)}`,
      }
    }
    // Envelope shape, before any byte of it is trusted.
    const shape = envelopeKeyProblem(keys)
    if (shape !== null) return malformed(i, `record ${i} ${shape}`)
    // Signature shape, before any decoding. Buffer.from(s, "hex") stops at the
    // first non-hex character and accepts arrays and {type:"Buffer"} objects,
    // so uppercase, trailing garbage, a byte array and an odd-length string all
    // decoded to the genuine bytes and VERIFIED on the last record (the
    // 2026-10-13 verify audit). An Ed25519 signature is 64 bytes: 128 lowercase
    // hex characters, as the signer emits them, or it is not a signature.
    if (typeof r.signature !== "string" || !ED25519_SIGNATURE_HEX.test(r.signature)) {
      return malformed(i, `record ${i} signature is not 128 lowercase hex characters`)
    }
    // This function is what an auditor points at a file from an UNTRUSTED
    // party, so every malformed input has to come back as a verdict. It used to
    // throw: `createPublicKey` on a hex string that is not an SPKI key raises
    // "Failed to read asymmetric key", and the crash surfaced in someone else's
    // tool with no way to distinguish "this evidence is bad" from "this verifier
    // is broken" (adversarial pass V3, 2026-07-25). Malformed is invalid, and
    // invalid is a return value.
    let sigOk: boolean
    try {
      const publicKey = createPublicKey({ key: Buffer.from(r.signerPublicKeyHex, "hex"), format: "der", type: "spki" })
      // Signature covers the full envelope (domain + payload + previousHash +
      // signedAt) via the ONE shared preimage definition from @sweetrust/mandate —
      // never the payload alone, so previousHash/signedAt are authenticated and
      // no second preimage definition can drift from the signer's (DAN-641).
      sigOk = edVerify(null, Buffer.from(signedPreimage(r)), publicKey, Buffer.from(r.signature, "hex"))
    } catch (err) {
      return malformed(i, `record ${i} could not be checked`, err)
    }
    if (!sigOk) {
      return { valid: false, firstInvalidIndex: i, reason: "signature-mismatch", anchoredThrough: null }
    }
    // Domain separation: a validly-signed record of the wrong protocol (e.g. a
    // mandate audit event) must not verify as a receipt (DAN-641).
    if (r.domain !== RECEIPT_DOMAIN) {
      return { valid: false, firstInvalidIndex: i, reason: "domain-mismatch", anchoredThrough: null }
    }
    // Interior (kernel) hash recomputation — trust's own serialization, one definition.
    // The signature authenticates the payload's BYTES, not its shape: a buggy
    // signer can sign `null`, and receiptBody would throw reading it.
    const e: unknown = r.payload
    if (typeof e !== "object" || e === null) {
      return malformed(i, `record ${i} carries no receipt payload (got ${typeName(e)})`)
    }
    const payload = e as Receipt
    const rebuilt = sha256Hex(receiptBody(payload))
    if (rebuilt !== payload.hash) {
      return { valid: false, firstInvalidIndex: i, reason: "hash-mismatch", anchoredThrough: null }
    }
    // Both chains must link: interior (kernel) and wrapper (mandate spec I8).
    if (payload.prevHash !== prevInteriorHash || payload.seq !== i || r.previousHash !== prevWrapperHash) {
      return { valid: false, firstInvalidIndex: i, reason: "hash-chain-broken", anchoredThrough: null }
    }
    prevInteriorHash = payload.hash
    verifiedHeads.push({ hash: payload.hash, seq: payload.seq })
    // The next wrapper link hashes the WHOLE record. The snapshot IS the whole
    // record once the envelope check passed: the same six keys, the same
    // values, and canonicalJSON sorts, so the bytes match what the writer
    // hashed. A value canonicalJSON cannot encode (a BigInt, a cycle) leaves
    // the signature valid and makes this record unlinkable, so it is malformed
    // HERE, at the record that carries it. verifyAuditChain learned this in
    // DAN-1159 item 3; it never came back here.
    try {
      prevWrapperHash = sha256Hex(canonicalJSON(r))
    } catch (err) {
      return malformed(i, `record ${i} cannot be hashed for the next link`, err)
    }
  }

  const anchor: unknown = opts?.anchor
  if (anchor !== undefined) {
    // Present but unusable (null, a head that is not a string) proves nothing,
    // so it fails as anchor-not-found: the same fail-closed reading the kind
    // dispatch below gives an unknown kind. `null` is present, not absent. A
    // non-string head can never equal a verified record's hash, so both
    // branches reach their not-found verdict on their own.
    const { kind, head } = (typeof anchor === "object" && anchor !== null ? anchor : {}) as {
      readonly kind?: unknown
      readonly head?: unknown
    }
    // Fail CLOSED on the kind: only an explicit "receipt" earns the weaker
    // membership check. Anything else — an unknown string, a JSON-hydrated
    // value, undefined from an untyped JS consumer — is treated as a SEAL and
    // gets head-equality. The union protects callers inside this repo, but this
    // package publishes to npm; defaulting to the permissive branch would hand a
    // JS consumer the exact hole DAN-643 closes.
    if (kind !== "receipt") {
      // SEAL: the anchored head must BE the head of the presented chain. Head-
      // equality — not membership — is what catches tail truncation, since a
      // truncated chain ends on a different (earlier) record.
      const last = verifiedHeads.at(-1)
      if (!last || last.hash !== head) {
        return {
          valid: false, firstInvalidIndex: null, reason: "anchor-not-found", anchoredThrough: null,
          detail: `sealing anchor ${preview(head)} is not the head of the presented chain — records after it were removed, or the wrong chain was presented`,
        }
      }
      return { valid: true, firstInvalidIndex: null, reason: "ok", anchoredThrough: last.seq }
    }
    // RECEIPT: a per-decision head. It proves the chain THROUGH its own seq only —
    // membership, never full-chain. Records after it may still be truncated.
    const hit = verifiedHeads.findIndex((h) => h.hash === head)
    if (hit === -1) {
      return {
        valid: false, firstInvalidIndex: null, reason: "anchor-not-found", anchoredThrough: null,
        detail: `receipt memo ${preview(head)} does not appear in the presented chain — the wrong chain was presented, or records up to it were removed`,
      }
    }
    return { valid: true, firstInvalidIndex: null, reason: "ok", anchoredThrough: verifiedHeads[hit]!.seq }
  }

  return { valid: true, firstInvalidIndex: null, reason: "ok", anchoredThrough: null }
}

// ── Anchor memo convention (the Sui side reads/writes these) ─────────────────
// Every cage settlement carries the chain head AS OF THE DECISION in its memo
// ("swee:rcpt:<head>"); a final anchor tx seals the full chain
// ("swee:anchor:<head>"). The memo lands in the on-chain PaymentReceipt object
// (payment.move `memo` field, accessor `receipt_memo`) — immutable, public,
// fetchable by any third party. No new Move code: the anchor rides the money.

export const RECEIPT_MEMO_PREFIX = "swee:rcpt:"
export const ANCHOR_MEMO_PREFIX = "swee:anchor:"

export const receiptMemo = (head: string): string => `${RECEIPT_MEMO_PREFIX}${head}`
export const anchorMemo = (head: string): string => `${ANCHOR_MEMO_PREFIX}${head}`

/**
 * Extract the anchored head AND its kind from a fetched memo (string or byte
 * payload). The kind is load-bearing: only a `swee:anchor:` SEAL catches tail
 * truncation (head-equality in `verifySignedChain`); a `swee:rcpt:` receipt
 * proves the chain through its own seq only. Returns null for a non-anchor memo.
 */
export function parseAnchorMemo(
  memo: string | Uint8Array | ReadonlyArray<number>,
): { kind: "anchor" | "receipt"; head: string } | null {
  const text = typeof memo === "string" ? memo : new TextDecoder().decode(Uint8Array.from(memo as ArrayLike<number>))
  if (text.startsWith(ANCHOR_MEMO_PREFIX)) return { kind: "anchor", head: text.slice(ANCHOR_MEMO_PREFIX.length) }
  if (text.startsWith(RECEIPT_MEMO_PREFIX)) return { kind: "receipt", head: text.slice(RECEIPT_MEMO_PREFIX.length) }
  return null
}
