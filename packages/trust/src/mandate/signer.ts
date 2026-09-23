/**
 * @sweetrust/mandate v1.0 — MandateSigner (Ed25519 audit-record signing)
 *
 * Per the mandate multi-tier + signing specification v0.2 I6 + I7 + I10.
 *
 * Responsibilities:
 *   - Sign MandateAuditEvent payloads via Ed25519 over canonical JSON
 *   - Verify SignedMandateAuditEvent records against their declared
 *     signerPublicKeyHex
 *   - Hash-chain helper: compute SHA-256 of canonical JSON of a previous
 *     signed event for the next record's previousHash field
 *
 * Two signer implementations (plain factories returning the service object):
 *   - makeInMemorySignerLive() — deterministic test signer; produces
 *     signatures of the form "inmem-<sha256-hex-of-canonical-json>"; the
 *     publicKeyHex is a stable test marker. Useful for tests + demos
 *     where Ed25519 setup is overkill.
 *   - makeEd25519SignerLive(config) — production signer using Node.js's
 *     `node:crypto` Ed25519 primitives. The signing key is INJECTED at
 *     construction (per INV-DCE-1 + INV-SEC-1). Never read from
 *     process.env inside the factory; that would be runtime config.
 *
 * Canonical JSON serialization (per I7):
 *   - Object keys sorted alphabetically
 *   - No whitespace
 *   - Identical input produces identical bytes (deterministic signing)
 */
import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto"
import type {
  ISO8601,
  Signed,
  SignedMandateAuditEvent,
} from "./types.ts"

/**
 * canonicalJSON — serialize a value to canonical JSON (sorted keys, no
 * whitespace). Deterministic across runs for any non-circular value.
 *
 * Used both for signing (producing the bytes the signature is computed
 * over) and for hash-chaining (producing the bytes the SHA-256 hash is
 * computed over). The two operations MUST agree on canonicalization or
 * verification will fail spuriously.
 */
const canon = (value: unknown): string | undefined => {
  // Honor toJSON() before anything else (Date, URL, custom carriers) — exactly
  // as JSON.stringify does. Without this, a Date signs as "{}" but round-trips
  // as its ISO string, breaking the invariant below.
  if (value !== null && typeof value === "object") {
    const toJSON = (value as { toJSON?: unknown }).toJSON
    if (typeof toJSON === "function") {
      return canon((value as { toJSON: () => unknown }).toJSON())
    }
  }
  if (value === null || typeof value !== "object") {
    // Matches JSON.stringify for every primitive, including the edge cases:
    // NaN/Infinity → "null", undefined/function/symbol → undefined (dropped
    // or nulled by the callers below), bigint → throws, as stringify does.
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    // JSON.stringify renders undefined/function/symbol ELEMENTS as null —
    // never as a hole. "[1,,2]" is not JSON; "[1,null,2]" is. Iterate by INDEX,
    // not Array.prototype.map: .map skips elision holes, so `?? "null"` never
    // fires for a true hole (`[1,,2]`), emitting invalid JSON. Indexing visits
    // holes as `undefined` → canon → "null" (DAN-646).
    const parts: string[] = []
    for (let i = 0; i < value.length; i++) parts.push(canon(value[i]) ?? "null")
    return "[" + parts.join(",") + "]"
  }
  // Keys whose values serialize to nothing (undefined, function, symbol) are
  // DROPPED, matching JSON.stringify: a signature over canonical bytes must
  // survive a JSON round-trip, and `"k":undefined` is not JSON.
  const record = value as Record<string, unknown>
  const parts: string[] = []
  for (const k of Object.keys(record).sort()) {
    const s = canon(record[k])
    if (s !== undefined) parts.push(JSON.stringify(k) + ":" + s)
  }
  return "{" + parts.join(",") + "}"
}

// INVARIANT (property-tested in test/canonical-property.test.ts): for any
// JSON-representable value x, canonicalJSON(x) parses as JSON and
// JSON.parse(canonicalJSON(x)) deep-equals JSON.parse(JSON.stringify(x)).
// Key order is the ONLY permitted difference (canonical = sorted).
export const canonicalJSON = (value: unknown): string => canon(value) as string

/**
 * sha256Hex — compute SHA-256 hash of a string, return as hex.
 */
export const sha256Hex = (input: string): string =>
  createHash("sha256").update(input).digest("hex")

/**
 * MANDATE_AUDIT_DOMAIN — domain-separation tag folded into the signed preimage
 * of every mandate audit record. Because the tag is INSIDE the signed bytes, a
 * signature minted for an audit record is cryptographically invalid as any
 * other record type (e.g. a SweeVerify receipt) even under a shared key. Bump
 * the version suffix only on a breaking preimage change. (DAN-641.)
 */
export const MANDATE_AUDIT_DOMAIN = "swee.mandate-audit.v1"

/**
 * signedPreimage — the EXACT bytes a Signed<P> record's signature is computed
 * over. THE single definition, shared by sign(), verify(), and any external
 * verifier (@sweetrust/verify's verifySignedChain), so the preimage can never
 * drift across packages — the same discipline that keeps canonicalJSON single.
 *
 * It binds the full authenticated envelope: the domain tag, the payload, the
 * chain link (previousHash), and the signing time (signedAt) — NOT the payload
 * alone. Signing the payload alone (pre-DAN-641) left previousHash and signedAt
 * outside the signature, so an attacker holding a validly-signed chain could
 * delete/reorder/retime records and recompute the (public) previousHash links
 * with every signature still valid. Binding previousHash makes any relink break
 * the signature; binding signedAt authenticates the evidence timestamp; binding
 * domain closes cross-protocol signature reuse.
 */
export const signedPreimage = <P>(env: {
  readonly domain: string
  readonly payload: P
  readonly previousHash: string | null
  readonly signedAt: string
}): string =>
  canonicalJSON({
    domain: env.domain,
    payload: env.payload,
    previousHash: env.previousHash,
    signedAt: env.signedAt,
  })

/**
 * MandateSignerService — typed interface every signer factory implements.
 */
export interface MandateSignerService {
  /**
   * Sign a payload. Computes the canonical JSON, signs it, returns the
   * Signed<P> record with previousHash threaded through from the caller
   * (caller is responsible for tracking the chain head).
   *
   * Payload-generic (v1.1): the signer never inspects payload structure —
   * it signs canonical bytes — so any consumer (mandate audit events,
   * SweeVerify receipts, future record types) shares ONE signing
   * implementation. Mandate call sites infer P = MandateAuditEvent and are
   * unchanged.
   */
  readonly sign: <P>(args: {
    readonly payload: P
    readonly previousHash: string | null
    /**
     * Domain-separation tag for this record type (e.g. MANDATE_AUDIT_DOMAIN,
     * or @sweetrust/verify's RECEIPT_DOMAIN). Folded into the signed preimage so
     * a signature is bound to its protocol context. Required since DAN-641.
     */
    readonly domain: string
  }) => Signed<P>

  /**
   * Verify a signed record's signature against its declared
   * signerPublicKeyHex. Returns true if the signature is valid for the
   * payload + key, false otherwise.
   */
  readonly verify: <P>(signed: Signed<P>) => boolean

  /**
   * The public key this signer signs with, hex-encoded. Persisted on
   * every signed record so verifier-only consumers can verify without
   * knowing the private key.
   */
  readonly publicKeyHex: string
}

const nowISO = (): ISO8601 => new Date().toISOString() as ISO8601

/**
 * makeInMemorySignerLive — test signer (a pure function of the signed envelope).
 *
 * Signatures are of the form `inmem-<sha256-hex-of-signedPreimage>`.
 * publicKeyHex is a stable test marker. Verification simply re-computes
 * the expected signature and compares. Deterministic GIVEN the full envelope —
 * but since DAN-641 the envelope includes `signedAt` (wall-clock at sign time),
 * two separate `sign()` calls on the same payload produce DIFFERENT signatures
 * (different `signedAt`). That is correct by design; each still verifies. Do not
 * assert cross-call signature equality.
 *
 * Useful for tests + demos where the signing operation is incidental
 * (we want to demonstrate the audit-chain shape, not the cryptographic
 * primitive). Not suitable for production — the "signature" is reproducible
 * by anyone who has the signed envelope, so it provides NO authenticity
 * guarantee.
 */
export const makeInMemorySignerLive = (
  publicKeyHex: string = "inmem-test-pubkey",
): MandateSignerService => ({
  publicKeyHex,
  sign: <P>({ payload, previousHash, domain }: { payload: P; previousHash: string | null; domain: string }): Signed<P> => {
    const signedAt = nowISO()
    const signature = "inmem-" + sha256Hex(signedPreimage({ domain, payload, previousHash, signedAt }))
    return {
      payload,
      signature,
      signerPublicKeyHex: publicKeyHex,
      signedAt,
      previousHash,
      domain,
    }
  },
  verify: <P>(signed: Signed<P>): boolean => {
    const expected = "inmem-" + sha256Hex(signedPreimage(signed))
    return signed.signature === expected
  },
})

/**
 * Ed25519SignerConfig — operator-supplied signing key material.
 *
 * The operator generates the key pair OUTSIDE the substrate (e.g., via
 * `openssl genpkey -algorithm ed25519`) and passes the PEM strings here
 * at construction time. Per INV-SEC-1 the keys are treated as
 * secrets; the substrate never logs them, never echoes them in errors,
 * never serializes them outside of the signing operation itself. Per
 * INV-DCE-1, the keys are NOT read from process.env inside the factory —
 * key wiring is compile-time wiring at the construction site.
 *
 * For verifier-only consumers (audit consumers that should be able to
 * verify but NOT sign), use makeEd25519VerifierLive with only the public
 * key; its `sign` throws (still a total function type — the substrate
 * guarantees a verifier is only used for verification; runtime misuse is
 * a programmer error, documented).
 */
export interface Ed25519SignerConfig {
  readonly privateKeyPem: string
  readonly publicKeyPem: string
}

/**
 * PEM (SPKI) → the hex form `verifyAuditChain` requires for
 * `trustedSignerPublicKeyHex`.
 *
 * 🛑 LIVES HERE ON PURPOSE (DAN-905). It used to live in `verify/verify.ts`,
 * which meant `@swee/trust/mandate` shipped `verifyAuditChain` with a MANDATORY
 * hex argument and no exported way to produce one — a consumer following the
 * README's own advice to import from the narrow subpath got a hard
 * `SyntaxError: does not provide an export named 'publicKeyHexFromPem'` and had
 * to reach into a different entry point to complete a call this one owns.
 *
 * Re-exporting it INTO the mandate barrel would have been the small fix and the
 * wrong one: `mandate` has no edges to `verify` (only the reverse), and the
 * whole selling point of the narrow subpath is not dragging in the rest of the
 * rail. So the definition moved DOWN to the module that needs it, and `verify`
 * — which already imports from `mandate` — re-exports it. No new edge; one
 * fewer.
 */
export const publicKeyHexFromPem = (publicKeyPem: string): string =>
  createPublicKey(publicKeyPem).export({ format: "der", type: "spki" }).toString("hex")

/**
 * makeEd25519SignerLive — production signer using node:crypto's Ed25519.
 *
 * Sign operation: canonical JSON → Buffer → ed25519 sign with private key
 * → hex-encoded signature.
 *
 * Verify operation: canonical JSON of payload → Buffer → ed25519 verify
 * against the public key declared on the record (NOT the factory's
 * publicKeyHex; that's the signer's own key, which may differ during
 * key rotation — v0.2.1 work).
 */
export const makeEd25519SignerLive = (
  config: Ed25519SignerConfig,
): MandateSignerService => {
  const privateKey = createPrivateKey(config.privateKeyPem)
  const publicKey = createPublicKey(config.publicKeyPem)
  // Hex-encode the SPKI-DER-serialized public key. Ed25519 raw keys are 32
  // bytes; the SPKI wrapper adds ~12 bytes of ASN.1 structure for a total
  // of ~44 bytes (88 hex chars). Verify (below) re-imports via the same
  // SPKI/DER pair so the format is symmetric. Persisted on every signed
  // record per spec I10. (Cross-runtime verifiers that expect the raw
  // 32-byte key — e.g., browser WebCrypto, Sui Move — must strip the
  // ASN.1 wrapper themselves; v0.2.1 may add a `rawPublicKeyHex` field.)
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" })
  const publicKeyHex = publicKeyDer.toString("hex")

  return {
    publicKeyHex,
    sign: <P>({ payload, previousHash, domain }: { payload: P; previousHash: string | null; domain: string }): Signed<P> => {
      const signedAt = nowISO()
      // Sign the full envelope (domain + payload + previousHash + signedAt),
      // not the payload alone — see signedPreimage. Ed25519 in node:crypto:
      // pass null for the algorithm parameter; ed25519 is its own algorithm
      // and does not parameterize over hash functions like ECDSA does.
      const signatureBuffer = edSign(null, Buffer.from(signedPreimage({ domain, payload, previousHash, signedAt })), privateKey)
      return {
        payload,
        signature: signatureBuffer.toString("hex"),
        signerPublicKeyHex: publicKeyHex,
        signedAt,
        previousHash,
        domain,
      }
    },
    verify: <P>(signed: Signed<P>): boolean => {
      // Verify against the public key declared on THIS RECORD, not the
      // signer's own key. This is what enables verifier-only consumers and
      // future key rotation. (Authorship — i.e. that the record was signed by
      // the EXPECTED operator key — is the caller's pin; see DAN-642.)
      const recordPublicKey = createPublicKey({
        key: Buffer.from(signed.signerPublicKeyHex, "hex"),
        format: "der",
        type: "spki",
      })
      const signatureBuffer = Buffer.from(signed.signature, "hex")
      return edVerify(null, Buffer.from(signedPreimage(signed)), recordPublicKey, signatureBuffer)
    },
  }
}

/**
 * Ed25519VerifierConfig — operator-supplied PUBLIC key only.
 *
 * Used by audit consumers (external auditors, compliance systems, post-mortem
 * analysis pipelines) who must verify the signed audit chain WITHOUT being
 * able to sign new records. The `sign` operation is structurally
 * unreachable — calling it throws. `verify` works via the per-record
 * `signerPublicKeyHex` (per spec I10), so verification doesn't depend on the
 * verifier's own configured public key matching the records' public keys
 * (future-proofs key rotation per spec I11).
 *
 * Closes spec mandate-v0-2 reconstruction-test #8: persist signed JSONL,
 * restart with verifier-only signer, verifyAuditChain returns valid:true.
 */
export interface Ed25519VerifierConfig {
  readonly publicKeyPem: string
}

/**
 * makeEd25519VerifierLive — verifier-only Ed25519 signer. Has NO private key
 * material in scope. `sign` throws if invoked (programmer error in the
 * consumer's wiring; would never be called in a correctly-wired
 * audit-consumer system).
 */
export const makeEd25519VerifierLive = (
  config: Ed25519VerifierConfig,
): MandateSignerService => {
  const publicKey = createPublicKey(config.publicKeyPem)
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" })
  const publicKeyHex = publicKeyDer.toString("hex")

  return {
    publicKeyHex,
    sign: (): never => {
      throw new Error(
        "MandateSigner: this is a verifier-only signer; calling sign() is a programmer error. Wire makeEd25519SignerLive on the producing side; verifier signers only run verify().",
      )
    },
    verify: <P>(signed: Signed<P>): boolean => {
      // Verify against the public key declared on the record (per spec
      // I10), not the verifier's own. Verifier-only consumers can validate
      // chains signed by any signer whose records carry the matching
      // public key; the operator decides which keys to trust at the
      // application layer (allow-list via verifyAuditChain caller, future
      // v0.2.1 work per spec I11).
      const recordPublicKey = createPublicKey({
        key: Buffer.from(signed.signerPublicKeyHex, "hex"),
        format: "der",
        type: "spki",
      })
      const signatureBuffer = Buffer.from(signed.signature, "hex")
      return edVerify(null, Buffer.from(signedPreimage(signed)), recordPublicKey, signatureBuffer)
    },
  }
}

/**
 * verifyAuditChain — walk a log of signed events, validate every signature
 * AND every hash-chain link. Per spec I8 + I9.
 *
 * Returns the first index where verification fails (or null if all valid)
 * plus a typed reason discriminator. Operators use this to identify
 * tampering AND record removal — a removed record breaks the chain at the
 * next surviving record's `previousHash` reference.
 *
 * Implementation note: takes the `signer` (MandateSignerService) as an
 * explicit parameter for the `verify` operation. The signer's verify uses
 * the per-record signerPublicKeyHex (NOT the signer's own key) so
 * verifier-only signers work correctly.
 *
 * `opts.trustedSignerPublicKeyHex` is REQUIRED, mirroring the sibling
 * `verifySignedChain` in @sweetrust/verify. Verifying a record against the key
 * it CARRIES proves the record is internally consistent, not that the honest
 * signer authored it — an attacker who obtains the log can rewrite every
 * event, re-sign under their OWN key, set each record's signerPublicKeyHex to
 * that key, and rebuild the hash chain; the result is locally consistent and
 * used to return valid:true. Pinning the expected key and rejecting any
 * record signed by a different one BEFORE the signature check closes the hole.
 * The audit log is only a "source of truth" if its authorship is pinned to a
 * key the verifier trusts out-of-band, not to a key the log carries about
 * itself. (LESSONS 2026-07-22: audit-log-is-truth must hold at EVERY security
 * decision — the embedded key is attacker-controllable, so it cannot be the
 * root of trust.)
 */
export const verifyAuditChain = (
  log: ReadonlyArray<SignedMandateAuditEvent>,
  signer: MandateSignerService,
  opts: { readonly trustedSignerPublicKeyHex: string },
): import("./types.ts").VerifyAuditChainResult => {
  // The container is checked before anything is read from it. A plain object
  // used to VERIFY: `{}.length` is undefined, so `=== 0` missed the empty-log
  // guard below, `i < undefined` never entered the loop, and control fell
  // through to valid:true (F6's residual, DAN-1159 item 5). verifySignedChain
  // has the same guard; a parity test holds the two to the same verdict.
  // `input` is `unknown` so the narrowing cannot leak `any[]` into `log`.
  const input: unknown = log
  if (!Array.isArray(input)) {
    return {
      valid: false,
      firstInvalidIndex: null,
      reason: "malformed-record" as const,
      detail: `expected an array of signed records (got ${input === null ? "null" : typeof input})`,
    }
  }

  // An empty log used to fold to valid:true, the loop's identity element and
  // the strongest claim it can make. An operator handed an empty file and told
  // "valid" has been told something false. Same lesson verifySignedChain learned
  // in adversarial pass V2 (2026-07-25); this function never got it (DAN-1159).
  if (log.length === 0) {
    return {
      valid: false,
      firstInvalidIndex: null,
      reason: "empty-chain" as const,
      detail: "no records were presented — there is nothing here to verify, which is not the same as nothing being wrong",
    }
  }

  // Every malformed input comes back as a verdict, never a throw. A crash here
  // surfaces in the operator's tool with no way to tell "this log is bad" from
  // "this verifier is broken" (verifySignedChain's pass V3). It used to throw on
  // a null record, a record key that is not SPKI, and anything canonicalJSON
  // cannot encode (a BigInt, a cycle).
  const malformed = (i: number, what: string, err?: unknown) => ({
    valid: false,
    firstInvalidIndex: i,
    reason: "malformed-record" as const,
    detail: err === undefined ? what : `${what}: ${err instanceof Error ? err.message : String(err)}`,
  })

  // The link each record must carry: null for the first, then the hash of the
  // whole previous SIGNED record.
  let expectedPreviousHash: string | null = null
  for (let i = 0; i < log.length; i++) {
    const candidate: unknown = log[i]
    if (typeof candidate !== "object" || candidate === null) {
      return malformed(i, `record ${i} is ${candidate === null ? "null" : `a ${typeof candidate}`}, not a signed record`)
    }
    const record = candidate as SignedMandateAuditEvent

    // Empty / missing signature
    if (!record.signature || record.signature.length === 0) {
      return {
        valid: false,
        firstInvalidIndex: i,
        reason: "missing-signature" as const,
      }
    }

    // Pinned-key check BEFORE signature verification (DAN-638/642). A record
    // signed by any key other than the pinned one is rejected regardless of
    // whether its self-referential signature validates. A missing `opts` pins
    // nothing, so nothing verifies: fail-closed, as a verdict (DAN-1159 item 5).
    if (record.signerPublicKeyHex !== opts?.trustedSignerPublicKeyHex) {
      return {
        valid: false,
        firstInvalidIndex: i,
        reason: "untrusted-signer" as const,
      }
    }

    // Signature verification (covers domain + payload + previousHash +
    // signedAt via signedPreimage — DAN-641).
    let sigOk: boolean
    try {
      sigOk = signer.verify(record)
    } catch (err) {
      return malformed(i, `record ${i} could not be checked`, err)
    }
    if (!sigOk) {
      return {
        valid: false,
        firstInvalidIndex: i,
        reason: "signature-mismatch" as const,
      }
    }

    // Domain separation: a validly-signed record of the WRONG protocol (e.g. a
    // SweeVerify receipt) must not pass as an audit event. The tag is inside
    // the signed preimage, so this compares an authenticated field (DAN-641).
    if (record.domain !== MANDATE_AUDIT_DOMAIN) {
      return {
        valid: false,
        firstInvalidIndex: i,
        reason: "domain-mismatch" as const,
      }
    }

    // Hash-chain verification: the first record must carry null, every later
    // one the hash of its predecessor.
    if (record.previousHash !== expectedPreviousHash) {
      return {
        valid: false,
        firstInvalidIndex: i,
        reason: "hash-chain-broken" as const,
      }
    }

    // The next link hashes the WHOLE record, which includes fields outside the
    // signed preimage. A field canonicalJSON cannot encode leaves the signature
    // valid and makes this record unlinkable, so it is malformed HERE, at the
    // record that carries it, not at its successor.
    try {
      expectedPreviousHash = sha256Hex(canonicalJSON(record))
    } catch (err) {
      return malformed(i, `record ${i} cannot be hashed for the next link`, err)
    }
  }

  return {
    valid: true,
    firstInvalidIndex: null,
    reason: "ok" as const,
  }
}
