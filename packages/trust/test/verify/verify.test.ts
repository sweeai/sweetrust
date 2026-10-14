/**
 * Tests for sweetrust/verify v0.1 — the evidence invariants, extracted from the
 * demo that specified them (sweeai verify.demo.ts, 10/10: a hostile-handoff
 * drill where every attack on the exported chain must be caught, including
 * the one — tail truncation — only the on-chain anchor can catch).
 *
 * Coverage map (attack → expected verdict):
 *   honest chain            → valid, anchor covers the full chain
 *   tamper (rewrite past)   → signature-mismatch
 *   splice (delete middle)  → hash-chain-broken
 *   forge (attacker re-signs everything with their own key) → untrusted-signer
 *   lie (signed payload whose interior hash doesn't rebuild) → hash-mismatch
 *   truncate (delete tail)  → valid locally (HONEST LIMIT) but anchor-not-found
 *                             when the anchored head is supplied
 * Plus: JSONL round-trip + rejection, memo convention parsing (string + bytes).
 */
import { describe, expect, test } from "vitest"
import { makeSink, Sourced, ReceiptLog, type Receipt, type Tier } from "../../src/gate/index.ts"
import {
  anchorMemo,
  canonicalJSON,
  generateSigningKeypair,
  makeEd25519ReceiptSigner,
  parseAnchorMemo,
  parseJSONL,
  publicKeyHexFromPem,
  receiptMemo,
  sha256Hex,
  SignedReceiptLog,
  verifySignedChain,
  type SignedReceipt,
} from "../../src/verify/index.ts"

// ── Fixture: a two-decision session (1 executed, 1 refused) ──────────────────

function session() {
  const keys = generateSigningKeypair()
  const signer = makeEd25519ReceiptSigner({ privateKeyPem: keys.privateKeyPem, publicKeyPem: keys.publicKeyPem })
  const log = new SignedReceiptLog(signer)
  const registryEntry = Sourced.fromAuthority("acct-ACME-001", "payee-registry")

  const pay = makeSink<{ to: Sourced<string> }, string>({
    name: "pay",
    requires: { to: "verified" } as Record<"to", Tier>,
    mode: "enforce",
    log,
    execute: ({ to }) => `paid ${to.value}`,
  })

  pay({ to: registryEntry }) // executed
  pay({ to: Sourced.fromLLM("acct-EVIL-666", "ExtractInvoice", []) }) // refused

  const trustedKey = publicKeyHexFromPem(keys.publicKeyPem)
  return { keys, signer, log, trustedKey }
}

// ── Signing + the honest path ─────────────────────────────────────────────────

describe("SignedReceiptLog", () => {
  test("signs every receipt as it lands — refusals included — and stays a drop-in ReceiptLog", () => {
    const { log } = session()
    expect(log).toBeInstanceOf(ReceiptLog)
    expect(log.all()).toHaveLength(2)
    expect(log.signed()).toHaveLength(2)
    expect(log.signed().some((r) => r.payload.decision === "refused")).toBe(true)
    expect(log.verifyChain()).toBe(true) // the interior kernel chain still verifies
  })

  test("wrapper chain follows sweetrust/mandate spec I8: previousHash = sha256(canonicalJSON(prev signed record)), null first", () => {
    const { log } = session()
    const [first, second] = log.signed()
    expect(first!.previousHash).toBeNull()
    expect(second!.previousHash).toBe(sha256Hex(canonicalJSON(first)))
  })

  test("head() is the interior chain head (genesis when empty)", () => {
    const keys = generateSigningKeypair()
    const empty = new SignedReceiptLog(
      makeEd25519ReceiptSigner({ privateKeyPem: keys.privateKeyPem, publicKeyPem: keys.publicKeyPem }),
    )
    expect(empty.head()).toBe("genesis")
    const { log } = session()
    expect(log.head()).toBe(log.all().at(-1)!.hash)
  })

  test("exportJSONL / parseJSONL round-trips; parseJSONL rejects non-receipts", () => {
    const { log } = session()
    const parsed = parseJSONL(log.exportJSONL())
    expect(parsed).toEqual([...log.signed()])
    expect(() => parseJSONL('{"not":"a receipt"}\n')).toThrow(/not a SignedReceipt/)
  })

  test("the honest chain verifies with only public material, anchor covering the full chain", () => {
    const { log, trustedKey } = session()
    const report = verifySignedChain(parseJSONL(log.exportJSONL()), {
      trustedSignerPublicKeyHex: trustedKey,
      anchor: { kind: "anchor", head: log.head() },
    })
    expect(report).toMatchObject({ valid: true, reason: "ok", anchoredThrough: log.all().length - 1 })
  })
})

// ── The attacks: every one must be CAUGHT ────────────────────────────────────

describe("verifySignedChain — attacks", () => {
  test("tamper: rewriting history breaks the signature", () => {
    const { log, trustedKey } = session()
    const tampered: SignedReceipt[] = JSON.parse(JSON.stringify(log.signed()))
    ;(tampered[0]!.payload.args as Record<string, { value: unknown }>).to!.value = "acct-EVIL-666"
    const r = verifySignedChain(tampered, { trustedSignerPublicKeyHex: trustedKey })
    expect(r.valid).toBe(false)
    expect(r.reason).toBe("signature-mismatch")
    expect(r.firstInvalidIndex).toBe(0)
  })

  test("splice: deleting the refusal from the middle breaks the hash chain", () => {
    const { log, trustedKey } = session()
    const spliced = [...log.signed()].filter((r) => r.payload.seq !== 0)
    const r = verifySignedChain(spliced, { trustedSignerPublicKeyHex: trustedKey })
    expect(r.valid).toBe(false)
    expect(r.reason).toBe("hash-chain-broken")
  })

  test("forge: a competent forger who re-signs a consistent chain with THEIR key is stopped by key pinning", () => {
    const { log, trustedKey } = session()
    const forgerKeys = generateSigningKeypair()
    const forger = makeEd25519ReceiptSigner({ privateKeyPem: forgerKeys.privateKeyPem, publicKeyPem: forgerKeys.publicKeyPem })
    const forgedLog = new SignedReceiptLog(forger)
    for (const r of log.signed()) {
      const { seq: _s, prevHash: _p, hash: _h, ...body } = r.payload
      forgedLog.append(body as Parameters<ReceiptLog["append"]>[0])
    }
    const r = verifySignedChain(forgedLog.signed(), { trustedSignerPublicKeyHex: trustedKey })
    expect(r.valid).toBe(false)
    expect(r.reason).toBe("untrusted-signer")
  })

  test("lie: a validly-signed payload whose interior hash doesn't rebuild → hash-mismatch", () => {
    const { signer, trustedKey } = session()
    const lying: Receipt = {
      seq: 0,
      at: new Date().toISOString(),
      sink: "pay",
      decision: "executed",
      args: {},
      prevHash: "genesis",
      hash: "not-the-real-hash",
    }
    const r = verifySignedChain([signer.sign(lying, null)], { trustedSignerPublicKeyHex: trustedKey })
    expect(r.valid).toBe(false)
    expect(r.reason).toBe("hash-mismatch")
  })

  test("truncate: the tail deletion is INVISIBLE locally (honest limit) but the anchor catches it", () => {
    const { log, trustedKey } = session()
    const truncated = [...log.signed()].slice(0, -1)
    const local = verifySignedChain(truncated, { trustedSignerPublicKeyHex: trustedKey })
    expect(local.valid).toBe(true) // a shorter chain is still a valid chain — stated, not hidden
    const anchored = verifySignedChain(truncated, { trustedSignerPublicKeyHex: trustedKey, anchor: { kind: "anchor", head: log.head() } })
    expect(anchored.valid).toBe(false)
    expect(anchored.reason).toBe("anchor-not-found")
  })

  test("missing signature is refused before any crypto runs", () => {
    const { log, trustedKey } = session()
    const stripped = [{ ...log.signed()[0]!, signature: "" }]
    const r = verifySignedChain(stripped, { trustedSignerPublicKeyHex: trustedKey })
    expect(r.valid).toBe(false)
    expect(r.reason).toBe("missing-signature")
  })
})

// ── The anchor-memo convention (the Sui side reads/writes these) ─────────────

describe("anchor memos", () => {
  test("receiptMemo / anchorMemo prefix the head; parseAnchorMemo returns kind + head", () => {
    expect(receiptMemo("abc")).toBe("swee:rcpt:abc")
    expect(anchorMemo("abc")).toBe("swee:anchor:abc")
    expect(parseAnchorMemo("swee:anchor:abc")).toEqual({ kind: "anchor", head: "abc" })
    expect(parseAnchorMemo("swee:rcpt:abc")).toEqual({ kind: "receipt", head: "abc" })
    expect(parseAnchorMemo("hijack:direct-call")).toBeNull()
  })

  test("parseAnchorMemo decodes vector<u8> byte payloads (how RPCs return the memo)", () => {
    const bytes = Array.from(new TextEncoder().encode(anchorMemo("deadbeef")))
    expect(parseAnchorMemo(bytes)).toEqual({ kind: "anchor", head: "deadbeef" })
  })

  // ── DAN-643: a receipt memo cannot masquerade as a full-chain seal ───────────
  test("truncation behind an intermediate RECEIPT memo: a seal catches it, a receipt only proves partial", () => {
    // A 3-decision session so an INTERIOR record survives truncation to be pointed at.
    const keys = generateSigningKeypair()
    const signer = makeEd25519ReceiptSigner({ privateKeyPem: keys.privateKeyPem, publicKeyPem: keys.publicKeyPem })
    const log = new SignedReceiptLog(signer)
    const registryEntry = Sourced.fromAuthority("acct-ACME-001", "payee-registry")
    const pay = makeSink<{ to: Sourced<string> }, string>({
      name: "pay", requires: { to: "verified" } as Record<"to", Tier>, mode: "enforce", log,
      execute: ({ to }) => `paid ${to.value}`,
    })
    pay({ to: registryEntry })
    pay({ to: registryEntry })
    pay({ to: registryEntry })
    const trustedKey = publicKeyHexFromPem(keys.publicKeyPem)

    const full = log.signed()
    expect(full.length).toBe(3)
    const truncated = full.slice(0, -1) // attacker drops the tail → [seq 0, seq 1]
    // The attacker points the auditor at an EARLIER decision's on-chain head — a legitimate
    // `swee:rcpt:` memo (seq 0) that still appears in the truncated chain but is NOT its head.
    const intermediate = full[0]!.payload.hash

    // Pre-DAN-643 hole: passed as a full seal it would have validated via membership.
    // Now a SEAL demands head-equality, so the truncation is caught.
    const asSeal = verifySignedChain(truncated, {
      trustedSignerPublicKeyHex: trustedKey,
      anchor: { kind: "anchor", head: intermediate },
    })
    expect(asSeal.valid).toBe(false)
    expect(asSeal.reason).toBe("anchor-not-found")

    // Honestly parsed as a RECEIPT it verifies, but only proves the chain THROUGH seq 0 —
    // it does NOT claim the full chain, so the auditor is not fooled about the missing tail.
    const asReceipt = verifySignedChain(truncated, {
      trustedSignerPublicKeyHex: trustedKey,
      anchor: { kind: "receipt", head: intermediate },
    })
    expect(asReceipt.valid).toBe(true)
    expect(asReceipt.anchoredThrough).toBe(0) // partial proof, NOT full-chain
    expect(asReceipt.anchoredThrough).toBeLessThan(truncated.length - 1)

    // The kind dispatch fails CLOSED. The TS union protects callers in this repo, but
    // this package publishes to npm: a JS consumer, or a kind hydrated from JSON/config/
    // an RPC, can hand us anything. Only an explicit "receipt" may take the weaker
    // membership branch — everything else is checked as a seal, so a garbage kind can
    // never silently reopen the truncation hole.
    for (const rogue of ["Anchor", "ANCHOR", "anchor ", "seal", "", undefined, null]) {
      const report = verifySignedChain(truncated, {
        trustedSignerPublicKeyHex: trustedKey,
        anchor: { kind: rogue as "anchor" | "receipt", head: intermediate },
      })
      expect(report.valid, `kind ${JSON.stringify(rogue)} must NOT downgrade to membership`).toBe(false)
      expect(report.reason).toBe("anchor-not-found")
    }
  })
})
