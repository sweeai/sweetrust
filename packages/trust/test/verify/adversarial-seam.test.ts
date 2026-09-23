/**
 * ADVERSARIAL SEAM AUDIT (transient — publish-safety review, 2026-07-22)
 * Attacks the Gate->Verify evidence seam per the four claims:
 *   1. signature scope (payload-only) => reorder/splice/drop
 *   2. interior(receiptBody) vs wrapper(canonicalJSON) serialization drift
 *   3. JSONL round-trip: non-round-trippable values + newline injection
 *   4. truncation + anchor (forged/duplicate/intermediate head)
 */
import { describe, expect, test } from "vitest"
import { makeSink, Sourced, type Tier } from "../../src/gate/index.ts"
import {
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
} from "../../src/verify/index.ts"

// Build a signed log of N "verified" payments with attacker-chosen arg values.
function buildLog(values: unknown[]) {
  const keys = generateSigningKeypair()
  const signer = makeEd25519ReceiptSigner({ privateKeyPem: keys.privateKeyPem, publicKeyPem: keys.publicKeyPem })
  const log = new SignedReceiptLog(signer)
  const pay = makeSink<{ to: Sourced<unknown> }, string>({
    name: "pay",
    requires: { to: "verified" } as Record<"to", Tier>,
    mode: "enforce",
    log,
    execute: ({ to }) => `paid ${JSON.stringify(to.value)}`,
  })
  for (const v of values) pay({ to: Sourced.fromAuthority(v, "reg") })
  const trustedKey = publicKeyHexFromPem(keys.publicKeyPem)
  return { log, trustedKey }
}

const roundtrip = (log: SignedReceiptLog) => parseJSONL(log.exportJSONL())

describe("CLAIM 1 — signature covers payload only; interior signed seq/prevHash bind order", () => {
  test("honest chain verifies", () => {
    const { log, trustedKey } = buildLog(["a", "b", "c"])
    const rep = verifySignedChain(roundtrip(log), { trustedSignerPublicKeyHex: trustedKey })
    expect(rep.valid).toBe(true)
  })

  test("REORDER is blocked (signed seq pins position)", () => {
    const { log, trustedKey } = buildLog(["a", "b", "c"])
    const recs = roundtrip(log)
    ;[recs[0], recs[1]] = [recs[1]!, recs[0]!] // swap first two
    const rep = verifySignedChain(recs, { trustedSignerPublicKeyHex: trustedKey })
    expect(rep.valid).toBe(false)
    expect(rep.reason).toBe("hash-chain-broken")
  })

  test("DROP-MIDDLE is blocked", () => {
    const { log, trustedKey } = buildLog(["a", "b", "c"])
    const recs = roundtrip(log)
    recs.splice(1, 1) // remove middle
    const rep = verifySignedChain(recs, { trustedSignerPublicKeyHex: trustedKey })
    expect(rep.valid).toBe(false)
    expect(rep.reason).toBe("hash-chain-broken")
  })

  test("PAYLOAD MUTATION without re-sign => signature-mismatch", () => {
    const { log, trustedKey } = buildLog(["a", "b", "c"])
    const recs = roundtrip(log)
    ;(recs[1]!.payload as any).sink = "TRANSFER-ALL"
    const rep = verifySignedChain(recs, { trustedSignerPublicKeyHex: trustedKey })
    expect(rep.valid).toBe(false)
    expect(rep.reason).toBe("signature-mismatch")
  })
})

// REGRESSION GUARD (DAN-641). This block originally DOCUMENTED a finding: the
// signature covered the payload only, so `signedAt` was unbound and an attacker
// could rewrite the entire signing-time column (timestamp forgery) and still
// verify. DAN-641 moved signing to the whole envelope (domain + payload +
// previousHash + signedAt), which closes it. These now assert the FIX — if
// either flips back to valid:true, envelope signing has regressed.
describe("REGRESSION (DAN-641) — wrapper metadata (signedAt) is bound by the signature", () => {
  test("rewrite EVERY signedAt + recompute wrapper chain => REJECTED", () => {
    const { log, trustedKey } = buildLog(["a", "b", "c"])
    const recs = roundtrip(log)
    // Attacker rewrites the entire signing-time column to a fabricated time,
    // then recomputes the (unsigned) wrapper previousHash chain to stay linked.
    for (const r of recs) (r as any).signedAt = "1999-01-01T00:00:00.000Z"
    for (let i = 0; i < recs.length; i++) {
      ;(recs[i] as any).previousHash = i === 0 ? null : sha256Hex(canonicalJSON(recs[i - 1]))
    }
    const rep = verifySignedChain(recs, { trustedSignerPublicKeyHex: trustedKey })
    // The envelope signature binds signedAt, so retiming the log is detected
    // even though the attacker faithfully recomputed every wrapper hash link.
    expect(rep.valid).toBe(false)
    expect(recs.every((r) => r.signedAt === "1999-01-01T00:00:00.000Z")).toBe(true)
  })

  test("mutate ONLY the final record's signedAt (no recompute needed) => REJECTED", () => {
    const { log, trustedKey } = buildLog(["a", "b", "c"])
    const recs = roundtrip(log)
    ;(recs[recs.length - 1] as any).signedAt = "1970-01-01T00:00:00.000Z"
    const rep = verifySignedChain(recs, { trustedSignerPublicKeyHex: trustedKey })
    expect(rep.valid).toBe(false)
  })
})

describe("CLAIM 2/3 — serialization round-trip integrity (drift + injection)", () => {
  test("nested object with unsorted keys, newline/unicode strings, Date => survives export->parse->verify", () => {
    const hostile = {
      z: 1,
      a: 2,
      nested: { "2": "two", "1": "one", ten: 10 },
      newline: "line1\nline2\ttab",
      quote: 'he said "hi" \\ end',
      when: new Date("2026-07-22T00:00:00.000Z"),
      big: 12345,
    }
    const { log, trustedKey } = buildLog([hostile, "second"])
    const recs = roundtrip(log)
    const rep = verifySignedChain(recs, { trustedSignerPublicKeyHex: trustedKey })
    expect(rep.valid).toBe(true)
  })

  test("NEWLINE INJECTION in a value string cannot forge an extra JSONL line", () => {
    // A value that, if not escaped, would look like its own JSONL record.
    const injected = 'x"}\n{"payload":{"seq":99},"signature":"deadbeef","signerPublicKeyHex":"00","previousHash":null}\n'
    const { log, trustedKey } = buildLog([injected])
    const jsonl = log.exportJSONL()
    const parsed = parseJSONL(jsonl)
    expect(parsed.length).toBe(1) // NOT 2 — the embedded newline was JSON-escaped
    const rep = verifySignedChain(parsed, { trustedSignerPublicKeyHex: trustedKey })
    expect(rep.valid).toBe(true)
  })
})

describe("CLAIM 4 — truncation + anchor", () => {
  test("tail truncation is LOCALLY valid (honest limit) but caught by the sealing anchor", () => {
    const { log, trustedKey } = buildLog(["a", "b", "c"])
    const fullHead = log.head()
    const recs = roundtrip(log)
    recs.pop() // drop the tail

    const noAnchor = verifySignedChain(recs, { trustedSignerPublicKeyHex: trustedKey })
    expect(noAnchor.valid).toBe(true) // documented limit

    // DAN-643 migration: `anchoredHead: string` became `anchor: { kind, head }`.
    // A `kind:"anchor"` memo is a SEAL over the whole chain, so a dropped tail
    // means the sealed head is absent from the records entirely.
    const withAnchor = verifySignedChain(recs, {
      trustedSignerPublicKeyHex: trustedKey,
      anchor: { kind: "anchor", head: fullHead },
    })
    expect(withAnchor.valid).toBe(false)
    expect(withAnchor.reason).toBe("anchor-not-found")
  })

  test("FOOTGUN — an INTERMEDIATE per-decision receipt memo cannot catch truncation after its point", () => {
    const { log, trustedKey } = buildLog(["a", "b", "c", "d"])
    const recs = roundtrip(log)
    // Per the memo convention, every settlement emits swee:rcpt:<head-as-of-decision>.
    // Take the head as of decision #1 (index 1) — a legitimate on-chain value.
    const intermediateHead = recs[1]!.payload.hash
    const memo = receiptMemo(intermediateHead)

    // Attacker truncates everything after decision #1.
    recs.splice(2)

    // Auditor picks up the intermediate memo and treats it as the anchor.
    // DAN-643 migration: parseAnchorMemo now returns { kind, head } rather than a
    // bare string — precisely so a per-decision RECEIPT cannot masquerade as a
    // full-chain SEAL. The footgun below is therefore no longer silent: it is
    // still possible, but the caller can now SEE it is holding a receipt.
    const anchor = parseAnchorMemo(memo)!
    expect(anchor.kind).toBe("receipt") // receiptMemo() emits swee:rcpt:, never a seal
    const rep = verifySignedChain(recs, { trustedSignerPublicKeyHex: trustedKey, anchor })
    // Truncation of records 2..3 passes because the intermediate head still appears.
    // This is the honest limit, not a bug — a receipt only proves coverage THROUGH
    // its own point. `anchoredThrough` is what tells the auditor how far it goes,
    // which is why treating it as a whole-chain claim requires kind === "anchor".
    expect(rep.valid).toBe(true)
    expect(rep.anchoredThrough).toBe(1)
  })
})

describe("DAN-1159 item 2 — the SIGNED path: a BigInt amount signs, exports and verifies", () => {
  // The production shape. SignedReceiptLog signs through canonicalJSON, which
  // throws on a BigInt, so before the fix the payment ran and the signed log
  // (and its JSONL export) never heard of it.
  test("a payment of 1 SUI in MIST lands on the signed chain", () => {
    // Its own sink, not buildLog: buildLog's execute() stringifies the value
    // itself, so it would throw inside the action and never test the receipt.
    const keys = generateSigningKeypair()
    const log = new SignedReceiptLog(
      makeEd25519ReceiptSigner({ privateKeyPem: keys.privateKeyPem, publicKeyPem: keys.publicKeyPem }),
    )
    let executed = 0
    const pay = makeSink<{ amount: Sourced<bigint> }, string>({
      name: "pay",
      requires: { amount: "verified" } as Record<"amount", Tier>,
      mode: "enforce",
      log,
      execute: () => {
        executed++
        return "paid"
      },
    })
    const out = pay({ amount: Sourced.fromAuthority(1_000_000_000n, "treasury") })
    expect(executed).toBe(1)
    expect(out.ok).toBe(true)
    expect(log.signed()).toHaveLength(1)
    const report = verifySignedChain(roundtrip(log), {
      trustedSignerPublicKeyHex: publicKeyHexFromPem(keys.publicKeyPem),
    })
    expect(report.valid).toBe(true)
  })
})
