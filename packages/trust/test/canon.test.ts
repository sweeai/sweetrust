/**
 * One canonicalization across the rail — the receipt's interior hash included.
 *
 * AGENTS.md promises a single `canonicalJSON` for every byte this package signs
 * or hashes. Until the 2026-10-13 rail audit the promise stopped one layer
 * short: `receiptBody` built the kernel's hash body with `JSON.stringify`,
 * which writes an object's keys in insertion order. The top level was pinned
 * by hand, but `args` is a tree of caller-shaped objects, so the bytes under
 * the hash depended on the order a sink's caller happened to build its values
 * in. An honest JSONL artifact handed through `jq -S`, a sorted-map round trip
 * or a pretty-printer then came back `hash-mismatch`, with every value in it
 * intact — SECURITY.md carried that as an honest limit.
 *
 * Every test in the "re-serialized" block below was watched RED before
 * `receiptBody` went through the shared canonicalization.
 */
import { describe, expect, test } from "vitest"
import { makeSink, ReceiptLog, receiptBody, Sourced, type Receipt } from "../src/gate/index.ts"
import {
  generateSigningKeypair,
  makeEd25519ReceiptSigner,
  parseJSONL,
  publicKeyHexFromPem,
  sha256Hex,
  SignedReceiptLog,
  verifySignedChain,
} from "../src/verify/index.ts"

// What `jq -S -c` does to a line: parse, sort the keys at every depth,
// re-serialize compactly. Written out here rather than borrowed from the
// module under test, so the oracle is independent of the fix.
const sortKeysDeep = (v: unknown): unknown =>
  Array.isArray(v)
    ? v.map(sortKeysDeep)
    : typeof v === "object" && v !== null
      ? Object.fromEntries(
          Object.keys(v)
            .sort()
            .map((k) => [k, sortKeysDeep((v as Record<string, unknown>)[k])]),
        )
      : v
const jqS = (line: string): string => JSON.stringify(sortKeysDeep(JSON.parse(line)))

// A value whose keys are deliberately out of order at two depths. The receipt
// wraps it in `{ value, tier, provenance }`, itself unsorted, so even a string
// argument used to be enough to trip this; the nesting makes the point twice.
const UNSORTED = { z: 1, a: 2, nested: { b: "two", a: "one" } }

function sessionWith(log: ReceiptLog) {
  const pay = makeSink<{ to: Sourced<typeof UNSORTED> }, string>({
    name: "pay",
    requires: { to: "verified" },
    mode: "enforce",
    log,
    execute: ({ to }) => `paid ${to.value.z}`,
  })
  pay({ to: Sourced.fromAuthority({ ...UNSORTED, nested: { ...UNSORTED.nested } }, "reg") }) // executed
  pay({ to: Sourced.fromLLM({ ...UNSORTED, nested: { ...UNSORTED.nested } }, "Extract", []) }) // refused
}

describe("the interior receipt hash survives a key-order re-serialization", () => {
  test("gate: receiptBody over a key-sorted copy of a receipt rebuilds the hash the log committed (what verifyChain recomputes per record)", () => {
    const log = new ReceiptLog()
    sessionWith(log)
    for (const r of log.all()) {
      const resorted = sortKeysDeep(r) as Receipt
      expect(JSON.stringify(resorted)).not.toBe(JSON.stringify(r)) // the copy really is reordered
      expect(sha256Hex(receiptBody(resorted))).toBe(r.hash)
    }
    expect(log.verifyChain()).toBe(true)
  })

  test("verify: an exported artifact run through `jq -S -c` still verifies, every record", () => {
    const keys = generateSigningKeypair()
    const log = new SignedReceiptLog(makeEd25519ReceiptSigner(keys))
    sessionWith(log)
    const lines = log.exportJSONL().split("\n").filter((l) => l.length > 0)
    const resorted = lines.map(jqS)
    expect(resorted).not.toEqual(lines) // the re-serialization changed bytes
    const report = verifySignedChain(parseJSONL(resorted.join("\n") + "\n"), {
      trustedSignerPublicKeyHex: publicKeyHexFromPem(keys.publicKeyPem),
    })
    expect(report).toMatchObject({ valid: true, reason: "ok", firstInvalidIndex: null })
  })

  test("CONTROL: the artifact as exportJSONL wrote it verifies (green before and after)", () => {
    const keys = generateSigningKeypair()
    const log = new SignedReceiptLog(makeEd25519ReceiptSigner(keys))
    sessionWith(log)
    const report = verifySignedChain(parseJSONL(log.exportJSONL()), {
      trustedSignerPublicKeyHex: publicKeyHexFromPem(keys.publicKeyPem),
    })
    expect(report.valid).toBe(true)
  })

  test("CONTROL: a re-sorted artifact with one VALUE changed is still refused — sorting did not blind the hash", () => {
    const keys = generateSigningKeypair()
    const log = new SignedReceiptLog(makeEd25519ReceiptSigner(keys))
    sessionWith(log)
    const records = parseJSONL(log.exportJSONL().split("\n").filter((l) => l.length > 0).map(jqS).join("\n") + "\n")
    ;(records[0]!.payload.args.to!.value as { z: number }).z = 999
    const report = verifySignedChain(records, { trustedSignerPublicKeyHex: publicKeyHexFromPem(keys.publicKeyPem) })
    expect(report.valid).toBe(false)
    expect(report.firstInvalidIndex).toBe(0)
  })
})
