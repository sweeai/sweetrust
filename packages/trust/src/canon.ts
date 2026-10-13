/**
 * sweetrust — the one canonicalization, as a leaf.
 *
 * Every byte this package signs or hashes goes through `canonicalJSON` and
 * `sha256Hex`: mandate's signed preimage and audit-chain link, verify's wrapper
 * link, and — since the 2026-10-13 rail audit — the gate's interior receipt
 * hash. AGENTS.md, "One canonicalization across the rail": two
 * canonicalizations means bytes hashed on one side fail on the other.
 *
 * WHY A LEAF. The two functions lived in `src/mandate/signer.ts`, and the gate
 * deliberately does not import mandate (each subpath stands alone; see
 * `src/index.ts`). So the gate hashed its receipts with `JSON.stringify` and a
 * hand-pinned top-level key order, and the `args` tree underneath kept its
 * insertion order. An honest exportJSONL artifact run through `jq -S` then
 * verified as tampered. This module imports nothing but `node:crypto`, so any
 * subpath may import it without importing another subpath. `signer.ts`
 * re-exports both names, so `sweetrust/mandate`, `sweetrust/verify` and the
 * root still hand out the identical function objects
 * (`test/index-barrel.test.ts`, `test/canon.test.ts`).
 */
import { createHash } from "node:crypto"

/**
 * canonicalJSON — serialize a value to canonical JSON (sorted keys, no
 * whitespace). Deterministic across runs for any non-circular value.
 *
 * Used both for signing (producing the bytes the signature is computed
 * over) and for hash-chaining (producing the bytes the SHA-256 hash is
 * computed over). The two operations MUST agree on canonicalization or
 * verification will fail spuriously.
 *
 * It follows JSON.stringify's SerializeJSONProperty step for step, so that a
 * signature made over an in-memory value still verifies after the value has
 * been through JSON.stringify and JSON.parse (an export, a store file). The
 * steps that matter, in order: `toJSON(key)` is called ONCE on an object (a
 * function included) or a BigInt, and its result is NOT asked for toJSON
 * again; a boxed Number / String / Boolean / BigInt is unwrapped; then the
 * primitives; then arrays and plain objects, whose keys are sorted (the one
 * permitted difference). Before the 2026-10-13 verify audit the first two
 * steps were wrong: toJSON was applied recursively and without its key, and a
 * boxed String signed as {"0":"a","1":"b"} while its export read "ab", so an
 * honest record failed to verify the moment it left memory.
 */
const unbox = (value: object): unknown => {
  // Internal-slot tests, in JSON.stringify's order. `valueOf` is called on the
  // PROTOTYPE so it answers for the slot alone, then the conversion is the
  // spec's (ToNumber / ToString honour an instance override, as stringify does).
  try { Number.prototype.valueOf.call(value); return Number(value) } catch { /* no [[NumberData]] */ }
  try { String.prototype.valueOf.call(value); return String(value) } catch { /* no [[StringData]] */ }
  try { return Boolean.prototype.valueOf.call(value) } catch { /* no [[BooleanData]] */ }
  try { return BigInt.prototype.valueOf.call(value) } catch { /* no [[BigIntData]] */ }
  return value
}

const canon = (value: unknown, key: string): string | undefined => {
  // Step 2: toJSON, once, with the key. Objects include functions here, and
  // BigInt is the one primitive stringify asks (so a BigInt.prototype.toJSON
  // installed by the host is honoured). The result is used as-is below: a
  // carrier returned by a carrier is serialized as a plain object.
  if ((typeof value === "object" && value !== null) || typeof value === "function" || typeof value === "bigint") {
    const toJSON = (value as { toJSON?: unknown }).toJSON
    if (typeof toJSON === "function") value = (toJSON as (this: unknown, k: string) => unknown).call(value, key)
  }
  // Step 4: a boxed primitive is its primitive.
  if (typeof value === "object" && value !== null) value = unbox(value)
  // Steps 5 to 9: the primitives. NaN/Infinity are null; a BigInt throws, as
  // stringify does; undefined, function and symbol are nothing (dropped as a
  // key, null as an element, by the two callers below).
  if (value === null) return "null"
  if (value === true) return "true"
  if (value === false) return "false"
  if (typeof value === "string") return JSON.stringify(value)
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "null"
  if (typeof value === "bigint") throw new TypeError("Do not know how to serialize a BigInt")
  if (typeof value !== "object") return undefined
  if (Array.isArray(value)) {
    // JSON.stringify renders undefined/function/symbol ELEMENTS as null —
    // never as a hole. "[1,,2]" is not JSON; "[1,null,2]" is. Iterate by INDEX,
    // not Array.prototype.map: .map skips elision holes, so `?? "null"` never
    // fires for a true hole (`[1,,2]`), emitting invalid JSON. Indexing visits
    // holes as `undefined` → canon → "null" (DAN-646). The key handed to an
    // element's toJSON is its index as a string, as stringify hands it.
    const parts: string[] = []
    for (let i = 0; i < value.length; i++) parts.push(canon(value[i], String(i)) ?? "null")
    return "[" + parts.join(",") + "]"
  }
  // Keys whose values serialize to nothing (undefined, function, symbol) are
  // DROPPED, matching JSON.stringify: a signature over canonical bytes must
  // survive a JSON round-trip, and `"k":undefined` is not JSON.
  const record = value as Record<string, unknown>
  const parts: string[] = []
  for (const k of Object.keys(record).sort()) {
    const s = canon(record[k], k)
    if (s !== undefined) parts.push(JSON.stringify(k) + ":" + s)
  }
  return "{" + parts.join(",") + "}"
}

// INVARIANT (property-tested in test/mandate/canonical-property.test.ts, with
// boxed primitives, nested toJSON carriers and key-reading toJSON among the
// generators since the 2026-10-13 verify audit): for any JSON-representable
// value x, canonicalJSON(x) parses as JSON and JSON.parse(canonicalJSON(x))
// deep-equals JSON.parse(JSON.stringify(x)). Key order is the ONLY permitted
// difference (canonical = sorted). The top-level key is "", as stringify's is.
export const canonicalJSON = (value: unknown): string => canon(value, "") as string

/**
 * sha256Hex — compute SHA-256 hash of a string, return as hex.
 */
export const sha256Hex = (input: string): string =>
  createHash("sha256").update(input).digest("hex")
