/**
 * poison — the intake harness behind AGENTS.md's "caller input is read once,
 * at the boundary".
 *
 * Wraps a caller-shaped object in a Proxy that lets every key be READ once and
 * throws `SecondRead` on the second `get` of the same key. The 2026-10-13
 * mandate CRITICAL was exactly this shape: a getter on `args` answered the
 * possession check with the genuine scope and every later read with forged
 * data, because the function read `args.mandate` at each site that wanted it.
 * A getter or Proxy can answer differently per read, so a second read is a
 * time-of-check/time-of-use hole, and this harness turns one into a thrown
 * error with the key's name on it.
 *
 * What does NOT count as a read, on purpose, so that an own-key snapshot
 * passes: `has` (`k in obj`), `ownKeys` (`Object.keys`, a spread) and
 * `getOwnPropertyDescriptor` (`Object.hasOwn`, the enumerability check inside
 * `Object.keys`). Taking the key list and then reading each key once is the
 * sanctioned shape; reading a key, checking something, and reading it again is
 * the hole.
 *
 * Function-valued properties are bound to the target before they are handed
 * back. A method called through the proxy (`candidate.describe()`) reads
 * `this.provenance` inside its own body; that is the method's business, not
 * the entry point's intake, and counting it would flag every class instance
 * on sight. The `get` of the method itself still counts.
 *
 * Getters on the target run with the TARGET as receiver, for the same reason:
 * the harness measures what the function under test reads from its argument,
 * not what the argument's own accessors read from themselves.
 */

export class SecondRead extends Error {
  override readonly name = "SecondRead"
  constructor(
    readonly label: string,
    readonly key: PropertyKey,
  ) {
    super(`${label}.${String(key)} was read a second time — a getter or Proxy could have answered differently; snapshot it once at the boundary`)
  }
}

/** Every key read so far, for a test that wants to assert the count or the set. */
const READS = new WeakMap<object, Map<PropertyKey, number>>()

export function poison<T extends object>(input: T, label = "input"): T {
  const seen = new Map<PropertyKey, number>()
  const proxy = new Proxy(input, {
    get(target, key) {
      const n = (seen.get(key) ?? 0) + 1
      seen.set(key, n)
      if (n > 1) throw new SecondRead(label, key)
      const v = Reflect.get(target, key)
      return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v
    },
    has: (target, key) => Reflect.has(target, key),
    ownKeys: (target) => Reflect.ownKeys(target),
    getOwnPropertyDescriptor: (target, key) => Reflect.getOwnPropertyDescriptor(target, key),
  })
  READS.set(proxy, seen)
  return proxy
}

/** The reads a poisoned object has seen, keyed by property. Empty for a plain object. */
export const readsOf = (poisoned: object): ReadonlyMap<PropertyKey, number> => READS.get(poisoned) ?? new Map()
