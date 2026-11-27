/**
 * A handle saved as JSON and loaded back (DAN-1593). `open()` returns bigint and Date limits;
 * plain JSON.stringify throws on a bigint, so a host writes a bigint-to-string replacer, and the
 * reloaded handle holds decimal strings and ISO strings. revoke, spend and remaining must still work
 * on it. For `spend` and `remaining`, a limit that is not the persisted form of a limit is still a
 * TypeError naming the field, with nothing sent. `revoke` never reads the handle's limits at all (the
 * last describe), so the funder's kill switch cannot depend on them.
 *
 * Tests whose names start "REGRESSION GUARD" or "SETUP GUARD" pass on main (1ff8d6a) too: they guard
 * behavior main already had, and are not proof of the fix.
 */
import { runInNewContext } from "node:vm"
import { describe, expect, it, vi } from "vitest"
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519"
import { normalizeSuiAddress } from "@mysten/sui/utils"
import { suiAllowances, type Remaining, type SuiAllowance } from "../src/index.ts"
import { DIGEST, allowanceState, mockChain, type MockChain } from "./helpers/mock-chain.ts"

const principal = Ed25519Keypair.generate()
const agent = Ed25519Keypair.generate()
const P = principal.toSuiAddress()
const A = agent.toSuiAddress()
const MERCHANT = normalizeSuiAddress("0x5e11e5")
const NOW = Date.parse("2026-11-22T00:00:00Z")
const DAY = 86_400_000
const HOUR = 3_600_000
/** The allowance open() made, as the chain would hold it: every limit kind open() can carry. */
const live = allowanceState({
  funder: P, spender: A, lifetimeCap: 1000n, startMs: BigInt(NOW - DAY), expiryMs: BigInt(NOW + DAY),
  rate: { limit: 5000n, spent: 0n, anchorMs: BigInt(NOW), index: 0n, window: { kind: "periodic", periodMs: BigInt(HOUR) } },
})

/** The host's side of persistence: a bigint replacer on the way out, plain JSON.parse (no reviver) on the way back. */
const save = (h: unknown): string => JSON.stringify(h, (_k, v) => (typeof v === "bigint" ? v.toString() : v))
const load = (s: string): SuiAllowance => JSON.parse(s) as SuiAllowance

/** A handle exactly as open() returns it, with every limit kind open() can carry (perSpendMax it refuses: nobody holds it). */
const openHandle = async (): Promise<SuiAllowance> => {
  const chain = mockChain(null, BigInt(NOW))
  chain.script.push({ kind: "executed", digest: DIGEST(0), timestampMs: NOW, created: true, after: live })
  const sui = suiAllowances({ client: chain.client, network: "sui:testnet" })
  const { allowance } = await sui.open({
    signer: principal, name: "persisted",
    allowance: { network: "sui:testnet", asset: "0x2::sui::SUI", spender: A, limits: { lifetimeCap: 1000n, rate: { amount: 5000n, windowMs: HOUR }, start: new Date(NOW - DAY), expiry: new Date(NOW + DAY), recipients: [MERCHANT] } },
  })
  if (allowance === null) throw new Error("open() returned no handle")
  return allowance
}

type Verb = "revoke" | "spend" | "remaining"
/** A live chain scripted so the verb would succeed if it got as far as sending. */
const run = async (verb: Verb, h: SuiAllowance): Promise<{ chain: MockChain; outcome: Promise<unknown> }> => {
  const chain = mockChain(live, BigInt(NOW))
  if (verb === "revoke") chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: NOW, after: null })
  if (verb === "spend") chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: NOW, after: { ...live, currentSpend: 600n } })
  const sui = suiAllowances({ client: chain.client, network: "sui:testnet" })
  const outcome =
    verb === "revoke" ? sui.revoke({ signer: principal, allowance: h })
      : verb === "spend" ? sui.spend({ signer: agent, allowance: h, amount: 600n, recipient: MERCHANT })
        : sui.remaining({ allowance: h })
  return { chain, outcome }
}

describe("a handle saved as JSON and loaded back", () => {
  it("SETUP GUARD, passes on main too, not fix proof: the helpers write the persisted form this file claims (bigints and dates became strings)", async () => {
    const back = load(save(await openHandle()))
    expect(back.limits.lifetimeCap).toBe("1000")
    expect(back.limits.expiry).toBe(new Date(NOW + DAY).toISOString())
  })

  it("revokes: the Allowance is deleted and the receipt says executed", async () => {
    const { chain, outcome } = await run("revoke", load(save(await openHandle())))
    const r = (await outcome) as { verdict: string }
    expect(r.verdict).toBe("executed")
    expect(chain.executed).toHaveLength(1)
  })

  it("spends: the spend executes and the library-held recipient list still binds", async () => {
    const { chain, outcome } = await run("spend", load(save(await openHandle())))
    const r = (await outcome) as { verdict: string }
    expect(r.verdict).toBe("executed")
    expect(chain.executed).toHaveLength(1)
    const other = suiAllowances({ client: mockChain(live, BigInt(NOW)).client, network: "sui:testnet" })
    const refused = await other.spend({ signer: agent, allowance: load(save(await openHandle())), amount: 1n, recipient: normalizeSuiAddress("0xbad") })
    expect(refused.verdict).toBe("refused")
  })

  it("reads remaining without sending anything, and still lists the library-held recipients", async () => {
    const { chain, outcome } = await run("remaining", load(save(await openHandle())))
    const r = (await outcome) as Remaining
    expect(r.active).toBe(true)
    expect(r.spendableNow).toBe("1000")
    const recipients = r.limits.find((l) => l.limit === "recipients")
    expect(recipients?.heldBy).toBe("library")
    expect(recipients?.verdict).toBe("held")
    expect(recipients?.value).toBe("1 address: 0x000000…5e11e5")
    expect(chain.executed).toHaveLength(0)
  })

  it("SETUP GUARD, passes on main too, not fix proof: the handle carries every limit kind open() can carry", async () => {
    const h = await openHandle()
    expect(Object.keys(h.limits).sort()).toEqual(["expiry", "lifetimeCap", "rate", "recipients", "start"])
    const back = load(save(h))
    expect(back.limits.rate).toEqual({ amount: "5000", windowMs: HOUR })
    expect(back.limits.start).toBe(new Date(NOW - DAY).toISOString())
  })

  it("round trip: the reloaded handle gives the same receipt lines as the in-memory one, for remaining and for a refused spend", async () => {
    const mem = await openHandle()
    const reloaded = load(save(mem))
    const remainingLines = async (h: SuiAllowance): Promise<unknown> => ((await (await run("remaining", h)).outcome) as Remaining).limits
    expect(await remainingLines(reloaded)).toEqual(await remainingLines(mem))
    const refusedLines = async (h: SuiAllowance): Promise<unknown> => {
      const sui = suiAllowances({ client: mockChain(live, BigInt(NOW)).client, network: "sui:testnet" })
      const r = await sui.spend({ signer: agent, allowance: h, amount: 1n, recipient: normalizeSuiAddress("0xbad") })
      expect(r.verdict).toBe("refused")
      return r.limits
    }
    const refused = await refusedLines(mem)
    expect((refused as Array<unknown>)).toHaveLength(5)
    expect(await refusedLines(reloaded)).toEqual(refused)
  })

  it("remaining reads a lifetime cap, rate amount and perSpendMax written as decimal strings", async () => {
    const h = load(save(await openHandle()))
    const edited = { ...h, limits: { ...h.limits, lifetimeCap: "1000", perSpendMax: "700", rate: { amount: "50", windowMs: 60_000 } } } as unknown as SuiAllowance
    const { chain, outcome } = await run("remaining", edited)
    const r = (await outcome) as Remaining
    expect(r.active).toBe(true) // read, not thrown: the strings were taken as amounts
    expect(chain.executed).toHaveLength(0)
  })

  it("remaining reads a handle whose expiry is past year 9999, which JSON writes in the extended-year form", async () => {
    const h = load(save(await openHandle()))
    const far = new Date(8.64e15).toISOString()
    expect(far.startsWith("+275760-")).toBe(true)
    const edited = { ...h, limits: { ...h.limits, expiry: far } } as unknown as SuiAllowance
    const { chain, outcome } = await run("remaining", edited)
    const r = (await outcome) as Remaining
    expect(r.limits.map((l) => l.limit)).toContain("expiry")
    expect(chain.executed).toHaveLength(0)
  })
})

/**
 * Not proof against main. Main (1ff8d6a) refused every case in this describe with a TypeError before sending
 * anything; the unlabelled cases fail on main only because main's wording differs, or because main throws first
 * on the fixture's string `lifetimeCap`. They guard against this branch's own earlier commits, which read the
 * persisted forms, from letting a malformed one through.
 */
describe("a persisted limit that is not the persisted form of a limit is refused, naming the field, before anything is sent", () => {
  const DIGITS = (f: string): string => `${f} must be a bigint, or the decimal digits of one as a handle saved as JSON holds it`
  const ROUNDED = (f: string): string => `${f} must be a bigint, or the decimal digits of one as a handle saved as JSON holds it; a JSON number may have been rounded, so it is refused`
  const BIGINT = (f: string): string => `${f} must be a bigint (base units)`
  const ISO = (f: string): string => `${f} must be a Date, or a time in the form Date.prototype.toISOString writes, as a handle saved as JSON holds it`
  const UNKNOWN_KEY = 'limits has an unknown key "__proto__"; the limits are lifetimeCap, rate, start, expiry, recipients, perSpendMax. A misspelled key would be dropped silently, so it is refused.'
  const bad: Array<[string, string, (h: SuiAllowance) => unknown]> = [
    ["lifetimeCap not numeric", DIGITS("limits.lifetimeCap"), (h) => ({ ...h.limits, lifetimeCap: "a lot" })],
    ["lifetimeCap fractional", DIGITS("limits.lifetimeCap"), (h) => ({ ...h.limits, lifetimeCap: "10.5" })],
    ["lifetimeCap negative", DIGITS("limits.lifetimeCap"), (h) => ({ ...h.limits, lifetimeCap: "-5" })],
    ["lifetimeCap empty", DIGITS("limits.lifetimeCap"), (h) => ({ ...h.limits, lifetimeCap: "" })],
    ["lifetimeCap a fractional number", ROUNDED("limits.lifetimeCap"), (h) => ({ ...h.limits, lifetimeCap: 1.5 })],
    ["REGRESSION GUARD, passes on main too, not fix proof: lifetimeCap a boolean", BIGINT("limits.lifetimeCap"), (h) => ({ ...h.limits, lifetimeCap: true })],
    ["REGRESSION GUARD, passes on main too, not fix proof: lifetimeCap null", BIGINT("limits.lifetimeCap"), (h) => ({ ...h.limits, lifetimeCap: null })],
    ["lifetimeCap an enormous digit string", DIGITS("limits.lifetimeCap"), (h) => ({ ...h.limits, lifetimeCap: "9".repeat(5000) })],
    ["rate.amount not numeric", DIGITS("limits.rate.amount"), (h) => ({ ...h.limits, rate: { amount: "x", windowMs: 1000 } })],
    ["perSpendMax not numeric", DIGITS("limits.perSpendMax"), (h) => ({ ...h.limits, perSpendMax: "x" })],
    ["expiry not a date", ISO("limits.expiry"), (h) => ({ ...h.limits, expiry: "tomorrow" })],
    ["expiry an invalid date", ISO("limits.expiry"), (h) => ({ ...h.limits, expiry: "2026-13-45T00:00:00.000Z" })],
    ["expiry null (an invalid Date saved)", "limits.expiry must be a Date", (h) => ({ ...h.limits, expiry: null })],
    ["expiry a number", "limits.expiry must be a Date", (h) => ({ ...h.limits, expiry: NOW })],
    ["start not a date", ISO("limits.start"), (h) => ({ ...h.limits, start: "soon" })],
    ["expiry a day the month does not have", ISO("limits.expiry"), (h) => ({ ...h.limits, expiry: "2026-02-31T00:00:00.000Z" })],
    // JSON.parse makes "__proto__" an own key; a copy that assigns it would swap the prototype instead.
    ["REGRESSION GUARD, passes on main too, not fix proof: a __proto__ key carrying a recipient list", UNKNOWN_KEY, (h) => ({ ...h.limits, ...JSON.parse('{"__proto__":{"recipients":["0xbad"]}}') })],
  ]
  // `revoke` is not in this loop: it never reads the handle's limits, see the last describe.
  for (const verb of ["spend", "remaining"] as const) {
    it.each(bad)(`${verb}: %s`, async (_label, message, mutate) => {
      const h = load(save(await openHandle()))
      const hurt = { ...h, limits: mutate(h) } as unknown as SuiAllowance
      const chain = mockChain(live, BigInt(NOW))
      const core = chain.client.core as unknown as Record<string, (...a: Array<unknown>) => unknown>
      const spies = Object.keys(core).map((k) => vi.spyOn(core, k))
      const sui = suiAllowances({ client: chain.client, network: "sui:testnet" })
      const call =
        verb === "spend" ? () => sui.spend({ signer: agent, allowance: hurt, amount: 1n, recipient: MERCHANT })
          : () => sui.remaining({ allowance: hurt })
      const err = await call().then(() => null, (e: unknown) => e)
      expect(err).toBeInstanceOf(TypeError)
      expect((err as TypeError).message).toBe(`sweetrust-sui ${verb}: ${message}`)
      expect(spies.reduce((n, s) => n + s.mock.calls.length, 0)).toBe(0)
      expect(chain.executed).toHaveLength(0)
    })
  }

  it("REGRESSION GUARD, passes on main too, not fix proof: open() still takes only the typed limits: a string cap is refused there, as before", async () => {
    const chain = mockChain(null, BigInt(NOW))
    const sui = suiAllowances({ client: chain.client, network: "sui:testnet" })
    const err = await sui.open({
      signer: principal, name: "strict",
      allowance: { network: "sui:testnet", asset: "0x2::sui::SUI", spender: A, limits: { lifetimeCap: "1000" as unknown as bigint } },
    }).then(() => null, (e: unknown) => e)
    expect(err).toBeInstanceOf(TypeError)
    expect((err as TypeError).message).toContain("limits.lifetimeCap must be a bigint")
    expect(chain.executed).toHaveLength(0)
  })
})

/**
 * A limit that `Object.keys` cannot see is a limit a copy of the own enumerable keys drops, and a dropped
 * `recipients` or `perSpendMax` lets `spend` pay any address (the cold read of 34624ea). The old code read each
 * limit by name, so a prototype or a getter held it; the persisted-form intake must not be weaker. It refuses the
 * shape instead, by name, before any chain call.
 *
 * Main (1ff8d6a) did not fail open on these shapes: it read each limit by name and refused the spend to 0xbad.
 * These tests fail on main only because their control uses string limits, which main cannot read. What they
 * guard against is the copy-only intake of the intermediate commits 6f2bc8e and 34624ea, not main.
 */
describe("a limits object that is not plain data is refused, so no limit is silently dropped", () => {
  const BAD = normalizeSuiAddress("0xbad")
  /** Limits that are valid for every verb, so a refusal below can only be for the shape. */
  const base = (): Record<string, unknown> => ({ lifetimeCap: "1000", expiry: new Date(NOW + DAY).toISOString() })
  const withProto = (name: string, value: unknown): unknown => Object.assign(Object.create({ [name]: value }) as object, base())
  const withClassGetter = (name: string, value: unknown): unknown => {
    class Held { get [name](): unknown { return value } }
    return Object.assign(new Held(), base())
  }
  const withOwnGetter = (name: string, value: unknown): unknown => Object.defineProperty(base(), name, { get: () => value, enumerable: true })
  const withHidden = (name: string, value: unknown): unknown => Object.defineProperty(base(), name, { value, enumerable: false })
  const PROTO = "limits must be a plain object: its prototype is neither Object.prototype nor null, so a limit on it would go unread and unenforced"
  const hidden = (name: string): string => `limits must be plain data: "${name}" is a getter, a setter or a non-enumerable property, so its value would go unread and unenforced`
  // [label, the same limit as plain data, the shape under test, the message]
  const shapes: Array<[string, Record<string, unknown>, unknown, string]> = []
  for (const [name, value] of [["recipients", [MERCHANT]], ["perSpendMax", "100"]] as const) {
    const plain = { ...base(), [name]: value }
    shapes.push([`${name} inherited from a prototype`, plain, withProto(name, value), PROTO])
    shapes.push([`${name} on a class getter`, plain, withClassGetter(name, value), PROTO])
    shapes.push([`${name} a getter of the object's own`, plain, withOwnGetter(name, value), hidden(name)])
    shapes.push([`${name} non-enumerable`, plain, withHidden(name, value), hidden(name)])
  }
  const spendTo = async (limits: unknown): Promise<{ executed: number; err: unknown; result: { verdict: string } | null }> => {
    const chain = mockChain(live, BigInt(NOW))
    chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: NOW, after: { ...live, currentSpend: 1n } })
    const sui = suiAllowances({ client: chain.client, network: "sui:testnet" })
    const h = { ...load(save(await openHandle())), limits } as unknown as SuiAllowance
    let result: { verdict: string } | null = null
    const err = await sui.spend({ signer: agent, allowance: h, amount: 1n, recipient: BAD }).then((r) => { result = r; return null }, (e: unknown) => e)
    return { executed: chain.executed.length, err, result }
  }

  it.each(shapes)("spend: %s sends nothing and is refused as a shape", async (_label, plain, limits, message) => {
    const control = await spendTo(plain)
    expect(control.err).toBeNull() // the same limit as plain data is read, so the refusal below is for the shape alone
    const { executed, err } = await spendTo(limits)
    expect(executed).toBe(0)
    expect(err).toBeInstanceOf(TypeError)
    expect((err as TypeError).message).toBe(`sweetrust-sui spend: ${message}`)
  })

  it("the control: the same limits as a plain object still refuse the address outside the list (red on main only because these limits are strings)", async () => {
    const { executed, err, result } = await spendTo({ ...base(), recipients: [MERCHANT] })
    expect(err).toBeNull()
    expect(result?.verdict).toBe("refused")
    expect(executed).toBe(0)
  })

  it("a null-prototype or frozen plain object is still plain data, and spend reads it", async () => {
    for (const limits of [Object.assign(Object.create(null) as object, base()), Object.freeze(base())]) {
      const { executed, err, result } = await spendTo({ ...(limits as Record<string, unknown>), recipients: [MERCHANT] })
      expect(err).toBeNull()
      expect(result?.verdict).toBe("refused") // 0xbad is outside the list: the list was read
      expect(executed).toBe(0)
    }
  })

  it("a plain object from another realm (a vm context) is refused: its prototype is not this realm's Object.prototype", async () => {
    const control = await spendTo(base())
    expect(control.err).toBeNull()
    const { executed, err } = await spendTo(runInNewContext(`({ lifetimeCap: "1000", expiry: ${JSON.stringify(new Date(NOW + DAY).toISOString())} })`))
    expect(executed).toBe(0)
    expect(err).toBeInstanceOf(TypeError)
    expect((err as TypeError).message).toBe(`sweetrust-sui spend: ${PROTO}`)
  })

  it("a rate that is not plain data is refused by name too", async () => {
    const control = await spendTo({ ...base(), rate: { amount: "50", windowMs: 60_000 } })
    expect(control.err).toBeNull()
    const rate = Object.defineProperty({ windowMs: 60_000 }, "amount", { value: "50", enumerable: false })
    const { executed, err } = await spendTo({ ...base(), rate })
    expect(executed).toBe(0)
    expect(err).toBeInstanceOf(TypeError)
    expect((err as TypeError).message).toBe(`sweetrust-sui spend: limits.rate must be plain data: "amount" is a getter, a setter or a non-enumerable property, so its value would go unread and unenforced`)
  })

  /**
   * A Proxy answers `ownKeys` and the property descriptors however it likes, so a copy built from those alone
   * can come out empty while an ordinary read still serves the real limits: `spend` would then pay 0xbad,
   * which a read by name refuses. Bigint limits, as open() returned them.
   */
  describe("a Proxy that lies to ownKeys or descriptors", () => {
    const real = (): Record<string, unknown> => ({ lifetimeCap: 1000n, expiry: new Date(NOW + DAY), recipients: [MERCHANT] })
    const NOT_PLAIN = (field: string, name: string): string =>
      `${field}.${name} reads differently from the copy of ${field}'s own properties (for example, a Proxy that hides or changes a key, or an Object.prototype polluted with this limit), so ${field} must be plain data and its value would go unread and unenforced`
    const getOnly = (target: Record<string, unknown>): unknown => new Proxy({}, { get: (_t, k) => target[k as string] })
    const hidesKey = (target: Record<string, unknown>, name: string): unknown =>
      new Proxy(target, { ownKeys: (t) => Reflect.ownKeys(t).filter((k) => k !== name) })
    const lies: Array<[string, Record<string, unknown>, unknown, string]> = [
      ["a get-only Proxy over {}", real(), getOnly(real()), NOT_PLAIN("limits", "lifetimeCap")],
      ["a Proxy whose ownKeys omits recipients", real(), hidesKey(real(), "recipients"), NOT_PLAIN("limits", "recipients")],
      [
        "a Proxy whose getOwnPropertyDescriptor lies about perSpendMax",
        { ...real(), perSpendMax: 100n },
        new Proxy({ ...real(), perSpendMax: 100n }, {
          getOwnPropertyDescriptor: (t, k) => k === "perSpendMax"
            ? { value: 10n ** 12n, writable: true, enumerable: true, configurable: true }
            : Reflect.getOwnPropertyDescriptor(t, k),
        }),
        NOT_PLAIN("limits", "perSpendMax"),
      ],
      [
        "a Proxy around rate",
        { ...real(), rate: { amount: 50n, windowMs: 60_000 } },
        { ...real(), rate: getOnly({ amount: 50n, windowMs: 60_000 }) },
        NOT_PLAIN("limits.rate", "amount"),
      ],
    ]

    it.each(lies)("spend: %s sends nothing and is refused as a shape", async (_label, plain, limits, message) => {
      const control = await spendTo(plain)
      expect(control.err).toBeNull()
      const { executed, err } = await spendTo(limits)
      expect(executed).toBe(0)
      expect(err).toBeInstanceOf(TypeError)
      expect((err as TypeError).message).toBe(`sweetrust-sui spend: ${message}`)
    })

    it("REGRESSION GUARD, passes on main and 917dd62 too, not fix proof: a Proxy that forwards every trap faithfully is read like plain data: the list is enforced", async () => {
      const { executed, err, result } = await spendTo(new Proxy(real(), {}))
      expect(err).toBeNull()
      expect(result?.verdict).toBe("refused") // 0xbad is outside the list: the list was read
      expect(executed).toBe(0)
    })

    /**
     * A Proxy that answers one way until its getPrototypeOf trap has run, then forwards to a target that lacks the
     * limit. Main read only `Object.keys` and one get per name, so it saw the limit and enforced it; the copy runs
     * after the getPrototypeOf trap, so it sees none. The values read first are the ones main read, and the copy
     * must equal them, so this is refused (the cold read of 917dd62, which paid 0xbad).
     */
    const turnsAfterProbe = (name: string, value: unknown): [Record<string, unknown>, unknown] => {
      const target = { lifetimeCap: 1000n, expiry: new Date(NOW + DAY) }
      const answers: Record<string, unknown> = { ...target, [name]: value }
      let probed = false
      const limits = new Proxy(target, {
        getPrototypeOf: (t) => { probed = true; return Reflect.getPrototypeOf(t) },
        get: (t, k) => (probed ? Reflect.get(t, k) : answers[k as string]),
      })
      return [answers, limits]
    }
    it.each([["recipients", [MERCHANT]], ["perSpendMax", 100n]] as const)(
      "spend: a Proxy that drops %s once its getPrototypeOf trap has run sends nothing and is refused",
      async (name, value) => {
        const [plain, limits] = turnsAfterProbe(name, value)
        const control = await spendTo(plain)
        expect(control.err).toBeNull()
        expect(control.result?.verdict).toBe("refused") // main's view of the limits refuses the spend to 0xbad
        expect(control.executed).toBe(0)
        const { executed, err } = await spendTo(limits)
        expect(executed).toBe(0)
        expect(err).toBeInstanceOf(TypeError)
        expect((err as TypeError).message).toBe(`sweetrust-sui spend: ${NOT_PLAIN("limits", name)}`)
      },
    )

    it("REGRESSION GUARD, passes on main too, not fix proof: spend: a recipient list whose answers change once the limits' getPrototypeOf trap has run is enforced as main read it", async () => {
      let probed = false
      const list = new Proxy([MERCHANT], { get: (t, k) => (probed && k === "0" ? BAD : Reflect.get(t, k)) })
      const limits = new Proxy({ lifetimeCap: 1000n, expiry: new Date(NOW + DAY), recipients: list }, {
        getPrototypeOf: (t) => { probed = true; return Reflect.getPrototypeOf(t) },
      })
      const { executed, err, result } = await spendTo(limits)
      expect(err).toBeNull()
      expect(result?.verdict).toBe("refused") // the list is read once, before any other trap, as main read it: [MERCHANT]
      expect(executed).toBe(0)
    })

    it("REGRESSION GUARD, passes on main and 917dd62 too, not fix proof: spend: a recipient list whose answers change once the expiry's getTime has run is read after it, as main read it", async () => {
      let timed = false
      class Timed extends Date { override getTime(): number { timed = true; return super.getTime() } }
      const list = new Proxy([MERCHANT], { get: (t, k) => (!timed && k === "0" ? BAD : Reflect.get(t, k)) })
      const { executed, err, result } = await spendTo({ lifetimeCap: 1000n, expiry: new Timed(NOW + DAY), recipients: list })
      expect(err).toBeNull()
      expect(result?.verdict).toBe("refused") // main read the expiry's time before the list, so it saw [MERCHANT]
      expect(executed).toBe(0)
    })

    it.each([
      ["remaining", hidesKey(real(), "recipients"), NOT_PLAIN("limits", "recipients")],
      ["remaining", turnsAfterProbe("recipients", [MERCHANT])[1], NOT_PLAIN("limits", "recipients")],
    ] as const)("%s: a Proxy is refused too, with no chain call", async (verb, limits, message) => {
      const chain = mockChain(live, BigInt(NOW))
      const core = chain.client.core as unknown as Record<string, (...a: Array<unknown>) => unknown>
      const spies = Object.keys(core).map((k) => vi.spyOn(core, k))
      const sui = suiAllowances({ client: chain.client, network: "sui:testnet" })
      const hurt = { ...load(save(await openHandle())), limits } as unknown as SuiAllowance
      const call = () => sui.remaining({ allowance: hurt })
      const err = await call().then(() => null, (e: unknown) => e)
      expect(err).toBeInstanceOf(TypeError)
      expect((err as TypeError).message).toBe(`sweetrust-sui ${verb}: ${message}`)
      expect(spies.reduce((n, s) => n + s.mock.calls.length, 0)).toBe(0)
      expect(chain.executed).toHaveLength(0)
    })
  })
})

/**
 * Not proof against main, like the describe above: main refused each of these with a TypeError before sending,
 * and the unlabelled cases fail on main only for its wording or its earlier throw on the string `lifetimeCap`.
 * They guard against this branch's own earlier commits.
 */
describe("spend refuses a persisted limit that rounds or rolls over", () => {
  it.each([
    ["REGRESSION GUARD, passes on main too, not fix proof: a JSON number that JSON.parse rounded (999.99999999999999999 reads as 1000)", "limits.lifetimeCap", { lifetimeCap: JSON.parse("999.99999999999999999") as number }],
    ["a whole JSON number for perSpendMax", "limits.perSpendMax", { perSpendMax: 5 }],
    ["a whole JSON number for rate.amount", "limits.rate.amount", { rate: { amount: 50, windowMs: 60_000 } }],
    ["an expiry at T24:00:00Z, which Date.parse rolls into the next day", "limits.expiry", { expiry: "2026-11-22T24:00:00Z" }],
    ["an expiry with minute 60", "limits.expiry", { expiry: "2026-11-22T10:60:00Z" }],
    ["a start with second 60", "limits.start", { start: "2026-11-22T10:00:60Z" }],
  ])("spend: %s", async (_label, field, patch) => {
    const h = load(save(await openHandle()))
    const chain = mockChain(live, BigInt(NOW))
    const sui = suiAllowances({ client: chain.client, network: "sui:testnet" })
    const hurt = { ...h, limits: { ...h.limits, ...patch } } as unknown as SuiAllowance
    const err = await sui.spend({ signer: agent, allowance: hurt, amount: 1n, recipient: MERCHANT }).then(() => null, (e: unknown) => e)
    expect(chain.executed).toHaveLength(0)
    expect(err).toBeInstanceOf(TypeError)
    expect((err as TypeError).message).toContain(field)
  })
})

/**
 * `revoke` never reads the handle's `limits`, in any form (DAN-1593). It deletes the Allowance object, and Sui
 * refuses every later spend against it whatever limits it held, so the limits cannot change what a revoke does.
 * Every case revokes, with `limits: []` on the receipt and the summary saying the limits were not read. The
 * identity fields (network, ids, funder, spender, asset) keep their strict intake, and `spend` and `remaining`
 * keep refusing a handle whose limits are not plain data.
 */
describe("revoke never reads the handle's limits", () => {
  const SAYS = "whatever limits it held, and revoke does not read the handle's limits."
  const base = (): Record<string, unknown> => ({ lifetimeCap: "1000", expiry: new Date(NOW + DAY).toISOString() })
  class Held { get recipients(): unknown { return [MERCHANT] } }
  /** A Proxy whose every trap throws `thrown`: the handler is itself a Proxy that answers any trap name. */
  const allTrapsThrow = (thrown: unknown): unknown => new Proxy({}, new Proxy({}, { get: () => () => { throw thrown } }))
  const forgedTypeError = Object.assign(Object.create(TypeError.prototype) as object, { message: 42 })
  /** Each case builds the whole handle, so one case can put a throwing getter on the handle's `limits` itself. */
  const withLimits = async (limits: unknown): Promise<SuiAllowance> => ({ ...load(save(await openHandle())), limits }) as unknown as SuiAllowance
  const cases: Array<[string, () => Promise<SuiAllowance>]> = [
    ["a plain live handle, as open() returned it (bigints and Dates)", openHandle],
    ["a handle saved as JSON and loaded back", async () => load(save(await openHandle()))],
    ["a class instance", () => withLimits(Object.assign(new Held(), base()))],
    ["a Proxy whose every trap throws a number", () => withLimits(allTrapsThrow(42))],
    ["a Proxy whose every trap throws a TypeError look-alike with a numeric message", () => withLimits(allTrapsThrow(forgedTypeError))],
    ["limits: null", () => withLimits(null)],
    ["limits missing", async () => { const { limits: _gone, ...rest } = load(save(await openHandle())); return rest as unknown as SuiAllowance }],
    ["a lifetimeCap string past u256", () => withLimits({ ...base(), lifetimeCap: `1${"0".repeat(78)}` })],
    ["a rate with windowMs: 0", () => withLimits({ ...base(), rate: { amount: "50", windowMs: 0 } })],
    ["a malformed persisted string (lifetimeCap \"abc\")", () => withLimits({ ...base(), lifetimeCap: "abc" })],
    ["a getter on the handle's limits that throws", async () => Object.defineProperty({ ...load(save(await openHandle())) }, "limits", { get: () => { throw 42 }, enumerable: true }) as unknown as SuiAllowance],
  ]
  const revokeWith = async (h: SuiAllowance): Promise<{ chain: MockChain; receipt: Awaited<ReturnType<ReturnType<typeof suiAllowances>["revoke"]>> }> => {
    const chain = mockChain(live, BigInt(NOW))
    chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: NOW, after: null })
    const sui = suiAllowances({ client: chain.client, network: "sui:testnet" })
    return { chain, receipt: await sui.revoke({ signer: principal, allowance: h }) }
  }

  it.each(cases)("%s: the Allowance is deleted, with no limit lines and the summary saying the limits were not read", async (_label, make) => {
    const { chain, receipt } = await revokeWith(await make())
    expect(receipt.verdict).toBe("executed")
    expect(receipt.refusal).toBeNull()
    expect(chain.executed).toHaveLength(1)
    expect(receipt.limits).toEqual([])
    expect(receipt.summary).toContain(`Sui refuses every later spend against it from any client, ${SAYS}`)
  })

  it("REGRESSION GUARD, passes on main too, not fix proof: the identity fields keep their strict intake: a bad funder or allowance id still throws, and nothing is sent", async () => {
    for (const patch of [{ funder: 5 }, { allowanceId: null }, { network: undefined }]) {
      const chain = mockChain(live, BigInt(NOW))
      const sui = suiAllowances({ client: chain.client, network: "sui:testnet" })
      const hurt = { ...load(save(await openHandle())), ...patch } as unknown as SuiAllowance
      await expect(sui.revoke({ signer: principal, allowance: hurt })).rejects.toThrow(TypeError)
      expect(chain.executed).toHaveLength(0)
    }
  })

  it("REGRESSION GUARD, passes on main too, not fix proof: spend and remaining still refuse what revoke goes through: a class instance, a malformed string, windowMs 0", async () => {
    for (const limits of [Object.assign(new Held(), base()), { ...base(), lifetimeCap: "abc" }, { ...base(), rate: { amount: "50", windowMs: 0 } }]) {
      const chain = mockChain(live, BigInt(NOW))
      const sui = suiAllowances({ client: chain.client, network: "sui:testnet" })
      const hurt = await withLimits(limits)
      await expect(sui.spend({ signer: agent, allowance: hurt, amount: 1n, recipient: MERCHANT })).rejects.toThrow(TypeError)
      await expect(sui.remaining({ allowance: hurt })).rejects.toThrow(TypeError)
      expect(chain.executed).toHaveLength(0)
    }
  })
})
