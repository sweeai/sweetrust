/**
 * humanConfirm is async (0.5.0).
 *
 * Through 0.4.0 the signature was `render: (question) => boolean` and the
 * verdict came back synchronously, so a human who answers over a network (a
 * phone, a voice call, a chat approval) could not be asked at all: an async
 * renderer's Promise was refused unread, by design, because it had not been
 * answered yet. A stranger's review of 0.4.0 named it (2026-10-31): the ask
 * tier of an agent harness is exactly the human on the other end of a wire.
 *
 * The shape now: `render` returns `boolean | Promise<boolean>`, and the verdict
 * is always `Promise<DeclassifyResult<T>>`. These cases pin what that must not
 * cost:
 *   - the async answer is honored, yes and no
 *   - a renderer that throws or rejects is a refusal, never an exception
 *   - a synchronous renderer still works
 *   - the question is built at the call, before any time passes
 *   - a caller who forgets `await` holds something whose `.ok` is not true
 */
import { describe, expect, it } from "vitest"
import { humanConfirm, Sourced, type DeclassifyResult } from "../../src/gate/trust.js"

const candidate = () => Sourced.fromChannel("ACME-8817", "email-inbound")

/** A human on the other end of a wire: answers after a real turn of the event loop. */
const later = <A>(answer: A, ms = 5) => new Promise<A>((resolve) => setTimeout(() => resolve(answer), ms))

describe("humanConfirm — an async human", () => {
  it("an async yes confirms: the value ascends to verified once the answer arrives", async () => {
    const r = await humanConfirm(candidate(), () => later(true))
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.tier).toBe("verified")
    expect(r.value.value).toBe("ACME-8817")
    const last = r.value.provenance.chain.at(-1)!
    expect(last.declassifier).toBe("humanConfirm")
    expect(last.from).toBe("untrusted")
    expect(last.to).toBe("verified")
  })

  it("an async no is a refusal, and the reason carries the question the human saw", async () => {
    const r = await humanConfirm(candidate(), () => later(false))
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toContain("declined")
    expect(r.reason).toContain("UNTRUSTED (origin: channel:email-inbound")
  })

  it("an `async` function renderer works the same as a Promise-returning one", async () => {
    expect((await humanConfirm(candidate(), async () => true)).ok).toBe(true)
    expect((await humanConfirm(candidate(), async () => false)).ok).toBe(false)
  })
})

describe("humanConfirm — no answer is a refusal (fail closed)", () => {
  it("a renderer that REJECTS is refused, not raised", async () => {
    const run = humanConfirm(candidate(), () => Promise.reject(new Error("call dropped")))
    await expect(run).resolves.toMatchObject({ ok: false })
    const r = await humanConfirm(candidate(), () => Promise.reject(new Error("call dropped")))
    if (r.ok) throw new Error("a rejected render confirmed")
    expect(r.reason).toContain("threw or rejected")
    expect(r.reason).toContain("call dropped")
  })

  it("a renderer that rejects LATER (after a real wait) is refused", async () => {
    const r = await humanConfirm(candidate(), () => later(null).then(() => { throw new Error("timed out") }))
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain("timed out")
  })

  it("a renderer that THROWS synchronously is refused, not raised", async () => {
    const r = await humanConfirm(candidate(), () => {
      throw new Error("no terminal attached")
    })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain("no terminal attached")
  })

  it("a renderer that rejects with a non-Error is refused, naming it", async () => {
    const r = await humanConfirm(candidate(), () => Promise.reject("hung up"))
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain("hung up")
  })

  it("a rejection reason that cannot be rendered is still a refusal, not a throw", async () => {
    // String(Object.create(null)) throws: building the reason must not.
    const r = await humanConfirm(candidate(), () => Promise.reject(Object.create(null)))
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain("could not be rendered")
  })

  it("the caller's own timeout turns a silent human into a refusal", async () => {
    const silent = new Promise<boolean>(() => {}) // never settles
    const withTimeout = (p: Promise<boolean>, ms: number) =>
      Promise.race([p, new Promise<boolean>((_, reject) => setTimeout(() => reject(new Error(`no answer in ${ms}ms`)), ms))])
    const r = await humanConfirm(candidate(), () => withTimeout(silent, 5))
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain("no answer in 5ms")
  })
})

describe("humanConfirm — the shape", () => {
  it("a synchronous renderer still works, yes and no", async () => {
    const yes = await humanConfirm(candidate(), () => true)
    expect(yes.ok).toBe(true)
    if (yes.ok) expect(yes.value.tier).toBe("verified")
    expect((await humanConfirm(candidate(), () => false)).ok).toBe(false)
  })

  it("the question is built and asked at the call, before any time passes", () => {
    let asked: string | undefined
    void humanConfirm(candidate(), (q) => {
      asked = q
      return later(false)
    })
    // No await yet: the renderer has already been handed the question.
    expect(asked).toContain("UNTRUSTED (origin: channel:email-inbound")
    expect(asked).toContain('"ACME-8817"')
  })

  it("the verdict is always a Promise, even for a synchronous renderer", () => {
    const p = humanConfirm(candidate(), () => true)
    expect(p).toBeInstanceOf(Promise)
    return p
  })

  it("a caller who forgets `await` reads no confirmation (the forgotten await fails closed)", async () => {
    // What a JavaScript caller with no compiler sees: `if (r.ok) spend(r.value)`.
    const pending = humanConfirm(candidate(), () => true)
    const r = pending as unknown as DeclassifyResult<string> // the caller's mistaken belief
    expect(pending).toBeInstanceOf(Promise)
    expect(r.ok).not.toBe(true)
    expect((r as { value?: unknown }).value).toBeUndefined()
    // The SAME call, awaited, is a yes: so the unawaited read above hid a real
    // confirmation, which is the case where failing closed matters.
    const settled = await pending
    expect(settled.ok).toBe(true)
  })
})

describe("humanConfirm pins the value the human was asked about (0.5.0 review)", () => {
  it("a caller that rewrites its object while the human decides cannot change what ascends", async () => {
    const payee = { name: "Alice", iban: "GB00-ALICE" }
    let asked = ""
    const pending = humanConfirm(Sourced.fromChannel(payee, "email-inbound"), async (q) => {
      asked = q
      await new Promise((r) => setTimeout(r, 10))
      return true
    })
    payee.iban = "DE99-EVIL" // after the question, before the answer
    const r = await pending
    expect(asked).toContain("GB00-ALICE")
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.value.value.iban).toBe("GB00-ALICE")
      expect(r.value.value).not.toBe(payee)
    }
  })

  it("a nested object is pinned too, not only the top level", async () => {
    const order = { item: "book", ship: { to: "Torrance" } }
    const pending = humanConfirm(Sourced.fromChannel(order, "email-inbound"), async () => {
      await new Promise((r) => setTimeout(r, 10))
      return true
    })
    order.ship.to = "Attacker St"
    const r = await pending
    expect(r.ok && r.value.value.ship.to).toBe("Torrance")
  })

  it("a value that cannot be copied is refused, and the human is never asked", async () => {
    let asked = false
    const r = await humanConfirm(Sourced.fromChannel({ run: () => 1 }, "email-inbound"), () => {
      asked = true
      return true
    })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toContain("could not be copied")
    expect(asked).toBe(false)
  })
})
