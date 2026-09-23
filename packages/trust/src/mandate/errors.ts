/**
 * MandateFailure — the Error every mandate refusal is thrown as (DAN-1159 item 4c).
 *
 * Mandate used to throw the bare `MandateError` object: `instanceof Error`
 * false, `message` and `stack` undefined, `String(e)` "[object Object]". Every
 * generic handler (Sentry, pino, `catch (e) { log(e.message) }`) recorded
 * `undefined` for a security refusal.
 *
 * Three properties are deliberate, and each is pinned by a test:
 *   · The union's fields are OWN properties of the instance, `_tag` first, so
 *     `e._tag` and every variant field read exactly as before. Consumers switch
 *     on `error._tag` today; a wrapper shape (`e.error._tag`) would break them.
 *   · `message` is the `_tag` ALONE. A field can carry an attacker's text
 *     (`MaliciousMandateMetadata.evidence` is the injected rationale itself),
 *     and a message reaches every log title and any model that reads the logs.
 *   · `name` lives on the PROTOTYPE, so `JSON.stringify(e)` is exactly the plain
 *     union it always was. An own `name` would be an enumerable key.
 *
 * One behavior does change: `structuredClone` of an Error keeps only name,
 * message, stack and cause (the HTML structured-clone rules), so `_tag` does
 * not survive a `postMessage` or a worker boundary. Send `{ ...e }` instead.
 */
import type { MandateError } from "./types.ts"

export class MandateFailure extends Error {
  static {
    this.prototype.name = "MandateFailure"
  }

  constructor(error: MandateError) {
    super(error._tag)
    Object.assign(this, error)
  }

  /**
   * Narrow a caught value to a refusal whose fields the compiler can see:
   * `if (MandateFailure.is(e)) switch (e._tag) { … }`. The same idiom as
   * gate's `Sourced.is()`.
   */
  static is(e: unknown): e is MandateFailure & MandateError {
    return e instanceof MandateFailure
  }
}
