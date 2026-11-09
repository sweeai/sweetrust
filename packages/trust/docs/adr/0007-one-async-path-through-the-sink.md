---
title:       "ADR 0007: every sink call returns a Promise, so there is one async path"
kind:        adr
status:      accepted
updated:     2026-11-08
owner:       sweetrust maintainers
verified_by: "N/A — narrative until 0.6.0 is built. This records a decision ahead of its code: at this writing makeSink in src/gate/trust.ts is synchronous. The tests that replace this line ship with the async sink."
---

# ADR 0007: every sink call returns a Promise, so there is one async path

**Status:** Accepted, 2026-11-07, when Danny approved the intent-layer spec.
**Implementation:** not started. The package is at 0.5.0, and this decision ships in 0.6.0.
**Force:** invariant once built. The check will be a test that an unjudged sink also returns a Promise. No such test exists yet, so nothing enforces this today.
**Date:** 2026-11-08 · **Tickets:** DAN-1205 (the async judge), DAN-1382 (this record)

## Context

The gate's judgment seam is synchronous. `JudgmentProvider.assess` returns a `JudgmentVerdict`, and
the function `makeSink` returns has the signature `(args: Args) => SinkResult<R>`. No real judge can
answer that way, because a judge is a model behind a network call or an inference step, and its
answer arrives as a Promise.

The seam also fails in the wrong direction when a provider is asynchronous anyway. TypeScript
rejects such a provider, but a JavaScript caller or a cast gets past the type. The sink then reads
the Promise as a verdict with no assessment, and an `assess` that would have resolved to a confident
`mismatch` produces `{ ok: true }`, a `judgment-flagged` receipt and an executed action. We ran this
against 0.5.0 while writing this record.

The intent layer needs a judge that can take seconds, that has a deadline, and that can be
cancelled. So the sink has to wait for it. The open question was how much of the kernel should
change shape in order to wait.

`src/gate/trust.ts` has already answered a version of that question. Its comment on the two argument
paths says that both now use one brand check "so they cannot drift apart — the carry-back failure
this file keeps finding in itself." The same file holds a second copy of the execute-and-record
sequence for flagged actions, and the comment there says "Same hole as the main path (V5)." Two
paths through this function have drifted before.

## Decision

**Every sink call returns a Promise, whether or not the sink is judged, and `assess` has exactly one
return shape.**

1. **The sink is asynchronous.** `makeSink` returns a function that returns a Promise. A judged sink
   awaits the judge before it can call `execute`. The caller's `result` has the type `Awaited<R>`.
2. **An unjudged sink takes the same path.** It has no judge to wait for, and it still returns a
   Promise. A caller never needs to know which kind of sink it holds.
3. **The provider is asynchronous and cancellable.** The signature is
   `assess(input: { purpose, action }, signal: AbortSignal): Promise<{ assessment, confidence, rationale }>`.
   A provider also declares a pinned `model`, and an empty one is a construction-time `TypeError`.
4. **The judge has a deadline.** A judged sink takes `timeoutMs`, which defaults to 5000. The abort
   signal fires at the deadline. In enforce mode the call is held, and a verdict that arrives
   afterward never executes anything.
5. **`execute` is awaited too.** The sink appends the receipt once `execute` settles. If `execute`
   rejects, an `errored` receipt carrying the verdict is recorded. `execute` gains an optional
   second argument, `{ authorizedBy }`, which ADR 0008 relies on.

## Alternatives considered

1. **`assess` returns `V | Promise<V>`, and the sink is async only when judged** (DAN-1205, option
   a). Rejected. One function would have two return shapes, a caller would have to know which sink
   it holds, and the sync and async paths would drift apart in the way this file has recorded.
2. **A separate `makeJudgedSink`** (DAN-1205, option c). Rejected. It has the same drift, and it
   makes an unjudged sink the easy default for moving money.

## Consequences

- **This is a breaking change in 0.6.0.** Every sink call site must await. `assess` takes one input
  object and a signal instead of `(action, args)`. The CHANGELOG entry for 0.6.0 must record both under
  Changed.
- **A forgotten `await` is a hazard in untyped code.** A caller that does not await reads `ok` from
  a Promise and gets `undefined`, while the action proceeds. TypeScript reports the mistake as a
  compile error, and JavaScript does not. The 0.6.0 migration note must say so.
- **An unjudged sink pays for a Promise it does not need.** We accept that cost in exchange for one
  path through the function.
- **The asynchronous failure above closes.** In enforce mode, there is no longer a shape a provider
  can return that the sink misreads as a verdict and then executes on. A rejected, late or malformed
  answer never reaches `execute`.
