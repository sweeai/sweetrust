# Security — `sweetrust-sui`

## Reporting a vulnerability

Open a [security advisory](https://github.com/sweeai/sweetrust/security/advisories/new) rather than
a public issue.

## Honest limits

What this package does **not** protect, stated before you find it yourself. The README carries the
same list.

- **A hijacked host can spend whatever the chain allows.** The spender's key lives on the host.
  Anyone holding it can spend up to the limits Sui holds (lifetime cap, rate, start, expiry),
  through any client, to anyone. Only `revoke`, signed by the funder, stops it.
- **`requireAuthorization` is in-process.** It spends a `SpendAuthorization` a sink issued, once, for
  one payment. A token is only as strong as the process holding it: code in the same process that
  reaches an execute context holds the token, and the spender's key can pay through another client
  regardless.
- **Library-held limits bind only spends routed through this library.** The recipient list is
  checked in-process before sending, and it lives in the handle `open()` returns, not on chain.
- **Sui's rate window is fixed, not rolling.** Up to twice the rate can pass across a window
  boundary.
- **No per-spend maximum in 0.1.** `open()` refuses one rather than drop it.
- **A receipt is this library's account.** It enters a SweeTrust log at tier `untrusted`; the
  transaction digest beside it is what a stranger checks on chain.
- **`chainSpends` trusts an unauthenticated indexer.** Nothing proves its answer, so a lying or
  lagging indexer can hide or invent a spend. It can also over-report: a spender can name a
  withdrawal it never redeems, and that lists as a spend. Over-reporting fails closed
  (`packages/trust/SECURITY.md`, "`chainSpends` and `reconcile` trust an unauthenticated indexer").
- **The kernel's `revokeMandate` does not stop money.** Revoking a SweeTrust mandate writes to the
  kernel's audit log; only `revoke` here deletes the on-chain allowance (`packages/trust/SECURITY.md`,
  "Revoking here does not stop money a chain already holds").
