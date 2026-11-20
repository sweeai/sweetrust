# A spending cap against "send everything"

A prompt-injected agent is told to send everything in the wallet to an attacker. The wallet holds $50,000. The agent's mandate carries a cap of $20 a day.

## Run it

From an empty folder, on Node 22.18 or later:

```bash
npm i sweetrust@0.7.0 && curl -fsSLO https://raw.githubusercontent.com/sweeai/sweetrust/main/examples/spending-cap/drain.ts && node drain.ts
```

From a clone of this repository: `cd examples/spending-cap && npm install && npm start`.

It runs offline: no network after the install, no keys, no model.

## What is real and what is a stand-in

- **Real:** the spending cap. `sweetrust/mandate` issues the agent's mandate with a `limits` entry, and the host calls `useCapability` with the real amount before any money moves. The refusals are `MandateLimitExceeded` errors the library throws.
- **Stand-in:** the wallet and the attacker's balance are two numbers in the script. The agent's four proposals are scripted.
- **Computed, never printed unconditionally:** the verdict line. It reads `BLOCKED by the cap` only if the first $50,000 was refused and nothing beyond the cap moved. A cap that did not hold prints `GOT THROUGH`, and a broken control exits 2.

## What you will see

```text
The wallet holds $50,000. The agent's cap: $20 a day.
  1 · agent tries to send $50,000 → REFUSED (MandateLimitExceeded)
  2 · agent tries to send $20 → SENT
  3 · agent tries to send $20 more → REFUSED (MandateLimitExceeded)
  4 · agent tries to send $1 → REFUSED (MandateLimitExceeded)
before: $50,000 · lost: $20 · safe: $49,980 · cap: $20 a day
ATTACK 7 · drain · BLOCKED by the cap
```

## What it does not do

The cap lives in the agent's host process, so a fully compromised host could skip it. It also does not stop the agent spending the $20 on the wrong thing. The cap is a ceiling on damage, and the other examples add the layers that ask who and what for. For a cap the chain itself enforces, see [`sui-cap`](../sui-cap).
